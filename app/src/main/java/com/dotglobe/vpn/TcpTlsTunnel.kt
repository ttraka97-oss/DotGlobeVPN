package com.dotglobe.vpn

import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate
import kotlin.concurrent.thread

/**
 * TCP/TLS Tunnel — connects via SSL with custom SNI.
 * Supports payload injection (bug host fronting).
 * Used for: TCP, TLS, SNI-based configs with custom payloads.
 */
class TcpTlsTunnel {

    private var sslSocket: SSLSocket? = null
    private var socksServer: java.net.ServerSocket? = null
    private var isRunning = false
    private var localSocksPort = 0

    interface TunnelCallback {
        fun onConnected()
        fun onDisconnected()
        fun onError(message: String)
        fun onLog(message: String)
        fun onStats(download: Long, upload: Long)
    }

    private var config_host = ""
    private var config_port = 0
    private var config_sni = ""

    fun connect(config: ConfigParser.VpnConfig, callback: TunnelCallback) {
        if (isRunning) {
            callback.onError("النفق يعمل بالفعل")
            return
        }

        config_host = config.host
        config_port = config.port
        config_sni = config.sni

        thread {
            try {
                callback.onLog("بدء اتصال TCP/TLS · ${config.host}:${config.port}")

                // Create SSL context that trusts all (for bug hosts)
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, arrayOf<TrustManager>(object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
                    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                }), java.security.SecureRandom())

                val factory = sslContext.socketFactory
                val socket = factory.createSocket() as SSLSocket

                // Configure TLS
                socket.enabledProtocols = arrayOf("TLSv1.2", "TLSv1.3")

                // Set SNI if provided
                val sniHost = if (config.sni.isNotEmpty()) config.sni else config.host
                try {
                    val params = socket.sslParameters
                    params.serverNames = listOf(javax.net.ssl.SNIHostName(sniHost))
                    socket.sslParameters = params
                } catch (e: Exception) {
                    callback.onLog("SNI: ${e.message}")
                }

                // Connect to server
                socket.connect(InetSocketAddress(config.host, config.port), 15000)
                socket.startHandshake()
                sslSocket = socket

                callback.onLog("تم اتصال TLS · SNI: $sniHost")

                // Send payload if provided (HTTP CONNECT or custom fronting)
                if (config.payload.isNotEmpty()) {
                    val payloadOut = socket.outputStream
                    payloadOut.write(config.payload.toByteArray())
                    payloadOut.flush()
                    callback.onLog("تم إرسال البايلود")
                }

                // Create SOCKS proxy
                socksServer = java.net.ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"))
                localSocksPort = socksServer?.localPort ?: 0
                isRunning = true

                callback.onLog("SOCKS proxy على المنفذ $localSocksPort")
                callback.onConnected()

                // Accept and route connections
                var totalDown = 0L
                var totalUp = 0L

                while (isRunning) {
                    try {
                        val client = socksServer?.accept() ?: break
                        thread {
                            try {
                                handleSocksClient(client, socket, callback)
                                synchronized(this) {
                                    totalDown += 2048
                                    totalUp += 1024
                                    callback.onStats(totalDown, totalUp)
                                }
                            } catch (_: Exception) {}
                        }
                    } catch (e: Exception) {
                        if (isRunning) callback.onLog("خطأ: ${e.message}")
                        break
                    }
                }

            } catch (e: Exception) {
                callback.onError("فشل TCP/TLS: ${e.message}")
                disconnect(callback)
            }
        }
    }

    private fun handleSocksClient(client: Socket, sslSocket: SSLSocket, callback: TunnelCallback) {
        val input = client.getInputStream()
        val output = client.getOutputStream()

        // SOCKS5 greeting
        val ver = input.read()
        if (ver != 5) { client.close(); return }
        val nmethods = input.read()
        val methods = ByteArray(nmethods)
        input.read(methods)
        output.write(byteArrayOf(5, 0))
        output.flush()

        // SOCKS5 request
        input.read() // ver
        val cmd = input.read()
        input.read() // reserved
        val atyp = input.read()

        val dstHost: String = when (atyp) {
            1 -> {
                val addr = ByteArray(4)
                input.read(addr)
                java.net.InetAddress.getByAddress(addr).hostAddress ?: ""
            }
            3 -> {
                val len = input.read()
                val domain = ByteArray(len)
                input.read(domain)
                String(domain, Charsets.UTF_8)
            }
            else -> { client.close(); return }
        }

        val portHi = input.read()
        val portLo = input.read()
        val dstPort = (portHi shl 8) or portLo

        callback.onLog("توجيه TLS: $dstHost:$dstPort")

        try {
            // Open a new SSL connection for this destination through the bug host
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            }), java.security.SecureRandom())

            val remoteSocket = sslContext.socketFactory.createSocket() as SSLSocket
            val sniHost = if (config_sni.isNotEmpty()) config_sni else dstHost
            try {
                val params = remoteSocket.sslParameters
                params.serverNames = listOf(javax.net.ssl.SNIHostName(sniHost))
                remoteSocket.sslParameters = params
            } catch (_: Exception) {}

            remoteSocket.connect(InetSocketAddress(config_host, config_port), 10000)
            remoteSocket.startHandshake()

            // Send CONNECT request
            val connectReq = "CONNECT $dstHost:$dstPort HTTP/1.1\r\nHost: $sniHost\r\n\r\n"
            remoteSocket.outputStream.write(connectReq.toByteArray())
            remoteSocket.outputStream.flush()

            // Read response
            val resp = ByteArray(1024)
            val respLen = remoteSocket.inputStream.read(resp)
            val respStr = String(resp, 0, respLen.coerceAtLeast(0))

            if (respStr.contains("200") || respStr.contains("OK")) {
                output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
                output.flush()

                // Bridge traffic
                val t1 = thread { pipe(input, remoteSocket.outputStream) }
                val t2 = thread { pipe(remoteSocket.inputStream, output) }
                t1.join()
                t2.join()
            } else {
                output.write(byteArrayOf(5, 1, 0, 1, 0, 0, 0, 0, 0, 0))
                output.flush()
            }

            remoteSocket.close()
        } catch (e: Exception) {
            output.write(byteArrayOf(5, 1, 0, 1, 0, 0, 0, 0, 0, 0))
            output.flush()
        }

        client.close()
    }

    private fun pipe(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(8192)
        try {
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                output.write(buffer, 0, read)
                output.flush()
            }
        } catch (_: Exception) {}
    }

    fun disconnect(callback: TunnelCallback? = null) {
        isRunning = false
        try { socksServer?.close() } catch (_: Exception) {}
        try { sslSocket?.close() } catch (_: Exception) {}
        socksServer = null
        sslSocket = null
        callback?.onDisconnected()
    }

    fun getSocksPort(): Int = localSocksPort
    fun isRunning(): Boolean = isRunning
}

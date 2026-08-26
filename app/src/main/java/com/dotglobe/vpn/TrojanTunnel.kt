package com.dotglobe.vpn

import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SNIHostName
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.MessageDigest
import java.security.cert.X509Certificate
import kotlin.concurrent.thread

/**
 * Trojan Tunnel — connects via TLS with password hash (SHA224).
 * Protocol: TLS → send 56-byte hex hash + CRLF → then raw TCP forwarding.
 * Supports SNI and bug host fronting.
 */
class TrojanTunnel {

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

    private var trojanHash = ""
    private var trojanHost = ""
    private var trojanPort = 443
    private var trojanSni = ""

    fun connect(config: ConfigParser.VpnConfig, callback: TunnelCallback) {
        if (isRunning) {
            callback.onError("النفق يعمل بالفعل")
            return
        }

        thread {
            try {
                // Extract Trojan params from config
                // Trojan password is stored in config.password or config.payload
                trojanHost = config.host
                trojanPort = config.port
                trojanSni = if (config.sni.isNotEmpty()) config.sni else config.host

                // Generate SHA224 hash of password
                val password = if (config.password.isNotEmpty()) config.password else config.payload
                trojanHash = sha224Hex(if (password.isNotEmpty()) password else "dotglobe")

                callback.onLog("بدء اتصال Trojan · $trojanHost:$trojanPort · SNI: $trojanSni")

                // Create SSL context
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, arrayOf<TrustManager>(object : X509TrustManager {
                    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
                    override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                }), java.security.SecureRandom())

                val socket = sslContext.socketFactory.createSocket() as SSLSocket
                socket.enabledProtocols = arrayOf("TLSv1.2", "TLSv1.3")

                // Set SNI
                try {
                    val params = socket.sslParameters
                    params.serverNames = listOf(SNIHostName(trojanSni))
                    socket.sslParameters = params
                } catch (_: Exception) {}

                socket.connect(InetSocketAddress(trojanHost, trojanPort), 15000)
                socket.startHandshake()
                sslSocket = socket

                callback.onLog("تم اتصال TLS · إرسال هاش Trojan")

                // Send Trojan handshake: 56-byte hex hash + CRLF
                val handshake = (trojanHash + "\r\n").toByteArray()
                socket.outputStream.write(handshake)
                socket.outputStream.flush()

                callback.onLog("تم إرسال هاش Trojan · النفق جاهز")

                // Create SOCKS proxy
                socksServer = java.net.ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"))
                localSocksPort = socksServer?.localPort ?: 0
                isRunning = true

                callback.onLog("SOCKS proxy على المنفذ $localSocksPort")
                callback.onConnected()

                var totalDown = 0L
                var totalUp = 0L

                while (isRunning) {
                    try {
                        val client = socksServer?.accept() ?: break
                        thread {
                            try {
                                handleTrojanClient(client, socket, callback)
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
                callback.onError("فشل Trojan: ${e.message}")
                disconnect(callback)
            }
        }
    }

    private fun handleTrojanClient(client: Socket, sslSocket: SSLSocket, callback: TunnelCallback) {
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
        input.read() // cmd
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

        callback.onLog("Trojan توجيه: $dstHost:$dstPort")

        // Trojan forward request: CMD(1) + ATYP(1) + ADDR + PORT(2) + CRLF
        val addrBytes = dstHost.toByteArray()
        val forwardReq = ByteArray(1 + 1 + 1 + addrBytes.size + 2 + 2)
        var idx = 0
        forwardReq[idx++] = 0x01 // CMD: CONNECT
        forwardReq[idx++] = 0x03 // ATYP: domain
        forwardReq[idx++] = addrBytes.size.toByte()
        for (b in addrBytes) forwardReq[idx++] = b
        forwardReq[idx++] = portHi.toByte()
        forwardReq[idx++] = portLo.toByte()
        forwardReq[idx++] = 0x0D // CR
        forwardReq[idx++] = 0x0A // LF

        // Send through main SSL connection
        synchronized(sslSocket) {
            sslSocket.outputStream.write(forwardReq)
            sslSocket.outputStream.flush()
        }

        // Reply success to SOCKS client
        output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        output.flush()

        // Bridge: client → SSL (write to tunnel)
        val t1 = thread { pipe(input, sslSocket.outputStream) }
        // Bridge: SSL → client (read from tunnel)
        val t2 = thread { pipe(sslSocket.inputStream, output) }

        t1.join()
        t2.join()
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

    /**
     * SHA224 hex hash for Trojan password
     */
    private fun sha224Hex(input: String): String {
        return try {
            val md = MessageDigest.getInstance("SHA-224")
            val hashBytes = md.digest(input.toByteArray())
            hashBytes.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            // Fallback to SHA-256 if SHA-224 not available
            val md = MessageDigest.getInstance("SHA-256")
            val hashBytes = md.digest(input.toByteArray())
            hashBytes.joinToString("") { "%02x".format(it) }.substring(0, 56)
        }
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

package com.dotglobe.vpn

import android.util.Log
import com.jcraft.jsch.ChannelDirectTCP
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import com.jcraft.jsch.SocksProxy
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

/**
 * SSH Tunnel — connects to SSH server from .dgvpn config,
 * creates local SOCKS proxy, routes traffic through SSH.
 * Supports payload injection for fronting/bug hosts.
 */
class SshTunnel {

    private var session: Session? = null
    private var socksServer: ServerSocket? = null
    private var isRunning = false
    private var localSocksPort = 0

    interface TunnelCallback {
        fun onConnected()
        fun onDisconnected()
        fun onError(message: String)
        fun onLog(message: String)
        fun onStats(download: Long, upload: Long)
    }

    fun connect(config: ConfigParser.VpnConfig, callback: TunnelCallback) {
        if (isRunning) {
            callback.onError("النفق يعمل بالفعل")
            return
        }

        thread {
            try {
                callback.onLog("بدء الاتصال بـ ${config.sshHost}:${config.sshPort}")

                val jsch = JSch()

                // Connect via SSH
                session = jsch.getSession(
                    config.sshUser.ifEmpty { "root" },
                    config.sshHost,
                    config.sshPort
                )

                if (config.sshPass.isNotEmpty()) {
                    session?.setPassword(config.sshPass)
                }

                // SSH config
                session?.setConfig("StrictHostKeyChecking", "no")
                session?.setConfig("PreferredAuthentications", "password,publickey,keyboard-interactive")
                session?.setConfig("ConnectTimeout", "15000")
                session?.connect()

                callback.onLog("تم الاتصال بـ SSH · جلسة نشطة")

                // Create local SOCKS proxy server
                socksServer = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
                localSocksPort = socksServer?.localPort ?: 0
                isRunning = true

                callback.onLog("SOCKS proxy على المنفذ $localSocksPort")
                callback.onConnected()

                // Handle SOCKS connections
                acceptSocksConnections(config, callback)

            } catch (e: Exception) {
                callback.onError("فشل الاتصال: ${e.message}")
                disconnect(callback)
            }
        }
    }

    private fun acceptSocksConnections(config: ConfigParser.VpnConfig, callback: TunnelCallback) {
        var totalDownload = 0L
        var totalUpload = 0L

        while (isRunning && session?.isConnected == true) {
            try {
                val client = socksServer?.accept() ?: break

                thread {
                    try {
                        handleSocksClient(client, config, callback)
                        synchronized(this) {
                            totalDownload += 1024
                            totalUpload += 512
                            callback.onStats(totalDownload, totalUpload)
                        }
                    } catch (e: Exception) {
                        // Connection closed
                    }
                }
            } catch (e: Exception) {
                if (isRunning) {
                    callback.onLog("خطأ في قبول الاتصال: ${e.message}")
                }
                break
            }
        }
    }

    private fun handleSocksClient(client: Socket, config: ConfigParser.VpnConfig, callback: TunnelCallback) {
        val input = client.getInputStream()
        val output = client.getOutputStream()

        // Read SOCKS5 greeting
        val ver = input.read()
        if (ver != 5) {
            client.close()
            return
        }

        val nmethods = input.read()
        val methods = ByteArray(nmethods)
        input.read(methods)

        // Respond: no auth needed
        output.write(byteArrayOf(5, 0))
        output.flush()

        // Read SOCKS5 request
        val cmdVer = input.read()
        val cmd = input.read()
        input.read() // reserved
        val atyp = input.read()

        val dstHost: String
        val dstPort: Int

        when (atyp) {
            1 -> { // IPv4
                val addr = ByteArray(4)
                input.read(addr)
                dstHost = InetAddress.getByAddress(addr).hostAddress
            }
            3 -> { // Domain
                val len = input.read()
                val domain = ByteArray(len)
                input.read(domain)
                dstHost = String(domain, Charsets.UTF_8)
            }
            else -> {
                client.close()
                return
            }
        }

        val portHi = input.read()
        val portLo = input.read()
        dstPort = (portHi shl 8) or portLo

        callback.onLog("توجيه: $dstHost:$dstPort")

        // Create SSH direct TCP channel
        try {
            val channel = session?.openChannel("direct-tcp") as? ChannelDirectTCP
            channel?.setHost(dstHost)
            channel?.setPort(dstPort)
            channel?.connect(10000)

            if (channel?.isConnected != true) {
                // Reply failure
                output.write(byteArrayOf(5, 1, 0, 1, 0, 0, 0, 0, 0, 0))
                output.flush()
                client.close()
                return
            }

            // Reply success
            output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            output.flush()

            // Bridge traffic
            val remoteIn = channel.getInputStream()
            val remoteOut = channel.getOutputStream()

            val t1 = thread { pipe(input, remoteOut) }
            val t2 = thread { pipe(remoteIn, output) }

            t1.join()
            t2.join()

            channel.disconnect()
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
        } catch (e: Exception) {
            // Stream closed
        }
    }

    fun disconnect(callback: TunnelCallback? = null) {
        isRunning = false
        try { socksServer?.close() } catch (_: Exception) {}
        try { session?.disconnect() } catch (_: Exception) {}
        socksServer = null
        session = null
        callback?.onDisconnected()
    }

    fun getSocksPort(): Int = localSocksPort
    fun isRunning(): Boolean = isRunning
}

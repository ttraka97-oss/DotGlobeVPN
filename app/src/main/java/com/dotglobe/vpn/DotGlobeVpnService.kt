package com.dotglobe.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel
import kotlin.concurrent.thread

class DotGlobeVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private var sshTunnel: SshTunnel? = null
    private var currentConfig: ConfigParser.VpnConfig? = null

    companion object {
        const val ACTION_CONNECT = "com.dotglobe.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.dotglobe.vpn.DISCONNECT"
        const val EXTRA_CONFIG = "config_json"
        private const val CHANNEL_ID = "dotglobe_vpn"
        private const val NOTIF_ID = 1
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val configJson = intent.getStringExtra(EXTRA_CONFIG) ?: return START_NOT_STICKY
                val config = ConfigParser.parse(configJson)
                if (config != null) {
                    currentConfig = config
                    startVpn(config)
                }
            }
            ACTION_DISCONNECT -> stopVpn()
        }
        return START_STICKY
    }

    private fun startVpn(config: ConfigParser.VpnConfig) {
        if (isRunning) return

        // Start SSH tunnel first
        sshTunnel = SshTunnel()
        sshTunnel?.connect(config, object : SshTunnel.TunnelCallback {
            override fun onConnected() {
                // Once SSH is connected, establish VPN interface
                establishVpnInterface(config)
            }
            override fun onDisconnected() {
                stopVpn()
            }
            override fun onError(message: String) {
                Log.e("DotGlobeVPN", "Tunnel error: $message")
                stopVpn()
            }
            override fun onLog(message: String) {
                Log.i("DotGlobeVPN", message)
            }
            override fun onStats(download: Long, upload: Long) {
                // Stats could be sent to UI via broadcast
            }
        })
    }

    private fun establishVpnInterface(config: ConfigParser.VpnConfig) {
        try {
            val builder = Builder()
                .setSession("DotGlobe VPN")
                .addAddress("10.8.0.2", 24)
                .addDnsServer(config.dns.ifEmpty { "1.1.1.1" })
                .addRoute("0.0.0.0", 0)
                .setMtu(1420)
                .setBlocking(true)

            // Allow apps to bypass if needed
            try {
                builder.addDisallowedApplication(packageName)
            } catch (_: Exception) {}

            vpnInterface = builder.establish()

            if (vpnInterface != null) {
                isRunning = true
                startForeground(NOTIF_ID, createNotification("DotGlobe VPN — متصل · ${config.name}"))

                // Start packet routing loop
                startPacketRouting()
            }
        } catch (e: Exception) {
            Log.e("DotGlobeVPN", "VPN interface error: ${e.message}")
            stopVpn()
        }
    }

    private fun startPacketRouting() {
        val pfd = vpnInterface ?: return

        thread {
            val input = FileInputStream(pfd.fileDescriptor)
            val output = FileOutputStream(pfd.fileDescriptor)
            val buffer = ByteArray(32767)

            try {
                while (isRunning && !Thread.interrupted()) {
                    val length = input.read(buffer)
                    if (length <= 0) continue

                    // Route packet through SOCKS proxy
                    val packet = buffer.copyOfRange(0, length)

                    // Parse IP header
                    if (packet.size < 20) continue
                    val version = (packet[0].toInt() shr 4) and 0x0F
                    if (version != 4) continue

                    // Get destination IP
                    val dstAddr = String.format("%d.%d.%d.%d",
                        packet[16].toInt() and 0xFF,
                        packet[17].toInt() and 0xFF,
                        packet[18].toInt() and 0xFF,
                        packet[19].toInt() and 0xFF
                    )

                    // Get source IP
                    val srcAddr = String.format("%d.%d.%d.%d",
                        packet[12].toInt() and 0xFF,
                        packet[13].toInt() and 0xFF,
                        packet[14].toInt() and 0xFF,
                        packet[15].toInt() and 0xFF
                    )

                    val protocol = packet[9].toInt() and 0xFF
                    val socksPort = sshTunnel?.getSocksPort() ?: 0

                    if (socksPort > 0) {
                        // Route TCP through SOCKS
                        if (protocol == 6) { // TCP
                            routeThroughSocks(packet, dstAddr, socksPort, output)
                        } else if (protocol == 17) { // UDP
                            // Forward DNS directly
                            output.write(packet)
                            output.flush()
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("DotGlobeVPN", "Routing error: ${e.message}")
            }
        }
    }

    private fun routeThroughSocks(packet: ByteArray, dstAddr: String, socksPort: Int, vpnOutput: FileOutputStream) {
        thread {
            try {
                val socket = SocketChannel.open()
                socket.connect(InetSocketAddress("127.0.0.1", socksPort))

                // SOCKS5 handshake
                val handshake = ByteBuffer.allocate(3)
                handshake.put(5.toByte())
                handshake.put(0.toByte())
                handshake.put(0.toByte())
                handshake.flip()
                socket.write(handshake)

                val response = ByteBuffer.allocate(2)
                socket.read(response)

                // Parse destination from packet
                val dstPort = ((packet[22].toInt() and 0xFF) shl 8) or (packet[23].toInt() and 0xFF)

                // SOCKS5 connect request (domain type)
                val dstBytes = dstAddr.toByteArray()
                val request = ByteBuffer.allocate(7 + dstBytes.size)
                request.put(5) // version
                request.put(1.toByte()) // connect
                request.put(0) // reserved
                request.put(3) // domain
                request.put(dstBytes.size.toByte())
                request.put(dstBytes)
                request.put((dstPort shr 8).toByte())
                request.put(dstPort.toByte())
                request.flip()
                socket.write(request)

                // Read response
                val connectResponse = ByteBuffer.allocate(10)
                socket.read(connectResponse)

                // If connected, pipe data
                if (connectResponse.get(1).toInt() == 0) {
                    // Forward packet data
                    val dataBuffer = ByteBuffer.wrap(packet)
                    socket.write(dataBuffer)
                }

                socket.close()
            } catch (e: Exception) {
                // Connection failed
            }
        }
    }

    private fun stopVpn() {
        isRunning = false
        try { sshTunnel?.disconnect() } catch (_: Exception) {}
        sshTunnel = null
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    private fun createNotification(text: String): Notification {
        val notificationManager = getSystemService(NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "DotGlobe VPN",
                NotificationManager.IMPORTANCE_LOW
            )
            notificationManager.createNotificationChannel(channel)
        }

        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("DotGlobe VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .build()
    }
}

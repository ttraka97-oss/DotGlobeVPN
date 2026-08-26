package com.dotglobe.vpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor

class DotGlobeVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false

    companion object {
        const val ACTION_CONNECT = "com.dotglobe.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.dotglobe.vpn.DISCONNECT"
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> startVpn()
            ACTION_DISCONNECT -> stopVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (isRunning) return

        try {
            val builder = Builder()
                .setSession("DotGlobe VPN")
                .addAddress("10.8.0.2", 24)
                .addDnsServer("1.1.1.1")
                .addRoute("0.0.0.0", 0)
                .setMtu(1420)
                .setBlocking(true)

            vpnInterface = builder.establish()

            if (vpnInterface != null) {
                isRunning = true
                startForeground(1, createNotification("DotGlobe VPN — متصل"))
            }
        } catch (e: Exception) {
            stopVpn()
        }
    }

    private fun stopVpn() {
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
        }
        vpnInterface = null
        isRunning = false
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

    private fun createNotification(text: String): android.app.Notification {
        val channelId = "dotglobe_vpn"
        val mNotificationManager = getSystemService(NOTIFICATION_SERVICE) as android.app.NotificationManager

        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            val channel = android.app.NotificationChannel(
                channelId,
                "DotGlobe VPN",
                android.app.NotificationManager.IMPORTANCE_LOW
            )
            mNotificationManager.createNotificationChannel(channel)
        }

        return android.app.Notification.Builder(this, channelId)
            .setContentTitle("DotGlobe VPN")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .build()
    }
}

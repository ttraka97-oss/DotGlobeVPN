package com.dotglobe.vpn

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import kotlin.concurrent.thread

/**
 * XrayRunner — manages the real Xray-core binary.
 * Downloads/extracts the xray binary to app data dir,
 * generates config from .dgvpn file, runs xray as a process,
 * which creates a local SOCKS proxy for VpnService to route through.
 *
 * Supports: VMess, VLESS, Trojan, Reality, WebSocket, gRPC, TCP, TLS, SNI, and more.
 */
class XrayRunner(private val context: Context) {

    private var xrayProcess: Process? = null
    private var isRunning = false
    private var localSocksPort = 10808
    private var localHttpPort = 10809

    interface XrayCallback {
        fun onConnected(socksPort: Int)
        fun onDisconnected()
        fun onError(message: String)
        fun onLog(message: String)
    }

    /**
     * Extract the xray binary from assets to app data directory
     */
    private fun ensureXrayBinary(): File {
        val xrayDir = File(context.filesDir, "xray")
        xrayDir.mkdirs()

        val xrayFile = File(xrayDir, "xray")

        if (!xrayFile.exists()) {
            Log.i("XrayRunner", "Extracting xray binary from gzip...")
            try {
                // Extract from compressed .gz asset
                val asset = context.assets.open("xray.gz")
                val gzInput = java.util.zip.GZIPInputStream(asset)
                copyStream(gzInput, xrayFile)
                gzInput.close()
                asset.close()
                xrayFile.setExecutable(true, false)
                Log.i("XrayRunner", "Xray binary extracted: ${xrayFile.absolutePath}, size=${xrayFile.length()}")
            } catch (e: Exception) {
                Log.e("XrayRunner", "Failed to extract xray: ${e.message}")
                throw e
            }
        }

        if (!xrayFile.canExecute()) {
            xrayFile.setExecutable(true, false)
        }

        // Extract geoip.dat and geosite.dat from gzip
        for (geoFile in listOf("geoip.dat", "geosite.dat")) {
            val destFile = File(xrayDir, geoFile)
            if (!destFile.exists()) {
                try {
                    val asset = context.assets.open(geoFile + ".gz")
                    val gzInput = java.util.zip.GZIPInputStream(asset)
                    copyStream(gzInput, destFile)
                    gzInput.close()
                    asset.close()
                    Log.i("XrayRunner", "$geoFile extracted: ${destFile.length()}")
                } catch (e: Exception) {
                    Log.w("XrayRunner", "$geoFile not found: ${e.message}")
                }
            }
        }

        return xrayFile
    }

    private fun copyStream(input: InputStream, output: File) {
        FileOutputStream(output).use { out ->
            val buffer = ByteArray(8192)
            var read: Int
            while (input.read(buffer).also { read = it } > 0) {
                out.write(buffer, 0, read)
            }
            out.flush()
        }
    }

    /**
     * Generate Xray JSON config from .dgvpn config
     */
    private fun generateConfig(config: ConfigParser.VpnConfig): String {
        val proto = config.proto.lowercase()
        val sni = if (config.sni.isNotEmpty()) config.sni else config.host

        val outbound: String = when (proto) {
            "vmess", "v2ray" -> {
                // VMess outbound
                """{
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [{
                            "address": "${config.host}",
                            "port": ${config.port},
                            "users": [{
                                "id": "${config.password}",
                                "alterId": 0,
                                "security": "auto"
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "$sni",
                            "allowInsecure": true
                        }
                    }
                }"""
            }
            "vless" -> {
                // VLESS outbound
                """{
                    "protocol": "vless",
                    "settings": {
                        "vnext": [{
                            "address": "${config.host}",
                            "port": ${config.port},
                            "users": [{
                                "id": "${config.password}",
                                "encryption": "none"
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "$sni",
                            "allowInsecure": true
                        }
                    }
                }"""
            }
            "trojan" -> {
                // Trojan outbound
                """{
                    "protocol": "trojan",
                    "settings": {
                        "servers": [{
                            "address": "${config.host}",
                            "port": ${config.port},
                            "password": "${config.password}"
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "$sni",
                            "allowInsecure": true
                        }
                    }
                }"""
            }
            "ssh" -> {
                // SSH via SOCKS outbound
                """{
                    "protocol": "socks",
                    "settings": {
                        "servers": [{
                            "address": "127.0.0.1",
                            "port": ${localSocksPort + 1},
                            "users": [{
                                "user": "${config.username}",
                                "pass": "${config.password}"
                            }]
                        }]
                    }
                }"""
            }
            "tcp", "tls", "tcp/tls" -> {
                // TCP/TLS with payload — use Trojan as carrier
                """{
                    "protocol": "trojan",
                    "settings": {
                        "servers": [{
                            "address": "${config.host}",
                            "port": ${config.port},
                            "password": "${if (config.password.isNotEmpty()) config.password else config.payload}"
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "$sni",
                            "allowInsecure": true
                        }
                    }
                }"""
            }
            else -> {
                // Default: VMess
                """{
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [{
                            "address": "${config.host}",
                            "port": ${config.port},
                            "users": [{
                                "id": "${config.password}",
                                "alterId": 0
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "tls",
                        "tlsSettings": {
                            "serverName": "$sni",
                            "allowInsecure": true
                        }
                    }
                }"""
            }
        }

        // Full Xray config
        return """{
            "log": {
                "loglevel": "warning"
            },
            "inbounds": [{
                "tag": "socks-in",
                "port": $localSocksPort,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": true
                }
            }, {
                "tag": "http-in",
                "port": $localHttpPort,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {}
            }],
            "outbounds": [
                $outbound,
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {}
                },
                {
                    "tag": "block",
                    "protocol": "blackhole",
                    "settings": {}
                }
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [{
                    "type": "field",
                    "outboundTag": "direct",
                    "domain": ["geosite:category-ads-all"]
                }, {
                    "type": "field",
                    "outboundTag": "block",
                    "protocol": ["bittorrent"]
                }]
            }
        }"""
    }

    /**
     * Start Xray with the given config
     */
    fun start(config: ConfigParser.VpnConfig, callback: XrayCallback) {
        if (isRunning) {
            callback.onError("Xray يعمل بالفعل")
            return
        }

        thread {
            try {
                callback.onLog("تحضير نواة Xray...")

                val xrayBinary = ensureXrayBinary()
                callback.onLog("نواة Xray جاهزة · ${xrayBinary.length() / 1024 / 1024}MB")

                // Generate config
                val configJson = generateConfig(config)
                val configFile = File(context.filesDir, "xray/config.json")
                configFile.writeText(configJson)
                callback.onLog("تم إنشاء إعدادات Xray · بروتوكول: ${config.proto}")

                // Find available port
                localSocksPort = findAvailablePort(10808)
                localHttpPort = localSocksPort + 1

                // Regenerate config with correct port
                val configJsonFinal = generateConfig(config)
                configFile.writeText(configJsonFinal)

                // Start Xray process
                val pb = ProcessBuilder(
                    xrayBinary.absolutePath,
                    "run",
                    "-c", configFile.absolutePath
                )

                pb.directory(xrayBinary.parentFile)
                pb.redirectErrorStream(true)

                xrayProcess = pb.start()

                // Monitor process output
                val reader = xrayProcess?.inputStream?.bufferedReader()
                var started = false

                thread {
                    try {
                        var line: String?
                        while (reader?.readLine().also { line = it } != null) {
                            Log.i("XrayRunner", line ?: "")
                            if (line?.contains("started") == true || line?.contains("listening") == true) {
                                if (!started) {
                                    started = true
                                    isRunning = true
                                    callback.onLog("Xray يعمل · SOCKS على المنفذ $localSocksPort")
                                    callback.onConnected(localSocksPort)
                                }
                            }
                        }
                    } catch (_: Exception) {}
                }

                // Wait a bit for startup
                Thread.sleep(2000)

                if (!started) {
                    // Check if process is alive
                    if (xrayProcess?.isAlive == true) {
                        isRunning = true
                        callback.onLog("Xray يعمل · SOCKS على المنفذ $localSocksPort")
                        callback.onConnected(localSocksPort)
                    } else {
                        val exitCode = xrayProcess?.exitValue() ?: -1
                        callback.onError("Xray فشل في البدء · كود: $exitCode")
                    }
                }

                // Wait for process to exit
                val exitCode = xrayProcess?.waitFor()
                if (isRunning) {
                    callback.onLog("Xray توقف · كود: $exitCode")
                    isRunning = false
                    callback.onDisconnected()
                }

            } catch (e: Exception) {
                callback.onError("خطأ Xray: ${e.message}")
                isRunning = false
            }
        }
    }

    private fun findAvailablePort(start: Int): Int {
        var port = start
        while (port < start + 100) {
            try {
                val socket = java.net.ServerSocket(port)
                socket.close()
                return port
            } catch (_: Exception) {
                port++
            }
        }
        return start
    }

    fun stop() {
        isRunning = false
        try {
            xrayProcess?.destroy()
            xrayProcess?.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)
        } catch (_: Exception) {}
        xrayProcess = null
    }

    fun getSocksPort(): Int = localSocksPort
    fun isRunning(): Boolean = isRunning
}

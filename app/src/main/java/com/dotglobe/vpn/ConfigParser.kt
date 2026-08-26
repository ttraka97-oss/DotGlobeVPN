package com.dotglobe.vpn

import android.util.Base64
import org.json.JSONObject

/**
 * Parses and decrypts .dgvpn config files.
 * Format: JSON with type "DotGlobe-VPN", encrypted payload in "enc" field.
 * Encryption: XOR cipher + Base64
 */
object ConfigParser {

    private const val CIPHER_KEY = "DotGlobeVPN_2026_ALPHA_GO_islem"

    data class VpnConfig(
        val name: String,
        val proto: String,
        val host: String,
        val port: Int,
        val transport: String,
        val dns: String,
        val payload: String,
        val sni: String,
        val username: String,
        val password: String,
        val uuid: String,
        val path: String,
        val tls: String,
        val sshHost: String,
        val sshPort: Int,
        val sshUser: String,
        val sshPass: String
    )

    /**
     * Parse raw .dgvpn file content
     */
    fun parse(content: String): VpnConfig? {
        return try {
            val json = JSONObject(content)
            if (json.optString("type") != "DotGlobe-VPN") return null

            val encData = json.optString("enc", "")
            val decrypted = if (encData.isNotEmpty()) decrypt(encData) else content

            val data = JSONObject(decrypted)

            VpnConfig(
                name = data.optString("name", "Unknown"),
                proto = data.optString("proto", "SSH"),
                host = data.optString("host", ""),
                port = data.optInt("port", 22),
                transport = data.optString("transport", "TCP"),
                dns = data.optString("dns", "1.1.1.1"),
                payload = data.optString("payload", ""),
                sni = data.optString("sni", ""),
                username = data.optString("user", ""),
                password = data.optString("pass", ""),
                uuid = data.optString("uuid", data.optString("id", "")),
                path = data.optString("path", ""),
                tls = data.optString("tls", ""),
                sshHost = data.optString("host", ""),
                sshPort = data.optInt("port", 22),
                sshUser = data.optString("user", ""),
                sshPass = data.optString("pass", "")
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Decrypt XOR + Base64 encoded config data
     */
    private fun decrypt(encData: String): String {
        return try {
            val decoded = Base64.decode(encData, Base64.DEFAULT)
            val keyBytes = CIPHER_KEY.toByteArray(Charsets.UTF_8)
            val result = ByteArray(decoded.size)
            for (i in decoded.indices) {
                result[i] = (decoded[i].toInt() xor keyBytes[i % keyBytes.size].toInt()).toByte()
            }
            String(result, Charsets.UTF_8)
        } catch (e: Exception) {
            ""
        }
    }
}

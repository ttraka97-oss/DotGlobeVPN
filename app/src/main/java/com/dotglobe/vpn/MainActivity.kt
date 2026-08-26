package com.dotglobe.vpn

import android.annotation.SuppressLint
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts

class MainActivity : ComponentActivity() {

    private lateinit var webView: WebView
    private var filePathCallback: ValueCallback<Array<Uri>>? = null
    private var pendingConfigContent: String? = null

    private val vpnStatusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val status = intent?.getStringExtra(DotGlobeVpnService.EXTRA_STATUS) ?: return
            val message = intent.getStringExtra(DotGlobeVpnService.EXTRA_MESSAGE) ?: ""
            webView.post {
                when (status) {
                    DotGlobeVpnService.STATUS_CONNECTING -> {
                        webView.evaluateJavascript(
                            "if(typeof onVpnConnecting === 'function'){onVpnConnecting('${message.replace("'", "\\'")}');}", null
                        )
                    }
                    DotGlobeVpnService.STATUS_CONNECTED -> {
                        webView.evaluateJavascript(
                            "if(typeof onVpnConnected === 'function'){onVpnConnected('${message.replace("'", "\\'")}');}", null
                        )
                    }
                    DotGlobeVpnService.STATUS_ERROR -> {
                        webView.evaluateJavascript(
                            "if(typeof onVpnError === 'function'){onVpnError('${message.replace("'", "\\'")}');}", null
                        )
                    }
                    DotGlobeVpnService.STATUS_DISCONNECTED -> {
                        webView.evaluateJavascript(
                            "if(typeof onVpnDisconnected === 'function'){onVpnDisconnected();}", null
                        )
                    }
                }
            }
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Security: log only, don't block users
        SecurityCheck.init(this)
        SecurityCheck.runFullSecurityCheck(this)

        webView = WebView(this)
        setContentView(webView)

        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = true
            allowContentAccess = true
            mediaPlaybackRequiresUserGesture = false
            mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
            cacheMode = android.webkit.WebSettings.LOAD_DEFAULT
        }

        webView.webViewClient = WebViewClient()
        webView.addJavascriptInterface(WebAppInterface(this), "Android")

        webView.webChromeClient = object : WebChromeClient() {
            override fun onShowFileChooser(
                webView: WebView?,
                callback: ValueCallback<Array<Uri>>?,
                params: FileChooserParams?
            ): Boolean {
                filePathCallback?.onReceiveValue(null)
                filePathCallback = callback

                val intent = Intent(Intent.ACTION_GET_CONTENT).apply {
                    type = "*/*"
                    putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("application/octet-stream", "*/*"))
                    addCategory(Intent.CATEGORY_OPENABLE)
                }
                fileChooserLauncher.launch(Intent.createChooser(intent, "اختر ملف .dgvpn"))
                return true
            }
        }

        webView.loadUrl("file:///android_asset/index.html")
        handleIntent(intent)

        // Register VPN status receiver
        registerReceiver(vpnStatusReceiver, IntentFilter(DotGlobeVpnService.BROADCAST_STATUS), RECEIVER_NOT_EXPORTED)
    }

    override fun onDestroy() {
        try { unregisterReceiver(vpnStatusReceiver) } catch (_: Exception) {}
        super.onDestroy()
    }

    private val fileChooserLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val results: Array<Uri>? = if (result.resultCode == RESULT_OK) {
            result.data?.data?.let { uri -> arrayOf(uri) }
        } else {
            null
        }
        filePathCallback?.onReceiveValue(results)
        filePathCallback = null
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            // VPN permission granted, connect
            pendingConfigContent?.let { startVpnService(it) }
            pendingConfigContent = null
        } else {
            webView.post {
                webView.evaluateJavascript(
                    "if(typeof onVpnPermission === 'function'){onVpnPermission(false);}", null
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        intent?.let { handleIntent(it) }
    }

    private fun handleIntent(intent: Intent) {
        val uri = intent.data ?: return
        if (uri.toString().endsWith(".dgvpn")) {
            contentResolver.openInputStream(uri)?.use { input ->
                val content = input.bufferedReader().readText()
                webView.post {
                    webView.evaluateJavascript(
                        "if(typeof handleImportedFile === 'function'){handleImportedFile(${escapeForJs(content)});}",
                        null
                    )
                }
            }
        }
    }

    private fun escapeForJs(text: String): String {
        val escaped = text.replace("\\", "\\\\")
            .replace("'", "\\'")
            .replace("\n", "\\n")
            .replace("\r", "")
        return "'$escaped'"
    }

    private fun startVpnService(configJson: String) {
        try {
            val intent = Intent(this, DotGlobeVpnService::class.java).apply {
                action = DotGlobeVpnService.ACTION_CONNECT
                putExtra(DotGlobeVpnService.EXTRA_CONFIG, configJson)
            }
            startService(intent)
            // Don't call onVpnConnected here — wait for VPN service to actually connect
            // The VPN service will broadcast connection status
            webView.post {
                webView.evaluateJavascript(
                    "if(typeof onVpnConnecting === 'function'){onVpnConnecting();}", null
                )
            }
        } catch (e: Exception) {
            Log.e("DotGlobeVPN", "Failed to start VPN: ${e.message}")
            webView.post {
                webView.evaluateJavascript(
                    "if(typeof onVpnError === 'function'){onVpnError('${e.message}');}", null
                )
            }
        }
    }

    private fun stopVpnService() {
        val intent = Intent(this, DotGlobeVpnService::class.java).apply {
            action = DotGlobeVpnService.ACTION_DISCONNECT
        }
        startService(intent)

        webView.post {
            webView.evaluateJavascript(
                "if(typeof onVpnDisconnected === 'function'){onVpnDisconnected();}", null
            )
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack()
        } else {
            @Suppress("DEPRECATION")
            super.onBackPressed()
        }
    }

    /**
     * JavaScript interface — called from HTML
     */
    inner class WebAppInterface(private val activity: Activity) {

        @JavascriptInterface
        fun showToast(message: String) {
            android.widget.Toast.makeText(activity, message, android.widget.Toast.LENGTH_SHORT).show()
        }

        @JavascriptInterface
        fun vibrate(duration: Long) {
            (activity.getSystemService(android.content.Context.VIBRATOR_SERVICE) as android.os.Vibrator)
                .vibrate(duration)
        }

        /**
         * Called when user presses the power button to connect.
         * configJson is the raw .dgvpn file content.
         */
        @JavascriptInterface
        fun connectVpn(configJson: String) {
            // Request VPN permission first
            pendingConfigContent = configJson
            val vpnIntent = VpnService.prepare(activity)
            if (vpnIntent != null) {
                // Need user permission
                vpnPermissionLauncher.launch(vpnIntent)
            } else {
                // Already have permission
                startVpnService(configJson)
            }
        }

        @JavascriptInterface
        fun disconnectVpn() {
            stopVpnService()
        }

        /**
         * Check if a config is valid (has server info)
         */
        @JavascriptInterface
        fun validateConfig(configJson: String): Boolean {
            val config = ConfigParser.parse(configJson)
            return config != null && config.host.isNotEmpty()
        }
    }
}

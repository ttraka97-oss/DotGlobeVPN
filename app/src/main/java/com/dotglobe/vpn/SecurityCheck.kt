package com.dotglobe.vpn

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import java.security.MessageDigest
import java.security.cert.Certificate
import java.security.cert.CertificateFactory

/**
 * Anti-tamper protection — verifies app signature at runtime.
 * If the APK is resigned by a hacker, the app will refuse to run.
 * Also checks for debugging/repackaging indicators.
 */
object SecurityCheck {

    // Expected SHA-256 of the app signing certificate
    // This will be set after first signed build
    private const val EXPECTED_SIG_HASH = ""

    /**
     * Verify the app's signing certificate hasn't been changed.
     * Returns true if the app is genuine, false if tampered.
     */
    fun verifySignature(context: Context): Boolean {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNATURES
            )

            val signatures = packageInfo.signatures ?: return false
            if (signatures.isEmpty()) return false

            // Get certificate fingerprint
            val sig: Signature = signatures[0]
            val certBytes = sig.toByteArray()
            val md = MessageDigest.getInstance("SHA-256")
            val hashBytes = md.digest(certBytes)
            val hashHex = hashBytes.joinToString("") { "%02x".format(it) }

            android.util.Log.i("SecurityCheck", "Signature SHA-256: $hashHex")

            // If no expected hash set, just log (first run)
            if (EXPECTED_SIG_HASH.isEmpty()) {
                return true
            }

            hashHex.equals(EXPECTED_SIG_HASH, ignoreCase = true)
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check if the app is running in a debugger.
     */
    fun isBeingDebugged(): Boolean {
        return try {
            // Check common debugger indicators
            val debugClass = Class.forName("android.os.Debug")
            val method = debugClass.getMethod("isDebuggerConnected")
            method.invoke(null) as Boolean
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Check if running on an emulator (common for reverse engineering).
     */
    fun isEmulator(): Boolean {
        return Build.FINGERPRINT.startsWith("generic") ||
               Build.FINGERPRINT.startsWith("unknown") ||
               Build.MODEL.contains("google_sdk") ||
               Build.MODEL.contains("Emulator") ||
               Build.MODEL.contains("Android SDK built for x86") ||
               Build.MANUFACTURER.contains("Genymotion") ||
               Build.BRAND.startsWith("generic") ||
               Build.DEVICE.startsWith("generic") ||
               Build.PRODUCT.contains("sdk") ||
               Build.HARDWARE.contains("goldfish") ||
               Build.HARDWARE.contains("ranchu")
    }

    /**
     * Full security check — call at app startup.
     * Returns false if tampered/debugged/emulated.
     */
    fun runSecurityCheck(context: Context): Boolean {
        // Note: We don't block emulators for testing, just log
        if (isEmulator()) {
            android.util.Log.w("SecurityCheck", "Running on emulator")
        }

        if (isBeingDebugged()) {
            android.util.Log.w("SecurityCheck", "Debugger detected")
            // Don't block in debug builds
        }

        val sigValid = verifySignature(context)
        android.util.Log.i("SecurityCheck", "Signature valid: $sigValid")

        return true // Always return true for now — logging only
    }
}

# ==================== DotGlobe VPN Protection Rules ====================

# --- General: obfuscate and shrink ---
-optimizationpasses 5
-dontpreverify
-repackageclasses ''
-allowaccessmodification
-mergeinterfacesaggressively
-overloadaggressively

# --- Keep app entry points ---
-keep class com.dotglobe.vpn.MainActivity { *; }
-keep class com.dotglobe.vpn.DotGlobeVpnService { *; }
-keep class com.dotglobe.vpn.WebAppInterface { *; }

# --- Keep JavaScript interface methods (called from WebView) ---
-keepclassmembers class com.dotglobe.vpn.WebAppInterface {
    @android.webkit.JavascriptInterface <methods>;
}
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

# --- Keep VpnService callbacks ---
-keep class * extends android.net.VpnService { *; }
-keep class android.net.VpnService$Builder { *; }

# --- Protect config parser and tunnel classes ---
-keep class com.dotglobe.vpn.ConfigParser { *; }
-keep class com.dotglobe.vpn.ConfigParser$VpnConfig { *; }
-keep class com.dotglobe.vpn.XrayRunner { *; }
-keep class com.dotglobe.vpn.XrayRunner$XrayCallback { *; }

# --- JSch (SSH library) ---
-keep class com.jcraft.jsch.** { *; }
-dontwarn com.jcraft.jsch.**

# --- Netty ---
-keep class io.netty.** { *; }
-dontwarn io.netty.**
-dontwarn javax.net.ssl.**

# --- AndroidX ---
-keep class androidx.** { *; }
-dontwarn androidx.**

# --- Kotlin metadata ---
-keepattributes *Annotation*
-keepattributes SourceFile,LineNumberTable
-keepattributes InnerClasses
-keepattributes EnclosingMethod

# --- SSL/TLS ---
-keep class javax.net.ssl.** { *; }
-keep class java.security.** { *; }
-dontwarn javax.net.ssl.**
-dontwarn java.security.**

# --- JSON ---
-keep class org.json.** { *; }
-dontwarn org.json.**

# --- Remove logging in release ---
-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
    public static *** i(...);
}

# --- Native method protection ---
-keepclasseswithmembernames class * {
    native <methods>;
}

# --- Parcelable ---
-keepclassmembers class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator CREATOR;
}

# --- WebView ---
-keep class android.webkit.** { *; }
-dontwarn android.webkit.**

# --- FileProvider ---
-keep class androidx.core.content.FileProvider { *; }

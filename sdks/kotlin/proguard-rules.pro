# Add project specific ProGuard rules here.

# Erebor SDK
-keep class io.erebor.sdk.** { *; }

# Kotlinx Serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt

# Keep serializers
-keep,includedescriptorclasses class io.erebor.sdk.**$$serializer { *; }
-keepclassmembers class io.erebor.sdk.** {
    *** Companion;
}
-keepclasseswithmembers class io.erebor.sdk.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# Kotlinx Serialization core
-keepclassmembers class kotlinx.serialization.json.** {
    *** Companion;
}
-keepclasseswithmembers class kotlinx.serialization.json.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep class kotlinx.serialization.descriptors.SerialDescriptor
-keep class * implements kotlinx.serialization.KSerializer

# OkHttp3
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase
-dontwarn org.codehaus.mojo.animal_sniffer.*
-dontwarn okhttp3.internal.platform.**
-dontwarn org.conscrypt.ConscryptHostnameVerifier

# Coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}

# Android
-keep class androidx.compose.** { *; }
-keep class androidx.security.crypto.** { *; }
-keep class androidx.biometric.** { *; }

# BouncyCastle
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**
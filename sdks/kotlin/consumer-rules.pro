# Consumer proguard rules for Erebor SDK
# These rules will be automatically applied to apps using this library

# Keep all public API
-keep public class io.erebor.sdk.** { public *; }

# Keep data classes for serialization
-keep @kotlinx.serialization.Serializable class * {
    *;
}

# Keep Compose functions
-keep @androidx.compose.runtime.Composable class * { *; }
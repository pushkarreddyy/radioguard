# Keep Room database entities and DAOs
-keep class androidx.room.** { *; }
-dontwarn androidx.room.**
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class * { *; }
-keep @androidx.room.Dao class * { *; }

# Keep Shizuku AIDL interfaces
-keep class rikka.shizuku.** { *; }
-keep class moe.shizuku.** { *; }

# Keep RadioGuard data models
-keep class com.security.radioguard.data.model.** { *; }

# Anti-tampering / Integrity validation: prevent inlining or stripping of integrity methods
-keepclassmembers class com.security.radioguard.security.AppIntegrityValidator {
    public static boolean verifyAppSignature(android.content.Context);
}
-keep class com.security.radioguard.security.RuntimeAntiHijackGuard { *; }
-keep class com.security.radioguard.security.DeviceIntegritySentry { *; }


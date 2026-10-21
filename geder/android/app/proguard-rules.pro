# Les méthodes natives sont résolues par nom depuis libgeder.so.
-keepclasseswithmembernames class dev.geder.core.GederEngine {
    native <methods>;
}

# Rappels du tunnel : appelés par nom et signature depuis le code natif.
-keep interface dev.geder.core.GederEngine$TunnelCallbacks { *; }
-keepclassmembers class * implements dev.geder.core.GederEngine$TunnelCallbacks {
    boolean protect(int);
    void onBlocked(java.lang.String);
}

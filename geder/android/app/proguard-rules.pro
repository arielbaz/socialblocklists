# Les méthodes natives sont résolues par nom depuis libgeder_core.so.
-keepclasseswithmembernames class dev.geder.core.GederEngine {
    native <methods>;
}

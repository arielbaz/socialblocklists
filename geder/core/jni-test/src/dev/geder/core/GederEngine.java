package dev.geder.core;

/**
 * Miroir Java des méthodes natives de android/.../GederEngine.kt, pour tester la
 * liaison JNI sur une JVM de bureau, sans SDK Android. Les signatures doivent rester
 * identiques à celles du fichier Kotlin.
 */
final class GederEngine {
    static native long nativeNew(byte[][] keys, byte[] resolverV4, byte[] resolverV6);
    static native void nativeFree(long handle);
    static native String nativeLoadList(long handle, byte[] data);
    static native boolean nativeIsDomainAllowed(long handle, String name);
    static native int nativeClassifyPacket(long handle, byte[] packet);
    static native byte[] nativeHandleDnsPacket(long handle, byte[] packet);
    static native byte[] nativeCompleteDnsPacket(long handle, byte[] packet, byte[] response);
    static native void nativePurge(long handle);
}

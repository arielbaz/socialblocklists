package dev.geder.core

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * Enveloppe Kotlin de la bibliothèque native `libgeder` : moteur et tunnel
 * (voir android-ffi/src/lib.rs).
 *
 * Sûre depuis plusieurs threads. Après [close], chaque appel renvoie la réponse
 * « refus » du moteur (handle nul) au lieu d'accéder à la mémoire libérée.
 */
class GederEngine(
    trustedKeys: List<ByteArray>,
    resolverV4: ByteArray,
    resolverV6: ByteArray?,
) : AutoCloseable {

    private val lock = ReentrantReadWriteLock()
    private var handle: Long = nativeNew(trustedKeys.toTypedArray(), resolverV4, resolverV6 ?: ByteArray(0))

    init {
        check(handle != 0L) { "clé de confiance invalide" }
    }

    sealed interface DnsPacketResult {
        /** Envoyer [query] au résolveur amont, puis appeler [completeDnsPacket]. */
        class Forward(val query: ByteArray) : DnsPacketResult

        /** Écrire [packet] sur la TUN. [blockedDomain] : domaine refusé, à proposer en demande d'ouverture. */
        class Reply(val packet: ByteArray, val blockedDomain: String?) : DnsPacketResult

        data object Drop : DnsPacketResult
    }

    /**
     * Rappels du tunnel, appelés depuis ses threads natifs. Les noms et signatures
     * sont utilisés par la liaison JNI : ne pas les renommer (voir proguard-rules.pro).
     */
    interface TunnelCallbacks {
        /** Sortir la socket `fd` du VPN (`VpnService.protect`). */
        fun protect(fd: Int): Boolean

        /** Un domaine a été refusé. */
        fun onBlocked(domain: String)
    }

    /**
     * Démarre le tunnel complet sur la TUN `fd` (obtenue par `detachFd()`), dont le
     * moteur devient propriétaire. Renvoie `null` si le tunnel tourne, sinon la raison.
     */
    fun startTunnel(fd: Int, mtu: Int, callbacks: TunnelCallbacks): String? =
        lock.read { nativeStartTunnel(handle, fd, mtu, callbacks) }

    /** Arrête le tunnel et ferme la TUN. Bloquant (quelques secondes au plus). */
    fun stopTunnel() = lock.read { nativeStopTunnel(handle) }

    /** Charge une liste signée. Renvoie `null` si elle est acceptée, sinon la raison du refus. */
    fun loadList(data: ByteArray): String? = lock.read { nativeLoadList(handle, data) }

    fun isDomainAllowed(name: String): Boolean = lock.read { nativeIsDomainAllowed(handle, name) }

    /** Verdict sur un paquet sortant : [ALLOW], [DNS_QUERY] ou un code `DENY_*`. */
    fun classifyPacket(packet: ByteArray): Int = lock.read { nativeClassifyPacket(handle, packet) }

    fun handleDnsPacket(packet: ByteArray): DnsPacketResult {
        val out = lock.read { nativeHandleDnsPacket(handle, packet) } ?: return DnsPacketResult.Drop
        return when (out.firstOrNull()) {
            DNS_FORWARD -> DnsPacketResult.Forward(out.copyOfRange(1, out.size))
            DNS_REPLY -> {
                val nameLen = out[1].toInt() and 0xff
                val name = if (nameLen == 0) null else String(out, 2, nameLen, Charsets.US_ASCII)
                DnsPacketResult.Reply(out.copyOfRange(2 + nameLen, out.size), name)
            }
            else -> DnsPacketResult.Drop
        }
    }

    /** Lie les IP de la réponse amont ; renvoie le paquet à écrire sur la TUN, ou `null`. */
    fun completeDnsPacket(packet: ByteArray, response: ByteArray): ByteArray? =
        lock.read { nativeCompleteDnsPacket(handle, packet, response) }

    /** Supprime les liaisons DNS -> IP expirées. */
    fun purge() = lock.read { nativePurge(handle) }

    override fun close() = lock.write {
        val h = handle
        handle = 0
        if (h != 0L) nativeFree(h)
    }

    companion object {
        init {
            System.loadLibrary("geder")
        }

        const val ALLOW = 0
        const val DNS_QUERY = 1
        const val DENY_UNBOUND_IP = 10
        const val DENY_QUIC = 11
        const val DENY_DNS_OVER_TLS = 12
        const val DENY_FOREIGN_DNS = 13
        const val DENY_PROTOCOL = 14
        const val DENY_BLOCKED_SNI = 15
        const val DENY_ECH = 16
        const val DENY_MALFORMED = 17
        const val DENY_FRAGMENT = 18

        private const val DNS_FORWARD: Byte = 0
        private const val DNS_REPLY: Byte = 1

        @JvmStatic private external fun nativeNew(keys: Array<ByteArray>, resolverV4: ByteArray, resolverV6: ByteArray): Long
        @JvmStatic private external fun nativeFree(handle: Long)
        @JvmStatic private external fun nativeLoadList(handle: Long, data: ByteArray): String?
        @JvmStatic private external fun nativeIsDomainAllowed(handle: Long, name: String): Boolean
        @JvmStatic private external fun nativeClassifyPacket(handle: Long, packet: ByteArray): Int
        @JvmStatic private external fun nativeHandleDnsPacket(handle: Long, packet: ByteArray): ByteArray?
        @JvmStatic private external fun nativeCompleteDnsPacket(handle: Long, packet: ByteArray, response: ByteArray): ByteArray?
        @JvmStatic private external fun nativePurge(handle: Long)
        @JvmStatic private external fun nativeStartTunnel(handle: Long, fd: Int, mtu: Int, callbacks: Any): String?
        @JvmStatic private external fun nativeStopTunnel(handle: Long)
    }
}

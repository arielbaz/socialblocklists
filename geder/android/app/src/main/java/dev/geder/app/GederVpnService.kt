package dev.geder.app

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import dev.geder.core.GederEngine
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * Filtre local, étape 1 du prototype : « mode DNS ».
 *
 * Seul le résolveur virtuel est routé dans la TUN. Chaque requête DNS passe par le
 * moteur : domaine hors liste blanche -> NXDOMAIN ; domaine autorisé -> transmis au
 * résolveur amont par une socket protégée, et ses IP sont liées dans le moteur.
 *
 * Étape 2 (à venir) : router tout le trafic (0.0.0.0/0, ::/0) dans la TUN et relayer
 * les connexions acceptées par [GederEngine.classifyPacket] (liaison DNS -> IP stricte).
 */
class GederVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    private var engine: GederEngine? = null
    private var reader: Thread? = null
    private var upstreamPool: ExecutorService? = null
    private var purgeTask: ScheduledFuture<*>? = null
    private val purgeTimer = Executors.newSingleThreadScheduledExecutor()
    private val writeLock = Any()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopFilter()
            stopSelf()
            return START_NOT_STICKY
        }
        startFilter()
        return START_STICKY
    }

    override fun onRevoke() {
        // En mode Device Owner, le VPN « toujours actif verrouillé » empêche d'arriver ici
        // par l'utilisateur ; sans lui, on s'arrête proprement.
        stopFilter()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopFilter()
        purgeTimer.shutdownNow()
        super.onDestroy()
    }

    @Synchronized
    private fun startFilter() {
        if (tun != null) return
        val engine = GederEngine(
            listOf(ListStore.trustedKey(this)),
            InetAddress.getByName(RESOLVER_V4).address,
            InetAddress.getByName(RESOLVER_V6).address,
        )
        ListStore.loadAll(this, engine)

        val pfd = Builder()
            .setSession("GEDER")
            .addAddress(CLIENT_V4, 32)
            .addRoute(RESOLVER_V4, 32)
            .addDnsServer(RESOLVER_V4)
            .addAddress(CLIENT_V6, 128)
            .addRoute(RESOLVER_V6, 128)
            .addDnsServer(RESOLVER_V6)
            .setBlocking(true)
            .establish()
        if (pfd == null) {
            // L'utilisateur n'a pas (encore) autorisé le VPN : voir MainActivity.
            engine.close()
            return
        }
        val pool = Executors.newFixedThreadPool(4)
        this.engine = engine
        this.tun = pfd
        this.upstreamPool = pool
        reader = thread(name = "geder-tun") { readLoop(pfd, engine, pool) }
        purgeTask = purgeTimer.scheduleWithFixedDelay({ engine.purge() }, 1, 1, TimeUnit.MINUTES)
        Log.i(TAG, "filtre démarré")
    }

    @Synchronized
    private fun stopFilter() {
        val pfd = tun ?: return
        tun = null
        try {
            pfd.close() // débloque la lecture en cours
        } catch (_: IOException) {
        }
        reader?.join(2000)
        reader = null
        purgeTask?.cancel(false)
        purgeTask = null
        // Pas d'attente sur le thread principal : une requête amont encore en vol
        // trouvera un moteur fermé (réponse « refus ») et une TUN fermée.
        upstreamPool?.shutdownNow()
        upstreamPool = null
        engine?.close()
        engine = null
        Log.i(TAG, "filtre arrêté")
    }

    private fun readLoop(pfd: ParcelFileDescriptor, engine: GederEngine, pool: ExecutorService) {
        val input = FileInputStream(pfd.fileDescriptor)
        val output = FileOutputStream(pfd.fileDescriptor)
        val buf = ByteArray(MAX_PACKET)
        while (true) {
            val n = try {
                input.read(buf)
            } catch (_: IOException) {
                break
            }
            if (n <= 0) continue
            val packet = buf.copyOf(n)
            when (val r = engine.handleDnsPacket(packet)) {
                is GederEngine.DnsPacketResult.Forward -> try {
                    pool.execute { forward(engine, packet, r.query, output) }
                } catch (_: RejectedExecutionException) {
                    break // arrêt en cours
                }
                is GederEngine.DnsPacketResult.Reply -> {
                    write(output, r.packet)
                    r.blockedDomain?.let { BlockedDomains.report(it) }
                }
                GederEngine.DnsPacketResult.Drop -> {}
            }
        }
    }

    private fun forward(engine: GederEngine, packet: ByteArray, query: ByteArray, output: FileOutputStream) {
        for (server in UPSTREAM) {
            try {
                DatagramSocket().use { socket ->
                    protect(socket) // sinon la requête repartirait dans notre propre TUN
                    socket.soTimeout = UPSTREAM_TIMEOUT_MS
                    socket.send(DatagramPacket(query, query.size, InetAddress.getByName(server), 53))
                    val resp = ByteArray(MAX_PACKET)
                    val dp = DatagramPacket(resp, resp.size)
                    socket.receive(dp)
                    engine.completeDnsPacket(packet, resp.copyOf(dp.length))?.let { write(output, it) }
                }
                return
            } catch (e: IOException) {
                Log.w(TAG, "résolveur $server indisponible : ${e.message}")
            }
        }
    }

    private fun write(output: FileOutputStream, packet: ByteArray) {
        synchronized(writeLock) {
            try {
                output.write(packet)
            } catch (e: IOException) {
                Log.w(TAG, "écriture TUN impossible : ${e.message}")
            }
        }
    }

    companion object {
        const val ACTION_STOP = "dev.geder.app.STOP"
        private const val TAG = "GederVpn"
        private const val MAX_PACKET = 32767
        private const val UPSTREAM_TIMEOUT_MS = 5000

        // Doivent correspondre à EngineConfig::default() côté Rust.
        const val CLIENT_V4 = "10.111.0.1"
        const val RESOLVER_V4 = "10.111.0.53"
        const val CLIENT_V6 = "fd00:6765:6465:72::1"
        const val RESOLVER_V6 = "fd00:6765:6465:72::53"

        // Résolveurs amont : Cloudflare « Families » (filtre déjà adulte + malveillant),
        // en couche supplémentaire derrière notre liste blanche.
        private val UPSTREAM = listOf("1.1.1.3", "1.0.0.3")
    }
}

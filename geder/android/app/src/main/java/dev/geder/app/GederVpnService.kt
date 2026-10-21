package dev.geder.app

import android.content.Intent
import android.net.VpnService
import android.os.Build
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
 * Filtre local GEDER.
 *
 * **Tunnel complet** (mode par défaut, étape 2) : tout le trafic IPv4 et IPv6 entre
 * dans la TUN, dont le descripteur est confié au tunnel Rust. Chaque nouvelle connexion
 * n'est ouverte que vers une IP que notre résolveur vient de renvoyer pour un domaine
 * autorisé ; le SNI est contrôlé sur le port 443 ; QUIC, DoT et DNS tiers sont refusés.
 *
 * **Mode DNS** (étape 1, secours) : seul le résolveur virtuel est routé dans la TUN ;
 * filtre plus faible, qui ne bloque pas les IP codées en dur.
 */
class GederVpnService : VpnService() {

    private var engine: GederEngine? = null
    private var running = false

    // Mode DNS uniquement.
    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null
    private var upstreamPool: ExecutorService? = null
    private var purgeTask: ScheduledFuture<*>? = null
    private val purgeTimer = Executors.newSingleThreadScheduledExecutor()
    private val writeLock = Any()

    private val callbacks = object : GederEngine.TunnelCallbacks {
        override fun protect(fd: Int): Boolean = this@GederVpnService.protect(fd)
        override fun onBlocked(domain: String) = BlockedDomains.report(domain)
    }

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
        if (running) return
        val engine = GederEngine(
            listOf(ListStore.trustedKey(this)),
            InetAddress.getByName(RESOLVER_V4).address,
            InetAddress.getByName(RESOLVER_V6).address,
        )
        ListStore.loadAll(this, engine)
        val started = if (FULL_TUNNEL) startFullTunnel(engine) else startDnsMode(engine)
        if (!started) {
            engine.close()
            return
        }
        this.engine = engine
        running = true
        Log.i(TAG, "filtre démarré (${if (FULL_TUNNEL) "tunnel complet" else "mode DNS"})")
    }

    private fun startFullTunnel(engine: GederEngine): Boolean {
        val builder = Builder()
            .setSession("GEDER")
            .setMtu(MTU)
            .addAddress(CLIENT_V4, 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer(RESOLVER_V4)
            .addAddress(CLIENT_V6, 128)
            .addRoute("::", 0)
            .addDnsServer(RESOLVER_V6)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        // null : l'utilisateur n'a pas (encore) autorisé le VPN, voir MainActivity.
        val pfd = builder.establish() ?: return false
        // Le tunnel Rust devient propriétaire du descripteur et le fermera à l'arrêt.
        val fd = pfd.detachFd()
        val error = engine.startTunnel(fd, MTU, callbacks)
        if (error != null) {
            // Le descripteur reste ouvert sans lecteur : tout le trafic est perdu
            // (fail-closed) jusqu'au prochain démarrage.
            Log.e(TAG, "tunnel non démarré : $error")
            return false
        }
        return true
    }

    private fun startDnsMode(engine: GederEngine): Boolean {
        val pfd = Builder()
            .setSession("GEDER")
            .addAddress(CLIENT_V4, 32)
            .addRoute(RESOLVER_V4, 32)
            .addDnsServer(RESOLVER_V4)
            .addAddress(CLIENT_V6, 128)
            .addRoute(RESOLVER_V6, 128)
            .addDnsServer(RESOLVER_V6)
            .setBlocking(true)
            .establish() ?: return false
        val pool = Executors.newFixedThreadPool(4)
        tun = pfd
        upstreamPool = pool
        reader = thread(name = "geder-tun") { readLoop(pfd, engine, pool) }
        purgeTask = purgeTimer.scheduleWithFixedDelay({ engine.purge() }, 1, 1, TimeUnit.MINUTES)
        return true
    }

    @Synchronized
    private fun stopFilter() {
        if (!running) return
        running = false
        val engine = this.engine ?: return
        this.engine = null

        tun?.let { pfd ->
            try {
                pfd.close() // débloque la lecture en cours
            } catch (_: IOException) {
            }
            reader?.join(2000)
        }
        tun = null
        reader = null
        purgeTask?.cancel(false)
        purgeTask = null
        // Pas d'attente sur le thread principal : une requête amont encore en vol
        // trouvera un moteur fermé (réponse « refus ») et une TUN fermée.
        upstreamPool?.shutdownNow()
        upstreamPool = null

        // L'arrêt du tunnel attend la fin de ses threads : hors du thread principal.
        thread(name = "geder-stop") {
            engine.stopTunnel()
            engine.close()
            Log.i(TAG, "filtre arrêté")
        }
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
        private const val MTU = 1500

        /** `false` : repli sur le mode DNS (étape 1), par exemple sur un téléphone récalcitrant. */
        const val FULL_TUNNEL = true

        // Doivent correspondre à EngineConfig::default() côté Rust.
        const val CLIENT_V4 = "10.111.0.1"
        const val RESOLVER_V4 = "10.111.0.53"
        const val CLIENT_V6 = "fd00:6765:6465:72::1"
        const val RESOLVER_V6 = "fd00:6765:6465:72::53"

        // Mode DNS : résolveurs amont Cloudflare « Families » (filtre adulte et malveillant),
        // en seconde couche. En tunnel complet, voir TunnelConfig::default() côté Rust.
        private val UPSTREAM = listOf("1.1.1.3", "1.0.0.3")
    }
}

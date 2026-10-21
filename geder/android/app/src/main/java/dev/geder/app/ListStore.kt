package dev.geder.app

import android.content.Context
import android.util.Base64
import android.util.Log
import dev.geder.core.GederEngine
import java.io.File

/**
 * Listes blanches signées : celles livrées avec l'APK (assets/lists) puis celles
 * téléchargées depuis le serveur (filesDir/lists). Le moteur vérifie chaque signature
 * et refuse une version plus ancienne que celle déjà chargée.
 */
object ListStore {
    private const val TAG = "GederLists"
    private const val ASSET_DIR = "lists"
    private const val KEY_ASSET = "keys/list-signing.pub"

    /** Clé publique Ed25519 des listes (32 octets), livrée dans l'APK. */
    fun trustedKey(context: Context): ByteArray {
        val b64 = context.assets.open(KEY_ASSET).bufferedReader().use { it.readText().trim() }
        return Base64.decode(b64, Base64.DEFAULT)
    }

    fun downloadedDir(context: Context): File = File(context.filesDir, ASSET_DIR).apply { mkdirs() }

    fun loadAll(context: Context, engine: GederEngine) {
        val bundled = context.assets.list(ASSET_DIR).orEmpty().sorted().map { name ->
            name to context.assets.open("$ASSET_DIR/$name").use { it.readBytes() }
        }
        val downloaded = downloadedDir(context).listFiles().orEmpty().sortedBy { it.name }.map { file ->
            file.name to file.readBytes()
        }
        for ((name, data) in bundled + downloaded) {
            val error = engine.loadList(data)
            if (error == null) {
                Log.i(TAG, "liste chargée : $name")
            } else {
                Log.w(TAG, "liste refusée : $name ($error)")
            }
        }
    }
}

/** Domaines refusés récemment, base du futur bouton « demander l'ouverture ». */
object BlockedDomains {
    private const val MAX = 50
    private val recent = LinkedHashSet<String>()

    @Synchronized
    fun report(domain: String) {
        recent.remove(domain)
        recent.add(domain)
        if (recent.size > MAX) recent.remove(recent.first())
    }

    @Synchronized
    fun recent(): List<String> = recent.toList().asReversed()
}

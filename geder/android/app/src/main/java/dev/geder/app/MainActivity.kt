package dev.geder.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/** Écran minimal du prototype : état, activation du filtre, domaines refusés. */
class MainActivity : Activity() {

    private lateinit var status: TextView
    private lateinit var blocked: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()
        status = TextView(this)
        blocked = TextView(this)
        val start = Button(this).apply {
            text = "Activer le filtre"
            setOnClickListener { requestVpn() }
        }
        setContentView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(pad, pad, pad, pad)
                addView(status)
                addView(start)
                addView(blocked)
            },
        )
    }

    override fun onResume() {
        super.onResume()
        val owner = DeviceOwnerPolicy.isDeviceOwner(this)
        if (owner) DeviceOwnerPolicy.apply(this)
        status.text = buildString {
            append("GEDER — prototype\n")
            append(if (owner) "Appareil verrouillé (Device Owner)\n" else "Appareil NON verrouillé : filtre désactivable\n")
        }
        val recent = BlockedDomains.recent()
        blocked.text = if (recent.isEmpty()) "" else "Refusés récemment :\n" + recent.joinToString("\n")
    }

    private fun requestVpn() {
        val consent = VpnService.prepare(this)
        if (consent != null) {
            startActivityForResult(consent, REQUEST_VPN)
        } else {
            onActivityResult(REQUEST_VPN, RESULT_OK, null)
        }
    }

    @Deprecated("API Activity simple, sans AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) {
            startService(Intent(this, GederVpnService::class.java))
        }
    }

    private companion object {
        const val REQUEST_VPN = 1
    }
}

package dev.geder.app

import android.app.Activity
import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.UserManager
import android.util.Log

/** Reçoit les événements d'administration ; applique la politique dès que possible. */
class GederAdminReceiver : DeviceAdminReceiver() {
    override fun onEnabled(context: Context, intent: Intent) {
        DeviceOwnerPolicy.apply(context)
    }

    override fun onProfileProvisioningComplete(context: Context, intent: Intent) {
        DeviceOwnerPolicy.apply(context)
    }
}

/**
 * Verrouillage de l'appareil en mode Device Owner. Sans ce mode, n'importe quel filtre
 * se désinstalle en quelques minutes ; avec lui, le filtre devient partie du téléphone.
 *
 * Le mode Device Owner ne s'active que sur un appareil fraîchement réinitialisé
 * (provisionnement par QR code) ou, en développement, par
 * `adb shell dpm set-device-owner dev.geder.app/.GederAdminReceiver`.
 */
object DeviceOwnerPolicy {
    private const val TAG = "GederPolicy"

    /** Interdictions appliquées à l'utilisateur filtré. */
    private val RESTRICTIONS = buildList {
        add(UserManager.DISALLOW_FACTORY_RESET) // réinitialisation = désinstallation
        add(UserManager.DISALLOW_SAFE_BOOT) // le mode sans échec désactive le VPN
        add(UserManager.DISALLOW_ADD_USER) // un nouvel utilisateur échapperait au filtre
        add(UserManager.DISALLOW_DEBUGGING_FEATURES) // ADB : désinstallation par câble
        add(UserManager.DISALLOW_CONFIG_VPN) // pas de VPN tiers
        add(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES) // pas d'APK de contournement
        add(UserManager.DISALLOW_CONFIG_DATE_TIME) // horloge : plages horaires, Shabbat
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            add(UserManager.DISALLOW_CONFIG_PRIVATE_DNS) // DNS privé (DoT) contournerait notre résolveur
        }
    }

    fun admin(context: Context) = ComponentName(context, GederAdminReceiver::class.java)

    fun isDeviceOwner(context: Context): Boolean =
        context.getSystemService(DevicePolicyManager::class.java).isDeviceOwnerApp(context.packageName)

    /** Applique toute la politique. Renvoie `false` si l'appli n'est pas Device Owner. */
    fun apply(context: Context): Boolean {
        if (!isDeviceOwner(context)) return false
        val dpm = context.getSystemService(DevicePolicyManager::class.java)
        val admin = admin(context)

        RESTRICTIONS.forEach { dpm.addUserRestriction(admin, it) }
        dpm.setUninstallBlocked(admin, context.packageName, true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Mode « opportuniste » : sans serveur DoT joignable, le système utilise notre DNS.
            dpm.setGlobalPrivateDnsModeOpportunistic(admin)
        }
        try {
            // VPN toujours actif et verrouillé : sans notre VPN, aucun accès réseau.
            dpm.setAlwaysOnVpnPackage(admin, context.packageName, true)
        } catch (e: Exception) {
            Log.e(TAG, "VPN toujours actif impossible : ${e.message}")
            return false
        }
        Log.i(TAG, "politique Device Owner appliquée")
        return true
    }
}

/**
 * Étapes du provisionnement par QR code exigées depuis Android 12 :
 * le système demande le mode voulu, puis la mise en conformité.
 */
class ProvisioningActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        when (intent?.action) {
            DevicePolicyManager.ACTION_GET_PROVISIONING_MODE -> {
                val result = Intent().putExtra(
                    DevicePolicyManager.EXTRA_PROVISIONING_MODE,
                    DevicePolicyManager.PROVISIONING_MODE_FULLY_MANAGED_DEVICE,
                )
                setResult(RESULT_OK, result)
            }
            DevicePolicyManager.ACTION_ADMIN_POLICY_COMPLIANCE -> {
                DeviceOwnerPolicy.apply(this)
                setResult(RESULT_OK)
            }
            else -> setResult(RESULT_CANCELED)
        }
        finish()
    }
}

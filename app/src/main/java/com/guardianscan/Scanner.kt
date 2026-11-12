package com.guardianscan

import android.app.admin.DevicePolicyManager
import android.app.usage.NetworkStats
import android.app.usage.NetworkStatsManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.provider.Settings

data class Finding(val level: Int, val title: String, val detail: String) // 1=info 2=atención 3=alto

object Scanner {
    private val STORES = setOf("com.android.vending", "com.sec.android.app.samsungapps",
        "com.huawei.appmarket", "com.xiaomi.mipicks", "com.amazon.venezia")
    private val DANGEROUS = setOf("android.permission.RECORD_AUDIO", "android.permission.CAMERA",
        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.READ_CALL_LOG",
        "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.READ_CONTACTS")

    /** Revisa apps, permisos y componentes que el spyware suele abusar. */
    fun scanApps(ctx: Context): List<Finding> {
        val out = mutableListOf<Finding>()
        val pm = ctx.packageManager
        val cr = ctx.contentResolver

        (Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: "")
            .split(":").filter { it.isNotBlank() }
            .forEach { out += Finding(2, "Servicio de accesibilidad activo", "$it\nPuede leer pantalla y teclado. Verifica que lo reconoces.") }

        (Settings.Secure.getString(cr, "enabled_notification_listeners") ?: "")
            .split(":").filter { it.isNotBlank() }
            .forEach { out += Finding(2, "Lee tus notificaciones", it) }

        val dpm = ctx.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        dpm.activeAdmins?.forEach { out += Finding(3, "Administrador de dispositivo", "${it.packageName}\nDifícil de desinstalar; común en stalkerware.") }

        for (p in pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)) {
            val ai = p.applicationInfo ?: continue
            if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0) continue
            var score = 0
            val why = mutableListOf<String>()

            val installer = if (Build.VERSION.SDK_INT >= 30)
                runCatching { pm.getInstallSourceInfo(p.packageName).installingPackageName }.getOrNull()
            else @Suppress("DEPRECATION") pm.getInstallerPackageName(p.packageName)
            if (installer == null || installer !in STORES) { score += 1; why += "instalada fuera de tienda oficial" }

            if (pm.getLaunchIntentForPackage(p.packageName) == null) { score += 2; why += "sin icono en el menú (oculta)" }

            val perms = p.requestedPermissions ?: emptyArray()
            val flags = p.requestedPermissionsFlags ?: IntArray(0)
            val granted = perms.indices.filter {
                perms[it] in DANGEROUS && flags.getOrElse(it) { 0 } and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
            }.map { perms[it].substringAfterLast('.') }
            if (granted.size >= 3) { score += 1; why += "permisos sensibles: ${granted.joinToString()}" }

            if (score >= 2) out += Finding(if (score >= 3) 3 else 2,
                "${pm.getApplicationLabel(ai)} (${p.packageName})", why.joinToString("\n• ", "• "))
        }
        if (out.isEmpty()) out += Finding(1, "Sin hallazgos", "No se detectaron señales comunes de spyware.")
        return out.sortedByDescending { it.level }
    }

    /** Subida/bajada por app en las últimas 24 h (requiere permiso "Acceso a uso"). */
    fun dataUsage(ctx: Context): List<Finding> {
        val nsm = ctx.getSystemService(Context.NETWORK_STATS_SERVICE) as NetworkStatsManager
        val pm = ctx.packageManager
        val end = System.currentTimeMillis(); val start = end - 24L * 3600 * 1000
        data class U(var rx: Long = 0, var tx: Long = 0, var bgTx: Long = 0)
        val map = HashMap<Int, U>()
        for (type in listOf(ConnectivityManager.TYPE_WIFI, ConnectivityManager.TYPE_MOBILE)) {
            val st = try { nsm.querySummary(type, null, start, end) } catch (e: Exception) {
                return listOf(Finding(2, "Sin permiso de uso", "Concede 'Acceso a uso' a GuardianScan en Ajustes.")) }
            val b = NetworkStats.Bucket()
            while (st.hasNextBucket()) {
                st.getNextBucket(b)
                val u = map.getOrPut(b.uid) { U() }
                u.rx += b.rxBytes; u.tx += b.txBytes
                if (b.state != NetworkStats.Bucket.STATE_FOREGROUND) u.bgTx += b.txBytes
            }
            st.close()
        }
        val mb = 1024.0 * 1024
        return map.entries.sortedByDescending { it.value.tx }.take(15).map { (uid, u) ->
            val name = pm.getPackagesForUid(uid)?.firstOrNull() ?: "uid $uid"
            val suspicious = u.bgTx > 20 * mb || (u.tx > 5 * mb && u.tx > u.rx)
            Finding(if (suspicious) 3 else 1, name,
                "↑ %.1f MB  ↓ %.1f MB  (segundo plano ↑ %.1f MB)".format(u.tx / mb, u.rx / mb, u.bgTx / mb))
        }
    }
}

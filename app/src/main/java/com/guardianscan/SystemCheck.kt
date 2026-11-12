package com.guardianscan

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import java.io.File
import java.security.KeyStore
import java.util.Locale

/** Integridad del sistema: lo que un atacante necesita cambiar para espiar o interceptar. */
object SystemCheck {
    fun run(ctx: Context): List<Finding> {
        val out = mutableListOf<Finding>(); val cr = ctx.contentResolver; val pm = ctx.packageManager

        runCatching {
            val d = java.text.SimpleDateFormat("yyyy-MM-dd", Locale.US).parse(Build.VERSION.SECURITY_PATCH)!!
            val days = (System.currentTimeMillis() - d.time) / 86400000
            out += if (days > 180) Finding(3, "Parche de seguridad antiguo", "${Build.VERSION.SECURITY_PATCH} (hace $days días). Expuesto a exploits ya corregidos.")
            else Finding(1, "Parche de seguridad", "${Build.VERSION.SECURITY_PATCH} (hace $days días)")
        }
        if (Build.TAGS?.contains("test-keys") == true) out += Finding(3, "Firmware no oficial", "Build.TAGS = test-keys")
        listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/app/Superuser.apk", "/data/local/bin/su")
            .filter { File(it).exists() }.forEach { out += Finding(3, "Rastro de root", it) }
        listOf("com.topjohnwu.magisk", "eu.chainfire.supersu", "me.weishu.kernelsu").forEach {
            runCatching { pm.getPackageInfo(it, 0); out += Finding(3, "Herramienta de root instalada", it) } }

        if (Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1) out += Finding(2, "Depuración USB (ADB) activa", "Permite control total desde una computadora conectada.")
        if (Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1) out += Finding(1, "Opciones de desarrollador activas", "")

        runCatching {
            val ks = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
            ks.aliases().toList().filter { it.startsWith("user:") }.forEach {
                out += Finding(3, "Certificado CA instalado por el usuario", "$it\nPermite interceptar tráfico HTTPS (MITM).") }
        }

        val proxy = Settings.Global.getString(cr, "http_proxy")
        if (!proxy.isNullOrBlank() && proxy != ":0") out += Finding(3, "Proxy global configurado", proxy)
        System.getProperty("http.proxyHost")?.takeIf { it.isNotBlank() }?.let { out += Finding(2, "Proxy de sistema", it) }

        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        if (cm.getNetworkCapabilities(cm.activeNetwork)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true)
            out += Finding(2, "Hay una VPN activa", "Todo tu tráfico pasa por ella. Confirma que es tuya (puede ser el monitor DNS).")

        for (p in pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)) {
            val ai = p.applicationInfo ?: continue
            if (ai.flags and ApplicationInfo.FLAG_SYSTEM != 0) continue
            if (ai.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) out += Finding(2, "App depurable", p.packageName)
            if (p.requestedPermissions?.contains("android.permission.REQUEST_INSTALL_PACKAGES") == true)
                out += Finding(2, "App que puede instalar otras apps", p.packageName)
        }
        return out
    }
}

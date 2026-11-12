package com.guardianscan

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.provider.Telephony
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

/** Indicadores de compromiso (STIX2), el mismo formato que usa MVT (Amnesty, mvt-indicators). */
object Ioc {
    val domains = HashSet<String>(); val urls = HashSet<String>()
    val apps = HashSet<String>(); val sha256 = HashSet<String>()
    private val rx = Regex("""([A-Za-z\-]+:[A-Za-z0-9_.\-]+)\s*=\s*'([^']*)'""")

    fun count() = domains.size + urls.size + apps.size + sha256.size

    fun loadSaved(ctx: Context) {
        domains.clear(); urls.clear(); apps.clear(); sha256.clear()
        File(ctx.filesDir, "ioc").listFiles()?.forEach { runCatching { parse(it.readText()) } }
    }

    fun import(ctx: Context, uri: Uri): Int {
        val txt = ctx.contentResolver.openInputStream(uri)!!.bufferedReader().readText()
        val before = count(); parse(txt)
        File(ctx.filesDir, "ioc").apply { mkdirs() }.let { File(it, "ioc_${System.nanoTime()}.stix").writeText(txt) }
        return count() - before
    }

    private fun parse(txt: String) {
        val objs = JSONObject(txt).optJSONArray("objects") ?: return
        for (i in 0 until objs.length()) {
            val p = objs.getJSONObject(i).optString("pattern"); if (p.isEmpty()) continue
            for (m in rx.findAll(p)) {
                val k = m.groupValues[1].lowercase().replace("-", ""); val v = m.groupValues[2]
                when {
                    k.startsWith("domainname") -> domains += v.lowercase()
                    k.startsWith("url") -> urls += v.lowercase()
                    k.startsWith("app:id") -> apps += v
                    "sha256" in k -> sha256 += v.lowercase()
                }
            }
        }
    }

    fun hostHit(h: String): Boolean {
        var s = h.lowercase()
        while (true) { if (s in domains) return true; val i = s.indexOf('.'); if (i < 0) return false; s = s.substring(i + 1) }
    }

    private fun sha(f: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { s -> val b = ByteArray(65536); while (true) { val n = s.read(b); if (n < 0) break; md.update(b, 0, n) } }
        return md.digest().joinToString("") { "%02x".format(it) }
    }

    /** Paquetes y hashes de APK (incluye apps del sistema) contra los IOC. */
    fun scanPackages(ctx: Context): List<Finding> {
        val out = mutableListOf<Finding>()
        for (p in ctx.packageManager.getInstalledPackages(0)) {
            if (p.packageName in apps) out += Finding(3, "IOC: app maliciosa conocida", p.packageName)
            val src = p.applicationInfo?.sourceDir ?: continue
            if (sha256.isNotEmpty()) runCatching {
                val h = sha(File(src)); if (h in sha256) out += Finding(3, "IOC: APK con hash malicioso", "${p.packageName}\n$h")
            }
        }
        return out
    }

    /** Dominios consultados por el monitor DNS contra los IOC. */
    fun scanDns(): List<Finding> = DnsVpnService.counts.keys.filter { hostHit(it) }
        .map { Finding(3, "IOC: dominio malicioso consultado", "$it (${DnsVpnService.counts[it]} veces)") }

    /** Enlaces dentro de tus SMS contra los IOC (como hace MVT en Android). */
    fun scanSms(ctx: Context): List<Finding> {
        if (ctx.checkSelfPermission(Manifest.permission.READ_SMS) != PackageManager.PERMISSION_GRANTED)
            return listOf(Finding(2, "SMS no revisados", "Sin permiso de lectura de SMS."))
        val out = mutableListOf<Finding>(); val urlRx = Regex("""https?://[^\s"'<>]+""", RegexOption.IGNORE_CASE)
        ctx.contentResolver.query(Telephony.Sms.CONTENT_URI, arrayOf("address", "body"), null, null, "date DESC")?.use { c ->
            while (c.moveToNext()) {
                val body = c.getString(1) ?: continue
                for (m in urlRx.findAll(body)) {
                    val u = m.value.lowercase().trimEnd('.', ',', ')')
                    val host = runCatching { java.net.URI(u).host }.getOrNull() ?: continue
                    if (u in urls || hostHit(host)) out += Finding(3, "IOC: enlace malicioso en SMS", "De: ${c.getString(0)}\n$u")
                }
            }
        }
        return out
    }
}

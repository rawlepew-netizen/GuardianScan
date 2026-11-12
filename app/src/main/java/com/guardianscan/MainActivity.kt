package com.guardianscan

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.widget.*

class MainActivity : Activity() {
    private lateinit var out: TextView
    private val ui = Handler(Looper.getMainLooper())
    private var showingDns = false
    private var report = ""

    override fun onCreate(b: Bundle?) {
        super.onCreate(b)
        Ioc.loadSaved(this)
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(32, 48, 32, 32) }
        fun btn(t: String, a: () -> Unit) = Button(this).apply { text = t; setOnClickListener { a() } }.also { root.addView(it) }
        btn("▶ Escaneo completo") { fullScan() }
        btn("Importar IOC (STIX2 .json / .stix2)") {
            startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                type = "*/*"; addCategory(Intent.CATEGORY_OPENABLE); putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true) }, 3)
        }
        btn("Monitor DNS (VPN local)") { toggleDns() }
        btn("Compartir informe") {
            startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_TEXT, report) }, "Informe"))
        }
        out = TextView(this).apply { textSize = 13f; setTextIsSelectable(true); text = "IOC cargados: ${Ioc.count()}" }
        root.addView(ScrollView(this).apply { addView(out) }, LinearLayout.LayoutParams(-1, 0, 1f))
        setContentView(root)
        ui.post(object : Runnable { override fun run() { if (showingDns) renderDns(); ui.postDelayed(this, 1500) } })
    }

    private fun fullScan() {
        if (checkSelfPermission(Manifest.permission.READ_SMS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.READ_SMS), 2); return }
        runScan()
    }

    override fun onRequestPermissionsResult(rq: Int, p: Array<out String>, r: IntArray) { if (rq == 2) runScan() }

    private fun runScan() {
        showingDns = false; out.text = "Escaneando… (calcular hashes de APK puede tardar un minuto)"
        Thread {
            val r = try {
                (SystemCheck.run(this) + Ioc.scanPackages(this) + Ioc.scanDns() + Ioc.scanSms(this) +
                    Scanner.scanApps(this) + Scanner.dataUsage(this)).sortedByDescending { it.level }
            } catch (e: Exception) { listOf(Finding(2, "Error", e.toString())) }
            ui.post { render(r) }
        }.start()
    }

    private fun render(f: List<Finding>) {
        val head = "IOC cargados: ${Ioc.count()}" +
            (if (Ioc.count() == 0) "\n⚠ Sin IOC no se compara contra indicadores conocidos de Pegasus/otros." else "") +
            "\n🔴 ${f.count { it.level == 3 }}  🟠 ${f.count { it.level == 2 }}\n\n"
        report = head + f.joinToString("\n\n") { (if (it.level == 3) "🔴 " else if (it.level == 2) "🟠 " else "🟢 ") + it.title + "\n" + it.detail }
        out.text = report
        if (f.any { it.title == "Sin permiso de uso" }) startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
    }

    private fun renderDns() {
        out.text = (if (DnsVpnService.running) "Monitor activo. Toca de nuevo el botón para detener.\n\n" else "Detenido.\n\n") +
            DnsVpnService.log.take(120).joinToString("\n")
    }

    private fun toggleDns() {
        showingDns = true
        if (DnsVpnService.running) { stopService(Intent(this, DnsVpnService::class.java)); return }
        val i = VpnService.prepare(this)
        if (i != null) startActivityForResult(i, 1) else startService(Intent(this, DnsVpnService::class.java))
    }

    override fun onActivityResult(rq: Int, rs: Int, d: Intent?) {
        if (rs != RESULT_OK) return
        if (rq == 1) startService(Intent(this, DnsVpnService::class.java))
        if (rq == 3 && d != null) {
            val uris = d.clipData?.let { c -> (0 until c.itemCount).map { c.getItemAt(it).uri } } ?: listOfNotNull(d.data)
            val n = uris.sumOf { runCatching { Ioc.import(this, it) }.getOrDefault(0) }
            out.text = "Importados $n indicadores nuevos. Total: ${Ioc.count()}"
        }
    }
}

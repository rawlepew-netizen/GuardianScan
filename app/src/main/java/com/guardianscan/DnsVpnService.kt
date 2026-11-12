package com.guardianscan

import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors

/**
 * VPN local que captura SOLO las consultas DNS (ruta 10.77.0.2/32), las registra y las
 * reenvía a un DNS real. No ve el contenido del tráfico, pero muestra con quién
 * intenta hablar cada app: dominios nuevos, balizas periódicas, dominios sospechosos.
 */
class DnsVpnService : VpnService() {
    companion object {
        @Volatile var running = false
        val log = CopyOnWriteArrayList<String>()
        val counts = ConcurrentHashMap<String, Int>()
        const val FAKE_DNS = "10.77.0.2"; const val UPSTREAM = "1.1.1.1"
        private val BAD_TLD = setOf("xyz", "top", "tk", "gq", "ml", "cf", "ga", "click", "zip")

        fun suspicious(d: String): String? {
            val labels = d.split('.')
            if (labels.any { it.length > 30 }) return "subdominio muy largo (posible exfiltración)"
            if (d.length > 60) return "dominio inusualmente largo"
            if (labels.last() in BAD_TLD) return "TLD de alto abuso"
            if ((counts[d] ?: 0) > 150) return "consultas repetitivas (baliza)"
            return null
        }
    }
    private var tun: ParcelFileDescriptor? = null
    private val pool = Executors.newFixedThreadPool(8)

    override fun onStartCommand(i: android.content.Intent?, f: Int, id: Int): Int {
        if (tun == null) {
            tun = Builder().setSession("GuardianScan").addAddress("10.77.0.1", 32)
                .addDnsServer(FAKE_DNS).addRoute(FAKE_DNS, 32).establish()
            running = tun != null
            if (running) Thread { loop() }.start()
        }
        return START_STICKY
    }

    private fun loop() {
        val input = FileInputStream(tun!!.fileDescriptor)
        val output = FileOutputStream(tun!!.fileDescriptor)
        val buf = ByteArray(32767)
        while (running) {
            val n = try { input.read(buf) } catch (e: Exception) { break }
            if (n <= 0) continue
            val pkt = buf.copyOf(n)
            val ihl = (pkt[0].toInt() and 0xF) * 4
            if (pkt[0].toInt() shr 4 != 4 || pkt[9].toInt() != 17 || n < ihl + 20) continue
            val dport = ((pkt[ihl + 2].toInt() and 0xFF) shl 8) or (pkt[ihl + 3].toInt() and 0xFF)
            if (dport != 53) continue
            val dns = pkt.copyOfRange(ihl + 8, n)
            record(parseName(dns))
            pool.execute {
                try {
                    val s = DatagramSocket(); protect(s); s.soTimeout = 3000
                    s.send(DatagramPacket(dns, dns.size, InetAddress.getByName(UPSTREAM), 53))
                    val rb = ByteArray(4096); val rp = DatagramPacket(rb, rb.size); s.receive(rp); s.close()
                    val reply = buildReply(pkt, ihl, rb.copyOf(rp.length))
                    synchronized(output) { output.write(reply) }
                } catch (_: Exception) {}
            }
        }
    }

    private fun record(name: String) {
        if (name.isEmpty()) return
        counts.merge(name, 1, Int::plus)
        val flag = suspicious(name)
        val t = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())
        log.add(0, (if (flag != null) "⚠ " else "") + "$t $name" + (flag?.let { "  → $it" } ?: ""))
        while (log.size > 300) log.removeAt(log.size - 1)
    }

    private fun parseName(d: ByteArray): String {
        val sb = StringBuilder(); var i = 12
        while (i < d.size && d[i].toInt() != 0) {
            val l = d[i].toInt() and 0xFF; if (i + 1 + l > d.size) break
            if (sb.isNotEmpty()) sb.append('.')
            sb.append(String(d, i + 1, l)); i += l + 1
        }
        return sb.toString().lowercase()
    }

    private fun buildReply(req: ByteArray, ihl: Int, dns: ByteArray): ByteArray {
        val total = ihl + 8 + dns.size; val r = ByteArray(total)
        System.arraycopy(req, 0, r, 0, ihl + 8)
        System.arraycopy(req, 16, r, 12, 4); System.arraycopy(req, 12, r, 16, 4)
        r[ihl] = req[ihl + 2]; r[ihl + 1] = req[ihl + 3]; r[ihl + 2] = req[ihl]; r[ihl + 3] = req[ihl + 1]
        r[2] = (total shr 8).toByte(); r[3] = total.toByte(); r[8] = 64
        r[10] = 0; r[11] = 0
        val ul = 8 + dns.size
        r[ihl + 4] = (ul shr 8).toByte(); r[ihl + 5] = ul.toByte(); r[ihl + 6] = 0; r[ihl + 7] = 0
        System.arraycopy(dns, 0, r, ihl + 8, dns.size)
        var sum = 0; var i = 0
        while (i < ihl) { sum += ((r[i].toInt() and 0xFF) shl 8) or (r[i + 1].toInt() and 0xFF); i += 2 }
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        val c = sum.inv() and 0xFFFF; r[10] = (c shr 8).toByte(); r[11] = c.toByte()
        return r
    }

    override fun onDestroy() { running = false; tun?.close(); tun = null; pool.shutdownNow() }
    override fun onRevoke() { onDestroy() }
}

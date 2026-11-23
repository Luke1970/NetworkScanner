package nl.sc00by.networkscanner.scan

import android.content.Context
import java.io.InputStream
import java.net.Inet6Address
import java.util.zip.GZIPInputStream

/** MAC address helpers + IEEE OUI → manufacturer lookup (assets/oui.dat = gzip TSV, built by tools/update-oui.py). */
object Oui {

    @Volatile
    private var table: Map<String, String> = emptyMap()

    fun load(context: Context) = load { context.assets.open("oui.dat") }

    fun load(open: () -> InputStream) {
        if (table.isNotEmpty()) return
        synchronized(this) {
            if (table.isNotEmpty()) return
            val map = HashMap<String, String>(50_000)
            open().use { raw ->
                GZIPInputStream(raw).bufferedReader().forEachLine { line ->
                    val tab = line.indexOf('\t')
                    if (tab == 6) map[line.substring(0, 6)] = line.substring(7)
                }
            }
            table = map
        }
    }

    /** Manufacturer for "AA:BB:CC:DD:EE:FF", or a note for randomized/private addresses. */
    fun vendor(mac: String): String? {
        if (isLocallyAdministered(mac)) return "randomized / private MAC"
        return table[mac.replace(":", "").take(6)]
    }

    fun isKnownVendor(mac: String) = !isLocallyAdministered(mac) && table.containsKey(mac.replace(":", "").take(6))

    fun isLocallyAdministered(mac: String) = (mac.substring(0, 2).toInt(16) and 0x02) != 0

    /** Accepts aa:bb:cc:dd:ee:ff, aa-bb-..., aabb.ccdd.eeff or aabbccddeeff; returns AA:BB:CC:DD:EE:FF. */
    fun normalize(raw: String): String? {
        val hex = raw.trim().replace(Regex("[:\\-.]"), "").uppercase()
        if (!hex.matches(Regex("[0-9A-F]{12}"))) return null
        if (hex == "000000000000" || hex == "FFFFFFFFFFFF") return null
        return hex.chunked(2).joinToString(":")
    }

    fun fromBytes(b: ByteArray, off: Int): String? =
        normalize((0 until 6).joinToString("") { "%02X".format(b[off + it].toInt() and 0xFF) })

    /** IPv6 interface IDs built with EUI-64 (…xx:xxff:fexx:xxxx) embed the MAC. */
    fun fromEui64(addr: Inet6Address): String? {
        val b = addr.address
        if ((b[11].toInt() and 0xFF) != 0xFF || (b[12].toInt() and 0xFF) != 0xFE) return null
        val mac = byteArrayOf((b[8].toInt() xor 0x02).toByte(), b[9], b[10], b[13], b[14], b[15])
        return fromBytes(mac, 0)
    }
}

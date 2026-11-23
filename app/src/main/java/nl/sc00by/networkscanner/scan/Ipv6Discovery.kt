package nl.sc00by.networkscanner.scan

import android.net.Network
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructTimeval
import java.net.Inet6Address
import java.net.InetSocketAddress

/**
 * IPv6 has no broadcast and a /64 is far too big to sweep, so devices are found by asking them:
 * one ICMPv6 echo request to the "all nodes" multicast group ff02::1 is answered by (almost)
 * every IPv6 device on the link. Android apps may use unprivileged ICMP "ping sockets", so no
 * root is needed. Windows ignores multicast pings; those PCs are only found through mDNS.
 */
object Ipv6Discovery {

    private val ALL_NODES = ByteArray(16).also { it[0] = 0xFF.toByte(); it[1] = 0x02; it[15] = 0x01 }

    /**
     * Pings ff02::1 once from every source address in [sources] (link-local, global, ULA); a device
     * answers from an address of the same scope, so each source reveals another set of addresses.
     */
    fun pingAllNodes(network: Network?, sources: List<Inet6Address>, scopeId: Int, listenMs: Long = 2500): Set<Inet6Address> {
        val found = mutableSetOf<Inet6Address>()
        val threads = sources.map { src ->
            Thread {
                val r = runCatching { pingFrom(network, src, scopeId, listenMs) }.getOrDefault(emptySet())
                synchronized(found) { found += r }
            }.also { it.start() }
        }
        threads.forEach { it.join(listenMs + 2000) }
        return synchronized(found) { found.toSet() }
    }

    private fun pingFrom(network: Network?, source: Inet6Address, scopeId: Int, listenMs: Long): Set<Inet6Address> {
        val fd = Os.socket(OsConstants.AF_INET6, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_ICMPV6)
        val found = mutableSetOf<Inet6Address>()
        try {
            runCatching { network?.bindSocket(fd) }
            val bindTo = if (source.isLinkLocalAddress) Inet6Address.getByAddress(null, source.address, scopeId) else source
            Os.bind(fd, bindTo, 0)
            Os.setsockoptInt(fd, OsConstants.IPPROTO_IPV6, OsConstants.IPV6_MULTICAST_IF, scopeId)
            Os.setsockoptTimeval(fd, OsConstants.SOL_SOCKET, OsConstants.SO_RCVTIMEO, StructTimeval.fromMillis(200))
            val dest = Inet6Address.getByAddress(null, ALL_NODES, scopeId)

            val start = System.currentTimeMillis()
            var sent = 0
            val buf = ByteArray(1500)
            while (true) {
                val elapsed = System.currentTimeMillis() - start
                if (elapsed >= listenMs) break
                // Second request after 0.8 s: multicast is lossy on Wi-Fi.
                if (sent == 0 || (sent == 1 && elapsed >= 800)) {
                    val echo = echoRequest(sent)
                    runCatching { Os.sendto(fd, echo, 0, echo.size, 0, dest, 0) }
                    sent++
                }
                val from = InetSocketAddress(0)
                val n = try {
                    Os.recvfrom(fd, buf, 0, buf.size, 0, from)
                } catch (e: ErrnoException) {
                    if (e.errno == OsConstants.EAGAIN || e.errno == OsConstants.EINTR) continue else throw e
                }
                // Type 129 = echo reply (the kernel already matched our identifier).
                if (n >= 8 && (buf[0].toInt() and 0xFF) == 129) (from.address as? Inet6Address)?.let { found += it }
            }
        } finally {
            runCatching { Os.close(fd) }
        }
        return found
    }

    /** ICMPv6 echo request; identifier and checksum are filled in by the kernel for ping sockets. */
    private fun echoRequest(seq: Int): ByteArray {
        val b = ByteArray(16)
        b[0] = 128.toByte()
        b[6] = (seq shr 8).toByte(); b[7] = seq.toByte()
        "NetScan!".toByteArray().copyInto(b, 8)
        return b
    }

    // ---- address helpers ---------------------------------------------------------------

    enum class Scope(val label: String) {
        GLOBAL("global"), UNIQUE_LOCAL("unique local"), SITE_LOCAL("site-local (old style)"), LINK_LOCAL("link-local")
    }

    fun scopeOf(a: Inet6Address): Scope = when {
        a.isLinkLocalAddress -> Scope.LINK_LOCAL
        (a.address[0].toInt() and 0xFE) == 0xFC -> Scope.UNIQUE_LOCAL
        a.isSiteLocalAddress -> Scope.SITE_LOCAL
        else -> Scope.GLOBAL
    }

    /** Text without zone, compressed ("fe80::1"), as people write IPv6 addresses. */
    fun text(a: Inet6Address): String = compress(a.address)

    /** Key used for scanning: link-local addresses carry the numeric interface scope. */
    fun key(a: Inet6Address, scopeId: Int): String =
        if (a.isLinkLocalAddress) "${text(a)}%$scopeId" else text(a)

    /** RFC 5952 form: lower case, leading zeros dropped, longest run of zero groups as "::". */
    fun compress(b: ByteArray): String {
        val g = IntArray(8) { ((b[2 * it].toInt() and 0xFF) shl 8) or (b[2 * it + 1].toInt() and 0xFF) }
        var bestStart = -1; var bestLen = 0
        var i = 0
        while (i < 8) {
            if (g[i] == 0) {
                var j = i
                while (j < 8 && g[j] == 0) j++
                if (j - i > bestLen && j - i >= 2) { bestStart = i; bestLen = j - i }
                i = j
            } else i++
        }
        if (bestStart < 0) return g.joinToString(":") { Integer.toHexString(it) }
        val head = (0 until bestStart).joinToString(":") { Integer.toHexString(g[it]) }
        val tail = (bestStart + bestLen until 8).joinToString(":") { Integer.toHexString(g[it]) }
        return "$head::$tail"
    }

    /** True if [a] lies inside [prefix]/[length]. */
    fun inPrefix(a: Inet6Address, prefix: Inet6Address, length: Int): Boolean {
        val x = a.address; val p = prefix.address
        var bits = length
        var i = 0
        while (bits > 0 && i < 16) {
            val mask = if (bits >= 8) 0xFF else (0xFF shl (8 - bits)) and 0xFF
            if ((x[i].toInt() and mask) != (p[i].toInt() and mask)) return false
            bits -= 8; i++
        }
        return true
    }

    /** Interface ID built from the MAC (ff:fe in the middle) instead of random (privacy / stable-privacy). */
    fun isEui64(a: Inet6Address) = (a.address[11].toInt() and 0xFF) == 0xFF && (a.address[12].toInt() and 0xFF) == 0xFE
}

package nl.sc00by.networkscanner.scan

import android.net.Network
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import kotlin.random.Random

/** Configuration a DHCP server handed back in reply to our DHCPINFORM. */
data class DhcpReply(
    val serverId: String?,
    val repliedFrom: String,
    val subnetMask: String?,
    val routers: List<String>,
    val dnsServers: List<String>,
    val domainName: String?,
    val searchDomains: List<String>,
    val ntpServers: List<String>,
    val winsServers: List<String>,
    val leaseSeconds: Long?,
    val nextServer: String?,       // siaddr: classic PXE "next-server"
    val tftpServerName: String?,   // option 66 or legacy sname field
    val tftpServerAddresses: List<String>, // option 150 (Cisco)
    val bootFile: String?,         // option 67 or legacy file field
    val wpadUrl: String?,          // option 252
    val otherOptions: List<Int>,
)

sealed interface DhcpQuery {
    data object Idle : DhcpQuery
    data object Running : DhcpQuery
    data class Done(val reply: DhcpReply) : DhcpQuery
    data class Failed(val reason: String) : DhcpQuery
}

/**
 * Sends a DHCPINFORM (RFC 2131 §3.4): "I already have an address, tell me your options".
 * Apps cannot bind UDP port 68, so we send from an ephemeral port. dnsmasq-based routers
 * reply to that port; servers that always reply to port 68 will look silent.
 */
object DhcpInform {

    private const val SERVER_PORT = 67
    private val COOKIE = byteArrayOf(99, 130.toByte(), 83, 99)
    private val REQUESTED = intArrayOf(1, 3, 6, 15, 42, 44, 51, 54, 66, 67, 119, 150, 252)
    private val HANDLED = setOf(0, 1, 3, 6, 15, 42, 44, 51, 52, 53, 54, 66, 67, 119, 150, 252, 255)

    fun query(network: Network, ownIp: Inet4Address, server: Inet4Address?, timeoutMs: Int = 2500): DhcpQuery {
        val xid = Random.nextInt()
        val target = server ?: InetAddress.getByName("255.255.255.255")
        DatagramSocket(null).use { socket ->
            socket.reuseAddress = true
            socket.broadcast = true
            socket.bind(InetSocketAddress(0))
            network.bindSocket(socket)
            socket.soTimeout = timeoutMs

            val request = buildInform(xid, ownIp)
            val response = ByteArray(1500)
            repeat(2) {
                socket.send(DatagramPacket(request, request.size, target, SERVER_PORT))
                val deadline = System.currentTimeMillis() + timeoutMs
                while (System.currentTimeMillis() < deadline) {
                    val packet = DatagramPacket(response, response.size)
                    try {
                        socket.receive(packet)
                    } catch (_: SocketTimeoutException) {
                        break
                    }
                    val reply = parse(packet.data.copyOf(packet.length), xid, packet.address.hostAddress ?: "?")
                    if (reply != null) return DhcpQuery.Done(reply)
                }
            }
        }
        return DhcpQuery.Failed(
            if (server == null) "No reply to broadcast DHCPINFORM"
            else "No reply from ${server.hostAddress} (it may only answer on port 68, which apps cannot use)"
        )
    }

    internal fun buildInform(xid: Int, ownIp: Inet4Address): ByteArray {
        val b = ByteBuffer.allocate(300)
        b.put(1).put(1).put(6).put(0)          // op=BOOTREQUEST, htype=Ethernet, hlen=6, hops
        b.putInt(xid)
        b.putShort(0).putShort(0)              // secs, flags (unicast reply)
        b.put(ownIp.address)                   // ciaddr
        b.put(ByteArray(12))                   // yiaddr, siaddr, giaddr
        // chaddr: Android hides the real MAC from apps; use a locally administered dummy.
        b.put(byteArrayOf(0x02, 0, ownIp.address[0], ownIp.address[1], ownIp.address[2], ownIp.address[3]))
        b.put(ByteArray(10 + 64 + 128))        // chaddr padding, sname, file
        b.put(COOKIE)
        b.put(53).put(1).put(8)                // DHCPINFORM
        b.put(55).put(REQUESTED.size.toByte()); REQUESTED.forEach { b.put(it.toByte()) }
        b.put(255.toByte())
        return b.array()
    }

    internal fun parse(p: ByteArray, xid: Int, from: String): DhcpReply? {
        if (p.size < 240 || p[0].toInt() != 2) return null
        if (ByteBuffer.wrap(p, 4, 4).int != xid) return null
        if (!p.copyOfRange(236, 240).contentEquals(COOKIE)) return null

        val opts = mutableMapOf<Int, ByteArray>()
        var i = 240
        while (i < p.size) {
            val code = p[i].toInt() and 0xFF
            if (code == 255) break
            if (code == 0) { i++; continue }
            if (i + 1 >= p.size) break
            val len = p[i + 1].toInt() and 0xFF
            if (i + 2 + len > p.size) break
            opts[code] = (opts[code] ?: ByteArray(0)) + p.copyOfRange(i + 2, i + 2 + len) // RFC 3396 concat
            i += 2 + len
        }
        val type = opts[53]?.firstOrNull()?.toInt()
        if (type != 5) return null // only DHCPACK carries the configuration

        val overload = opts[52]?.firstOrNull()?.toInt() ?: 0
        val legacySname = if (overload and 2 == 0) cString(p, 44, 64) else null
        val legacyFile = if (overload and 1 == 0) cString(p, 108, 128) else null
        val siaddr = ipv4(p, 20).takeIf { it != "0.0.0.0" }

        return DhcpReply(
            serverId = opts[54]?.let { ipList(it).firstOrNull() },
            repliedFrom = from,
            subnetMask = opts[1]?.let { ipList(it).firstOrNull() },
            routers = opts[3]?.let(::ipList).orEmpty(),
            dnsServers = opts[6]?.let(::ipList).orEmpty(),
            domainName = opts[15]?.let { text(it) },
            searchDomains = opts[119]?.let(::dnsNames).orEmpty(),
            ntpServers = opts[42]?.let(::ipList).orEmpty(),
            winsServers = opts[44]?.let(::ipList).orEmpty(),
            leaseSeconds = opts[51]?.takeIf { it.size == 4 }?.let { ByteBuffer.wrap(it).int.toLong() and 0xFFFFFFFFL },
            nextServer = siaddr,
            tftpServerName = opts[66]?.let { text(it) } ?: legacySname,
            tftpServerAddresses = opts[150]?.let(::ipList).orEmpty(),
            bootFile = opts[67]?.let { text(it) } ?: legacyFile,
            wpadUrl = opts[252]?.let { text(it) },
            otherOptions = opts.keys.filterNot { it in HANDLED }.sorted(),
        )
    }

    private fun ipv4(p: ByteArray, off: Int) =
        (0 until 4).joinToString(".") { (p[off + it].toInt() and 0xFF).toString() }

    private fun ipList(b: ByteArray) = (0 until b.size / 4).map { ipv4(b, it * 4) }

    private fun text(b: ByteArray) = String(b, Charsets.US_ASCII).trimEnd('\u0000').trim().ifEmpty { null }

    private fun cString(p: ByteArray, off: Int, len: Int): String? {
        val end = (off until off + len).firstOrNull { p[it].toInt() == 0 } ?: (off + len)
        return String(p, off, end - off, Charsets.US_ASCII).trim().ifEmpty { null }
    }

    /** Option 119: DNS wire-format names with compression pointers relative to the option data. */
    private fun dnsNames(b: ByteArray): List<String> {
        val names = mutableListOf<String>()
        var pos = 0
        while (pos < b.size) {
            val labels = mutableListOf<String>()
            var p = pos
            var jumped = false
            var guard = 0
            while (p < b.size && guard++ < 128) {
                val len = b[p].toInt() and 0xFF
                when {
                    len == 0 -> { if (!jumped) pos = p + 1; break }
                    len and 0xC0 == 0xC0 -> {
                        if (p + 1 >= b.size) return names
                        if (!jumped) pos = p + 2
                        jumped = true
                        p = ((len and 0x3F) shl 8) or (b[p + 1].toInt() and 0xFF)
                    }
                    else -> {
                        if (p + 1 + len > b.size) return names
                        labels += String(b, p + 1, len, Charsets.US_ASCII)
                        p += 1 + len
                    }
                }
            }
            if (labels.isNotEmpty()) names += labels.joinToString(".")
            if (guard >= 128) break
        }
        return names
    }
}

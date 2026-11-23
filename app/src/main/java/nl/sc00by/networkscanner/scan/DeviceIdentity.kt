package nl.sc00by.networkscanner.scan

import android.net.Network
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.net.URL
import java.nio.ByteBuffer
import javax.net.SocketFactory
import kotlin.random.Random

/**
 * A MAC address and the protocol that revealed it. [exact] = false when it came from a device ID
 * (UPnP UDN/serial, AirPlay ID): right manufacturer, but the interface MAC may differ slightly.
 */
data class MacInfo(val mac: String, val source: String, val exact: Boolean = true)

/** What a device told us about itself over discovery protocols. */
data class Identity(
    val mac: MacInfo? = null,
    val mdnsName: String? = null,
    val netbiosName: String? = null,
    val upnpName: String? = null,
    /** SSDP "SERVER:" header, e.g. "Linux/5.10 UPnP/1.0 …" or "Microsoft-Windows/10.0 UPnP/1.0". */
    val upnpServer: String? = null,
    /** mDNS _device-info model, e.g. "MacBookPro18,1" or "iPhone15,2". */
    val model: String? = null,
) {
    fun merge(other: Identity) = Identity(
        mac = pickMac(mac, other.mac),
        mdnsName = mdnsName ?: other.mdnsName,
        netbiosName = netbiosName ?: other.netbiosName,
        upnpName = upnpName ?: other.upnpName,
        upnpServer = upnpServer ?: other.upnpServer,
        model = model ?: other.model,
    )

    private fun pickMac(a: MacInfo?, b: MacInfo?): MacInfo? = when {
        a == null -> b
        b == null -> a
        Oui.isLocallyAdministered(a.mac) && !Oui.isLocallyAdministered(b.mac) -> b
        !a.exact && b.exact -> b
        else -> a
    }
}

/** Collects a UDP request/response exchange on one socket bound to the LAN network. */
private inline fun udpExchange(
    network: Network?,
    timeoutMs: Int,
    send: (DatagramSocket) -> Unit,
    onPacket: (DatagramPacket) -> Unit,
) {
    DatagramSocket(null).use { socket ->
        socket.reuseAddress = true
        socket.broadcast = true
        socket.bind(InetSocketAddress(0))
        network?.bindSocket(socket) // null only in JVM tests
        send(socket)
        val deadline = System.currentTimeMillis() + timeoutMs
        val buf = ByteArray(9000)
        while (true) {
            val left = deadline - System.currentTimeMillis()
            if (left <= 0) break
            socket.soTimeout = left.toInt()
            val packet = DatagramPacket(buf, buf.size)
            try {
                socket.receive(packet)
            } catch (_: SocketTimeoutException) {
                break
            }
            runCatching { onPacket(packet) }
        }
    }
}

// ---------------------------------------------------------------------------------------
// NetBIOS node status (UDP 137): Windows, Samba, many NAS boxes return name + MAC.
// ---------------------------------------------------------------------------------------
object NetBios {

    private val REQUEST: ByteArray = ByteBuffer.allocate(50).apply {
        putShort(0x4C53).putShort(0).putShort(1).putShort(0).putShort(0).putShort(0)
        put(0x20)
        put("CK".toByteArray()); repeat(15) { put("AA".toByteArray()) } // "*" + 15 NULs, half-ASCII encoded
        put(0)
        putShort(0x21).putShort(1) // NBSTAT, IN
    }.array()

    fun query(network: Network?, ips: List<String>, timeoutMs: Int = 2000): Map<String, Identity> {
        val result = mutableMapOf<String, Identity>()
        udpExchange(network, timeoutMs, send = { s ->
            for (ip in ips) {
                runCatching { s.send(DatagramPacket(REQUEST, REQUEST.size, InetAddress.getByName(ip), 137)) }
            }
        }) { p ->
            parse(p.data.copyOf(p.length))?.let { result[p.address.hostAddress!!] = it }
        }
        return result
    }

    private fun parse(b: ByteArray): Identity? {
        if (b.size < 57) return null
        var pos = 12
        while (pos < b.size && b[pos].toInt() != 0) {           // skip the echoed name
            if (b[pos].toInt() and 0xC0 == 0xC0) { pos += 1; break }
            pos += (b[pos].toInt() and 0xFF) + 1
        }
        pos += 1 + 2 + 2 + 4 + 2                                 // end, type, class, ttl, rdlength
        if (pos >= b.size) return null
        val count = b[pos].toInt() and 0xFF
        pos += 1
        var name: String? = null
        repeat(count) { i ->
            val off = pos + i * 18
            if (off + 18 > b.size) return null
            val suffix = b[off + 15].toInt() and 0xFF
            val group = (b[off + 16].toInt() and 0x80) != 0
            if (name == null && suffix == 0 && !group) name = String(b, off, 15, Charsets.US_ASCII).trim()
        }
        val macOff = pos + count * 18
        val mac = if (macOff + 6 <= b.size) Oui.fromBytes(b, macOff) else null
        return Identity(mac = mac?.let { MacInfo(it, "NetBIOS") }, netbiosName = name)
    }
}

// ---------------------------------------------------------------------------------------
// mDNS / Bonjour via "legacy unicast" queries (RFC 6762 §6.7): we query from an ephemeral
// port and responders answer us directly, so no multicast lock or port 5353 is needed.
// ---------------------------------------------------------------------------------------
object Mdns {

    private val SERVICES = listOf(
        "_workstation._tcp.local", "_raop._tcp.local", "_airplay._tcp.local", "_hue._tcp.local",
        "_device-info._tcp.local", "_googlecast._tcp.local", "_http._tcp.local", "_smb._tcp.local",
        "_ipp._tcp.local", "_hap._tcp.local", "_esphomelib._tcp.local", "_home-assistant._tcp.local",
        "_sonos._tcp.local", "_spotify-connect._tcp.local", "_ssh._tcp.local", "_printer._tcp.local",
    )
    private val GROUP: InetAddress by lazy { InetAddress.getByName("224.0.0.251") }

    private val WORKSTATION_MAC = Regex("\\[([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})]")
    private val RAOP_MAC = Regex("^([0-9A-Fa-f]{12})@")

    /** Browse common service types; also asks reverse (PTR) names for [reverseFor]. */
    fun query(network: Network?, reverseFor: List<String> = emptyList(), timeoutMs: Int = 2500): Map<String, Identity> {
        val questions = if (reverseFor.isEmpty()) SERVICES.map { it to 12 }
        else reverseFor.map { ip -> ip.split('.').reversed().joinToString(".") + ".in-addr.arpa" to 12 }
        val result = mutableMapOf<String, Identity>()
        udpExchange(network, timeoutMs, send = { s ->
            // Keep packets small: 12 questions per packet.
            questions.chunked(12).forEach { chunk ->
                val q = buildQuery(chunk)
                repeat(2) { s.send(DatagramPacket(q, q.size, GROUP, 5353)) }
            }
        }) { p ->
            for ((ip, id) in parse(p.data.copyOf(p.length), p.address)) {
                result[ip] = result[ip]?.merge(id) ?: id
            }
        }
        return result
    }

    private fun buildQuery(questions: List<Pair<String, Int>>): ByteArray {
        val out = ByteArrayOutputStream()
        val header = ByteBuffer.allocate(12).putShort(Random.nextInt(1, 0xFFFF).toShort()).putShort(0)
            .putShort(questions.size.toShort()).putShort(0).putShort(0).putShort(0)
        out.write(header.array())
        for ((name, type) in questions) {
            name.split('.').forEach { label -> out.write(label.length); out.write(label.toByteArray()) }
            out.write(0)
            out.write(byteArrayOf(0, type.toByte(), 0, 1))
        }
        return out.toByteArray()
    }

    private class Rr(val name: String, val type: Int, val text: String?, val txt: List<String>, val v6: Inet6Address?)

    /** An IPv6 address announced over mDNS, with the host name and IPv4 address in the same answer. */
    data class Aaaa(val address: Inet6Address, val name: String, val ipv4: String?)

    /** "…ip6.arpa" name for a reverse lookup: the 32 hex nibbles in reverse order. */
    fun reverseName6(a: Inet6Address): String = buildString {
        for (i in 15 downTo 0) {
            val v = a.address[i].toInt()
            append(Integer.toHexString(v and 0xF)).append('.')
            append(Integer.toHexString((v shr 4) and 0xF)).append('.')
        }
        append("ip6.arpa")
    }

    /**
     * Reverse mDNS for IPv6 addresses: asks "who is …ip6.arpa?" (PTR). Apple devices and Linux with
     * Avahi answer with their host name, also for link-local addresses that DNS can't resolve.
     * Returns address text → name.
     */
    fun reverse6(network: Network?, addresses: List<Inet6Address>, timeoutMs: Int = 2000): Map<String, String> {
        if (addresses.isEmpty()) return emptyMap()
        val byName = addresses.associateBy { reverseName6(it) }
        val result = mutableMapOf<String, String>()
        udpExchange(network, timeoutMs, send = { s ->
            byName.keys.map { it to 12 }.chunked(10).forEach { chunk ->
                val q = buildQuery(chunk)
                repeat(2) { s.send(DatagramPacket(q, q.size, GROUP, 5353)) }
            }
        }) { p ->
            for (rr in records(p.data.copyOf(p.length))) {
                if (rr.type != 12) continue
                val addr = byName[rr.name.lowercase()] ?: continue
                val name = rr.text?.removeSuffix(".")?.removeSuffix(".local")?.takeIf { it.isNotBlank() } ?: continue
                result.putIfAbsent(Ipv6Discovery.text(addr), name)
            }
        }
        return result
    }

    /** Browse the same service types, collecting AAAA records (IPv6 addresses) and their names. */
    fun queryAaaa(network: Network?, timeoutMs: Int = 2500): List<Aaaa> {
        val out = mutableListOf<Aaaa>()
        udpExchange(network, timeoutMs, send = { s ->
            SERVICES.map { it to 12 }.chunked(12).forEach { chunk ->
                val q = buildQuery(chunk)
                repeat(2) { s.send(DatagramPacket(q, q.size, GROUP, 5353)) }
            }
        }) { p ->
            val rrs = records(p.data.copyOf(p.length))
            val v4 = rrs.filter { it.type == 1 && it.text != null }.associate { it.name to it.text }
            rrs.filter { it.type == 28 && it.v6 != null }.forEach { rr ->
                out += Aaaa(rr.v6!!, rr.name.removeSuffix(".local"), v4[rr.name])
            }
        }
        return out.distinctBy { it.address }
    }

    private fun records(b: ByteArray): List<Rr> {
        if (b.size < 12) return emptyList()
        val bb = ByteBuffer.wrap(b)
        val qd = bb.getShort(4).toInt() and 0xFFFF
        val rrCount = (bb.getShort(6).toInt() and 0xFFFF) + (bb.getShort(8).toInt() and 0xFFFF) +
            (bb.getShort(10).toInt() and 0xFFFF)
        var pos = 12
        repeat(qd) { pos = readName(b, pos).second + 4 }

        val rrs = mutableListOf<Rr>()
        repeat(rrCount) {
            if (pos >= b.size) return@repeat
            val (name, after) = readName(b, pos)
            if (after + 10 > b.size) return@repeat
            val type = bb.getShort(after).toInt() and 0xFFFF
            val len = bb.getShort(after + 8).toInt() and 0xFFFF
            val data = after + 10
            if (data + len > b.size) return@repeat
            rrs += when (type) {
                1 -> Rr(name, type, if (len == 4) InetAddress.getByAddress(b.copyOfRange(data, data + 4)).hostAddress else null, emptyList(), null)
                28 -> Rr(name, type, null, emptyList(), if (len == 16) InetAddress.getByAddress(b.copyOfRange(data, data + 16)) as? Inet6Address else null)
                12 -> Rr(name, type, readName(b, data).first, emptyList(), null)
                33 -> Rr(name, type, readName(b, data + 6).first, emptyList(), null)
                16 -> Rr(name, type, null, readTxt(b, data, len), null)
                else -> Rr(name, type, null, emptyList(), null)
            }
            pos = data + len
        }
        return rrs
    }

    private fun parse(b: ByteArray, from: InetAddress): Map<String, Identity> {
        val rrs = records(b)
        // Attribute the packet to the host it describes (its A record), else to the sender.
        val aRecord = rrs.firstOrNull { it.type == 1 && it.text != null && !it.name.endsWith("in-addr.arpa") }
        val ip = aRecord?.text ?: (from as? Inet4Address)?.hostAddress ?: return emptyMap()
        var hostName = aRecord?.name?.removeSuffix(".local")
        rrs.firstOrNull { it.type == 12 && it.name.endsWith(".in-addr.arpa") }?.text?.let {
            hostName = hostName ?: it.removeSuffix(".local")
        }

        val model = rrs.filter { it.name.contains("_device-info._tcp") }.flatMap { it.txt }
            .firstOrNull { it.startsWith("model=", ignoreCase = true) }?.substringAfter('=')?.takeIf { it.isNotBlank() }
        val macs = mutableListOf<MacInfo>()
        for (rr in rrs) {
            val instance = if (rr.type == 12) rr.text.orEmpty() else rr.name
            WORKSTATION_MAC.find(instance)?.let { m -> Oui.normalize(m.groupValues[1])?.let { macs += MacInfo(it, "mDNS") } }
            RAOP_MAC.find(instance)?.let { m ->
                Oui.normalize(m.groupValues[1])?.takeIf(Oui::isKnownVendor)?.let { macs += MacInfo(it, "AirPlay ID", exact = false) }
            }
            for (kv in rr.txt) {
                val key = kv.substringBefore('=').lowercase()
                val value = kv.substringAfter('=', "")
                when (key) {
                    "mac", "macaddress", "hwaddr" -> Oui.normalize(value)?.let { macs += MacInfo(it, "mDNS") }
                    // AirPlay deviceid is often a MAC, but some vendors (e.g. LG TVs) put a made-up ID here.
                    "deviceid" -> Oui.normalize(value)?.takeIf(Oui::isKnownVendor)
                        ?.let { macs += MacInfo(it, "AirPlay ID", exact = false) }
                    "bridgeid" -> if (value.length == 16 && value.substring(6, 10).equals("FFFE", true)) {
                        Oui.normalize(value.take(6) + value.takeLast(6))?.let { macs += MacInfo(it, "mDNS (Hue)") }
                    }
                }
            }
            rr.v6?.takeIf { it.isLinkLocalAddress }?.let(Oui::fromEui64)?.let { macs += MacInfo(it, "IPv6 EUI-64") }
        }
        val best = macs.firstOrNull { it.exact && !Oui.isLocallyAdministered(it.mac) }
            ?: macs.firstOrNull { !Oui.isLocallyAdministered(it.mac) } ?: macs.firstOrNull()
        if (best == null && hostName == null && model == null) return emptyMap()
        return mapOf(ip to Identity(mac = best, mdnsName = hostName, model = model))
    }

    private fun readTxt(b: ByteArray, start: Int, len: Int): List<String> {
        val out = mutableListOf<String>()
        var p = start
        while (p < start + len) {
            val l = b[p].toInt() and 0xFF
            if (p + 1 + l > start + len) break
            out += String(b, p + 1, l, Charsets.UTF_8)
            p += 1 + l
        }
        return out
    }

    /** DNS name with compression; returns the name and the position after it. */
    private fun readName(b: ByteArray, start: Int): Pair<String, Int> {
        val labels = mutableListOf<String>()
        var p = start
        var end = -1
        var hops = 0
        while (p < b.size && hops++ < 64) {
            val len = b[p].toInt() and 0xFF
            when {
                len == 0 -> { if (end < 0) end = p + 1; break }
                len and 0xC0 == 0xC0 -> {
                    if (p + 1 >= b.size) break
                    if (end < 0) end = p + 2
                    p = ((len and 0x3F) shl 8) or (b[p + 1].toInt() and 0xFF)
                }
                else -> {
                    if (p + 1 + len > b.size) break
                    labels += String(b, p + 1, len, Charsets.UTF_8)
                    p += 1 + len
                }
            }
        }
        return labels.joinToString(".") to (if (end < 0) b.size else end)
    }
}

// ---------------------------------------------------------------------------------------
// SSDP / UPnP: M-SEARCH, then read each device description XML (name, model, often the MAC).
// ---------------------------------------------------------------------------------------
object Ssdp {

    private val LOCATION = Regex("^LOCATION:\\s*(\\S+)", setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE))
    private val SERVER = Regex("^SERVER:\\s*(.+?)\\s*$", setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE))

    /** Device IP → description URLs, and IP → SERVER header (OS hint). */
    data class Result(val locations: Map<String, Set<String>>, val servers: Map<String, String>)

    fun discover(network: Network?, timeoutMs: Int = 3000): Result {
        val msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n" +
            "MX: 2\r\nST: ssdp:all\r\nUSER-AGENT: Android UPnP/1.1 NetworkScanner/0.3\r\n\r\n").toByteArray()
        val group = InetAddress.getByName("239.255.255.250")
        val found = mutableMapOf<String, MutableSet<String>>()
        val servers = mutableMapOf<String, String>()
        udpExchange(network, timeoutMs, send = { s -> repeat(2) { s.send(DatagramPacket(msg, msg.size, group, 1900)) } }) { p ->
            val text = String(p.data, 0, p.length, Charsets.ISO_8859_1)
            val ip = p.address.hostAddress ?: return@udpExchange
            LOCATION.find(text)?.groupValues?.get(1)?.let { found.getOrPut(ip) { mutableSetOf() } += it }
            SERVER.find(text)?.groupValues?.get(1)?.let { servers.putIfAbsent(ip, it) }
        }
        return Result(found, servers)
    }

    /** Fetches description XMLs for one device (max 3) and extracts identity. */
    fun describe(socketFactory: SocketFactory, ip: String, locations: Set<String>): Identity? {
        var identity: Identity? = null
        for (loc in locations.take(3)) {
            val xml = fetch(socketFactory, ip, loc) ?: continue
            val id = parse(xml)
            identity = identity?.merge(id) ?: id
            if (identity.mac != null && identity.upnpName != null) break
        }
        return identity
    }

    private fun parse(xml: String): Identity {
        fun tag(name: String) = Regex("<$name>\\s*([^<]*?)\\s*</$name>", RegexOption.IGNORE_CASE)
            .find(xml)?.groupValues?.get(1)?.takeIf { it.isNotBlank() }?.let(::unescape)

        val friendly = tag("friendlyName")
        val maker = tag("manufacturer")
        val model = listOfNotNull(tag("modelName"), tag("modelNumber")).distinct().joinToString(" ").ifEmpty { null }
        val name = listOfNotNull(friendly, listOfNotNull(maker, model).joinToString(" ").ifEmpty { null }?.let { "($it)" })
            .joinToString(" ").ifEmpty { null }

        val mac = tag("macAddress")?.let(Oui::normalize)?.let { MacInfo(it, "UPnP") }
            ?: (tag("serialNumber")?.let(Oui::normalize)?.takeIf(Oui::isKnownVendor)
                ?: tag("UDN")?.substringAfterLast('-')?.let(Oui::normalize)?.takeIf(Oui::isKnownVendor))
                ?.let { MacInfo(it, "UPnP device ID", exact = false) }
        return Identity(mac = mac, upnpName = name)
    }

    private fun unescape(s: String) = s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        .replace("&quot;", "\"").replace("&apos;", "'")

    /** Plain HTTP/1.0 GET over a LAN-bound socket (avoids chunked encoding and cleartext policy). */
    private fun fetch(socketFactory: SocketFactory, ip: String, location: String): String? {
        val url = runCatching { URL(location) }.getOrNull() ?: return null
        if (url.protocol != "http" || url.host != ip) return null
        val socket = socketFactory.createSocket()
        return try {
            socket.connect(InetSocketAddress(ip, if (url.port > 0) url.port else 80), 1500)
            socket.soTimeout = 2000
            val path = url.file.ifEmpty { "/" }
            val host = if (url.port > 0) "${url.host}:${url.port}" else url.host
            socket.getOutputStream().write("GET $path HTTP/1.0\r\nHost: $host\r\nConnection: close\r\n\r\n".toByteArray())
            val out = ByteArrayOutputStream()
            val buf = ByteArray(8192)
            val input = socket.getInputStream()
            try {
                while (out.size() < 128_000) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                }
            } catch (_: SocketTimeoutException) {
            }
            String(out.toByteArray(), Charsets.UTF_8).substringAfter("\r\n\r\n", "")
        } catch (_: IOException) {
            null
        } finally {
            runCatching { socket.close() }
        }
    }
}

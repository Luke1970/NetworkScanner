package nl.sc00by.networkscanner.scan

import java.util.concurrent.TimeUnit

/** Best guess at a device's operating system and the clues behind it. */
data class OsGuess(val name: String, val evidence: List<String>)

/**
 * Passive OS fingerprinting. Android apps cannot send raw packets, so instead of nmap-style
 * TCP/IP stack probing we combine what devices say about themselves (banners, UPnP/mDNS)
 * with the initial TTL of their ping replies.
 */
object OsFingerprint {

    /** Initial TTL family of a ping reply (on the local subnet the TTL arrives unchanged). */
    fun pingTtl(ip: String, timeoutSec: Int = 1): Int? = runCatching {
        val proc = ProcessBuilder("ping", "-c", "1", "-W", timeoutSec.toString(), ip).redirectErrorStream(true).start()
        val out = proc.inputStream.bufferedReader().readText()
        proc.waitFor((timeoutSec + 2).toLong(), TimeUnit.SECONDS)
        proc.destroy()
        Regex("ttl=(\\d+)").find(out)?.groupValues?.get(1)?.toInt()
    }.getOrNull()

    fun ttlFamily(ttl: Int): String = when {
        ttl <= 64 -> "Linux / Unix / macOS / iOS / Android"
        ttl <= 128 -> "Windows"
        else -> "network device / embedded"
    }

    /** One clue: an OS name, how specific it is (higher wins) and where it came from. */
    private data class Clue(val os: String, val weight: Int, val source: String)

    fun guess(
        ttl: Int?,
        openPorts: Collection<Int>,
        software: Collection<String>,
        identity: Identity,
        vendor: String?,
    ): OsGuess? {
        val clues = mutableListOf<Clue>()

        software.forEach { clues += fromSoftware(it) }
        identity.upnpServer?.let { clues += fromUpnpServer(it) }
        identity.model?.let { clues += fromAppleModel(it) }
        listOfNotNull(identity.mdnsName, identity.netbiosName).forEach { n ->
            when {
                n.contains("webOS", true) -> clues += Clue("LG webOS", 70, "device name")
                n.contains("Tizen", true) -> clues += Clue("Samsung Tizen", 70, "device name")
                n.startsWith("iPhone", true) -> clues += Clue("iOS", 60, "device name")
                n.startsWith("iPad", true) -> clues += Clue("iPadOS", 60, "device name")
                n.contains("MacBook", true) || n.contains("iMac", true) -> clues += Clue("macOS", 60, "device name")
                n.startsWith("android-", true) || n.contains("Galaxy", true) || n.contains("Pixel", true) ->
                    clues += Clue("Android", 50, "device name")
                n.contains("raspberrypi", true) -> clues += Clue("Linux (Raspberry Pi OS)", 50, "device name")
            }
        }
        identity.upnpName?.let { n ->
            when {
                n.contains("webOS", true) -> clues += Clue("LG webOS", 80, "UPnP device")
                n.contains("Tizen", true) || n.contains("Samsung", true) && n.contains("TV", true) ->
                    clues += Clue("Samsung Tizen", 60, "UPnP device")
                n.contains("FRITZ!", true) -> clues += Clue("FRITZ!OS", 80, "UPnP device")
                n.contains("Synology", true) -> clues += Clue("Synology DSM (Linux)", 80, "UPnP device")
                n.contains("Sonos", true) -> clues += Clue("Sonos (Linux)", 70, "UPnP device")
            }
        }
        if (62078 in openPorts) clues += Clue("iOS / iPadOS", 70, "port 62078")
        if (5555 in openPorts) clues += Clue("Android", 50, "port 5555 (ADB)")
        if (3389 in openPorts) clues += Clue("Windows", 60, "port 3389 (RDP)")
        if (135 in openPorts && 445 in openPorts) clues += Clue("Windows", 55, "ports 135+445")
        if (548 in openPorts) clues += Clue("macOS", 40, "port 548 (AFP)")
        if (445 in openPorts && 135 !in openPorts) clues += Clue("Linux / NAS (Samba)", 25, "SMB without MS-RPC")
        vendor?.let { v ->
            if (v.startsWith("Apple", true)) clues += Clue("Apple (iOS / macOS)", 20, "MAC vendor")
            if (v.contains("Raspberry Pi", true)) clues += Clue("Linux (Raspberry Pi)", 30, "MAC vendor")
            if (v.contains("Espressif", true)) clues += Clue("ESP32/ESP8266 firmware", 30, "MAC vendor")
        }
        ttl?.let { t ->
            clues += Clue(
                when {
                    t <= 64 -> "Linux / Unix"
                    t <= 128 -> "Windows"
                    else -> "network device / embedded"
                },
                10, "TTL $t",
            )
        }
        if (clues.isEmpty()) return null

        val best = clues.maxBy { it.weight }
        // Supporting clues: same OS family, or a TTL consistent with it.
        val support = clues.filter { it !== best && (agrees(it.os, best.os) || it.source.startsWith("TTL") && ttlFits(ttl, best.os)) }
        val conflict = ttl != null && !ttlFits(ttl, best.os) && best.weight < 50
        val name = if (conflict) "${best.os}?" else best.os
        return OsGuess(name, (listOf(best) + support).map { it.source }.distinct())
    }

    private fun agrees(a: String, b: String): Boolean {
        fun family(s: String) = when {
            s.contains("Windows", true) -> "win"
            s.contains("iOS", true) || s.contains("macOS", true) || s.contains("Apple", true) -> "apple"
            s.contains("Android", true) -> "android"
            else -> "unix"
        }
        return family(a) == family(b)
    }

    private fun ttlFits(ttl: Int?, os: String): Boolean = when {
        ttl == null -> true
        os.contains("Windows", true) -> ttl in 65..128
        os.contains("network device", true) || os.contains("IOS", false) -> true
        else -> ttl <= 64 || ttl > 128 // unix-likes use 64; some embedded stacks use 255
    }

    private val DEBIAN_RELEASE = mapOf("deb9" to "9", "deb10" to "10", "deb11" to "11", "deb12" to "12", "deb13" to "13")

    private fun fromSoftware(s: String): List<Clue> {
        val out = mutableListOf<Clue>()
        val src = when {
            s.startsWith("SSH-") -> "SSH banner"
            else -> "server banner"
        }
        Regex("deb(\\d+)u?").find(s)?.let { m ->
            out += Clue("Linux (Debian ${DEBIAN_RELEASE["deb${m.groupValues[1]}"] ?: m.groupValues[1]})", 90, src)
        }
        when {
            s.contains("OpenSSH_for_Windows", true) -> out += Clue("Windows", 95, src)
            s.contains("Ubuntu", true) -> out += Clue("Linux (Ubuntu)", 85, src)
            s.contains("Raspbian", true) -> out += Clue("Linux (Raspberry Pi OS)", 85, src)
            s.contains("Debian", true) -> out += Clue("Linux (Debian)", 80, src)
            s.contains("Fedora", true) -> out += Clue("Linux (Fedora)", 80, src)
            s.contains("Red Hat", true) || s.contains("RHEL", false) -> out += Clue("Linux (Red Hat)", 80, src)
            s.contains("CentOS", true) -> out += Clue("Linux (CentOS)", 80, src)
            s.contains("Rocky", true) -> out += Clue("Linux (Rocky)", 80, src)
            s.contains("AlmaLinux", true) -> out += Clue("Linux (AlmaLinux)", 80, src)
            s.contains("FreeBSD", true) -> out += Clue("FreeBSD", 85, src)
            s.contains("OpenBSD", true) -> out += Clue("OpenBSD", 85, src)
            s.contains("Microsoft-IIS", true) || s.contains("Microsoft-HTTPAPI", true) -> out += Clue("Windows", 85, src)
            s.contains("Win64", true) || s.contains("Win32", true) -> out += Clue("Windows", 75, src)
            s.contains("ROSSSH", true) || s.contains("MikroTik", true) -> out += Clue("MikroTik RouterOS", 90, src)
            s.contains("Cisco", true) -> out += Clue("Cisco IOS", 80, src)
            s.contains("dropbear", true) -> out += Clue("Linux (embedded)", 60, src)
            s.contains("lighttpd", true) || s.contains("Boa/", true) || s.contains("GoAhead", true) ||
                s.contains("mini_httpd", true) || s.contains("uhttpd", true) -> out += Clue("Linux (embedded)", 35, src)
            s.contains("Darwin", true) -> out += Clue("macOS", 70, src)
            s.contains("OpenSSH", true) -> out += Clue("Linux / Unix", 30, src)
        }
        return out
    }

    private fun fromUpnpServer(s: String): List<Clue> {
        val src = "UPnP server header"
        Regex("Linux/([0-9][0-9.]*)", RegexOption.IGNORE_CASE).find(s)?.let {
            val os = if (s.contains("Android", true)) "Android (Linux ${it.groupValues[1]})" else "Linux ${it.groupValues[1]}"
            return listOf(Clue(os, 55, src))
        }
        return when {
            s.contains("Windows", true) -> listOf(Clue("Windows" + (Regex("Windows[/ ]([0-9.]+)").find(s)?.let { " ${it.groupValues[1]}" } ?: ""), 75, src))
            s.contains("Darwin", true) -> listOf(Clue("macOS / iOS", 60, src))
            s.contains("WebOS", true) -> listOf(Clue("LG webOS", 80, src))
            s.contains("Tizen", true) -> listOf(Clue("Samsung Tizen", 80, src))
            s.contains("Android", true) -> listOf(Clue("Android", 70, src))
            s.contains("FreeRTOS", true) -> listOf(Clue("FreeRTOS", 70, src))
            s.contains("Linux", true) -> listOf(Clue("Linux", 50, src))
            else -> emptyList()
        }
    }

    private fun fromAppleModel(model: String): List<Clue> {
        val src = "mDNS model $model"
        return when {
            // Samba's vfs_fruit pretends to be a Mac so Finder shows a nice icon.
            model.equals("MacSamba", true) || model.startsWith("Xserve", true) -> listOf(Clue("Linux / NAS (Samba)", 75, src))
            model.startsWith("iPhone") -> listOf(Clue("iOS", 90, src))
            model.startsWith("iPad") -> listOf(Clue("iPadOS", 90, src))
            model.startsWith("AppleTV") -> listOf(Clue("tvOS", 90, src))
            model.startsWith("AudioAccessory") -> listOf(Clue("HomePod (audioOS)", 90, src))
            model.startsWith("Mac") || model.startsWith("iMac") || model.startsWith("MacBook") -> listOf(Clue("macOS", 90, src))
            model.startsWith("Watch") -> listOf(Clue("watchOS", 90, src))
            else -> emptyList()
        }
    }
}

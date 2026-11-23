package nl.sc00by.networkscanner.scan

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import java.io.IOException
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicInteger
import javax.net.SocketFactory

/**
 * OPEN = connected; REFUSED = host sent a reset; NO_ANSWER = silently dropped (but the host
 * answered ARP, so it exists); UNREACHABLE = ARP failed, nobody uses this address.
 */
enum class Probe { OPEN, REFUSED, NO_ANSWER, UNREACHABLE }

/**
 * TCP connect scanner. Android apps have no raw sockets, so every probe is a full
 * connect(): success = open, "connection refused" = closed but the host exists.
 */
class Scanner(
    private val socketFactory: SocketFactory,
    private val connectTimeoutMs: Int = 400,
    parallelism: Int = 256,
) {
    private companion object {
        /** "discard" port: almost never open, so we get a quick reset or a silent drop. */
        const val PRESENCE_PORT = 9
        const val PRESENCE_TIMEOUT_MS = 5000
        const val MAX_SILENT_ANYWAY = 32
    }

    // Dispatchers.IO views created with limitedParallelism may exceed IO's default 64 threads.
    val io = Dispatchers.IO.limitedParallelism(parallelism)

    fun probe(ip: String, port: Int, timeoutMs: Int = connectTimeoutMs): Probe {
        val socket = socketFactory.createSocket()
        return try {
            socket.connect(InetSocketAddress(inetAddressOf(ip), port), timeoutMs)
            Probe.OPEN
        } catch (_: SocketTimeoutException) {
            Probe.NO_ANSWER
        } catch (e: IOException) {
            // Android: "… ECONNREFUSED (Connection refused)"; desktop JVM: "Connection refused",
            // NoRouteToHostException "No route to host".
            val msg = e.message.orEmpty()
            when {
                msg.contains("ECONNREFUSED") || msg.contains("Connection refused", ignoreCase = true) -> Probe.REFUSED
                e is java.net.NoRouteToHostException || msg.contains("EHOSTUNREACH") || msg.contains("ENETUNREACH") ||
                    msg.contains("No route to host", ignoreCase = true) -> Probe.UNREACHABLE
                else -> Probe.NO_ANSWER
            }
        } finally {
            try { socket.close() } catch (_: IOException) {}
        }
    }

    /**
     * Phase 1: find every device, including ones behind a "stealth" firewall (Windows, phones).
     *
     * Before the phone can send a packet to a LAN address its kernel must resolve the MAC via ARP,
     * and every device answers ARP. So one connect() per address with a timeout longer than the
     * ARP give-up time (~3 s) tells us: EHOSTUNREACH = empty address, timeout = a device that
     * drops our packets, reset/connect = a device that answers.
     * If (nearly) every address times out, the network is doing something odd (proxy ARP,
     * client isolation), so we fall back to classic probing of common ports.
     *
     * [onAlive] gets the open ports seen and whether the device ignored the probe (stealth).
     */
    suspend fun discover(
        ips: List<String>,
        onProgress: (done: Int) -> Unit,
        onAlive: (ip: String, openPorts: List<Int>, stealth: Boolean) -> Unit,
    ) = coroutineScope {
        val done = AtomicInteger()
        val answered = AtomicInteger()
        val silent = java.util.concurrent.ConcurrentLinkedQueue<String>()
        coroutineScope {
            for (ip in ips) {
                launch(io) {
                    when (probe(ip, PRESENCE_PORT, PRESENCE_TIMEOUT_MS)) {
                        Probe.OPEN -> { answered.incrementAndGet(); onAlive(ip, listOf(PRESENCE_PORT), false) }
                        Probe.REFUSED -> { answered.incrementAndGet(); onAlive(ip, emptyList(), false) }
                        Probe.NO_ANSWER -> silent += ip
                        Probe.UNREACHABLE -> {}
                    }
                    onProgress(done.incrementAndGet())
                }
            }
        }
        // Real LANs have a handful of firewalled devices next to many that answer. Proxy ARP
        // (e.g. the Android emulator, some mesh/hotspot setups) makes nearly every address "silent".
        val arpTrickWorks = silent.size < ips.size * 0.8 &&
            (silent.size <= MAX_SILENT_ANYWAY || silent.size <= 2 * answered.get())
        if (arpTrickWorks) {
            silent.forEach { onAlive(it, emptyList(), true) }
        } else {
            classicDiscover(ips) { ip, open -> onAlive(ip, open, false) }
        }
    }

    /** Fallback: a host is alive if any common port connects or refuses. */
    private suspend fun classicDiscover(ips: List<String>, onAlive: (String, List<Int>) -> Unit) = coroutineScope {
        for (ip in ips) {
            launch(io) {
                var alive = false
                val open = mutableListOf<Int>()
                for (port in Ports.DISCOVERY) {
                    ensureActive()
                    when (probe(ip, port)) {
                        Probe.OPEN -> { alive = true; open += port }
                        Probe.REFUSED -> alive = true
                        else -> {}
                    }
                }
                if (alive) onAlive(ip, open)
            }
        }
    }

    /** Phase 2: scan [ports] on one host, reporting each open port as soon as it is found. */
    suspend fun scanPorts(ip: String, ports: List<Int>, onOpen: (Int) -> Unit) = coroutineScope {
        for (port in ports) {
            launch(io) {
                if (probe(ip, port) == Probe.OPEN) onOpen(port)
            }
        }
    }
}

/**
 * Parses a numeric IPv4/IPv6 literal (never a DNS lookup). Link-local IPv6 addresses carry their
 * interface as a numeric scope: "fe80::1%12".
 */
fun inetAddressOf(ip: String): InetAddress {
    val pct = ip.indexOf('%')
    if (pct < 0) return InetAddress.getByName(ip)
    val base = InetAddress.getByName(ip.substring(0, pct)).address
    return Inet6Address.getByAddress(null, base, ip.substring(pct + 1).toInt())
}

/** Host part for URLs and Host headers: IPv6 in brackets, without the scope. */
fun urlHost(ip: String): String = if (':' in ip) "[${ip.substringBefore('%')}]" else ip

package nl.sc00by.networkscanner.scan

import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Runs the real discovery protocols from the build machine against the LAN.
 * Opt-in: LAN_TEST=1 ./gradlew testDebugUnitTest --tests '*LanDiscoveryLiveTest*' -i
 */
class LanDiscoveryLiveTest {

    @Test
    fun discoverIdentities() {
        assumeTrue(System.getenv("LAN_TEST") == "1")
        Oui.load { File("src/main/assets/oui.dat").inputStream() }
        val subnet = System.getenv("LAN_PREFIX") ?: "192.168.1."
        val ips = (1..254).map { "$subnet$it" }

        val mdns = Mdns.query(null)
        val ssdpRes = Ssdp.discover(null)
        val ssdp = ssdpRes.locations
        val nb = NetBios.query(null, ips)
        val mdnsRev = Mdns.query(null, reverseFor = (mdns.keys + ssdp.keys + nb.keys).filter { it.startsWith(subnet) })
        val upnp = ssdp.mapValues { (ip, locs) -> Ssdp.describe(javax.net.SocketFactory.getDefault(), ip, locs) }

        val all = sortedSetOf(compareBy<String> { it.substringAfterLast('.').toIntOrNull() ?: 0 })
        all += mdns.keys + ssdp.keys + ssdpRes.servers.keys + nb.keys + mdnsRev.keys
        for (ip in all.filter { it.startsWith(subnet) }) {
            var id = Identity()
            listOf(mdns[ip], mdnsRev[ip], nb[ip], upnp[ip], ssdpRes.servers[ip]?.let { Identity(upnpServer = it) })
                .forEach { if (it != null) id = id.merge(it) }
            val vendor = id.mac?.let { Oui.vendor(it.mac) }
            val ttl = Regex("ttl=(\\d+)").find(ProcessBuilder("ping", "-c", "1", "-W", "1", ip).start().inputStream.bufferedReader().readText())?.groupValues?.get(1)?.toInt()
            val os = OsFingerprint.guess(ttl, emptyList(), emptyList(), id, vendor)
            println("LIVE\t$ip\t${id.mac?.mac ?: "-"}\t${id.mac?.source ?: ""}${if (id.mac?.exact == false) "~" else ""}\t${vendor ?: ""}\t" +
                listOfNotNull(id.mdnsName, id.netbiosName, id.upnpName).joinToString(" | ") +
                "\tOS=${os?.name} <- ${os?.evidence}")
        }
    }

    @Test
    fun presenceSweep() {
        assumeTrue(System.getenv("LAN_TEST") == "1")
        val subnet = System.getenv("LAN_PREFIX") ?: "192.168.1."
        val found = java.util.concurrent.ConcurrentHashMap<String, Boolean>()
        val start = System.currentTimeMillis()
        kotlinx.coroutines.runBlocking {
            Scanner(javax.net.SocketFactory.getDefault()).discover(
                (1..254).map { "$subnet$it" },
                onProgress = {},
                onAlive = { ip, _, stealth -> found[ip] = stealth },
            )
        }
        val ms = System.currentTimeMillis() - start
        println("SWEEP\t${found.size} hosts (${found.values.count { it }} stealth) in ${ms} ms")
        println("SWEEP\t" + found.keys.map { it.substringAfterLast('.').toInt() }.sorted().joinToString(" "))
        println("SWEEP\tstealth: " + found.filterValues { it }.keys.map { it.substringAfterLast('.').toInt() }.sorted().joinToString(" "))
    }
}

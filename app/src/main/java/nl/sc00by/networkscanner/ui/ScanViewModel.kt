package nl.sc00by.networkscanner.ui

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import nl.sc00by.networkscanner.scan.DhcpInform
import nl.sc00by.networkscanner.scan.DhcpQuery
import nl.sc00by.networkscanner.scan.Identity
import nl.sc00by.networkscanner.scan.Ipv6Discovery
import nl.sc00by.networkscanner.scan.MobileInfo
import nl.sc00by.networkscanner.scan.BluetoothInfo
import android.os.Build
import android.telephony.TelephonyCallback
import android.telephony.TelephonyDisplayInfo
import android.telephony.TelephonyManager
import nl.sc00by.networkscanner.scan.Mdns
import nl.sc00by.networkscanner.scan.NetBios
import nl.sc00by.networkscanner.scan.OsFingerprint
import nl.sc00by.networkscanner.scan.Oui
import nl.sc00by.networkscanner.scan.Ssdp
import nl.sc00by.networkscanner.scan.LocalNetwork
import nl.sc00by.networkscanner.scan.NetworkDetails
import nl.sc00by.networkscanner.scan.Ports
import nl.sc00by.networkscanner.scan.Scanner
import nl.sc00by.networkscanner.scan.ServiceDetector
import nl.sc00by.networkscanner.scan.ServiceInfo
import nl.sc00by.networkscanner.scan.inetAddressOf
import java.net.Inet4Address
import java.net.Inet6Address
import kotlinx.coroutines.async
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger

/** [service] is null while the port is still being identified. */
data class OpenPort(val port: Int, val service: ServiceInfo? = null)

data class HostResult(
    val ip: String,
    val hostname: String? = null,
    val isSelf: Boolean = false,
    val ports: List<OpenPort> = emptyList(),
    val scanning: Boolean = true,
    val identity: Identity = Identity(),
    /** Manufacturer from the MAC's OUI. */
    val vendor: String? = null,
    /** How the device was found when it did not answer the TCP probes. */
    val foundVia: String? = null,
    /** TTL of a ping reply (OS family hint). */
    val ttl: Int? = null,
    /** Present on the network (answered ARP) but dropped the presence probe. */
    val stealth: Boolean = false,
) {
    val sortKey: Long = LocalNetwork.ipToLong(ip)
}

/** One IPv6 address of a device. */
data class V6Address(val text: String, val scope: Ipv6Discovery.Scope, val eui64: Boolean)

/**
 * A device found over IPv6. Addresses that clearly belong together (same MAC in an EUI-64
 * interface ID, same mDNS name) are grouped; [ip] is the address that gets port-scanned.
 */
data class Host6(
    val ip: String,
    val addresses: List<V6Address>,
    val isSelf: Boolean = false,
    val isRouter: Boolean = false,
    /** MAC from an EUI-64 interface ID. */
    val mac: String? = null,
    val mdnsName: String? = null,
    /** IPv4 address announced in the same mDNS answer. */
    val ipv4: String? = null,
    val hostname: String? = null,
    val foundVia: String = "",
    val ports: List<OpenPort> = emptyList(),
    val scanning: Boolean = true,
)

enum class PortScope(val label: String) { COMMON("Common ports"), ALL("All 65535") }

data class ScanState(
    val network: LocalNetwork? = null,
    val details: NetworkDetails? = null,
    val dhcp: DhcpQuery = DhcpQuery.Idle,
    val scope: PortScope = PortScope.COMMON,
    val running: Boolean = false,
    val phase: String = "Ready",
    val progress: Float = 0f,
    val hosts: List<HostResult> = emptyList(),
    val hosts6: List<Host6> = emptyList(),
    val mobile: MobileInfo? = null,
    val bluetooth: BluetoothInfo? = null,
    val v6Running: Boolean = false,
    /** Status line of the IPv6 card. */
    val v6Status: String? = null,
)

class ScanViewModel(app: Application) : AndroidViewModel(app) {

    private val _state = MutableStateFlow(ScanState())
    val state: StateFlow<ScanState> = _state.asStateFlow()

    private var job: Job? = null
    private var infoJob: Job? = null

    private val telephony = app.getSystemService(TelephonyManager::class.java)
    /** What the status bar shows on top of the network type (4G+, 5G NSA, 5G+), from TelephonyDisplayInfo. */
    private var displayOverride: Int? = null
    private var displayCallback: Any? = null

    init {
        refreshInfo()
        viewModelScope.launch(Dispatchers.IO) { runCatching { Oui.load(app) } }
    }

    fun setScope(scope: PortScope) = _state.update { it.copy(scope = scope) }

    fun refreshNetwork() {
        val net = LocalNetwork.detect(getApplication())
        _state.update { it.copy(network = net, details = net?.let { n -> NetworkDetails.read(getApplication(), n) }) }
        refreshMobile()
    }

    // ---- mobile network ----------------------------------------------------------------

    /** Re-reads operator, signal, cell and mobile data connection (cheap, no network traffic). */
    fun refreshMobile() {
        listenDisplayInfo()
        val info = runCatching { MobileInfo.read(getApplication(), displayOverride) }.getOrNull()
        _state.update { it.copy(mobile = info) }
        refreshBluetooth()
    }

    private var bluetoothJob: Job? = null

    /** Re-reads adapter, paired and connected devices; the profile queries are asynchronous. */
    fun refreshBluetooth() {
        bluetoothJob?.cancel()
        bluetoothJob = viewModelScope.launch {
            val info = runCatching { BluetoothInfo.read(getApplication()) }.getOrNull()
            _state.update { it.copy(bluetooth = info) }
        }
    }

    /** 5G NSA is reported as LTE plus a display override; listen for it (Android 12+, may need phone permission). */
    private fun listenDisplayInfo() {
        if (Build.VERSION.SDK_INT < 31 || telephony == null || displayCallback != null) return
        val cb = object : TelephonyCallback(), TelephonyCallback.DisplayInfoListener {
            override fun onDisplayInfoChanged(info: TelephonyDisplayInfo) {
                displayOverride = info.overrideNetworkType
                _state.update { it.copy(mobile = runCatching { MobileInfo.read(getApplication(), displayOverride) }.getOrNull()) }
            }
        }
        runCatching {
            telephony.registerTelephonyCallback(getApplication<Application>().mainExecutor, cb)
            displayCallback = cb
        }
    }

    override fun onCleared() {
        if (Build.VERSION.SDK_INT >= 31) (displayCallback as? TelephonyCallback)?.let { runCatching { telephony?.unregisterTelephonyCallback(it) } }
    }

    /** Re-reads the network configuration and asks the DHCP server for its options. */
    fun refreshInfo() {
        refreshNetwork()
        val net = _state.value.network ?: run {
            _state.update { it.copy(dhcp = DhcpQuery.Failed("Not connected to Wi-Fi or Ethernet")) }
            return
        }
        val server = _state.value.details?.dhcpServer
        infoJob?.cancel()
        infoJob = viewModelScope.launch {
            _state.update { it.copy(dhcp = DhcpQuery.Running) }
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    DhcpInform.query(
                        net.network,
                        InetAddress.getByName(net.address) as Inet4Address,
                        server?.let { InetAddress.getByName(it) as Inet4Address },
                    )
                }.getOrElse { DhcpQuery.Failed("DHCP query failed: ${it.message ?: it.javaClass.simpleName}") }
            }
            _state.update { it.copy(dhcp = result) }
        }
    }

    fun stop() {
        job?.cancel()
        job = null
        _state.update { s ->
            s.copy(
                running = false, phase = "Stopped", hosts = s.hosts.map { it.copy(scanning = false) },
                v6Running = false, hosts6 = s.hosts6.map { it.copy(scanning = false) },
                v6Status = if (s.v6Running) "Stopped" else s.v6Status,
            )
        }
    }

    fun start() {
        refreshNetwork()
        val net = _state.value.network ?: run {
            _state.update { it.copy(phase = "Not connected to Wi-Fi or Ethernet") }
            return
        }
        val scanner = Scanner(net.socketFactory)
        val detector = ServiceDetector(net.socketFactory)
        val ports = if (_state.value.scope == PortScope.ALL) Ports.ALL else Ports.COMMON
        val ips = net.hostAddresses()

        job?.cancel()
        job = viewModelScope.launch {
            _state.update {
                it.copy(running = true, hosts = emptyList(), hosts6 = emptyList(), progress = 0f, phase = "Finding devices…")
            }
            // IPv6 runs alongside the whole IPv4 scan.
            val v6 = launch { scanIpv6(net, scanner, detector, ports) }

            // Phase 1: TCP discovery, with mDNS + SSDP running alongside
            var ssdpLocations: Map<String, Set<String>> = emptyMap()
            var ssdpServers: Map<String, String> = emptyMap()
            coroutineScope {
                launch(Dispatchers.IO) {
                    runCatching { Mdns.query(net.network) }.getOrNull()?.forEach { (ip, id) ->
                        if (net.contains(ip)) addIdentity(ip, id, net.address, via = "mDNS")
                    }
                }
                launch(Dispatchers.IO) {
                    val ssdp = runCatching { Ssdp.discover(net.network) }.getOrNull()
                    ssdpLocations = ssdp?.locations.orEmpty().filterKeys { net.contains(it) }
                    ssdpServers = ssdp?.servers.orEmpty().filterKeys { net.contains(it) }
                    (ssdpLocations.keys + ssdpServers.keys).forEach { ip ->
                        addIdentity(ip, Identity(upnpServer = ssdpServers[ip]), net.address, via = "UPnP")
                    }
                }
                scanner.discover(
                    ips,
                    onProgress = { done ->
                        _state.update { it.copy(progress = done.toFloat() / ips.size, phase = "Finding devices… $done/${ips.size}") }
                    },
                    onAlive = { ip, open, stealth -> addAlive(ip, open, net.address, stealth) },
                )
            }

            // Phase 2: port scan + identification per host, all hosts in parallel
            val hosts = _state.value.hosts.map { it.ip }
            val hostsDone = AtomicInteger()
            _state.update { it.copy(progress = 0f, phase = "Scanning ports on ${hosts.size} devices…") }

            coroutineScope {
                // Identity lookups for everything found: NetBIOS, reverse mDNS, UPnP descriptions.
                launch(Dispatchers.IO) {
                    runCatching { NetBios.query(net.network, hosts) }.getOrNull()
                        ?.forEach { (ip, id) -> addIdentity(ip, id, net.address) }
                }
                launch(Dispatchers.IO) {
                    runCatching { Mdns.query(net.network, reverseFor = hosts) }.getOrNull()
                        ?.forEach { (ip, id) -> if (ip in hosts) addIdentity(ip, id, net.address) }
                }
                // Ping TTL per host (OS family); a few at a time, each is a short-lived process.
                val pingSlots = kotlinx.coroutines.sync.Semaphore(16)
                for (ip in hosts) {
                    launch(Dispatchers.IO) {
                        val ttl = pingSlots.withPermit { OsFingerprint.pingTtl(ip) }
                        if (ttl != null) updateHost(ip) { it.copy(ttl = ttl) }
                    }
                }
                for ((ip, locations) in ssdpLocations) {
                    launch(Dispatchers.IO) {
                        runCatching { Ssdp.describe(net.socketFactory, ip, locations) }.getOrNull()
                            ?.let { addIdentity(ip, it, net.address) }
                    }
                }
                for (ip in hosts) {
                    launch {
                        launch(scanner.io) { resolveHostname(ip) }
                        coroutineScope {
                            val identifying = mutableSetOf<Int>()
                            fun identify(port: Int) {
                                synchronized(identifying) { if (!identifying.add(port)) return }
                                launch(scanner.io) { setPort(ip, OpenPort(port, detector.identify(ip, port))) }
                            }
                            _state.value.hosts.firstOrNull { it.ip == ip }?.ports?.forEach { identify(it.port) }
                            scanner.scanPorts(ip, ports) { port ->
                                setPort(ip, OpenPort(port), keepExisting = true)
                                identify(port)
                            }
                        }
                        updateHost(ip) { it.copy(scanning = false) }
                        val done = hostsDone.incrementAndGet()
                        _state.update {
                            it.copy(progress = done.toFloat() / hosts.size, phase = "Scanning ports… $done/${hosts.size} devices done")
                        }
                    }
                }
            }
            if (v6.isActive) _state.update { it.copy(phase = "IPv4 done; finishing IPv6…") }
            v6.join()
            val total = _state.value.hosts.sumOf { it.ports.size }
            val v6Count = _state.value.hosts6.sumOf { it.addresses.size }
            _state.update {
                it.copy(running = false, progress = 1f,
                    phase = "Done: ${plural(hosts.size, "device")}, ${plural(total, "open port")} · " +
                        plural(v6Count, "IPv6 address", "IPv6 addresses"))
            }
        }
    }

    /** Finds IPv6 devices (multicast ping + mDNS), groups their addresses and port-scans each device. */
    private suspend fun scanIpv6(net: LocalNetwork, scanner: Scanner, detector: ServiceDetector, ports: List<Int>) = coroutineScope {
        _state.update { it.copy(v6Running = true, v6Status = "Asking all IPv6 devices (ff02::1)…") }
        val props = net.linkProperties
        val own = props.linkAddresses.mapNotNull { la -> (la.address as? Inet6Address)?.let { it to la.prefixLength } }
        // LinkProperties addresses usually carry no scope; the interface index is the scope of link-local addresses.
        val scopeId = own.firstNotNullOfOrNull { (a, _) -> a.scopeId.takeIf { a.isLinkLocalAddress && it != 0 } }
            ?: runCatching { android.system.Os.if_nametoindex(net.interfaceName) }.getOrNull()?.takeIf { it > 0 }
            ?.takeIf { own.any { (a, _) -> a.isLinkLocalAddress } }
        if (scopeId == null) {
            _state.update { it.copy(v6Running = false, v6Status = "IPv6 is not active on this network.") }
            return@coroutineScope
        }
        val routers = props.routes.filter { it.isDefaultRoute }.mapNotNull { it.gateway as? Inet6Address }
            .filter { !it.isAnyLocalAddress }.map { Ipv6Discovery.text(it) }.toSet()
        val onLink = { a: Inet6Address ->
            a.isLinkLocalAddress || own.any { (p, len) -> !p.isLinkLocalAddress && Ipv6Discovery.inPrefix(a, p, len) }
        }

        val mdnsJob = async(Dispatchers.IO) { runCatching { Mdns.queryAaaa(net.network) }.getOrDefault(emptyList()) }
        val pinged = withContext(Dispatchers.IO) {
            Ipv6Discovery.pingAllNodes(net.network, own.map { it.first }.take(4), scopeId)
        }
        val mdns = mdnsJob.await().filter { onLink(it.address) && !it.address.isMulticastAddress }

        // Every address once, with how it was found.
        val via = linkedMapOf<String, MutableSet<String>>()
        val addrOf = mutableMapOf<String, Inet6Address>()
        fun add(a: Inet6Address, how: String) {
            val t = Ipv6Discovery.text(a)
            addrOf.getOrPut(t) { a }
            via.getOrPut(t) { mutableSetOf() } += how
        }
        own.forEach { add(it.first, "this phone") }
        pinged.forEach { add(it, "ping") }
        mdns.forEach { add(it.address, "mDNS") }
        val ownTexts = own.map { Ipv6Discovery.text(it.first) }.toSet()
        val mdnsByAddr = mdns.associateBy { Ipv6Discovery.text(it.address) }

        // Group addresses of one device: shared EUI-64 MAC, shared mDNS name, or both ours.
        val groupOf = mutableMapOf<String, Int>()
        val groups = mutableListOf<MutableSet<String>>()
        fun tags(t: String) = listOfNotNull(
            addrOf[t]?.takeIf(Ipv6Discovery::isEui64)?.let { Oui.fromEui64(it) }?.let { "mac:$it" },
            mdnsByAddr[t]?.name?.lowercase()?.let { "name:$it" },
            "self".takeIf { t in ownTexts },
        )
        val tagGroup = mutableMapOf<String, Int>()
        for (t in via.keys) {
            val hits = tags(t).mapNotNull { tagGroup[it] }.distinct()
            val g = if (hits.isEmpty()) groups.size.also { groups.add(mutableSetOf()) } else hits.first()
            // Merge any other groups this address links together.
            for (other in hits.drop(1)) {
                groups[g] += groups[other]; groups[other].forEach { groupOf[it] = g }; groups[other].clear()
                tagGroup.entries.filter { it.value == other }.forEach { it.setValue(g) }
            }
            groups[g] += t; groupOf[t] = g
            tags(t).forEach { tagGroup[it] = g }
        }

        val rank = { t: String -> addrOf[t]!!.let(Ipv6Discovery::scopeOf).ordinal }
        val hosts6 = groups.filter { it.isNotEmpty() }.map { set ->
            val sorted = set.sortedWith(compareBy(rank).thenBy { it })
            val primary = addrOf[sorted.first()]!!
            val mac = sorted.firstNotNullOfOrNull { t -> addrOf[t]?.takeIf(Ipv6Discovery::isEui64)?.let { Oui.fromEui64(it) } }
            val name = sorted.firstNotNullOfOrNull { mdnsByAddr[it] }
            Host6(
                ip = Ipv6Discovery.key(primary, scopeId),
                addresses = sorted.map { t ->
                    val a = addrOf[t]!!
                    V6Address(t, Ipv6Discovery.scopeOf(a), Ipv6Discovery.isEui64(a))
                },
                isSelf = sorted.any { it in ownTexts },
                isRouter = sorted.any { it in routers },
                mac = mac,
                mdnsName = name?.name,
                ipv4 = sorted.firstNotNullOfOrNull { mdnsByAddr[it]?.ipv4 },
                foundVia = sorted.flatMap { via[it].orEmpty() }.distinct().filter { it != "this phone" }.joinToString(" + "),
            )
        }.sortedWith(compareByDescending<Host6> { it.isRouter }.thenBy { it.isSelf }.thenBy { it.addresses.first().text })

        val count = hosts6.sumOf { it.addresses.size }
        _state.update {
            it.copy(hosts6 = hosts6, v6Status = "Scanning ports on ${plural(hosts6.size, "IPv6 device")} (${plural(count, "address", "addresses")})…")
        }

        coroutineScope {
            // Names: reverse mDNS for every address (works for link-local too), in one exchange.
            launch(Dispatchers.IO) {
                val ask = hosts6.filter { it.mdnsName == null && !it.isSelf }.flatMap { h -> h.addresses.mapNotNull { addrOf[it.text] } }
                val names = runCatching { Mdns.reverse6(net.network, ask) }.getOrDefault(emptyMap())
                for (h in hosts6) {
                    val name = h.addresses.firstNotNullOfOrNull { names[it.text] } ?: continue
                    updateHost6(h.ip) { it.copy(mdnsName = it.mdnsName ?: name) }
                }
            }
            for (h in hosts6) {
            launch {
                // Reverse DNS for routable addresses, first one that has a name.
                launch(scanner.io) {
                    for (a in h.addresses.filter { it.scope != Ipv6Discovery.Scope.LINK_LOCAL }) {
                        val name = runCatching { inetAddressOf(a.text).canonicalHostName }.getOrNull()
                        if (name != null && ':' !in name) {
                            updateHost6(h.ip) { it.copy(hostname = name) }
                            break
                        }
                    }
                }
                coroutineScope {
                    scanner.scanPorts(h.ip, ports) { port ->
                        setPort6(h.ip, OpenPort(port))
                        launch(scanner.io) { setPort6(h.ip, OpenPort(port, detector.identify(h.ip, port))) }
                    }
                }
                updateHost6(h.ip) { it.copy(scanning = false) }
            }
        } }
        val open = _state.value.hosts6.sumOf { it.ports.size }
        _state.update {
            it.copy(v6Running = false,
                v6Status = if (hosts6.isEmpty()) null else "Done: ${plural(hosts6.size, "device")}, ${plural(count, "address", "addresses")}, ${plural(open, "open port")}")
        }
    }

    private fun updateHost6(ip: String, change: (Host6) -> Host6) = _state.update { s ->
        s.copy(hosts6 = s.hosts6.map { if (it.ip == ip) change(it) else it })
    }

    private fun setPort6(ip: String, port: OpenPort) = updateHost6(ip) { h ->
        val existing = h.ports.firstOrNull { it.port == port.port }
        if (existing?.service != null && port.service == null) return@updateHost6 h
        h.copy(ports = (h.ports.filterNot { it.port == port.port } + port).sortedBy { it.port })
    }

    /** Reverse DNS via the router; blocking, so call it on an IO dispatcher. */
    private fun resolveHostname(ip: String) {
        val name = runCatching { InetAddress.getByName(ip).canonicalHostName }.getOrNull()
        if (name != null && name != ip) updateHost(ip) { it.copy(hostname = name) }
    }

    /** TCP discovery found [ip]; merge with an entry mDNS/SSDP may already have created. */
    private fun addAlive(ip: String, open: List<Int>, selfIp: String, stealth: Boolean) = _state.update { s ->
        val existing = s.hosts.firstOrNull { it.ip == ip }
        val host = existing?.copy(
            ports = (existing.ports + open.map { OpenPort(it) }).distinctBy { it.port }.sortedBy { it.port },
            foundVia = null,
            stealth = stealth,
        ) ?: HostResult(ip, isSelf = ip == selfIp, ports = open.map { OpenPort(it) }, stealth = stealth)
        s.copy(hosts = (s.hosts.filterNot { it.ip == ip } + host).sortedBy { it.sortKey })
    }

    /** Merge identity info; creates the host if only a discovery protocol knew about it. */
    private fun addIdentity(ip: String, id: Identity, selfIp: String, via: String? = null) = _state.update { s ->
        val existing = s.hosts.firstOrNull { it.ip == ip }
            ?: HostResult(ip, isSelf = ip == selfIp, foundVia = via)
        val merged = existing.identity.merge(id)
        val host = existing.copy(identity = merged, vendor = merged.mac?.let { Oui.vendor(it.mac) })
        s.copy(hosts = (s.hosts.filterNot { it.ip == ip } + host).sortedBy { it.sortKey })
    }

    private fun updateHost(ip: String, change: (HostResult) -> HostResult) = _state.update { s ->
        s.copy(hosts = s.hosts.map { if (it.ip == ip) change(it) else it })
    }

    private fun setPort(ip: String, port: OpenPort, keepExisting: Boolean = false) = updateHost(ip) { h ->
        val existing = h.ports.firstOrNull { it.port == port.port }
        if (existing != null && keepExisting) return@updateHost h
        h.copy(ports = (h.ports.filterNot { it.port == port.port } + port).sortedBy { it.port })
    }
}

private fun plural(n: Int, one: String, many: String = one + "s") = "$n ${if (n == 1) one else many}"

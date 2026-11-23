package nl.sc00by.networkscanner.scan

import android.content.Context
import android.net.ConnectivityManager
import android.net.wifi.WifiManager
import android.os.Build
import android.net.LinkProperties
import java.net.Inet4Address
import java.net.Inet6Address

data class RouteEntry(val destination: String, val gateway: String?, val interfaceName: String?)

/** One IPv6 address of the phone, with how it was configured (from the kernel's address flags). */
data class V6Config(
    val address: String,
    val prefixLength: Int,
    val scope: Ipv6Discovery.Scope,
    /** e.g. "SLAAC, stable privacy (RFC 7217)", "SLAAC, temporary (privacy)", "DHCPv6 / static". */
    val method: String,
    val deprecated: Boolean,
)

/** IPv6 configuration of the LAN interface as Android reports it. */
data class Ipv6Details(
    val addresses: List<V6Config>,
    /** On-link prefixes the router advertised, e.g. 2a02:a46f:1234:1::/64. */
    val prefixes: List<String>,
    val gateways: List<String>,
    /** MAC of the router, when its link-local address is EUI-64 based. */
    val gatewayMac: String?,
    /** IPv6 recursive DNS servers (router advertisement RDNSS or DHCPv6). */
    val dnsServers: List<String>,
    /** DNS search list (DHCP option 15/119 or router advertisement DNSSL). */
    val searchDomains: List<String>,
    val nat64Prefix: String?,
    val routes: List<RouteEntry>,
    /** One-line summary: how the phone got its IPv6 setup. */
    val configuration: String,
)

/** IPv4 configuration as Android reports it (no network traffic needed). */
data class NetworkDetails(
    val interfaceName: String,
    val ipAddress: String,
    val prefixLength: Int,
    val netmask: String,
    val broadcast: String,
    val gateway: String?,
    val dhcpServer: String?,
    val leaseSeconds: Long?,
    val dnsServers: List<String>,
    val domains: String?,
    val privateDns: String?,
    val mtu: Int?,
    val vlanId: Int?,
    val routes: List<RouteEntry>,
    val ipv6: Ipv6Details,
) {
    companion object {
        fun read(context: Context, net: LocalNetwork): NetworkDetails {
            val lp = net.linkProperties
            val ipLong = LocalNetwork.ipToLong(net.address)
            val mask = (0xFFFFFFFFL shl (32 - net.prefixLength)) and 0xFFFFFFFFL
            val legacy = legacyDhcpInfo(context)

            val dhcpServer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                lp.dhcpServerAddress?.hostAddress
            } else null
            // DhcpInfo is deprecated but is still the only public source of the lease time.
            val legacyServer = legacy?.serverAddress?.takeIf { it != 0 }?.let(::littleEndianIp)
            val legacyMatches = legacy != null && littleEndianIp(legacy.ipAddress) == net.address

            return NetworkDetails(
                interfaceName = net.interfaceName,
                ipAddress = net.address,
                prefixLength = net.prefixLength,
                netmask = LocalNetwork.intToIp(mask),
                broadcast = LocalNetwork.intToIp((ipLong and mask) or (mask.inv() and 0xFFFFFFFFL)),
                gateway = lp.routes.firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }?.gateway?.hostAddress,
                dhcpServer = dhcpServer ?: legacyServer.takeIf { legacyMatches },
                leaseSeconds = legacy?.leaseDuration?.takeIf { legacyMatches && it > 0 }?.toLong(),
                dnsServers = lp.dnsServers.filterIsInstance<Inet4Address>().mapNotNull { it.hostAddress },
                domains = lp.domains?.takeIf { it.isNotBlank() },
                privateDns = when {
                    !lp.isPrivateDnsActive -> null
                    lp.privateDnsServerName != null -> lp.privateDnsServerName
                    else -> "automatic (opportunistic)"
                },
                mtu = lp.mtu.takeIf { it > 0 },
                vlanId = VLAN_IN_NAME.find(net.interfaceName)?.groupValues?.get(1)?.toIntOrNull()?.takeIf { it in 1..4094 },
                routes = routes(context, v6 = false),
                ipv6 = readIpv6(context, lp),
            )
        }

        // Kernel address flags (linux/if_addr.h); LinkAddress.getFlags() passes them on.
        private const val IFA_F_TEMPORARY = 0x01
        private const val IFA_F_DADFAILED = 0x08
        private const val IFA_F_DEPRECATED = 0x20
        private const val IFA_F_MANAGETEMPADDR = 0x100
        private const val IFA_F_STABLE_PRIVACY = 0x800

        private fun readIpv6(context: Context, lp: LinkProperties): Ipv6Details {
            val addresses = lp.linkAddresses.filter { it.address is Inet6Address }.map { la ->
                val a = la.address as Inet6Address
                val scope = Ipv6Discovery.scopeOf(a)
                val f = la.flags
                val method = when {
                    f and IFA_F_TEMPORARY != 0 -> "SLAAC, temporary (privacy extensions)"
                    f and IFA_F_STABLE_PRIVACY != 0 -> "SLAAC, stable privacy (RFC 7217)"
                    Ipv6Discovery.isEui64(a) -> "SLAAC, EUI-64 (from the MAC)"
                    scope == Ipv6Discovery.Scope.LINK_LOCAL -> "automatic (link-local)"
                    f and IFA_F_MANAGETEMPADDR != 0 -> "SLAAC"
                    la.prefixLength == 128 -> "DHCPv6"
                    else -> "static or DHCPv6"
                } + if (f and IFA_F_DADFAILED != 0) " · duplicate address on the network!" else ""
                V6Config(Ipv6Discovery.text(a), la.prefixLength, scope, method, deprecated = f and IFA_F_DEPRECATED != 0)
            }.sortedWith(compareBy({ it.deprecated }, { it.scope.ordinal }, { it.address }))

            val defaults = lp.routes.filter { it.isDefaultRoute && it.gateway is Inet6Address }
            val gateways = defaults.mapNotNull { (it.gateway as? Inet6Address)?.let(Ipv6Discovery::text) }.distinct()
            val gatewayMac = defaults.firstNotNullOfOrNull { r ->
                (r.gateway as? Inet6Address)?.takeIf(Ipv6Discovery::isEui64)?.let(Oui::fromEui64)
            }
            val prefixes = lp.routes.filter { r ->
                val d = r.destination.address
                d is Inet6Address && !d.isLinkLocalAddress && !d.isMulticastAddress && r.destination.prefixLength in 1..127 &&
                    (r.gateway == null || r.gateway!!.isAnyLocalAddress)
            }.map { "${Ipv6Discovery.text(it.destination.address as Inet6Address)}/${it.destination.prefixLength}" }.distinct()
            val nat64 = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) lp.nat64Prefix?.let {
                "${Ipv6Discovery.text(it.address as Inet6Address)}/${it.prefixLength}"
            } else null

            val routable = addresses.filter { it.scope != Ipv6Discovery.Scope.LINK_LOCAL && !it.deprecated }
            val configuration = when {
                addresses.isEmpty() -> "IPv6 is off on this interface"
                routable.isEmpty() && gateways.isEmpty() -> "link-local only: no IPv6 router on this network"
                routable.isEmpty() -> "router present, but no usable IPv6 address yet"
                else -> buildList {
                    if (routable.any { it.method.startsWith("SLAAC") }) add("SLAAC (router advertisement)")
                    if (routable.any { it.method.startsWith("DHCPv6") || it.method.startsWith("static") }) add("DHCPv6 or static")
                    if (routable.any { it.method.contains("temporary") }) add("privacy addresses on")
                    if (gateways.isEmpty()) add("no default route (no IPv6 internet)")
                }.joinToString(" · ")
            }

            return Ipv6Details(
                addresses = addresses,
                prefixes = prefixes,
                gateways = gateways,
                gatewayMac = gatewayMac,
                dnsServers = lp.dnsServers.filterIsInstance<Inet6Address>().map(Ipv6Discovery::text),
                searchDomains = lp.domains.orEmpty().split(' ', ',').filter { it.isNotBlank() },
                nat64Prefix = nat64,
                routes = routes(context, v6 = true),
                configuration = configuration,
            )
        }

        /** VLAN sub-interfaces are named like eth0.10 or vlan10; Wi-Fi clients only ever see untagged frames. */
        private val VLAN_IN_NAME = Regex("(?:\\.|vlan)(\\d{1,4})$")

        /** IPv4 or IPv6 routes of every network Android knows about (Wi-Fi, mobile, VPN …). */
        private fun routes(context: Context, v6: Boolean): List<RouteEntry> {
            val cm = context.getSystemService(ConnectivityManager::class.java) ?: return emptyList()
            @Suppress("DEPRECATION")
            val networks = cm.allNetworks
            return networks.flatMap { n -> cm.getLinkProperties(n)?.routes.orEmpty() }
                .filter { if (v6) it.destination.address is Inet6Address else it.destination.address is Inet4Address }
                // Multicast routes (ff00::/8) are always there and say nothing.
                .filterNot { it.destination.address.isMulticastAddress }
                .map { r ->
                    val dest = r.destination.address
                    RouteEntry(
                        destination = if (dest is Inet6Address) "${Ipv6Discovery.text(dest)}/${r.destination.prefixLength}"
                        else r.destination.toString(),
                        gateway = r.gateway?.takeIf { !it.isAnyLocalAddress }?.let { g ->
                            if (g is Inet6Address) Ipv6Discovery.text(g) else g.hostAddress
                        },
                        interfaceName = r.`interface`,
                    )
                }
                .distinct()
                .sortedWith(compareBy({ it.destination != "0.0.0.0/0" && it.destination != "::/0" }, { it.interfaceName }, { it.destination }))
        }

        @Suppress("DEPRECATION")
        private fun legacyDhcpInfo(context: Context) =
            runCatching { context.applicationContext.getSystemService(WifiManager::class.java)?.dhcpInfo }.getOrNull()

        /** DhcpInfo stores addresses as little-endian ints. */
        private fun littleEndianIp(v: Int) =
            "${v and 255}.${(v shr 8) and 255}.${(v shr 16) and 255}.${(v shr 24) and 255}"
    }
}

package nl.sc00by.networkscanner.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import nl.sc00by.networkscanner.scan.DhcpQuery
import nl.sc00by.networkscanner.scan.DhcpReply
import nl.sc00by.networkscanner.scan.Ipv6Details
import nl.sc00by.networkscanner.scan.MobileInfo
import nl.sc00by.networkscanner.scan.BluetoothInfo
import nl.sc00by.networkscanner.scan.BtDevice
import androidx.compose.material3.OutlinedButton
import nl.sc00by.networkscanner.scan.NetworkDetails
import nl.sc00by.networkscanner.scan.Oui

private const val NOT_FOUND = "not found"

@Composable
fun NetworkInfoCard(
    details: NetworkDetails?,
    dhcp: DhcpQuery,
    mobile: MobileInfo?,
    bluetooth: BluetoothInfo?,
    onRefresh: () -> Unit,
    onAllowPhone: () -> Unit,
    onAllowLocation: () -> Unit,
    onAllowBluetooth: () -> Unit,
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            CardTitle("Network info") {
                TextButton(onClick = onRefresh, enabled = dhcp != DhcpQuery.Running) { Text("Refresh") }
            }
            if (details == null) {
                Text("Not connected to Wi-Fi or Ethernet", style = MaterialTheme.typography.bodyMedium)
            } else {
                LanSections(details, dhcp)
            }
            if (mobile != null) {
                HorizontalDivider(Modifier.padding(vertical = 6.dp))
                MobileSection(mobile, onAllowPhone, onAllowLocation)
            }
            if (bluetooth != null) {
                HorizontalDivider(Modifier.padding(vertical = 6.dp))
                BluetoothSection(bluetooth, onAllowBluetooth)
            }
        }
    }
}

/** Wi-Fi / Ethernet part: IPv4, IPv4 routes, DHCP, IPv6, IPv6 routes. */
@Composable
private fun LanSections(details: NetworkDetails, dhcp: DhcpQuery) {
            val reply = (dhcp as? DhcpQuery.Done)?.reply

            SectionTitle("IPv4")
            SelectionContainer {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    InfoRow("Interface", details.interfaceName)
                    InfoRow("IP address", details.ipAddress)
                    InfoRow("Netmask", "${details.netmask} (/${details.prefixLength})")
                    InfoRow("Broadcast", details.broadcast)
                    InfoRow("Gateway", details.gateway ?: reply?.routers?.joinOrNull() ?: NOT_FOUND)
                    InfoRow("DHCP server", details.dhcpServer ?: reply?.serverId ?: "$NOT_FOUND (static IP?)")
                    InfoRow("Lease time", (details.leaseSeconds ?: reply?.leaseSeconds)?.let(::formatDuration) ?: NOT_FOUND)
                    InfoRow("DNS servers", details.dnsServers.joinOrNull() ?: reply?.dnsServers?.joinOrNull() ?: NOT_FOUND)
                    details.privateDns?.let { InfoRow("Private DNS", it) }
                    InfoRow("Domain name", reply?.domainName ?: details.domains ?: NOT_FOUND)
                    reply?.searchDomains?.joinOrNull()?.let { InfoRow("Search domains", it) }
                    details.mtu?.let { InfoRow("MTU", it.toString()) }
                    InfoRow(
                        "VLAN ID",
                        details.vlanId?.toString()
                            ?: if (details.interfaceName.startsWith("wlan")) "not visible (Wi-Fi frames are untagged)"
                            else "none (untagged)",
                    )
                }
            }

            HorizontalDivider(Modifier.padding(vertical = 6.dp))
            RoutingTable("Routing table (IPv4)", details.routes)

            HorizontalDivider(Modifier.padding(vertical = 6.dp))
            DhcpSection(dhcp)

            HorizontalDivider(Modifier.padding(vertical = 6.dp))
            Ipv6Section(details.ipv6)
            HorizontalDivider(Modifier.padding(vertical = 6.dp))
            RoutingTable("Routing table (IPv6)", details.ipv6.routes)
}

/** Mobile network: operator, network type (2G … 5G), signal, serving cell and the mobile data connection. */
@Composable
private fun MobileSection(m: MobileInfo, onAllowPhone: () -> Unit, onAllowLocation: () -> Unit) {
    SectionTitle("Mobile network")
    SelectionContainer {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            if (!m.hasTelephony) {
                InfoRow("Status", "$NOT_FOUND (no mobile radio)")
            } else {
                InfoRow("Operator", listOfNotNull(m.operatorName, m.mccMnc?.let { "MCC/MNC $it" }, m.country).joinOrNull() ?: NOT_FOUND)
                InfoRow("SIM", listOfNotNull(m.simState, m.simOperator?.takeIf { it != m.operatorName }?.let { "from $it" },
                    m.simCount?.takeIf { it > 1 }?.let { "$it SIM slots" }).joinToString(" · "))
                InfoRow(
                    "Network type",
                    m.networkType ?: m.technologyGuess?.let { "$it (estimated from signal)" } ?: NOT_FOUND,
                )
                InfoRow("Roaming", if (m.roaming) "yes" else "no")
                m.dataEnabled?.let { InfoRow("Mobile data", if (it) "switched on" else "switched off") }
                m.signals.forEach { sig ->
                    InfoRow(
                        "Signal ${sig.technology}",
                        listOfNotNull(sig.dBm?.let { "$it dBm" }, "${sig.level}/4 bars").joinToString(" · "),
                    )
                    if (sig.details.isNotEmpty()) InfoRow("", sig.details, dim = true)
                }
                if (m.signals.isEmpty()) InfoRow("Signal", "no service")
                m.cell?.let { c ->
                    InfoRow("Serving cell", listOfNotNull(c.technology, c.cellId?.let { "ID $it" }).joinToString(" · "))
                    listOfNotNull(c.area, c.pci?.let { "PCI $it" }, c.channel, c.bands?.let { "band $it" })
                        .joinOrNull()?.let { InfoRow("", it, dim = true) }
                }
            }
            val c = m.connection
            if (c == null) {
                InfoRow("Data connection", "not active (Wi-Fi is used; mobile data starts when Wi-Fi drops)", dim = true)
            } else {
                InfoRow("Data connection", if (c.isDefault) "active (default route)" else "standby (Wi-Fi is the default)")
                c.interfaceName?.let { InfoRow("Interface", it) }
                c.addresses.forEachIndexed { i, a -> InfoRow(if (i == 0) "IP addresses" else "", a) }
                InfoRow("DNS servers", c.dnsServers.joinOrNull() ?: NOT_FOUND)
                c.mtu?.let { InfoRow("MTU", it.toString()) }
                if (c.downKbps != null || c.upKbps != null) {
                    InfoRow("Speed estimate", listOfNotNull(c.downKbps?.let { "↓ ${mbps(it)}" }, c.upKbps?.let { "↑ ${mbps(it)}" })
                        .joinToString("  ") + " (Android estimate)")
                }
                InfoRow("Internet", if (c.validated) "working (checked by Android)" else "not confirmed")
                InfoRow("Metered", if (c.metered) "yes" else "no")
                c.nat64Prefix?.let { InfoRow("NAT64 prefix", "$it (IPv6-only with 464XLAT)") }
            }
        }
    }
    if (m.hasTelephony && (!m.phonePermission || !m.locationPermission)) {
        Text(
            listOfNotNull(
                "The exact network type (GPRS, EDGE, HSPA, LTE, 5G) needs phone access; Android calls it " +
                    "\"make and manage phone calls\", but the app only reads the network state.".takeIf { !m.phonePermission },
                "Serving cell details need location access.".takeIf { !m.locationPermission },
            ).joinToString(" "),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            if (!m.phonePermission) OutlinedButton(onClick = onAllowPhone) { Text("Allow phone access") }
            if (!m.locationPermission) OutlinedButton(onClick = onAllowLocation) { Text("Allow location") }
        }
    }
}

/** Bluetooth: adapter, features, paired devices with their connections, and a Bluetooth IP network. */
@Composable
private fun BluetoothSection(b: BluetoothInfo, onAllow: () -> Unit) {
    SectionTitle("Bluetooth")
    SelectionContainer {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            InfoRow("Status", b.state.takeIf { b.supported } ?: "$NOT_FOUND (${b.state})")
            b.name?.let { InfoRow("Device name", it) }
            b.versionGuess?.let { InfoRow("Version", "$it (estimated from features)") }
            if (b.features.isNotEmpty()) InfoRow("Features", b.features.joinToString(", "))
            if (b.supported && b.connectPermission) {
                if (b.devices.isEmpty()) InfoRow("Paired devices", "none")
                b.devices.forEachIndexed { i, d -> BtDeviceRows(if (i == 0) "Paired devices" else "", d) }
                b.otherConnected.forEachIndexed { i, d -> BtDeviceRows(if (i == 0) "Connected (LE)" else "", d) }
            }
            val n = b.network
            InfoRow(
                "Bluetooth network",
                if (n == null) "none (no Bluetooth tethering in use)"
                else "connected" + if (n.isDefault) " (default route)" else " (standby)",
            )
            if (n != null) {
                n.interfaceName?.let { InfoRow("Interface", it) }
                n.addresses.forEachIndexed { i, a -> InfoRow(if (i == 0) "IP addresses" else "", a) }
                InfoRow("DNS servers", n.dnsServers.joinOrNull() ?: NOT_FOUND)
            }
        }
    }
    if (b.supported && !b.connectPermission) {
        Text(
            "Device name, paired and connected devices need Bluetooth access (\"Nearby devices\").",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedButton(onClick = onAllow) { Text("Allow Bluetooth access") }
    }
}

@Composable
private fun BtDeviceRows(label: String, d: BtDevice) {
    InfoRow(label, (d.name ?: "(no name)") + if (d.connectedVia.isNotEmpty()) "  ● connected" else "")
    val vendor = Oui.vendor(d.address)
    InfoRow(
        "",
        listOfNotNull(
            d.address + (vendor?.let { "  $it" } ?: ""),
            listOfNotNull(d.kind, d.type).joinToString(" · "),
            d.connectedVia.takeIf { it.isNotEmpty() }?.joinToString(", ", prefix = "via "),
        ).joinToString("\n"),
        dim = true,
    )
}

private fun mbps(kbps: Int) = if (kbps >= 1000) "${"%.1f".format(kbps / 1000.0).removeSuffix(".0")} Mbps" else "$kbps kbps"

@Composable
private fun RoutingTable(title: String, routes: List<nl.sc00by.networkscanner.scan.RouteEntry>) {
    SectionTitle(title)
    if (routes.isEmpty()) {
        Text("no routes reported", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.outline)
        return
    }
    SelectionContainer {
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Row {
                listOf("Destination" to 1.3f, "Gateway" to 1f, "Interface" to 0.7f).forEach { (h, w) ->
                    Text(h, Modifier.weight(w), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            routes.forEach { r ->
                Row {
                    val mono = MaterialTheme.typography.bodySmall
                    Text(if (r.destination == "0.0.0.0/0" || r.destination == "::/0") "default" else r.destination, Modifier.weight(1.3f), style = mono, fontFamily = FontFamily.Monospace)
                    Text(r.gateway ?: "direct", Modifier.weight(1f), style = mono, fontFamily = FontFamily.Monospace,
                        color = if (r.gateway == null) MaterialTheme.colorScheme.outline else MaterialTheme.colorScheme.onSurface)
                    Text(r.interfaceName ?: "?", Modifier.weight(0.7f), style = mono, fontFamily = FontFamily.Monospace)
                }
            }
        }
    }
}

/** Fields only the DHCP server itself can tell us (Android does not expose them to apps). */
@Composable
private fun DhcpSection(dhcp: DhcpQuery) {
    SectionTitle("From DHCP server (DHCPINFORM)")
    when (dhcp) {
        DhcpQuery.Idle -> Unit
        // Same rows as the result, so the layout below does not jump when the answer arrives.
        DhcpQuery.Running -> {
            Row(verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
                Text("Asking DHCP server…", style = MaterialTheme.typography.bodySmall)
            }
            DhcpRows(null)
        }
        is DhcpQuery.Failed -> {
            Text(dhcp.reason, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
            DhcpRows(null)
        }
        is DhcpQuery.Done -> DhcpRows(dhcp.reply)
    }
}

@Composable
private fun DhcpRows(r: DhcpReply?) {
    val unknown = if (r == null) "unknown" else NOT_FOUND
    SelectionContainer {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            if (r != null && r.serverId != null && r.serverId != r.repliedFrom) InfoRow("Replied from", r.repliedFrom)
            InfoRow("NTP servers", r?.ntpServers?.joinOrNull() ?: unknown)
            InfoRow(
                "TFTP / PXE",
                listOfNotNull(
                    r?.tftpServerName,
                    r?.tftpServerAddresses?.joinOrNull(),
                    r?.nextServer?.let { "next-server $it" },
                ).joinOrNull() ?: unknown,
            )
            InfoRow("Boot file", r?.bootFile ?: unknown)
            r?.winsServers?.joinOrNull()?.let { InfoRow("WINS servers", it) }
            r?.wpadUrl?.let { InfoRow("WPAD (proxy)", it) }
            r?.otherOptions?.takeIf { it.isNotEmpty() }?.let { InfoRow("Other options", it.joinToString(", ")) }
        }
    }
}

/** Android's view of the IPv6 setup: addresses and how they were made, router, prefixes, DNS. */
@Composable
private fun Ipv6Section(v6: Ipv6Details) {
    SectionTitle("IPv6")
    SelectionContainer {
        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            InfoRow("Configuration", v6.configuration)
            if (v6.addresses.isEmpty()) InfoRow("Addresses", NOT_FOUND)
            v6.addresses.forEachIndexed { i, a ->
                InfoRow(if (i == 0) "Addresses" else "", "${a.address}/${a.prefixLength}")
                InfoRow("", "${a.scope.label} · ${a.method}" + if (a.deprecated) " · deprecated (no longer used for new connections)" else "", dim = true)
            }
            InfoRow("Prefixes", v6.prefixes.joinOrNull() ?: NOT_FOUND)
            InfoRow("Gateway", v6.gateways.joinOrNull() ?: NOT_FOUND)
            v6.gatewayMac?.let { mac -> InfoRow("Router MAC", "$mac  ${Oui.vendor(mac) ?: "unknown manufacturer"}") }
            InfoRow("Recursive DNS", v6.dnsServers.joinOrNull() ?: NOT_FOUND)
            InfoRow("DNS search list", v6.searchDomains.joinOrNull() ?: NOT_FOUND)
            v6.nat64Prefix?.let { InfoRow("NAT64 prefix", it) }
            Text(
                "Recursive DNS comes from the router advertisement (RDNSS) or DHCPv6; the search list " +
                    "from DHCP or the router advertisement (DNSSL). Android doesn't say which, and doesn't " +
                    "show the router advertisement itself (M/O flags, lifetimes).",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String, dim: Boolean = false) {
    Row {
        Text(
            label,
            modifier = Modifier.width(120.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            fontWeight = if (dim || value.startsWith(NOT_FOUND) || value == "unknown") FontWeight.Normal else FontWeight.Medium,
            color = if (dim || value.startsWith(NOT_FOUND) || value == "unknown") MaterialTheme.colorScheme.outline
            else MaterialTheme.colorScheme.onSurface,
        )
    }
}

private fun List<String>.joinOrNull(): String? = takeIf { it.isNotEmpty() }?.joinToString(", ")

private fun formatDuration(seconds: Long): String {
    val d = seconds / 86_400
    val h = seconds % 86_400 / 3_600
    val m = seconds % 3_600 / 60
    val human = listOfNotNull(
        d.takeIf { it > 0 }?.let { "${it}d" },
        h.takeIf { it > 0 }?.let { "${it}h" },
        m.takeIf { it > 0 }?.let { "${it}m" },
    ).joinToString(" ").ifEmpty { "${seconds}s" }
    return "$human ($seconds s)"
}

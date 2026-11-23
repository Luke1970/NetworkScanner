package nl.sc00by.networkscanner.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import nl.sc00by.networkscanner.scan.Identity
import nl.sc00by.networkscanner.scan.MacInfo
import nl.sc00by.networkscanner.scan.OsFingerprint
import nl.sc00by.networkscanner.scan.Oui

private fun found6Title(state: ScanState): String {
    val n = state.hosts6.sumOf { it.addresses.size }
    return "Found IPv6 addresses" + if (n > 0) " ($n)" else ""
}

@Composable
private fun Host6Status(state: ScanState) {
    val text = state.v6Status ?: if (state.hosts6.isEmpty() && !state.v6Running) "No IPv6 devices answered." else null
    if (text != null) {
        Row(Modifier.padding(top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            if (state.v6Running) {
                CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp)
                Spacer(Modifier.width(8.dp))
            }
            Text(text, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

/** Phone layout: one card listing every IPv6 device. */
@Composable
fun Found6Card(state: ScanState, modifier: Modifier = Modifier) {
    Card(modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            CardTitle(found6Title(state))
            Host6Status(state)
            state.hosts6.forEachIndexed { i, h ->
                HorizontalDivider(Modifier.padding(vertical = 4.dp))
                Host6Entry(h, state.hosts)
            }
        }
    }
}

/** Tablet layout: one outlined card per device in as many columns as fit. */
@Composable
fun Found6Grid(state: ScanState, modifier: Modifier = Modifier) {
    Card(modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            CardTitle(found6Title(state))
            Host6Status(state)
            Masonry(minColumnWidth = 300.dp, spacing = 10.dp, modifier = Modifier.padding(top = 8.dp)) {
                state.hosts6.forEach { h ->
                    OutlinedCard(Modifier.fillMaxWidth()) {
                        Box(Modifier.padding(horizontal = 12.dp, vertical = 4.dp)) { Host6Entry(h, state.hosts) }
                    }
                }
            }
        }
    }
}

@Composable
private fun Host6Entry(h: Host6, v4Hosts: List<HostResult>) {
    val primary = h.addresses.first()
    val vendor = h.mac?.let { Oui.vendor(it) }
    // Same device in the IPv4 list: announced together over mDNS, same MAC, or same mDNS name.
    val v4Host = (h.ipv4?.let { ip -> v4Hosts.firstOrNull { it.ip == ip } }) ?: v4Hosts.firstOrNull { v ->
        (h.mac != null && v.identity.mac?.mac.equals(h.mac, ignoreCase = true)) ||
            (h.mdnsName != null && v.identity.mdnsName.equals(h.mdnsName, ignoreCase = true))
    } ?: v4Hosts.firstOrNull { it.isSelf && h.isSelf }
    val v4 = h.ipv4 ?: v4Host?.ip
    // Best name: own mDNS / DNS name, else what the same device is called on IPv4.
    val name = h.mdnsName ?: h.hostname ?: v4Host?.let { v ->
        v.identity.mdnsName ?: v.hostname ?: v.identity.netbiosName ?: v.identity.upnpName
    }
    val os = remember(h.ports, h.mac, h.mdnsName, vendor) {
        OsFingerprint.guess(
            ttl = null,
            openPorts = h.ports.map { it.port },
            software = h.ports.mapNotNull { it.service?.software },
            identity = Identity(mac = h.mac?.let { MacInfo(it, "IPv6 EUI-64") }, mdnsName = h.mdnsName),
            vendor = vendor,
        )
    }
    Column(Modifier.padding(vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            SelectionContainer(Modifier.weight(1f)) {
                Text(
                    primary.text,
                    style = MaterialTheme.typography.titleSmall,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            if (h.scanning) CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
        }
        if (name != null) {
            Text(name, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium, color = headerInk())
        }
        val tags = listOfNotNull("this phone".takeIf { h.isSelf }, "router".takeIf { h.isRouter })
        if (tags.isNotEmpty()) {
            Text(tags.joinToString(" · "), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
        }
        SelectionContainer {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                LabeledLine("Type", addressType(primary), dim = false, mono = false)
                h.addresses.drop(1).forEach { a ->
                    LabeledLine("Also", a.text, dim = false)
                    LabeledLine("", addressType(a), dim = true, mono = false)
                }
                LabeledLine(
                    "MAC",
                    h.mac?.let { "$it  ${vendor ?: "unknown manufacturer"}" }
                        ?: if (h.isSelf) "hidden by Android" else "not in the address (random interface ID)",
                    dim = h.mac == null,
                    mono = h.mac == null,
                )
                v4?.let { LabeledLine("IPv4", it, dim = false) }
                when {
                    os != null -> {
                        LabeledLine("OS", os.name, dim = false, mono = false)
                        LabeledLine("", "from " + os.evidence.joinToString(", "), dim = true, mono = false)
                    }
                    !h.scanning -> LabeledLine("OS", "unknown", dim = true, mono = false)
                }
                listOfNotNull(
                    h.hostname?.let { "DNS" to it },
                    h.mdnsName?.let { "mDNS" to it },
                    name?.takeIf { h.hostname == null && h.mdnsName == null }?.let { "Name" to "$it (from IPv4)" },
                )
                    .distinctBy { it.second.lowercase() }
                    .forEach { (label, value) -> LabeledLine(label, value, dim = false, mono = false) }
                if (h.foundVia.isNotEmpty()) LabeledLine("Found", "via ${h.foundVia}", dim = true, mono = false)
            }
        }
        if (h.ports.isEmpty() && !h.scanning) {
            Text("No open ports found", style = MaterialTheme.typography.bodySmall)
        }
        h.ports.forEach { PortRow(h.ip, it) }
    }
}

private fun addressType(a: V6Address) =
    a.scope.label + if (a.eui64) " · MAC-based (EUI-64)" else " · random interface ID"

/** Places children in the shortest of as many equal columns as fit (a non-lazy staggered grid). */
@Composable
fun Masonry(minColumnWidth: Dp, spacing: Dp, modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Layout(content, modifier) { measurables, constraints ->
        val gap = spacing.roundToPx()
        val width = constraints.maxWidth
        val cols = ((width + gap) / (minColumnWidth.roundToPx() + gap)).coerceAtLeast(1)
        val colWidth = (width - gap * (cols - 1)) / cols
        val heights = IntArray(cols)
        val placed = measurables.map { m ->
            val p = m.measure(Constraints.fixedWidth(colWidth))
            val c = heights.indices.minBy { heights[it] }
            val y = heights[c]
            heights[c] += p.height + gap
            Triple(p, c * (colWidth + gap), y)
        }
        val height = ((heights.maxOrNull() ?: 0) - gap).coerceAtLeast(0)
        layout(width, height) { placed.forEach { (p, x, y) -> p.place(x, y) } }
    }
}

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
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import nl.sc00by.networkscanner.scan.WifiInfoParser
import java.text.DateFormat
import java.util.Date

@Composable
fun WifiCard(
    state: WifiState,
    onRefresh: () -> Unit,
    onAllow: () -> Unit,
    onLocationSettings: () -> Unit,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            CardTitle("Wifi" + if (state.networks.isNotEmpty()) " (${state.networks.size})" else "") {
                if (!state.needsPermission) TextButton(onClick = onRefresh, enabled = !state.scanning) { Text("Refresh") }
                TextButton(onClick = onClose) { Text("Close") }
            }
            when {
                state.needsPermission -> {
                    Text(
                        "Android only shows nearby Wi-Fi networks to apps with location permission. " +
                            "The app doesn't use or store your location.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Button(onClick = onAllow) { Text("Allow") }
                }
                else -> {
                    if (state.scanning) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                            Spacer(Modifier.width(8.dp))
                            Text("Scanning for networks…", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    state.notice?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    if (state.locationOff) OutlinedButton(onClick = onLocationSettings) { Text("Location settings") }
                    state.lastUpdate?.let {
                        Text(
                            "Updated " + DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date(it)),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    state.networks.forEachIndexed { i, n ->
                        if (i > 0) HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
                        WifiEntry(n)
                    }
                    if (state.networks.isNotEmpty()) {
                        Text(
                            "Beacon interval: Android's Wi-Fi API doesn't pass it on (it's a fixed field of the " +
                                "beacon, not an information element). Almost all routers use 100 TU = 102.4 ms. " +
                                "Load and DTIM are only shown when the access point advertises them.",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun WifiEntry(n: WifiNetwork) {
    SelectionContainer {
        Column(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    n.ssid ?: "(hidden network)",
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    fontStyle = if (n.ssid == null) FontStyle.Italic else FontStyle.Normal,
                )
                Text(
                    "${n.rssi} dBm",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                )
            }
            if (n.connected) {
                Text(
                    "● connected" + listOfNotNull(
                        n.linkRxMbps?.let { "↓ $it Mbps" }, n.linkTxMbps?.let { "↑ $it Mbps" },
                    ).joinToString(" · ", prefix = if (n.linkRxMbps != null || n.linkTxMbps != null) " · link " else ""),
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    color = headerInk(),
                )
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                LinearProgressIndicator(
                    progress = { WifiInfoParser.signalPercent(n.rssi) / 100f },
                    modifier = Modifier.width(80.dp),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    "${WifiInfoParser.signalPercent(n.rssi)} % · ${WifiInfoParser.signalLabel(n.rssi)}",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            WifiLine("BSSID", n.bssid, mono = true)
            WifiLine("Vendor", n.vendor ?: "unknown")
            WifiLine(
                "Radio",
                listOfNotNull(
                    n.band,
                    n.channel?.let { "channel $it" },
                    n.width,
                    "${n.frequency} MHz",
                ).joinToString(" · "),
            )
            WifiLine("Wi-Fi gen", n.generation ?: "unknown")
            val s = n.security
            WifiLine("Protocol", s.protocol, warn = s.weak)
            WifiLine("Security", s.type + if (s.adHoc) " · ad-hoc" else "")
            WifiLine("Encryption", s.encryption, warn = s.weak)
            if (s.keyManagement.isNotEmpty()) WifiLine("Key mgmt", s.keyManagement.joinToString(", "))
            WifiLine("PMF (802.11w)", s.pmf ?: "no")
            WifiLine("WPS", wpsText(s.wps, n.wps), warn = s.wps && n.wps?.locked != true)
            WifiLine("Traffic", trafficText(n))
            n.dtim?.let { WifiLine("DTIM", "every $it beacon" + if (it > 1) "s" else "") }
            val extras = listOfNotNull(
                n.country?.let { "country $it" },
                "802.11mc RTT".takeIf { n.rttResponder },
                "Passpoint / Hotspot 2.0".takeIf { n.passpoint },
                "seen ${n.ageSeconds} s ago".takeIf { n.ageSeconds > 10 },
            )
            if (extras.isNotEmpty()) WifiLine("Other", extras.joinToString(" · "))
        }
    }
}

private fun wpsText(advertised: Boolean, wps: WifiInfoParser.Wps?): String {
    if (!advertised && wps == null) return "no"
    val parts = mutableListOf("yes")
    wps?.let {
        if (it.version2) parts += "v2.0"
        when (it.configured) {
            true -> parts += "configured"
            false -> parts += "not configured"
            null -> {}
        }
        if (it.locked) parts += "PIN locked"
    }
    val device = wps?.description()
    return parts.joinToString(", ") + (device?.let { "\nAP says: $it" } ?: "")
}

private fun trafficText(n: WifiNetwork): String {
    val load = n.load?.let {
        "${it.stations} client${if (it.stations == 1) "" else "s"} · channel ${it.utilizationPercent} % busy"
    } ?: "load not advertised"
    val shared = when (n.sameChannel) {
        0 -> "no other networks on this channel"
        1 -> "1 other network on this channel"
        else -> "${n.sameChannel} other networks on this channel"
    }
    return "$load\n$shared"
}

@Composable
private fun WifiLine(label: String, value: String, mono: Boolean = false, warn: Boolean = false) {
    Row {
        Text(
            label,
            modifier = Modifier.width(104.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = if (mono) FontFamily.Monospace else null,
            color = if (warn) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface,
            fontWeight = if (warn) FontWeight.Bold else null,
        )
    }
}

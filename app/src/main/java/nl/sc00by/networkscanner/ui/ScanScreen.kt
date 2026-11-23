package nl.sc00by.networkscanner.ui

import androidx.compose.ui.semantics.Role
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.clickable
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateListOf
import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import android.widget.Toast
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.height
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInParent
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import kotlinx.coroutines.launch
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import nl.sc00by.networkscanner.scan.OsFingerprint
import nl.sc00by.networkscanner.scan.Oui
import nl.sc00by.networkscanner.scan.ServiceInfo
import nl.sc00by.networkscanner.scan.urlHost
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextLinkStyles
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withLink

/** Android 17+ blocks all LAN traffic (TCP times out, UDP gets EPERM) unless this is granted. */
private val NEEDS_LAN_PERMISSION = Build.VERSION.SDK_INT >= 37
private const val LAN_PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"

private fun hasLanPermission(context: Context) = !NEEDS_LAN_PERMISSION ||
    ContextCompat.checkSelfPermission(context, LAN_PERMISSION) == PackageManager.PERMISSION_GRANTED

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(vm: ScanViewModel = viewModel()) {
    val state by vm.state.collectAsStateWithLifecycle()
    val context = LocalContext.current

    var lanAllowed by remember { mutableStateOf(hasLanPermission(context)) }
    var startScanAfterGrant by remember { mutableStateOf(false) }
    val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { ok ->
        lanAllowed = ok
        if (ok) {
            vm.refreshInfo()
            if (startScanAfterGrant) vm.start()
        }
        startScanAfterGrant = false
    }
    // Ask once on first launch; DHCP query needs it too.
    LaunchedEffect(Unit) {
        if (!lanAllowed) permissionLauncher.launch(LAN_PERMISSION)
    }
    // The user may have granted it in system settings meanwhile.
    LifecycleResumeEffect(Unit) {
        val now = hasLanPermission(context)
        if (now && !lanAllowed) vm.refreshInfo()
        vm.refreshMobile()
        lanAllowed = now
        onPauseOrDispose {}
    }
    val startScan = {
        if (lanAllowed) vm.start() else {
            startScanAfterGrant = true
            permissionLauncher.launch(LAN_PERMISSION)
        }
    }

    // Cards opened from the top bar (Wifi / Info), most recently opened first, shown above the rest.
    val panels = remember { mutableStateListOf<Panel>() }
    val wifiVm: WifiViewModel = viewModel()
    val wifiState by wifiVm.state.collectAsStateWithLifecycle()
    val wifiPermissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        wifiVm.refresh()
    }
    val requestWifiPermission = {
        wifiPermissionLauncher.launch(
            buildList {
                add(Manifest.permission.ACCESS_FINE_LOCATION)
                add(Manifest.permission.ACCESS_COARSE_LOCATION)
                if (Build.VERSION.SDK_INT >= 33) add(Manifest.permission.NEARBY_WIFI_DEVICES)
            }.toTypedArray()
        )
    }

    // Mobile part of the Network info card: phone state (exact network type) and location (serving cell).
    val mobilePermissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        vm.refreshMobile()
    }
    val onAllowPhone = {
        mobilePermissionLauncher.launch(
            if (Build.VERSION.SDK_INT >= 33) arrayOf(Manifest.permission.READ_BASIC_PHONE_STATE)
            else arrayOf(Manifest.permission.READ_PHONE_STATE)
        )
    }
    val onAllowLocation = {
        mobilePermissionLauncher.launch(arrayOf(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION))
    }
    val onAllowBluetooth = {
        if (Build.VERSION.SDK_INT >= 31) mobilePermissionLauncher.launch(arrayOf(Manifest.permission.BLUETOOTH_CONNECT))
    }
    val netInfo: @Composable () -> Unit = {
        NetworkInfoCard(
            state.details, state.dhcp, state.mobile, state.bluetooth,
            { vm.refreshInfo() }, onAllowPhone, onAllowLocation, onAllowBluetooth,
        )
    }

    val onSettings = {
        context.startActivity(
            Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", context.packageName, null))
        )
    }
    val showFound = state.running || state.hosts.isNotEmpty() || state.progress >= 1f

    // One decision for top bar and content; LocalConfiguration updates on rotation (configChanges).
    val wide = LocalConfiguration.current.screenWidthDp.dp >= TWO_PANE_MIN_WIDTH
    val leftScroll = rememberScrollState()
    var scanCardTop by remember { mutableStateOf(0) }
    var scanCardHeight by remember { mutableStateOf(0) }
    val scope = rememberCoroutineScope()
    val listState = rememberLazyListState()
    var foundCardHeight by remember { mutableStateOf(0) }
    var found6CardHeight by remember { mutableStateOf(0) }
    val rightScroll = rememberScrollState()
    val scanFromTopBar = {
        startScan()
        scope.launch {
            if (wide) leftScroll.animateScrollTo(scanCardTop)
            // Items above "controls": open panels, permission card (if shown), netinfo.
            else listState.animateScrollToItem(panels.size + (if (lanAllowed) 0 else 1) + 1)
        }
        Unit
    }
    val openPanel = { p: Panel ->
        panels.remove(p)
        panels.add(0, p)
        if (p == Panel.WIFI) {
            if (wifiVm.hasPermission()) wifiVm.refresh() else requestWifiPermission()
        }
        scope.launch {
            if (wide) leftScroll.animateScrollTo(0) else listState.animateScrollToItem(0)
        }
        Unit
    }
    val onLocationSettings = { context.startActivity(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS)) }
    val panelContent: @Composable (Panel) -> Unit = { p ->
        when (p) {
            Panel.WIFI -> WifiCard(
                wifiState,
                onRefresh = wifiVm::refresh,
                onAllow = requestWifiPermission,
                onLocationSettings = onLocationSettings,
                onClose = { panels.remove(Panel.WIFI) },
            )
            Panel.INFO -> InfoCard(onClose = { panels.remove(Panel.INFO) })
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        "Network Scanner",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                },
                actions = {
                    if (state.running) {
                        TopBarLink("Stop", vm::stop)
                    } else {
                        TopBarLink("Scan", scanFromTopBar)
                    }
                    TopBarLink("Wifi") { openPanel(Panel.WIFI) }
                    TopBarLink("Info") { openPanel(Panel.INFO) }
                    Spacer(Modifier.width(4.dp))
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = TopBarYellow,
                    titleContentColor = Color.Black,
                ),
            )
        },
    ) { inner ->
        // Re-evaluated whenever the window size changes (rotation, split screen, foldables).
        BoxWithConstraints(Modifier.fillMaxSize().padding(inner)) {
            if (!wide) {
                val density = LocalDensity.current
                val paneHeight = maxHeight - 24.dp
                LazyColumn(
                    state = listState,
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(horizontal = 16.dp, vertical = 12.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    panels.forEach { p -> item(key = p.name) { panelContent(p) } }
                    if (!lanAllowed) {
                        item(key = "permission") { PermissionCard({ permissionLauncher.launch(LAN_PERMISSION) }, onSettings) }
                    }
                    item(key = "netinfo") { netInfo() }
                    item(key = "controls") {
                        ScanCard(state, vm, startScan, Modifier.onGloballyPositioned { scanCardHeight = it.size.height })
                    }
                    if (showFound) item(key = "found") {
                        FoundCard(state.hosts, state.running, Modifier.onGloballyPositioned { foundCardHeight = it.size.height })
                    }
                    if (showFound) item(key = "found6") {
                        Found6Card(state, Modifier.onGloballyPositioned { found6CardHeight = it.size.height })
                    }
                    // Enough room below the scan card that the top-bar Scan button can scroll it to the top.
                    item(key = "filler") {
                        val below = with(density) { (if (showFound) foundCardHeight + found6CardHeight else 0).toDp() } +
                            if (showFound) 24.dp else 0.dp
                        val filler = paneHeight - with(density) { scanCardHeight.toDp() } - below - 12.dp
                        if (filler > 0.dp) Spacer(Modifier.height(filler))
                    }
                }
            } else {
                // Left: network info + scan controls. Right: devices in as many columns as fit.
                val leftWidth = (maxWidth * 0.4f).coerceIn(320.dp, 460.dp)
                // Height of the left pane, so the scan card can always be scrolled to its top.
                val paneHeight = maxHeight - 24.dp
                Row(
                    Modifier.fillMaxSize().padding(horizontal = 16.dp, vertical = 12.dp),
                    horizontalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    val density = LocalDensity.current
                    Column(
                        Modifier.width(leftWidth).fillMaxHeight().verticalScroll(leftScroll),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        panels.forEach { p -> key(p) { panelContent(p) } }
                        if (!lanAllowed) PermissionCard({ permissionLauncher.launch(LAN_PERMISSION) }, onSettings)
                        netInfo()
                        ScanCard(
                            state, vm, startScan,
                            Modifier.onGloballyPositioned {
                                scanCardTop = it.positionInParent().y.toInt()
                                scanCardHeight = it.size.height
                            },
                        )
                        val filler = paneHeight - with(density) { scanCardHeight.toDp() } - 12.dp
                        if (filler > 0.dp) Spacer(Modifier.height(filler))
                    }
                    Column(
                        Modifier.weight(1f).fillMaxHeight().verticalScroll(rightScroll),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        FoundGrid(state.hosts, state.running, showFound)
                        if (showFound) Found6Grid(state)
                    }
                }
            }
        }
    }
}

private val TWO_PANE_MIN_WIDTH = 600.dp

@Composable
private fun ScanCard(state: ScanState, vm: ScanViewModel, onScan: () -> Unit, modifier: Modifier = Modifier) {
    Card(modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            CardTitle("Network scan")
            val net = state.network
            Text(
                if (net == null) "No Wi-Fi / Ethernet network" else
                    "${net.interfaceName} · ${net.address}/${net.prefixLength} → scanning ${net.cidr}" +
                        if (net.isTruncated) " (limited)" else "",
                style = MaterialTheme.typography.bodyMedium,
            )
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                PortScope.entries.forEachIndexed { i, scope ->
                    SegmentedButton(
                        selected = state.scope == scope,
                        onClick = { vm.setScope(scope) },
                        enabled = !state.running,
                        shape = SegmentedButtonDefaults.itemShape(i, PortScope.entries.size),
                    ) { Text(scope.label) }
                }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (state.running) {
                    OutlinedButton(onClick = vm::stop) { Text("Stop") }
                } else {
                    Button(onClick = onScan) { Text("Scan network") }
                }
                Spacer(Modifier.width(12.dp))
                Text(state.phase, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
            }
            if (state.running) LinearProgressIndicator(progress = { state.progress }, modifier = Modifier.fillMaxWidth())
        }
    }
}

private enum class Panel { WIFI, INFO }

private val EMAIL = Regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}")

/** Shows assets/NetworkScanner.txt (copied from the project root at build time), version and build time. */
@Composable
private fun InfoCard(onClose: () -> Unit) {
    val context = LocalContext.current
    fun asset(name: String) = runCatching { context.assets.open(name).bufferedReader().use { it.readText() } }.getOrNull()?.trim()
    val built = remember { asset("buildtime.txt") }
    val pkg = remember { runCatching { context.packageManager.getPackageInfo(context.packageName, 0) }.getOrNull() }
    val version = listOfNotNull(pkg?.versionName, built).joinToString(", ")
    val text = remember {
        val raw = asset("NetworkScanner.txt") ?: "Network Scanner"
        // The "Version:" line in NetworkScanner.txt gets the real version and build date/time.
        val versionLine = Regex("(?im)^(\\s*Version\\s*:).*$")
        if (versionLine.containsMatchIn(raw)) raw.replace(versionLine) { "${it.groupValues[1]} $version" }
        else "$raw\n\nVersion: $version"
    }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            CardTitle("Info") { TextButton(onClick = onClose) { Text("Close") } }
            val ink = headerInk()
            val linked = remember(text, ink) {
                val links = TextLinkStyles(SpanStyle(color = ink, fontWeight = FontWeight.Bold, textDecoration = TextDecoration.Underline))
                buildAnnotatedString {
                    var last = 0
                    for (m in EMAIL.findAll(text)) {
                        append(text.substring(last, m.range.first))
                        withLink(LinkAnnotation.Url("mailto:${m.value}", links)) { append(m.value) }
                        last = m.range.last + 1
                    }
                    append(text.substring(last))
                }
            }
            SelectionContainer { Text(linked, style = MaterialTheme.typography.bodyMedium) }
        }
    }
}

@Composable
private fun PermissionCard(onAllow: () -> Unit, onSettings: () -> Unit) {
    Card(
        Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Local network access is off", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            Text(
                "Android blocks this app from reaching devices on your network until you allow " +
                    "\"Nearby devices\". Without it the scan only finds this phone and your DNS server.",
                style = MaterialTheme.typography.bodySmall,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onAllow) { Text("Allow") }
                OutlinedButton(onClick = onSettings) { Text("App settings") }
            }
        }
    }
}

@Composable
private fun FoundCard(hosts: List<HostResult>, running: Boolean, modifier: Modifier = Modifier) {
    Card(modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            CardTitle("Found IPv4 addresses" + if (hosts.isNotEmpty()) " (${hosts.size})" else "")
            if (hosts.isEmpty()) {
                Text(
                    if (running) "Searching…" else "No devices answered.",
                    Modifier.padding(top = 8.dp),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            hosts.forEachIndexed { i, host ->
                if (i > 0) HorizontalDivider(Modifier.padding(vertical = 4.dp))
                HostEntry(host)
            }
        }
    }
}

/** Wide-screen variant: one card per device in an adaptive multi-column grid. */
@Composable
private fun FoundGrid(hosts: List<HostResult>, running: Boolean, started: Boolean, modifier: Modifier = Modifier) {
    Card(modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp)) {
            CardTitle("Found IPv4 addresses" + if (hosts.isNotEmpty()) " (${hosts.size})" else "")
            if (hosts.isEmpty()) {
                Text(
                    when {
                        running -> "Searching…"
                        started -> "No devices answered."
                        else -> "Press \"Scan network\" to find the devices on this network."
                    },
                    Modifier.padding(top = 8.dp),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            Masonry(minColumnWidth = 300.dp, spacing = 10.dp, modifier = Modifier.padding(top = 8.dp)) {
                hosts.forEach { host ->
                    key(host.ip) {
                        OutlinedCard(Modifier.fillMaxWidth()) {
                            Box(Modifier.padding(horizontal = 12.dp, vertical = 4.dp)) { HostEntry(host) }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun HostEntry(host: HostResult) {
    Column(Modifier.padding(vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                host.ip,
                style = MaterialTheme.typography.titleMedium,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.SemiBold,
            )
            if (host.isSelf) {
                Spacer(Modifier.width(8.dp))
                Text("this phone", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
            }
            Spacer(Modifier.weight(1f))
            if (host.scanning) CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
        }
        IdentityLines(host)
        if (host.ports.isEmpty() && !host.scanning) {
            Text(
                when {
                    host.foundVia != null -> "No open ports found (only answered ${host.foundVia})"
                    host.stealth && host.ttl == null ->
                        "Present on the network, but ignores all probes (firewall, e.g. Windows or a sleeping phone)"
                    else -> "No open ports found (device answered)"
                },
                style = MaterialTheme.typography.bodySmall,
            )
        }
        host.ports.forEach { PortRow(host.ip, it) }
    }
}

@Composable
private fun IdentityLines(host: HostResult) {
    val id = host.identity
    val mac = id.mac
    // Look up again at render time in case the OUI table finished loading after the MAC was found.
    val vendor = host.vendor ?: mac?.let { Oui.vendor(it.mac) }
    val macText = when {
        mac != null -> buildString {
            append(mac.mac)
            if (!mac.exact) append(" ≈")
            append("  ")
            append(vendor ?: "unknown manufacturer")
        }
        host.isSelf -> "hidden by Android"
        host.scanning -> "looking…"
        else -> "not revealed by device"
    }
    val macSource = mac?.let {
        "via ${it.source}" + if (!it.exact) " · network MAC may differ slightly" else ""
    }
    val os = remember(host.ttl, host.ports, id, vendor) {
        OsFingerprint.guess(
            ttl = host.ttl,
            openPorts = host.ports.map { it.port },
            software = host.ports.mapNotNull { it.service?.software },
            identity = id,
            vendor = vendor,
        )
    }
    SelectionContainer {
        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
            LabeledLine("MAC", macText, dim = mac == null, mono = mac == null)
            macSource?.let { LabeledLine("", it, dim = true, mono = false) }
            when {
                os != null -> {
                    LabeledLine("OS", os.name, dim = false, mono = false)
                    LabeledLine("", "from " + os.evidence.joinToString(", "), dim = true, mono = false)
                }
                !host.scanning -> LabeledLine("OS", "unknown", dim = true, mono = false)
            }
            listOfNotNull(
                host.hostname?.let { "DNS" to it },
                id.mdnsName?.let { "mDNS" to it },
                id.netbiosName?.let { "NetBIOS" to it },
                id.upnpName?.let { "UPnP" to it },
            ).distinctBy { it.second.lowercase() }.forEach { (label, value) -> LabeledLine(label, value, dim = false, mono = false) }
        }
    }
}

@Composable
internal fun LabeledLine(label: String, value: String, dim: Boolean, mono: Boolean = true) {
    Row {
        Text(
            label,
            Modifier.width(64.dp),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            value,
            Modifier.weight(1f),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = if (mono) FontFamily.Monospace else null,
            color = if (dim) MaterialTheme.colorScheme.outline else MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Composable
internal fun PortRow(ip: String, open: OpenPort) {
    val context = LocalContext.current
    val uri = remember(ip, open) { open.service?.takeIf { '%' !in ip }?.let { linkFor(it, urlHost(ip), open.port) } }
    val launchable = remember(uri) { uri != null && hasAppFor(context, uri) }

    Row(verticalAlignment = Alignment.CenterVertically) {
        PortBadge(open.port, launchable) {
            try {
                context.startActivity(Intent(Intent.ACTION_VIEW, uri))
            } catch (_: ActivityNotFoundException) {
                Toast.makeText(context, "No app can open $uri", Toast.LENGTH_SHORT).show()
            }
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(open.service?.name ?: "identifying…", style = MaterialTheme.typography.bodyMedium)
            open.service?.detail?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

/** Filled + underlined when tapping opens a client app; outlined plain number otherwise. */
@Composable
private fun PortBadge(port: Int, clickable: Boolean, onClick: () -> Unit) {
    val shape = RoundedCornerShape(8.dp)
    val modifier = Modifier.width(72.dp)
    val label: @Composable () -> Unit = {
        Text(
            port.toString(),
            modifier = Modifier.padding(vertical = 6.dp).fillMaxWidth(),
            textAlign = TextAlign.Center,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.Bold,
            textDecoration = if (clickable) TextDecoration.Underline else null,
        )
    }
    if (clickable) {
        Surface(
            onClick = onClick,
            modifier = modifier,
            shape = shape,
            color = MaterialTheme.colorScheme.primary,
            contentColor = MaterialTheme.colorScheme.onPrimary,
            content = label,
        )
    } else {
        Surface(
            modifier = modifier,
            shape = shape,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
            color = MaterialTheme.colorScheme.surface,
            contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
            content = label,
        )
    }
}

private fun linkFor(service: ServiceInfo, ip: String, port: Int): Uri? {
    val s = when (service.scheme) {
        "http" -> if (port == 80) "http://$ip/" else "http://$ip:$port/"
        "https" -> if (port == 443) "https://$ip/" else "https://$ip:$port/"
        "rtsp" -> "rtsp://$ip:$port/"
        "ftp" -> "ftp://$ip:$port/"
        "smb" -> "smb://$ip/"
        "ssh", "telnet", "vnc" -> "${service.scheme}://$ip:$port"
        else -> null
    }
    return s?.let(Uri::parse)
}

private val appCache = mutableMapOf<String, Boolean>()

/** True if some installed app handles this kind of link (cached per scheme). */
private fun hasAppFor(context: Context, uri: Uri): Boolean = synchronized(appCache) {
    appCache.getOrPut(uri.scheme.orEmpty()) {
        val intent = Intent(Intent.ACTION_VIEW, uri)
        val pm = context.packageManager
        val matches = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION") pm.queryIntentActivities(intent, 0)
        }
        matches.isNotEmpty()
    }
}

/** Same yellow as the launcher icon background. */
private val TopBarYellow = Color(0xFFFFD600)

/** Underlined black text link in the top bar (instead of a button). */
@Composable
private fun TopBarLink(text: String, onClick: () -> Unit) {
    Text(
        text,
        modifier = Modifier
            .clickable(onClick = onClick, role = Role.Button)
            .padding(horizontal = 8.dp, vertical = 12.dp),
        color = Color.Black,
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.Bold,
        textDecoration = TextDecoration.Underline,
    )
}

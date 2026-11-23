package nl.sc00by.networkscanner.ui

import android.Manifest
import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.wifi.ScanResult
import android.net.wifi.WifiManager
import android.os.Build
import android.os.SystemClock
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import nl.sc00by.networkscanner.scan.Oui
import nl.sc00by.networkscanner.scan.WifiInfoParser
import nl.sc00by.networkscanner.scan.WifiInfoParser.Ie

/** One access point (one BSSID) as heard in the last Wi-Fi scan. */
data class WifiNetwork(
    val ssid: String?,
    val bssid: String,
    val vendor: String?,
    val frequency: Int,
    val band: String,
    val channel: Int?,
    val width: String?,
    val generation: String?,
    val rssi: Int,
    val security: WifiInfoParser.Security,
    val wps: WifiInfoParser.Wps?,
    val load: WifiInfoParser.BssLoad?,
    val dtim: Int?,
    val country: String?,
    val rttResponder: Boolean,
    val passpoint: Boolean,
    val ageSeconds: Long,
    /** Other access points heard on the same channel (co-channel congestion). */
    val sameChannel: Int = 0,
    val connected: Boolean = false,
    val linkRxMbps: Int? = null,
    val linkTxMbps: Int? = null,
)

data class WifiState(
    val networks: List<WifiNetwork> = emptyList(),
    val lastUpdate: Long? = null,
    val scanning: Boolean = false,
    /** Why there are no (fresh) results: permission, Wi-Fi off, location off, throttled. */
    val notice: String? = null,
    val needsPermission: Boolean = false,
    val locationOff: Boolean = false,
)

class WifiViewModel(app: Application) : AndroidViewModel(app) {
    private val wifi = app.getSystemService(WifiManager::class.java)
    private val location = app.getSystemService(LocationManager::class.java)

    private val _state = MutableStateFlow(WifiState())
    val state: StateFlow<WifiState> = _state.asStateFlow()

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val fresh = intent.getBooleanExtra(WifiManager.EXTRA_RESULTS_UPDATED, false)
            load(notice = if (fresh) null else "Android didn't run a new scan; showing the previous results.")
        }
    }

    init {
        ContextCompat.registerReceiver(
            app, receiver, IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION), ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    override fun onCleared() {
        runCatching { getApplication<Application>().unregisterReceiver(receiver) }
    }

    fun hasPermission(): Boolean {
        val ctx = getApplication<Application>()
        return ContextCompat.checkSelfPermission(ctx, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
    }

    /** Ask Android for a new scan; results arrive through the broadcast (or the cached ones are shown). */
    @Suppress("DEPRECATION") // startScan is deprecated but still the only way to request a scan
    fun refresh() {
        if (!hasPermission()) {
            _state.update { it.copy(needsPermission = true, notice = null) }
            return
        }
        val locationOn = location?.isLocationEnabled ?: true
        if (!wifi.isWifiEnabled) {
            _state.update { it.copy(needsPermission = false, locationOff = !locationOn, notice = "Wi-Fi is switched off.") }
            return
        }
        if (!locationOn) {
            _state.update {
                it.copy(needsPermission = false, locationOff = true,
                    notice = "Location is switched off. Android only returns Wi-Fi scan results while location is on.")
            }
            return
        }
        val started = runCatching { wifi.startScan() }.getOrDefault(false)
        _state.update { it.copy(needsPermission = false, locationOff = false, scanning = started) }
        load(
            notice = if (started) null else
                "Android limits apps to 4 Wi-Fi scans per 2 minutes; showing the most recent results.",
            stillScanning = started,
        )
    }

    /**
     * Routers derive the BSSIDs of extra SSIDs (guest network, other bands) from their base MAC with
     * the "locally administered" bit set, so look the vendor up with that bit cleared.
     */
    private fun apVendor(bssid: String): String? {
        if (!Oui.isLocallyAdministered(bssid)) return Oui.vendor(bssid)
        val first = bssid.substring(0, 2).toInt(16) and 0x02.inv()
        val base = "%02x".format(first) + bssid.substring(2)
        return Oui.vendor(base)?.takeIf { Oui.isKnownVendor(base) }?.let { "$it (virtual BSSID)" }
            ?: "locally administered BSSID"
    }

    private fun load(notice: String?, stillScanning: Boolean = false) {
        viewModelScope.launch(Dispatchers.IO) {
            Oui.load(getApplication<Application>())
            loadNow(notice, stillScanning)
        }
    }

    @Suppress("DEPRECATION")
    private fun loadNow(notice: String?, stillScanning: Boolean) {
        val results = runCatching { wifi.scanResults }.getOrNull().orEmpty()
        val info = runCatching { wifi.connectionInfo }.getOrNull()
        val connectedBssid = info?.bssid?.lowercase()?.takeIf { it != "02:00:00:00:00:00" }
        val nowMicros = SystemClock.elapsedRealtime() * 1000

        val networks = results.map { r -> convert(r, nowMicros) }.map { n ->
            if (n.bssid == connectedBssid && info != null) n.copy(
                connected = true,
                linkRxMbps = info.rxLinkSpeedMbps.takeIf { it > 0 },
                linkTxMbps = info.txLinkSpeedMbps.takeIf { it > 0 },
            ) else n
        }
        val withCongestion = networks.map { n ->
            n.copy(sameChannel = networks.count { it !== n && it.band == n.band && it.channel == n.channel })
        }.sortedWith(compareByDescending<WifiNetwork> { it.connected }.thenByDescending { it.rssi })

        _state.update {
            it.copy(
                networks = withCongestion,
                lastUpdate = System.currentTimeMillis(),
                scanning = stillScanning,
                notice = notice ?: if (withCongestion.isEmpty()) "No Wi-Fi networks found." else null,
            )
        }
    }

    @Suppress("DEPRECATION")
    private fun convert(r: ScanResult, nowMicros: Long): WifiNetwork {
        val ies: List<Ie> = if (Build.VERSION.SDK_INT >= 30) {
            r.informationElements.map { ie ->
                val buf = ie.bytes.duplicate()
                val data = ByteArray(buf.remaining()).also { buf.get(it) }
                Ie(ie.id, ie.idExt, data)
            }
        } else emptyList()
        val standard = if (Build.VERSION.SDK_INT >= 30) r.wifiStandard else 0
        val bssid = r.BSSID.lowercase()
        val ssid = r.SSID?.takeIf { it.isNotEmpty() && it != "<unknown ssid>" && it.any { c -> c != '\u0000' } }
        return WifiNetwork(
            ssid = ssid,
            bssid = bssid,
            vendor = apVendor(bssid),
            frequency = r.frequency,
            band = WifiInfoParser.band(r.frequency),
            channel = WifiInfoParser.channel(r.frequency),
            width = WifiInfoParser.channelWidth(r.channelWidth),
            generation = WifiInfoParser.generation(standard, r.frequency) ?: WifiInfoParser.generationFromIes(ies, r.frequency),
            rssi = r.level,
            security = WifiInfoParser.security(r.capabilities.orEmpty()),
            wps = WifiInfoParser.wps(ies),
            load = WifiInfoParser.bssLoad(ies),
            dtim = WifiInfoParser.dtimPeriod(ies),
            country = WifiInfoParser.country(ies),
            rttResponder = r.is80211mcResponder,
            passpoint = r.isPasspointNetwork,
            ageSeconds = ((nowMicros - r.timestamp) / 1_000_000).coerceAtLeast(0),
        )
    }
}

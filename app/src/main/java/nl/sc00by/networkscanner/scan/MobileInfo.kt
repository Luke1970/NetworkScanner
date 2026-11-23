package nl.sc00by.networkscanner.scan

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.telephony.CellIdentityGsm
import android.telephony.CellIdentityLte
import android.telephony.CellIdentityNr
import android.telephony.CellIdentityWcdma
import android.telephony.CellInfo
import android.telephony.CellInfoGsm
import android.telephony.CellInfoLte
import android.telephony.CellInfoNr
import android.telephony.CellInfoWcdma
import android.telephony.CellSignalStrength
import android.telephony.CellSignalStrengthCdma
import android.telephony.CellSignalStrengthGsm
import android.telephony.CellSignalStrengthLte
import android.telephony.CellSignalStrengthNr
import android.telephony.CellSignalStrengthTdscdma
import android.telephony.CellSignalStrengthWcdma
import android.telephony.TelephonyDisplayInfo
import android.telephony.TelephonyManager
import androidx.core.content.ContextCompat
import java.net.Inet6Address

/** Signal of one radio technology the phone currently hears from its serving cell(s). */
data class MobileSignal(val technology: String, val dBm: Int?, val level: Int, val details: String)

/** The cell the phone is registered on (needs location permission). */
data class ServingCell(val technology: String, val cellId: String?, val area: String?, val pci: String?, val channel: String?, val bands: String?)

/** The mobile data connection as ConnectivityManager sees it. */
data class MobileConnection(
    val isDefault: Boolean,
    val interfaceName: String?,
    val addresses: List<String>,
    val dnsServers: List<String>,
    val mtu: Int?,
    val downKbps: Int?,
    val upKbps: Int?,
    val metered: Boolean,
    val roaming: Boolean,
    val validated: Boolean,
    val nat64Prefix: String?,
)

/** Everything the Network info card shows about the mobile network. */
data class MobileInfo(
    val hasTelephony: Boolean,
    val simState: String,
    val operatorName: String?,
    val mccMnc: String?,
    val country: String?,
    val simOperator: String?,
    val roaming: Boolean,
    val dataEnabled: Boolean?,
    /** Exact data network type, e.g. "4G LTE" (needs phone permission), with the 5G/4G+ display override. */
    val networkType: String?,
    /** Best guess from the signal strengths when the exact type is not available. */
    val technologyGuess: String?,
    val signals: List<MobileSignal>,
    val cell: ServingCell?,
    val connection: MobileConnection?,
    val phonePermission: Boolean,
    val locationPermission: Boolean,
    val simCount: Int?,
) {
    companion object {
        fun read(context: Context, displayOverride: Int?): MobileInfo {
            val pm = context.packageManager
            val tm = context.getSystemService(TelephonyManager::class.java)
            val hasTelephony = pm.hasSystemFeature(PackageManager.FEATURE_TELEPHONY) && tm != null
            val phonePerm = granted(context, Manifest.permission.READ_PHONE_STATE) ||
                (Build.VERSION.SDK_INT >= 33 && granted(context, Manifest.permission.READ_BASIC_PHONE_STATE))
            val locationPerm = granted(context, Manifest.permission.ACCESS_FINE_LOCATION)
            val connection = readConnection(context)
            if (!hasTelephony) {
                return MobileInfo(false, "no SIM / no mobile radio", null, null, null, null, false, null, null, null,
                    emptyList(), null, connection, phonePerm, locationPerm, null)
            }
            tm!!
            val dataType = if (phonePerm) runCatching { tm.dataNetworkType }.getOrNull() else null
            val signals = runCatching { tm.signalStrength?.cellSignalStrengths.orEmpty() }.getOrDefault(emptyList())
                .mapNotNull(::signal)
            val cell = if (locationPerm) runCatching { servingCell(tm.allCellInfo.orEmpty()) }.getOrNull() else null

            return MobileInfo(
                hasTelephony = true,
                simState = simState(tm.simState),
                operatorName = tm.networkOperatorName?.takeIf { it.isNotBlank() },
                mccMnc = tm.networkOperator?.takeIf { it.length >= 5 }?.let { "${it.take(3)} / ${it.drop(3)}" },
                country = tm.networkCountryIso?.takeIf { it.isNotBlank() }?.uppercase(),
                simOperator = tm.simOperatorName?.takeIf { it.isNotBlank() },
                roaming = tm.isNetworkRoaming,
                dataEnabled = runCatching { tm.isDataEnabled }.getOrNull(),
                networkType = dataType?.let { typeName(it, displayOverride) },
                technologyGuess = guessFromSignals(signals, displayOverride),
                signals = signals,
                cell = cell,
                connection = connection,
                phonePermission = phonePerm,
                locationPermission = locationPerm,
                simCount = if (Build.VERSION.SDK_INT >= 30) runCatching { tm.activeModemCount }.getOrNull() else null,
            )
        }

        private fun granted(context: Context, permission: String) =
            ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED

        private fun simState(s: Int) = when (s) {
            TelephonyManager.SIM_STATE_READY -> "ready"
            TelephonyManager.SIM_STATE_ABSENT -> "no SIM"
            TelephonyManager.SIM_STATE_PIN_REQUIRED -> "PIN required"
            TelephonyManager.SIM_STATE_PUK_REQUIRED -> "PUK required (blocked)"
            TelephonyManager.SIM_STATE_NETWORK_LOCKED -> "network locked"
            TelephonyManager.SIM_STATE_NOT_READY -> "not ready"
            TelephonyManager.SIM_STATE_PERM_DISABLED -> "permanently disabled"
            TelephonyManager.SIM_STATE_CARD_IO_ERROR -> "card error"
            TelephonyManager.SIM_STATE_CARD_RESTRICTED -> "restricted"
            else -> "unknown"
        }

        /** Network type with generation, refined by what the status bar shows (4G+, 5G NSA, 5G+). */
        @Suppress("DEPRECATION")
        fun typeName(type: Int, displayOverride: Int?): String {
            val base = when (type) {
                TelephonyManager.NETWORK_TYPE_GPRS -> "2G · GPRS"
                TelephonyManager.NETWORK_TYPE_EDGE -> "2G · EDGE (2.75G)"
                TelephonyManager.NETWORK_TYPE_GSM -> "2G · GSM"
                TelephonyManager.NETWORK_TYPE_CDMA -> "2G · CDMA"
                TelephonyManager.NETWORK_TYPE_1xRTT -> "2G · CDMA 1xRTT"
                TelephonyManager.NETWORK_TYPE_IDEN -> "2G · iDEN"
                TelephonyManager.NETWORK_TYPE_UMTS -> "3G · UMTS"
                TelephonyManager.NETWORK_TYPE_EVDO_0, TelephonyManager.NETWORK_TYPE_EVDO_A,
                TelephonyManager.NETWORK_TYPE_EVDO_B -> "3G · CDMA EV-DO"
                TelephonyManager.NETWORK_TYPE_EHRPD -> "3G · eHRPD"
                TelephonyManager.NETWORK_TYPE_TD_SCDMA -> "3G · TD-SCDMA"
                TelephonyManager.NETWORK_TYPE_HSDPA, TelephonyManager.NETWORK_TYPE_HSUPA,
                TelephonyManager.NETWORK_TYPE_HSPA -> "3.5G · HSPA"
                TelephonyManager.NETWORK_TYPE_HSPAP -> "3.75G · HSPA+"
                TelephonyManager.NETWORK_TYPE_LTE -> "4G · LTE"
                TelephonyManager.NETWORK_TYPE_NR -> "5G · NR standalone (SA)"
                TelephonyManager.NETWORK_TYPE_IWLAN -> "Wi-Fi calling (IWLAN)"
                else -> "unknown / not connected"
            }
            val refined = when (displayOverride) {
                TelephonyDisplayInfo.OVERRIDE_NETWORK_TYPE_LTE_CA -> "4G+ · LTE carrier aggregation"
                TelephonyDisplayInfo.OVERRIDE_NETWORK_TYPE_LTE_ADVANCED_PRO -> "4.5G · LTE Advanced Pro"
                TelephonyDisplayInfo.OVERRIDE_NETWORK_TYPE_NR_NSA -> "5G · NR non-standalone (NSA, LTE anchor)"
                TelephonyDisplayInfo.OVERRIDE_NETWORK_TYPE_NR_NSA_MMWAVE,
                TelephonyDisplayInfo.OVERRIDE_NETWORK_TYPE_NR_ADVANCED -> "5G+ · NR advanced (mmWave / high band)"
                else -> null
            }
            return refined ?: base
        }

        private fun guessFromSignals(signals: List<MobileSignal>, displayOverride: Int?): String? {
            val techs = signals.map { it.technology }.toSet()
            return when {
                displayOverride != null && displayOverride != TelephonyDisplayInfo.OVERRIDE_NETWORK_TYPE_NONE ->
                    typeName(TelephonyManager.NETWORK_TYPE_UNKNOWN, displayOverride)
                "5G NR" in techs && "4G LTE" in techs -> "5G · NR non-standalone (NSA, LTE anchor)"
                "5G NR" in techs -> "5G · NR"
                "4G LTE" in techs -> "4G · LTE"
                "3G WCDMA" in techs || "3G TD-SCDMA" in techs -> "3G (UMTS / HSPA)"
                "2G GSM" in techs -> "2G · GSM (GPRS / EDGE)"
                "CDMA" in techs -> "CDMA"
                else -> null
            }
        }

        private fun valid(v: Int) = v != CellInfo.UNAVAILABLE && v != Int.MAX_VALUE

        private fun signal(s: CellSignalStrength): MobileSignal? {
            val dbm = s.dbm.takeIf(::valid)
            return when (s) {
                is CellSignalStrengthNr -> MobileSignal("5G NR", dbm, s.level, listOfNotNull(
                    s.ssRsrp.takeIf(::valid)?.let { "SS-RSRP $it dBm" },
                    s.ssRsrq.takeIf(::valid)?.let { "SS-RSRQ $it dB" },
                    s.ssSinr.takeIf(::valid)?.let { "SS-SINR $it dB" },
                ).joinToString(" · "))
                is CellSignalStrengthLte -> MobileSignal("4G LTE", dbm, s.level, listOfNotNull(
                    s.rsrp.takeIf(::valid)?.let { "RSRP $it dBm" },
                    s.rsrq.takeIf(::valid)?.let { "RSRQ $it dB" },
                    s.rssnr.takeIf(::valid)?.let { "SNR $it dB" },
                    s.timingAdvance.takeIf(::valid)?.let { "TA $it" },
                ).joinToString(" · "))
                is CellSignalStrengthWcdma -> MobileSignal("3G WCDMA", dbm, s.level,
                    listOfNotNull(s.ecNo.takeIf(::valid)?.let { "Ec/No $it dB" }).joinToString(" · "))
                is CellSignalStrengthTdscdma -> MobileSignal("3G TD-SCDMA", dbm, s.level,
                    listOfNotNull(s.rscp.takeIf(::valid)?.let { "RSCP $it dBm" }).joinToString(" · "))
                is CellSignalStrengthGsm -> MobileSignal("2G GSM", dbm, s.level, listOfNotNull(
                    s.rssi.takeIf(::valid)?.let { "RSSI $it dBm" },
                    s.bitErrorRate.takeIf { valid(it) && it in 0..7 }?.let { "BER $it" },
                    s.timingAdvance.takeIf(::valid)?.let { "TA $it" },
                ).joinToString(" · "))
                is CellSignalStrengthCdma -> MobileSignal("CDMA", dbm, s.level, "")
                else -> null
            }?.takeIf { it.dBm != null || it.details.isNotEmpty() }
        }

        private fun servingCell(cells: List<CellInfo>): ServingCell? {
            val c = cells.firstOrNull { it.isRegistered } ?: return null
            fun v(x: Int) = x.takeIf(::valid)?.toString()
            fun bands(b: IntArray?) = b?.takeIf { it.isNotEmpty() }?.joinToString(", ")
            return when (c) {
                is CellInfoNr -> (c.cellIdentity as CellIdentityNr).let { id ->
                    ServingCell("5G NR", id.nci.takeIf { it != Long.MAX_VALUE && it != CellInfo.UNAVAILABLE_LONG }?.toString(),
                        v(id.tac)?.let { "TAC $it" }, v(id.pci), v(id.nrarfcn)?.let { "NR-ARFCN $it" },
                        if (Build.VERSION.SDK_INT >= 30) bands(id.bands)?.let { "n$it" } else null)
                }
                is CellInfoLte -> (c.cellIdentity as CellIdentityLte).let { id ->
                    ServingCell("4G LTE", v(id.ci)?.let { "$it (eNB ${id.ci shr 8}, sector ${id.ci and 0xFF})" },
                        v(id.tac)?.let { "TAC $it" }, v(id.pci), v(id.earfcn)?.let { "EARFCN $it" + (id.bandwidth.takeIf(::valid)?.let { b -> " · ${b / 1000} MHz wide" } ?: "") },
                        if (Build.VERSION.SDK_INT >= 30) bands(id.bands)?.let { "B$it" } else null)
                }
                is CellInfoWcdma -> (c.cellIdentity as CellIdentityWcdma).let { id ->
                    ServingCell("3G WCDMA", v(id.cid), v(id.lac)?.let { "LAC $it" }, v(id.psc)?.let { "PSC $it" },
                        v(id.uarfcn)?.let { "UARFCN $it" }, null)
                }
                is CellInfoGsm -> (c.cellIdentity as CellIdentityGsm).let { id ->
                    ServingCell("2G GSM", v(id.cid), v(id.lac)?.let { "LAC $it" }, v(id.bsic)?.let { "BSIC $it" },
                        v(id.arfcn)?.let { "ARFCN $it" }, null)
                }
                else -> null
            }
        }

        /** The cellular network, if one is up (often only while Wi-Fi is off, unless "mobile data always active"). */
        private fun readConnection(context: Context): MobileConnection? {
            val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
            @Suppress("DEPRECATION")
            val net = cm.allNetworks.firstOrNull { cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true }
                ?: return null
            val caps = cm.getNetworkCapabilities(net) ?: return null
            val lp = cm.getLinkProperties(net)
            return MobileConnection(
                isDefault = cm.activeNetwork == net,
                interfaceName = lp?.interfaceName,
                addresses = lp?.linkAddresses.orEmpty().map { la ->
                    val a = la.address
                    (if (a is Inet6Address) Ipv6Discovery.text(a) else a.hostAddress) + "/" + la.prefixLength
                },
                dnsServers = lp?.dnsServers.orEmpty().map { if (it is Inet6Address) Ipv6Discovery.text(it) else it.hostAddress ?: "?" }
                    .sortedBy { it.contains(':') },
                mtu = lp?.mtu?.takeIf { it > 0 },
                downKbps = caps.linkDownstreamBandwidthKbps.takeIf { it > 0 },
                upKbps = caps.linkUpstreamBandwidthKbps.takeIf { it > 0 },
                metered = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
                roaming = !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING),
                validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
                nat64Prefix = if (Build.VERSION.SDK_INT >= 30) lp?.nat64Prefix?.let {
                    "${Ipv6Discovery.text(it.address as Inet6Address)}/${it.prefixLength}"
                } else null,
            )
        }
    }
}

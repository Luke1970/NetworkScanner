package nl.sc00by.networkscanner.scan

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothClass
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import androidx.core.content.ContextCompat
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withTimeoutOrNull
import java.net.Inet6Address
import kotlin.coroutines.resume

/** A paired (bonded) Bluetooth device. */
data class BtDevice(
    val name: String?,
    val address: String,
    /** Classic (BR/EDR), Low Energy, or both. */
    val type: String,
    /** From the Bluetooth device class, e.g. "headphones", "car audio", "computer". */
    val kind: String?,
    /** Profiles it is connected over right now, e.g. "audio (A2DP)", "calls (HFP)". */
    val connectedVia: List<String>,
)

/** An IP network over Bluetooth (the phone uses another device's Bluetooth tethering). */
data class BtNetwork(val isDefault: Boolean, val interfaceName: String?, val addresses: List<String>, val dnsServers: List<String>)

/** Everything the Network info card shows about Bluetooth. */
data class BluetoothInfo(
    val supported: Boolean,
    val state: String,
    val enabled: Boolean,
    val name: String?,
    /** Best estimate of the Bluetooth version from the supported features. */
    val versionGuess: String?,
    val features: List<String>,
    val devices: List<BtDevice>,
    /** Connected over LE (GATT) but not paired, e.g. a fitness band in use by an app. */
    val otherConnected: List<BtDevice>,
    val network: BtNetwork?,
    /** Android 12+: needed for name, paired and connected devices. */
    val connectPermission: Boolean,
) {
    companion object {
        private val PROFILES = buildList {
            add(BluetoothProfile.A2DP to "audio (A2DP)")
            add(BluetoothProfile.HEADSET to "calls (HFP)")
            add(BluetoothProfile.HEARING_AID to "hearing aid")
            if (Build.VERSION.SDK_INT >= 33) add(BluetoothProfile.LE_AUDIO to "LE Audio")
        }

        fun hasConnectPermission(context: Context) = Build.VERSION.SDK_INT < 31 ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED

        /** Reads adapter, features, paired devices and (asynchronously, via profile proxies) connections. */
        @SuppressLint("MissingPermission") // every protected call is behind connectPermission and runCatching
        suspend fun read(context: Context): BluetoothInfo {
            val network = readNetwork(context)
            val manager = context.getSystemService(BluetoothManager::class.java)
            val adapter = manager?.adapter
            val permission = hasConnectPermission(context)
            if (adapter == null || !context.packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH)) {
                return BluetoothInfo(false, "not available on this device", false, null, null, emptyList(),
                    emptyList(), emptyList(), network, permission)
            }
            val state = runCatching { adapter.state }.getOrDefault(BluetoothAdapter.STATE_OFF)
            val enabled = state == BluetoothAdapter.STATE_ON
            val features = if (enabled) features(adapter) else emptyList()

            val connected: Map<String, MutableSet<String>> = if (enabled && permission) connectedByProfile(context, adapter) else emptyMap()
            val gatt = if (enabled && permission) runCatching { manager.getConnectedDevices(BluetoothProfile.GATT) }.getOrDefault(emptyList()) else emptyList()
            val bonded = if (permission) runCatching { adapter.bondedDevices.orEmpty().toList() }.getOrDefault(emptyList()) else emptyList()
            val bondedAddresses = bonded.map { it.address }.toSet()

            fun device(d: BluetoothDevice, extra: List<String> = emptyList()) = BtDevice(
                name = runCatching { d.alias ?: d.name }.getOrNull()?.takeIf { it.isNotBlank() },
                address = d.address,
                type = when (runCatching { d.type }.getOrDefault(BluetoothDevice.DEVICE_TYPE_UNKNOWN)) {
                    BluetoothDevice.DEVICE_TYPE_CLASSIC -> "Classic"
                    BluetoothDevice.DEVICE_TYPE_LE -> "Low Energy"
                    BluetoothDevice.DEVICE_TYPE_DUAL -> "Classic + LE"
                    else -> "unknown"
                },
                kind = runCatching { d.bluetoothClass }.getOrNull()?.let(::kindOf),
                connectedVia = (connected[d.address].orEmpty() + extra).sorted(),
            )
            val gattOnly = gatt.filter { it.address !in bondedAddresses }.map { device(it, listOf("LE (GATT)")) }
            val gattBonded = gatt.map { it.address }.toSet()
            val devices = bonded.map { d -> device(d, if (d.address in gattBonded && "LE (GATT)" !in connected[d.address].orEmpty()) listOf("LE (GATT)") else emptyList()) }
                .sortedWith(compareBy({ it.connectedVia.isEmpty() }, { it.name?.lowercase() ?: "~" }))

            return BluetoothInfo(
                supported = true,
                state = when (state) {
                    BluetoothAdapter.STATE_ON -> "on"
                    BluetoothAdapter.STATE_OFF -> "off"
                    BluetoothAdapter.STATE_TURNING_ON -> "turning on"
                    BluetoothAdapter.STATE_TURNING_OFF -> "turning off"
                    else -> "unknown"
                },
                enabled = enabled,
                name = if (permission) runCatching { adapter.name }.getOrNull() else null,
                versionGuess = if (enabled) versionGuess(adapter) else null,
                features = features,
                devices = devices,
                otherConnected = gattOnly,
                network = network,
                connectPermission = permission,
            )
        }

        private fun supported(code: Int) = Build.VERSION.SDK_INT >= 33 && code == BluetoothStatusCodes.FEATURE_SUPPORTED

        private fun features(a: BluetoothAdapter): List<String> = buildList {
            runCatching {
                if (a.isLe2MPhySupported) add("LE 2M PHY (2 Mbit/s)")
                if (a.isLeCodedPhySupported) add("LE Coded PHY (long range)")
                if (a.isLeExtendedAdvertisingSupported) add("LE extended advertising")
                if (a.isLePeriodicAdvertisingSupported) add("LE periodic advertising")
                if (a.isMultipleAdvertisementSupported) add("multiple advertisements")
                if (a.isOffloadedFilteringSupported) add("scan filtering in the chip")
                if (Build.VERSION.SDK_INT >= 33) {
                    if (supported(a.isLeAudioSupported)) add("LE Audio")
                    if (supported(a.isLeAudioBroadcastSourceSupported)) add("Auracast broadcast")
                }
            }
        }

        /** Android has no API for the version; the features imply a minimum. */
        private fun versionGuess(a: BluetoothAdapter): String = runCatching {
            when {
                Build.VERSION.SDK_INT >= 33 && supported(a.isLeAudioSupported) -> "5.2 or newer (LE Audio)"
                a.isLe2MPhySupported || a.isLeCodedPhySupported || a.isLeExtendedAdvertisingSupported -> "5.0 or newer"
                a.isMultipleAdvertisementSupported -> "4.1 or newer"
                else -> "4.x or older"
            }
        }.getOrDefault("unknown")

        private fun kindOf(c: BluetoothClass): String? = when (c.deviceClass) {
            BluetoothClass.Device.AUDIO_VIDEO_HEADPHONES -> "headphones"
            BluetoothClass.Device.AUDIO_VIDEO_WEARABLE_HEADSET, BluetoothClass.Device.AUDIO_VIDEO_HANDSFREE -> "headset"
            BluetoothClass.Device.AUDIO_VIDEO_LOUDSPEAKER, BluetoothClass.Device.AUDIO_VIDEO_PORTABLE_AUDIO -> "speaker"
            BluetoothClass.Device.AUDIO_VIDEO_CAR_AUDIO -> "car audio"
            BluetoothClass.Device.AUDIO_VIDEO_HIFI_AUDIO -> "hi-fi audio"
            BluetoothClass.Device.AUDIO_VIDEO_VIDEO_DISPLAY_AND_LOUDSPEAKER -> "TV / display"
            BluetoothClass.Device.WEARABLE_WRIST_WATCH -> "watch"
            BluetoothClass.Device.COMPUTER_LAPTOP -> "laptop"
            BluetoothClass.Device.PHONE_SMART, BluetoothClass.Device.PHONE_CELLULAR -> "phone"
            else -> when (c.majorDeviceClass) {
                BluetoothClass.Device.Major.AUDIO_VIDEO -> "audio / video"
                BluetoothClass.Device.Major.COMPUTER -> "computer"
                BluetoothClass.Device.Major.PHONE -> "phone"
                BluetoothClass.Device.Major.PERIPHERAL -> "keyboard / mouse / controller"
                BluetoothClass.Device.Major.WEARABLE -> "wearable"
                BluetoothClass.Device.Major.HEALTH -> "health device"
                BluetoothClass.Device.Major.IMAGING -> "printer / camera"
                BluetoothClass.Device.Major.NETWORKING -> "network access point"
                BluetoothClass.Device.Major.TOY -> "toy"
                else -> null
            }
        }

        /** Asks each audio profile which devices are connected; each answer arrives through a proxy callback. */
        @SuppressLint("MissingPermission")
        private suspend fun connectedByProfile(context: Context, adapter: BluetoothAdapter): Map<String, MutableSet<String>> {
            val result = mutableMapOf<String, MutableSet<String>>()
            for ((profile, label) in PROFILES) {
                val devices = withTimeoutOrNull(1500) {
                    suspendCancellableCoroutine<List<BluetoothDevice>> { cont ->
                        val listener = object : BluetoothProfile.ServiceListener {
                            override fun onServiceConnected(p: Int, proxy: BluetoothProfile) {
                                val list = runCatching { proxy.connectedDevices }.getOrDefault(emptyList())
                                runCatching { adapter.closeProfileProxy(p, proxy) }
                                if (cont.isActive) cont.resume(list)
                            }
                            override fun onServiceDisconnected(p: Int) {}
                        }
                        val ok = runCatching { adapter.getProfileProxy(context, listener, profile) }.getOrDefault(false)
                        if (!ok && cont.isActive) cont.resume(emptyList())
                    }
                }.orEmpty()
                devices.forEach { result.getOrPut(it.address) { mutableSetOf() } += label }
            }
            return result
        }

        private fun readNetwork(context: Context): BtNetwork? {
            val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
            @Suppress("DEPRECATION")
            val net = cm.allNetworks.firstOrNull {
                cm.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) == true
            } ?: return null
            val lp = cm.getLinkProperties(net)
            return BtNetwork(
                isDefault = cm.activeNetwork == net,
                interfaceName = lp?.interfaceName,
                addresses = lp?.linkAddresses.orEmpty().map { la ->
                    val a = la.address
                    (if (a is Inet6Address) Ipv6Discovery.text(a) else a.hostAddress) + "/" + la.prefixLength
                },
                dnsServers = lp?.dnsServers.orEmpty().map { if (it is Inet6Address) Ipv6Discovery.text(it) else it.hostAddress ?: "?" },
            )
        }
    }
}

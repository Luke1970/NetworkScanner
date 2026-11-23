package nl.sc00by.networkscanner.scan

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import java.net.Inet4Address
import javax.net.SocketFactory

/** The Wi-Fi/Ethernet IPv4 network the phone is on. */
data class LocalNetwork(
    val interfaceName: String,
    val address: String,
    val prefixLength: Int,
    val network: Network,
    val linkProperties: LinkProperties,
) {
    val socketFactory: SocketFactory get() = network.socketFactory

    /** Never scan more than a /22 (1022 hosts) even if the LAN is bigger. */
    val scanPrefix: Int get() = prefixLength.coerceIn(MIN_PREFIX, 30)
    val isTruncated: Boolean get() = prefixLength < MIN_PREFIX

    val cidr: String get() = "${intToIp(networkInt())}/$scanPrefix"

    fun hostAddresses(): List<String> {
        val net = networkInt()
        val size = 1L shl (32 - scanPrefix)
        return (1 until size - 1).map { intToIp(net + it) }
    }

    /** True if [ip] is a host address inside the scanned range. */
    fun contains(ip: String): Boolean {
        val v = runCatching { ipToLong(ip) }.getOrNull() ?: return false
        val net = networkInt()
        return v > net && v < net + (1L shl (32 - scanPrefix)) - 1
    }

    private fun networkInt(): Long {
        val mask = (0xFFFFFFFFL shl (32 - scanPrefix)) and 0xFFFFFFFFL
        return ipToLong(address) and mask
    }

    companion object {
        const val MIN_PREFIX = 22

        /** Finds the Wi-Fi or Ethernet network even when a VPN is the default route. */
        fun detect(context: Context): LocalNetwork? {
            val cm = context.getSystemService(ConnectivityManager::class.java) ?: return null
            @Suppress("DEPRECATION")
            val candidates: List<Network> = listOfNotNull(cm.activeNetwork) + cm.allNetworks
            for (network in candidates.distinct()) {
                val caps = cm.getNetworkCapabilities(network) ?: continue
                val isLan = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
                if (!isLan) continue
                val props = cm.getLinkProperties(network) ?: continue
                val link = props.linkAddresses.firstOrNull {
                    it.address is Inet4Address && !it.address.isLoopbackAddress
                } ?: continue
                return LocalNetwork(
                    interfaceName = props.interfaceName ?: "?",
                    address = link.address.hostAddress ?: continue,
                    prefixLength = link.prefixLength,
                    network = network,
                    linkProperties = props,
                )
            }
            return null
        }

        fun ipToLong(ip: String): Long =
            ip.split('.').fold(0L) { acc, part -> (acc shl 8) or part.toLong() }

        fun intToIp(v: Long): String =
            "${(v shr 24) and 255}.${(v shr 16) and 255}.${(v shr 8) and 255}.${v and 255}"
    }
}

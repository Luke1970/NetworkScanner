package nl.sc00by.networkscanner.scan

/**
 * Pure parsing helpers for Wi-Fi scan results (no Android types, so they're unit-testable).
 *
 * Android hands us: the capabilities string ("[RSN-PSK+SAE-CCMP][ESS][WPS][MFPC]"), the frequency,
 * the channel width, the Wi-Fi standard and the raw 802.11 information elements (IEs) from the
 * beacon / probe response. Everything shown on the Wifi card is derived from those.
 */
object WifiInfoParser {

    // ---- band / channel ----------------------------------------------------------------------

    fun band(freqMhz: Int): String = when (freqMhz) {
        in 2400..2500 -> "2.4 GHz"
        in 4900..5899 -> "5 GHz"
        in 5925..7125 -> "6 GHz"
        in 57000..71000 -> "60 GHz"
        else -> "$freqMhz MHz"
    }

    fun channel(freqMhz: Int): Int? = when (freqMhz) {
        2484 -> 14
        in 2412..2472 -> (freqMhz - 2407) / 5
        5935 -> 2
        in 5955..7115 -> (freqMhz - 5950) / 5
        in 4900..5899 -> (freqMhz - 5000) / 5
        in 57000..71000 -> (freqMhz - 56160) / 2160
        else -> null
    }

    /** android.net.wifi.ScanResult.CHANNEL_WIDTH_* → MHz label. */
    fun channelWidth(code: Int): String? = when (code) {
        0 -> "20 MHz"
        1 -> "40 MHz"
        2 -> "80 MHz"
        3 -> "160 MHz"
        4 -> "80+80 MHz"
        5 -> "320 MHz"
        else -> null
    }

    // ---- Wi-Fi generation --------------------------------------------------------------------

    /** android.net.wifi.ScanResult.WIFI_STANDARD_* → marketing name + IEEE amendment. */
    fun generation(standard: Int, freqMhz: Int): String? = when (standard) {
        1 -> if (freqMhz < 3000) "802.11b/g (legacy)" else "802.11a (legacy)"
        4 -> "Wi-Fi 4 (802.11n)"
        5 -> "Wi-Fi 5 (802.11ac)"
        6 -> if (freqMhz >= 5925) "Wi-Fi 6E (802.11ax)" else "Wi-Fi 6 (802.11ax)"
        7 -> "WiGig (802.11ad)"
        8 -> "Wi-Fi 7 (802.11be)"
        else -> null
    }

    /** Fallback when Android reports "unknown": the highest capability IE present. */
    fun generationFromIes(ies: List<Ie>, freqMhz: Int): String? {
        val std = when {
            ies.any { it.id == 255 && it.idExt == 108 } -> 8 // EHT capabilities
            ies.any { it.id == 255 && it.idExt == 35 } -> 6 // HE capabilities
            ies.any { it.id == 191 } -> 5 // VHT capabilities
            ies.any { it.id == 45 } -> 4 // HT capabilities
            ies.isNotEmpty() -> 1
            else -> 0
        }
        return generation(std, freqMhz)
    }

    // ---- security ----------------------------------------------------------------------------

    data class Security(
        /** e.g. "WPA2-Personal", "WPA2/WPA3-Personal (transition)", "Open (no encryption)". */
        val protocol: String,
        /** Personal / Enterprise / Open / Enhanced Open / WEP. */
        val type: String,
        /** Ciphers, e.g. "AES-CCMP", "AES-CCMP + TKIP". */
        val encryption: String,
        /** Key management as Android names it: PSK, SAE, EAP/SHA1, OWE, … */
        val keyManagement: List<String>,
        /** Protected Management Frames (802.11w). */
        val pmf: String?,
        val wps: Boolean,
        val adHoc: Boolean,
        /** WEP, TKIP-only WPA or open: worth a warning. */
        val weak: Boolean,
    )

    fun security(capabilities: String): Security {
        val groups = Regex("\\[([^\\]]*)]").findAll(capabilities).map { it.groupValues[1] }.toList()
        var wpa1 = false
        var rsn = false
        val akms = linkedSetOf<String>()
        val ciphers = linkedSetOf<String>()
        var wep = false
        var wapi = false
        for (g in groups) {
            val parts = g.split('-')
            when (parts[0]) {
                "WPA" -> wpa1 = true
                "WPA2", "RSN" -> rsn = true
                "WEP" -> wep = true
                "WAPI" -> wapi = true
            }
            if (parts[0] in setOf("WPA", "WPA2", "RSN") && parts.size >= 2) {
                parts[1].split('+').filter { it.isNotBlank() }.forEach { akms += it }
                // Remaining segments are ciphers ("CCMP", "CCMP+TKIP", "GCMP" "256" …), plus
                // sometimes a trailing "[PREAUTH]"-style flag which isn't a cipher.
                parts.drop(2).joinToString("-").replace("-preauth", "", ignoreCase = true).split('+').filter { it.isNotBlank() }.forEach { ciphers += it }
            }
        }
        val flags = groups.toSet()
        val wps = "WPS" in flags
        val adHoc = "IBSS" in flags
        val pmf = when {
            "MFPR" in flags -> "required"
            "MFPC" in flags -> "capable"
            else -> null
        }

        val hasSae = akms.any { it.contains("SAE") }
        val hasPsk = akms.any { it.contains("PSK") && !it.startsWith("WAPI") }
        val hasEap = akms.any { it.contains("EAP") }
        val suiteB = akms.any { it.contains("SUITE_B") || it.contains("SUITE-B") }
        val owe = akms.any { it.contains("OWE") }

        val (protocol, type) = when {
            wep -> "WEP" to "WEP (obsolete)"
            wapi -> "WAPI" to "Personal"
            suiteB -> "WPA3-Enterprise 192-bit" to "Enterprise (802.1X)"
            hasEap && rsn && pmf == "required" -> "WPA3-Enterprise" to "Enterprise (802.1X)"
            hasEap && rsn && wpa1 -> "WPA/WPA2-Enterprise" to "Enterprise (802.1X)"
            hasEap && rsn -> "WPA2-Enterprise" to "Enterprise (802.1X)"
            hasEap -> "WPA-Enterprise" to "Enterprise (802.1X)"
            hasSae && hasPsk -> "WPA2/WPA3-Personal (transition)" to "Personal (password)"
            hasSae -> "WPA3-Personal" to "Personal (password)"
            hasPsk && rsn && wpa1 -> "WPA/WPA2-Personal" to "Personal (password)"
            hasPsk && rsn -> "WPA2-Personal" to "Personal (password)"
            hasPsk -> "WPA-Personal" to "Personal (password)"
            owe -> "Enhanced Open (OWE)" to "Open, encrypted"
            rsn || wpa1 -> (if (rsn) "WPA2" else "WPA") to "Unknown"
            else -> "Open (no encryption)" to "Open"
        }

        val encryption = when {
            wep -> "WEP (RC4)"
            protocol.startsWith("Open") -> "none"
            ciphers.isEmpty() -> "unknown"
            else -> ciphers.joinToString(" + ") { cipherName(it) }
        }
        val weak = wep || protocol.startsWith("Open (no") ||
            (ciphers.isNotEmpty() && ciphers.all { it == "TKIP" }) || (wpa1 && !rsn)
        return Security(protocol, type, encryption, akms.toList(), pmf, wps, adHoc, weak)
    }

    private fun cipherName(c: String) = when (c.uppercase()) {
        "CCMP" -> "AES-CCMP"
        "CCMP-256" -> "AES-CCMP-256"
        "GCMP", "GCMP-128" -> "AES-GCMP"
        "GCMP-256" -> "AES-GCMP-256"
        "TKIP" -> "TKIP (obsolete)"
        "SMS4" -> "SMS4"
        else -> c
    }

    // ---- information elements ----------------------------------------------------------------

    /** One 802.11 information element; idExt is only meaningful for id 255. */
    class Ie(val id: Int, val idExt: Int, val data: ByteArray)

    /** BSS Load element (id 11): what the AP itself says about how busy it is. */
    data class BssLoad(val stations: Int, val utilizationPercent: Int, val admissionCapacity: Int)

    fun bssLoad(ies: List<Ie>): BssLoad? {
        val d = ies.firstOrNull { it.id == 11 }?.data ?: return null
        if (d.size < 5) return null
        val stations = u8(d, 0) or (u8(d, 1) shl 8)
        val util = (u8(d, 2) * 100 + 127) / 255
        val adm = u8(d, 3) or (u8(d, 4) shl 8)
        return BssLoad(stations, util, adm)
    }

    /** DTIM period from the TIM element (id 5); only present in beacons, not probe responses. */
    fun dtimPeriod(ies: List<Ie>): Int? {
        val d = ies.firstOrNull { it.id == 5 }?.data ?: return null
        return if (d.size >= 2 && u8(d, 1) > 0) u8(d, 1) else null
    }

    /** Country element (id 7): two-letter regulatory domain. */
    fun country(ies: List<Ie>): String? {
        val d = ies.firstOrNull { it.id == 7 }?.data ?: return null
        if (d.size < 2) return null
        val cc = String(d, 0, 2, Charsets.US_ASCII)
        return cc.takeIf { it.all { ch -> ch in 'A'..'Z' } }
    }

    /** What the access point tells about itself in its WPS element. */
    data class Wps(
        val configured: Boolean?,
        val locked: Boolean,
        val manufacturer: String?,
        val model: String?,
        val modelNumber: String?,
        val deviceName: String?,
        val version2: Boolean,
    ) {
        fun description(): String? =
            listOfNotNull(manufacturer, listOfNotNull(model, modelNumber).distinct().joinToString(" ").ifBlank { null },
                deviceName?.takeIf { d -> listOfNotNull(model, modelNumber).none { d.contains(it) } }?.let { "\"$it\"" })
                .distinct().joinToString(" ").ifBlank { null }
    }

    /** WPS vendor-specific element: id 221, OUI 00:50:F2, type 4, then big-endian TLVs. */
    fun wps(ies: List<Ie>): Wps? {
        val chunks = ies.filter {
            it.id == 221 && it.data.size >= 4 &&
                u8(it.data, 0) == 0x00 && u8(it.data, 1) == 0x50 && u8(it.data, 2) == 0xF2 && u8(it.data, 3) == 0x04
        }
        if (chunks.isEmpty()) return null
        // A long WPS element can be split over several IEs; concatenate the payloads.
        val d = chunks.fold(ByteArray(0)) { acc, ie -> acc + ie.data.copyOfRange(4, ie.data.size) }
        var configured: Boolean? = null
        var locked = false
        var manufacturer: String? = null
        var model: String? = null
        var modelNumber: String? = null
        var deviceName: String? = null
        var v2 = false
        var i = 0
        while (i + 4 <= d.size) {
            val type = (u8(d, i) shl 8) or u8(d, i + 1)
            val len = (u8(d, i + 2) shl 8) or u8(d, i + 3)
            val start = i + 4
            if (start + len > d.size) break
            val value = d.copyOfRange(start, start + len)
            fun str() = String(value, Charsets.UTF_8).trim { it <= ' ' || it == '\u0000' }.ifBlank { null }
            when (type) {
                0x1044 -> if (len >= 1) configured = u8(value, 0) == 2
                0x1057 -> if (len >= 1) locked = u8(value, 0) == 1
                0x1021 -> manufacturer = str()
                0x1023 -> model = str()
                0x1024 -> modelNumber = str()
                0x1011 -> deviceName = str()
                // WFA vendor extension (00:37:2A) with sub-element 0 = Version2
                0x1049 -> if (len >= 3 && u8(value, 0) == 0x00 && u8(value, 1) == 0x37 && u8(value, 2) == 0x2A) v2 = true
            }
            i = start + len
        }
        return Wps(configured, locked, manufacturer, model, modelNumber, deviceName, v2)
    }

    // ---- signal ------------------------------------------------------------------------------

    /** Rough quality: -100 dBm → 0 %, -50 dBm or better → 100 %. */
    fun signalPercent(dBm: Int): Int = ((dBm + 100) * 2).coerceIn(0, 100)

    fun signalLabel(dBm: Int): String = when {
        dBm >= -55 -> "excellent"
        dBm >= -67 -> "good"
        dBm >= -75 -> "fair"
        dBm >= -85 -> "weak"
        else -> "very weak"
    }

    private fun u8(b: ByteArray, i: Int) = b[i].toInt() and 0xFF
}

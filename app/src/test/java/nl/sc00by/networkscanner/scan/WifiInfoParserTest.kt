package nl.sc00by.networkscanner.scan

import nl.sc00by.networkscanner.scan.WifiInfoParser.Ie
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WifiInfoParserTest {

    @Test fun wpa2Personal() {
        val s = WifiInfoParser.security("[WPA2-PSK-CCMP][RSN-PSK-CCMP][ESS][WPS]")
        assertEquals("WPA2-Personal", s.protocol)
        assertEquals("AES-CCMP", s.encryption)
        assertTrue(s.wps)
        assertFalse(s.weak)
    }

    @Test fun wpa3Transition() {
        val s = WifiInfoParser.security("[RSN-PSK+SAE-CCMP][ESS][MFPC]")
        assertEquals("WPA2/WPA3-Personal (transition)", s.protocol)
        assertEquals("capable", s.pmf)
        assertEquals(listOf("PSK", "SAE"), s.keyManagement)
    }

    @Test fun wpa3OnlyAndEnterprise() {
        assertEquals("WPA3-Personal", WifiInfoParser.security("[RSN-SAE-CCMP][ESS][MFPR][MFPC]").protocol)
        assertEquals("WPA2-Enterprise", WifiInfoParser.security("[RSN-EAP/SHA1-CCMP][ESS]").protocol)
        assertEquals("WPA3-Enterprise 192-bit", WifiInfoParser.security("[RSN-EAP_SUITE_B_192-GCMP-256][ESS][MFPR]").protocol)
        assertEquals("AES-GCMP-256", WifiInfoParser.security("[RSN-EAP_SUITE_B_192-GCMP-256][ESS][MFPR]").encryption)
    }

    @Test fun weakNetworks() {
        assertTrue(WifiInfoParser.security("[WEP][ESS]").weak)
        val open = WifiInfoParser.security("[ESS]")
        assertEquals("Open (no encryption)", open.protocol)
        assertTrue(open.weak)
        val wpa = WifiInfoParser.security("[WPA-PSK-TKIP][ESS]")
        assertEquals("WPA-Personal", wpa.protocol)
        assertTrue(wpa.weak)
        assertEquals("Enhanced Open (OWE)", WifiInfoParser.security("[RSN-OWE-CCMP][ESS][MFPR]").protocol)
    }

    @Test fun channels() {
        assertEquals(1, WifiInfoParser.channel(2412))
        assertEquals(13, WifiInfoParser.channel(2472))
        assertEquals(14, WifiInfoParser.channel(2484))
        assertEquals(36, WifiInfoParser.channel(5180))
        assertEquals(165, WifiInfoParser.channel(5825))
        assertEquals(1, WifiInfoParser.channel(5955))
        assertEquals("6 GHz", WifiInfoParser.band(5955))
        assertEquals("Wi-Fi 6E (802.11ax)", WifiInfoParser.generation(6, 5955))
        assertEquals("Wi-Fi 6 (802.11ax)", WifiInfoParser.generation(6, 5180))
    }

    @Test fun informationElements() {
        val bssLoad = Ie(11, 0, byteArrayOf(12, 0, 0x80.toByte(), 0x10, 0x27))
        val tim = Ie(5, 0, byteArrayOf(0, 3, 0, 0))
        val country = Ie(7, 0, "NL ".toByteArray() + byteArrayOf(1, 13, 20))
        val he = Ie(255, 35, ByteArray(4))
        val ies = listOf(bssLoad, tim, country, he)
        assertEquals(WifiInfoParser.BssLoad(12, 50, 10000), WifiInfoParser.bssLoad(ies))
        assertEquals(3, WifiInfoParser.dtimPeriod(ies))
        assertEquals("NL", WifiInfoParser.country(ies))
        assertEquals("Wi-Fi 6 (802.11ax)", WifiInfoParser.generationFromIes(ies, 5180))
        assertNull(WifiInfoParser.wps(ies))
    }

    @Test fun wpsElement() {
        fun tlv(type: Int, v: ByteArray) = byteArrayOf((type shr 8).toByte(), type.toByte(), 0, v.size.toByte()) + v
        val payload = byteArrayOf(0x00, 0x50, 0xF2.toByte(), 0x04) +
            tlv(0x104A, byteArrayOf(0x10)) +
            tlv(0x1044, byteArrayOf(2)) +
            tlv(0x1021, "AVM".toByteArray()) +
            tlv(0x1023, "FRITZ!Box".toByteArray()) +
            tlv(0x1024, "5690 Pro".toByteArray()) +
            tlv(0x1011, "FRITZ!Box 5690 Pro".toByteArray()) +
            tlv(0x1049, byteArrayOf(0x00, 0x37, 0x2A, 0x00, 0x01, 0x20))
        val wps = WifiInfoParser.wps(listOf(Ie(221, 0, payload)))!!
        assertEquals(true, wps.configured)
        assertTrue(wps.version2)
        assertEquals("AVM", wps.manufacturer)
        assertEquals("AVM FRITZ!Box 5690 Pro", wps.description())
    }
}

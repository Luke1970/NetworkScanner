package nl.sc00by.networkscanner.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class OsFingerprintTest {

    private fun guess(
        ttl: Int? = null,
        ports: List<Int> = emptyList(),
        software: List<String> = emptyList(),
        id: Identity = Identity(),
        vendor: String? = null,
    ) = OsFingerprint.guess(ttl, ports, software, id, vendor)

    @Test fun debianFromSshBanner() =
        assertEquals("Linux (Debian 12)", guess(64, listOf(22), listOf("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"))!!.name)

    @Test fun windowsFromTtlAndPorts() =
        assertEquals("Windows", guess(128, listOf(135, 139, 445))!!.name)

    @Test fun sambaIsNotAMac() =
        assertEquals("Linux / NAS (Samba)", guess(64, id = Identity(model = "MacSamba"))!!.name)

    @Test fun iphoneFromPort() =
        assertEquals("iOS / iPadOS", guess(64, listOf(62078), vendor = "Apple, Inc.")!!.name)

    @Test fun webosFromName() =
        assertEquals("LG webOS", guess(64, id = Identity(mdnsName = "LGwebOSTV"))!!.name)

    @Test fun linuxKernelFromUpnp() =
        assertEquals("Linux 4.14.141", guess(64, id = Identity(upnpServer = "Linux/4.14.141, UPnP/1.0, Portable SDK for UPnP devices/1.6.22"))!!.name)

    @Test fun weakGuessContradictedByTtlIsMarked() =
        assertEquals("Linux (embedded)?", guess(128, software = listOf("lighttpd/1.4.59"))!!.name)

    @Test fun nothingKnown() = assertNull(guess())

    @Test fun ttlOnly() = assertEquals("Linux / Unix", guess(64)!!.name)
}

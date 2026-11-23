package nl.sc00by.networkscanner.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.net.Inet4Address

class DhcpInformTest {

    private val ownIp = InetAddress.getByName("192.168.1.50") as Inet4Address

    /** Turns our own DHCPINFORM into a DHCPACK the way a server would. */
    private fun ackFor(request: ByteArray, options: ByteArray, sname: String = "", file: String = ""): ByteArray {
        val p = request.copyOf(240)
        p[0] = 2 // BOOTREPLY
        byteArrayOf(192.toByte(), 168.toByte(), 1, 5).copyInto(p, 20) // siaddr / next-server
        sname.toByteArray().copyInto(p, 44)
        file.toByteArray().copyInto(p, 108)
        return p + options + byteArrayOf(255.toByte())
    }

    private fun opt(code: Int, vararg data: Int) = byteArrayOf(code.toByte(), data.size.toByte()) + data.map { it.toByte() }
    private fun opt(code: Int, text: String) = byteArrayOf(code.toByte(), text.length.toByte()) + text.toByteArray()

    @Test
    fun parsesFullAck() {
        val req = DhcpInform.buildInform(0x12345678, ownIp)
        assertEquals(1, req[0].toInt())
        assertEquals(8, req[242].toInt()) // option 53 = DHCPINFORM

        val opts = ByteArrayOutputStream().apply {
            write(opt(53, 5))
            write(opt(54, 192, 168, 1, 1))
            write(opt(1, 255, 255, 255, 0))
            write(opt(3, 192, 168, 1, 1))
            write(opt(6, 192, 168, 1, 9, 1, 1, 1, 1))
            write(opt(15, "lan"))
            write(opt(42, 192, 168, 1, 1, 192, 168, 1, 9))
            write(opt(66, "tftp.lan"))
            write(opt(67, "pxelinux.0"))
            // option 119: "lan" then "home.lan" using a compression pointer to offset 0
            write(opt(119, 3, 'l'.code, 'a'.code, 'n'.code, 0, 4, 'h'.code, 'o'.code, 'm'.code, 'e'.code, 0xC0, 0))
            write(opt(28, 192, 168, 1, 255))
        }.toByteArray()

        val r = DhcpInform.parse(ackFor(req, opts), 0x12345678, "192.168.1.1")!!
        assertEquals("192.168.1.1", r.serverId)
        assertEquals("255.255.255.0", r.subnetMask)
        assertEquals(listOf("192.168.1.9", "1.1.1.1"), r.dnsServers)
        assertEquals("lan", r.domainName)
        assertEquals(listOf("lan", "home.lan"), r.searchDomains)
        assertEquals(listOf("192.168.1.1", "192.168.1.9"), r.ntpServers)
        assertEquals("tftp.lan", r.tftpServerName)
        assertEquals("pxelinux.0", r.bootFile)
        assertEquals("192.168.1.5", r.nextServer)
        assertEquals(listOf(28), r.otherOptions)
    }

    @Test
    fun fallsBackToLegacySnameAndFileFields() {
        val req = DhcpInform.buildInform(7, ownIp)
        val r = DhcpInform.parse(ackFor(req, opt(53, 5), sname = "boot-srv", file = "undionly.kpxe"), 7, "x")!!
        assertEquals("boot-srv", r.tftpServerName)
        assertEquals("undionly.kpxe", r.bootFile)
    }

    @Test
    fun rejectsWrongXidAndNonAck() {
        val req = DhcpInform.buildInform(7, ownIp)
        assertNull(DhcpInform.parse(ackFor(req, opt(53, 5)), 8, "x"))
        assertNull(DhcpInform.parse(ackFor(req, opt(53, 6)), 7, "x")) // DHCPNAK
    }
}

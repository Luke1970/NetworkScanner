package nl.sc00by.networkscanner.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.net.SocketFactory

class PrinterPortTest {
    /** A socket factory that fails the test if anything tries to connect. */
    private val noConnect = object : SocketFactory() {
        override fun createSocket() = throw AssertionError("raw printer port must not be probed")
        override fun createSocket(h: String?, p: Int) = createSocket()
        override fun createSocket(h: String?, p: Int, a: java.net.InetAddress?, lp: Int) = createSocket()
        override fun createSocket(h: java.net.InetAddress?, p: Int) = createSocket()
        override fun createSocket(h: java.net.InetAddress?, p: Int, a: java.net.InetAddress?, lp: Int) = createSocket()
    }

    @Test fun rawPrintPortsAreNeverSentData() {
        for (port in Ports.PRINT_PORTS) {
            val info = ServiceDetector(noConnect).identify("192.0.2.20", port)
            assertTrue(info.detail!!.startsWith("not probed"))
        }
        assertEquals("Printer (JetDirect)", ServiceDetector(noConnect).identify("192.0.2.20", 9100).name)
    }
}

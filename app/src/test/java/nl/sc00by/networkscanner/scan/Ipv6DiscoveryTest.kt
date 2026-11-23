package nl.sc00by.networkscanner.scan

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.Inet6Address
import java.net.InetAddress

class Ipv6DiscoveryTest {
    private fun v6(s: String) = InetAddress.getByName(s) as Inet6Address

    @Test fun compressesLikeRfc5952() {
        assertEquals("fe80::1", Ipv6Discovery.compress(v6("fe80:0:0:0:0:0:0:1").address))
        assertEquals("2001:db8::1:0:0:1", Ipv6Discovery.compress(v6("2001:db8:0:0:1:0:0:1").address))
        assertEquals("2001:db8:0:1:1:1:1:1", Ipv6Discovery.compress(v6("2001:db8:0:1:1:1:1:1").address))
        assertEquals("::", Ipv6Discovery.compress(ByteArray(16)))
    }

    @Test fun scopesAndPrefixes() {
        assertEquals(Ipv6Discovery.Scope.LINK_LOCAL, Ipv6Discovery.scopeOf(v6("fe80::1")))
        assertEquals(Ipv6Discovery.Scope.UNIQUE_LOCAL, Ipv6Discovery.scopeOf(v6("fd12:3456::1")))
        assertEquals(Ipv6Discovery.Scope.GLOBAL, Ipv6Discovery.scopeOf(v6("2a02:a46f::1")))
        assertTrue(Ipv6Discovery.inPrefix(v6("2a02:a46f:1:2::99"), v6("2a02:a46f:1:2::1"), 64))
        assertFalse(Ipv6Discovery.inPrefix(v6("2a02:a46f:1:3::99"), v6("2a02:a46f:1:2::1"), 64))
    }

    @Test fun eui64AndKeys() {
        val a = v6("fe80::211:22ff:fe33:4455")
        assertTrue(Ipv6Discovery.isEui64(a))
        assertEquals("00:11:22:33:44:55", Oui.fromEui64(a)?.lowercase())
        assertEquals("fe80::211:22ff:fe33:4455%7", Ipv6Discovery.key(a, 7))
        assertEquals("[fe80::1]", urlHost("fe80::1%7"))
        assertEquals("192.168.1.1", urlHost("192.168.1.1"))
        assertEquals(7, (inetAddressOf("fe80::1%7") as Inet6Address).scopeId)
    }

    @Test fun reverseMdnsName() {
        assertEquals(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa",
            Mdns.reverseName6(v6("fe80::1")),
        )
    }
}

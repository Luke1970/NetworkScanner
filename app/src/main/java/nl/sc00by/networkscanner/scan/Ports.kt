package nl.sc00by.networkscanner.scan

/** A service name expected on a port, plus a URI scheme if the port alone is reliable enough to link. */
data class KnownService(val name: String, val impliedScheme: String? = null)

object Ports {

    /** Probed on every address to decide whether a device exists there (open OR refused = alive). */
    val DISCOVERY: List<Int> = listOf(
        80, 443, 22, 445, 139, 53, 554, 8080, 8443, 5000, 8000, 8008, 9100, 62078, 7000, 1883,
    )

    val KNOWN: Map<Int, KnownService> = mapOf(
        20 to KnownService("FTP data"),
        21 to KnownService("FTP"),
        22 to KnownService("SSH"),
        23 to KnownService("Telnet"),
        25 to KnownService("SMTP"),
        53 to KnownService("DNS"),
        80 to KnownService("HTTP"),
        81 to KnownService("HTTP (alt)"),
        88 to KnownService("Kerberos"),
        110 to KnownService("POP3"),
        111 to KnownService("RPC portmapper"),
        135 to KnownService("MS RPC"),
        139 to KnownService("NetBIOS / SMB", "smb"),
        143 to KnownService("IMAP"),
        179 to KnownService("BGP"),
        389 to KnownService("LDAP"),
        443 to KnownService("HTTPS"),
        445 to KnownService("SMB", "smb"),
        465 to KnownService("SMTPS"),
        514 to KnownService("rsh / syslog"),
        515 to KnownService("LPD printer"),
        548 to KnownService("AFP (Apple file sharing)"),
        554 to KnownService("RTSP"),
        587 to KnownService("SMTP submission"),
        631 to KnownService("IPP printer"),
        636 to KnownService("LDAPS"),
        873 to KnownService("rsync"),
        902 to KnownService("VMware"),
        993 to KnownService("IMAPS"),
        995 to KnownService("POP3S"),
        1080 to KnownService("SOCKS proxy"),
        1400 to KnownService("Sonos"),
        1433 to KnownService("MS SQL"),
        1521 to KnownService("Oracle DB"),
        1723 to KnownService("PPTP VPN"),
        1880 to KnownService("Node-RED"),
        1883 to KnownService("MQTT"),
        1925 to KnownService("Philips TV (JointSpace)"),
        1926 to KnownService("Philips TV (JointSpace TLS)"),
        2049 to KnownService("NFS"),
        2375 to KnownService("Docker API"),
        2376 to KnownService("Docker API (TLS)"),
        3000 to KnownService("Web app / Grafana"),
        3128 to KnownService("HTTP proxy"),
        3306 to KnownService("MySQL / MariaDB"),
        3389 to KnownService("Remote Desktop (RDP)"),
        3689 to KnownService("DAAP (iTunes)"),
        4444 to KnownService("Web / Metasploit"),
        5000 to KnownService("UPnP / Synology / web app"),
        5001 to KnownService("Synology HTTPS"),
        5060 to KnownService("SIP"),
        5222 to KnownService("XMPP"),
        5357 to KnownService("WSD (Windows)"),
        5432 to KnownService("PostgreSQL"),
        5555 to KnownService("ADB (Android debug)"),
        5601 to KnownService("Kibana"),
        5672 to KnownService("AMQP / RabbitMQ"),
        5900 to KnownService("VNC"),
        5901 to KnownService("VNC :1"),
        6000 to KnownService("X11"),
        6053 to KnownService("ESPHome API"),
        6379 to KnownService("Redis"),
        6443 to KnownService("Kubernetes API"),
        6667 to KnownService("IRC"),
        7000 to KnownService("AirPlay"),
        7001 to KnownService("WebLogic / AirPlay"),
        7547 to KnownService("TR-069 (ISP router mgmt)"),
        8000 to KnownService("HTTP (alt) / Hikvision SDK"),
        8001 to KnownService("HTTP (alt)"),
        8008 to KnownService("Chromecast / HTTP"),
        8009 to KnownService("Chromecast / AJP"),
        8080 to KnownService("HTTP (alt)"),
        8081 to KnownService("HTTP (alt)"),
        8086 to KnownService("InfluxDB"),
        8088 to KnownService("HTTP (alt)"),
        8089 to KnownService("Splunk"),
        8096 to KnownService("Jellyfin"),
        8123 to KnownService("Home Assistant"),
        8200 to KnownService("Vault / DLNA"),
        8443 to KnownService("HTTPS (alt)"),
        8554 to KnownService("RTSP (alt)"),
        8581 to KnownService("Homebridge"),
        8883 to KnownService("MQTT (TLS)"),
        8888 to KnownService("HTTP (alt)"),
        8899 to KnownService("HTTP (alt)"),
        9000 to KnownService("Portainer / web app"),
        9001 to KnownService("HTTP (alt)"),
        9090 to KnownService("Prometheus / Cockpit"),
        9091 to KnownService("Transmission"),
        9100 to KnownService("Printer (JetDirect)"),
        9200 to KnownService("Elasticsearch"),
        9443 to KnownService("HTTPS (alt)"),
        9999 to KnownService("HTTP (alt)"),
        10000 to KnownService("Webmin"),
        11211 to KnownService("Memcached"),
        32400 to KnownService("Plex"),
        34567 to KnownService("XMEye DVR"),
        37777 to KnownService("Dahua DVR"),
        49152 to KnownService("UPnP"),
        49153 to KnownService("UPnP"),
        62078 to KnownService("Apple device sync"),
    )

    val COMMON: List<Int> = (KNOWN.keys + DISCOVERY).distinct().sorted()

    val ALL: List<Int> = (1..65535).toList()

    /** Ports where the client talks first; skip waiting for a greeting there. */
    val CLIENT_SPEAKS_FIRST: Set<Int> = setOf(
        80, 81, 443, 554, 1400, 1880, 1925, 1926, 3000, 5000, 5001, 7000, 8000, 8001, 8008, 8080, 8081,
        8088, 8096, 8123, 8443, 8554, 8581, 8888, 8899, 9000, 9001, 9090, 9443, 9999, 10000, 32400,
    )

    val RTSP_PORTS: Set<Int> = setOf(554, 8554)

    /**
     * Raw printing ports: a printer prints whatever bytes arrive here, so the HTTP/TLS/RTSP probes
     * would come out as pages of garbage. These are reported by port number only, never probed.
     */
    val PRINT_PORTS: Set<Int> = setOf(515, 9100, 9101, 9102, 9103)
}

package nl.sc00by.networkscanner.scan

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.SocketFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/** What runs on a port. [scheme] is set when a client app could open it. */
data class ServiceInfo(
    val name: String,
    val detail: String? = null,
    val scheme: String? = null,
    /** Raw software identification (SSH banner, HTTP/RTSP Server header) for OS fingerprinting. */
    val software: String? = null,
)

/** Identifies a service by greeting (banner), HTTP, TLS and RTSP probes, falling back to the port number. */
class ServiceDetector(private val socketFactory: SocketFactory) {

    fun identify(ip: String, port: Int): ServiceInfo {
        val known = Ports.KNOWN[port]
        if (port in Ports.PRINT_PORTS) {
            return ServiceInfo(known?.name ?: "Printer (raw)", detail = "not probed: a printer prints whatever is sent to this port")
        }

        if (port !in Ports.CLIENT_SPEAKS_FIRST) {
            val banner = readBanner(ip, port)
            if (banner != null && banner.isNotEmpty()) return classifyBanner(banner, port, known)
        }
        if (port in Ports.RTSP_PORTS) rtspProbe(ip, port)?.let { return it }
        httpProbe(ip, port, tls = false)?.let { return it }
        tlsProbe(ip, port, known)?.let { return it }
        rtspProbe(ip, port)?.let { return it }

        return ServiceInfo(known?.name ?: "Unknown", detail = "no response to probes", scheme = known?.impliedScheme)
    }

    // ---- greeting / banner -------------------------------------------------------------

    private fun readBanner(ip: String, port: Int): ByteArray? = withSocket(ip, port, readTimeout = 1200) { s ->
        val buf = ByteArray(512)
        val n = try { s.getInputStream().read(buf) } catch (_: SocketTimeoutException) { 0 }
        if (n > 0) buf.copyOf(n) else ByteArray(0)
    }

    private fun classifyBanner(bytes: ByteArray, port: Int, known: KnownService?): ServiceInfo {
        val text = String(bytes, Charsets.ISO_8859_1)
        val line = firstLine(text)
        return when {
            bytes[0] == 0xFF.toByte() -> ServiceInfo("Telnet", null, "telnet")
            text.startsWith("SSH-") -> ServiceInfo("SSH", line, "ssh", software = line)
            text.startsWith("RFB ") -> ServiceInfo("VNC", line, "vnc")
            text.startsWith("220") && (text.contains("FTP", true) || port == 21) -> ServiceInfo("FTP", line, "ftp", software = line)
            text.startsWith("220") && (text.contains("SMTP", true) || port in setOf(25, 465, 587)) ->
                ServiceInfo("SMTP", line)
            text.startsWith("+OK") -> ServiceInfo("POP3", line)
            text.startsWith("* OK") -> ServiceInfo("IMAP", line)
            text.contains("mysql_native_password") || text.contains("MariaDB") -> ServiceInfo("MySQL / MariaDB", line)
            port == 23 || text.contains("login:", true) -> ServiceInfo("Telnet", line, "telnet")
            text.startsWith("HTTP/") -> ServiceInfo("HTTP", line, "http")
            else -> ServiceInfo(known?.name ?: "Unknown", "banner: $line", known?.impliedScheme)
        }
    }

    // ---- HTTP / HTTPS ------------------------------------------------------------------

    private fun httpRequest(ip: String, port: Int) =
        "GET / HTTP/1.1\r\nHost: ${urlHost(ip)}:$port\r\nUser-Agent: NetworkScanner/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            .toByteArray(Charsets.ISO_8859_1)

    private fun httpProbe(ip: String, port: Int, tls: Boolean): ServiceInfo? = withSocket(ip, port, 1500) { raw ->
        raw.getOutputStream().apply { write(httpRequest(ip, port)); flush() }
        parseHttp(readUpTo(raw.getInputStream(), 16_384), tls = false)
    }

    private fun tlsProbe(ip: String, port: Int, known: KnownService?): ServiceInfo? = withSocket(ip, port, 2000) { raw ->
        val ssl = trustAllFactory.createSocket(raw, ip.substringBefore('%'), port, true) as SSLSocket
        ssl.soTimeout = 2000
        ssl.startHandshake()
        val cert = ssl.session.peerCertificates.firstOrNull() as? X509Certificate
        val cn = cert?.subjectX500Principal?.name?.let { Regex("CN=([^,]+)").find(it)?.groupValues?.get(1) }
        ssl.outputStream.apply { write(httpRequest(ip, port)); flush() }
        val http = parseHttp(readUpTo(ssl.inputStream, 16_384), tls = true)
        when {
            http != null -> http.copy(detail = listOfNotNull(http.detail, cn?.let { "cert: $it" }).joinToString(" · "))
            else -> ServiceInfo("TLS · ${known?.name ?: "unknown"}", cn?.let { "cert: $it" })
        }
    }

    private fun parseHttp(bytes: ByteArray, tls: Boolean): ServiceInfo? {
        if (bytes.isEmpty()) return null
        val text = String(bytes, Charsets.ISO_8859_1)
        if (text.startsWith("RTSP/")) return ServiceInfo("RTSP", firstLine(text), "rtsp")
        if (!text.startsWith("HTTP/")) return null

        val head = text.substringBefore("\r\n\r\n")
        fun header(name: String) = Regex("^$name:\\s*(.+)$", setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE))
            .find(head)?.groupValues?.get(1)?.trim()

        val status = firstLine(text).split(' ').getOrNull(1)
        val server = header("Server")
        val realm = header("WWW-Authenticate")?.let { Regex("realm=\"([^\"]*)\"").find(it)?.groupValues?.get(1) }
        val title = Regex("<title[^>]*>(.*?)</title>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
            .find(text)?.groupValues?.get(1)?.replace(Regex("\\s+"), " ")?.trim()?.take(60)
            ?.takeIf { it.isNotEmpty() }

        val detail = listOfNotNull(
            title?.let { "“$it”" },
            server,
            realm?.let { "realm: $it" },
            status?.takeIf { it != "200" }?.let { "status $it" },
        ).joinToString(" · ").ifEmpty { null }

        return if (tls) ServiceInfo("HTTPS", detail, "https", software = server)
        else ServiceInfo("HTTP", detail, "http", software = server)
    }

    // ---- RTSP --------------------------------------------------------------------------

    private fun rtspProbe(ip: String, port: Int): ServiceInfo? = withSocket(ip, port, 1500) { s ->
        s.getOutputStream().apply {
            write("OPTIONS rtsp://${urlHost(ip)}:$port/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: NetworkScanner/0.1\r\n\r\n".toByteArray())
            flush()
        }
        val text = String(readUpTo(s.getInputStream(), 4096), Charsets.ISO_8859_1)
        if (!text.startsWith("RTSP/")) return@withSocket null
        val server = Regex("^Server:\\s*(.+)$", setOf(RegexOption.IGNORE_CASE, RegexOption.MULTILINE))
            .find(text)?.groupValues?.get(1)?.trim()
        ServiceInfo("RTSP", server ?: firstLine(text), "rtsp", software = server)
    }

    // ---- helpers -----------------------------------------------------------------------

    private fun <T> withSocket(ip: String, port: Int, readTimeout: Int, block: (Socket) -> T?): T? {
        val socket = socketFactory.createSocket()
        return try {
            socket.connect(InetSocketAddress(inetAddressOf(ip), port), 1500)
            socket.soTimeout = readTimeout
            block(socket)
        } catch (_: IOException) {
            null
        } catch (_: RuntimeException) {
            null
        } finally {
            try { socket.close() } catch (_: IOException) {}
        }
    }

    private fun readUpTo(input: InputStream, max: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        try {
            while (out.size() < max) {
                val n = input.read(buf)
                if (n < 0) break
                out.write(buf, 0, n)
            }
        } catch (_: SocketTimeoutException) {
        } catch (_: IOException) {
        }
        return out.toByteArray()
    }

    private fun firstLine(text: String): String =
        text.lineSequence().firstOrNull { it.isNotBlank() }.orEmpty()
            .map { if (it in ' '..'~') it else '.' }.joinToString("").trim().take(100)

    private companion object {
        /** Only used to fingerprint services (read cert name, server header); no user data is sent. */
        val trustAllFactory: SSLSocketFactory by lazy {
            val trustAll = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
            SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustAll), SecureRandom()) }.socketFactory
        }
    }
}

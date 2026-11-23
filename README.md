# Network Scanner

An Android app that shows basic information about your mobile network,
data connection, Wi-Fi and Bluetooth, and lists every IP client it finds
on the local network.

Written in Kotlin with Jetpack Compose. Android 10 (API 29) or later.

## What it shows

- **Local network:** every device that answers. It probes a set of common
  TCP ports; a refused connection also counts, because the host is there.
  For each device it shows:
  - name: mDNS/Bonjour, NetBIOS, UPnP/SSDP;
  - MAC address and vendor, from the IEEE OUI list built into the app;
  - open ports and services, linked where they can be opened;
  - an OS guess based on TTL and other clues.
- **IPv6:** neighbours found with a multicast ping and mDNS.
- **Network details:** IP addresses, gateway, DNS, DHCP (DHCPINFORM).
- **Wi-Fi:** the current connection and nearby networks.
- **Mobile network:** network type (GPRS, EDGE, LTE, 5G), serving cell and
  band.
- **Bluetooth:** this phone's device name, and paired and connected devices.

## Install

Download the APK from the
[releases](https://github.com/Luke1970/NetworkScanner/releases) or from
<https://sc00by.nl/software/NetworkScanner/>, and open it on the phone.
Allow installing from that source when Android asks.

## Permissions and known limits

- Network access, for the scan.
- Location, for the Wi-Fi scan and the mobile serving cell (cell ID, band).
- Phone state, for the exact mobile network type. On Android 13 and later
  it is granted automatically; on older versions a button asks for it.
- Bluetooth ("Nearby devices"), for the Bluetooth name and the paired and
  connected devices.
- Android limits Wi-Fi scans to 4 every 2 minutes.
- The reported OS is an educated guess.
- Some devices stay hidden behind a stealth firewall, and some networks
  detect and block scanning.
- Windows PCs do not answer the IPv6 multicast ping. They only show up when
  they announce themselves via mDNS.
- Printer ports 9100-9103 and LPD port 515 are not probed, because a printer
  prints whatever is sent to them. They are listed by port number only.

## Building

You need JDK 17 or later and the Android SDK (`sdk.dir` in
`local.properties`, or `ANDROID_HOME`).

    ./gradlew assembleDebug          # app/build/outputs/apk/debug/
    ./gradlew testDebugUnitTest      # unit tests

`tools/update-oui.py` rebuilds the vendor list
(`app/src/main/assets/oui.dat`) from the IEEE registry.
`NetworkScanner.txt` is the text behind the app's Info button.

## License

GPL-3.0, see [LICENSE](LICENSE). (C) Lucien van Lint.

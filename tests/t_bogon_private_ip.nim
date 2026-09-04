## Unit and integration tests for Bogon, Private, and Loopback IP Handling.
## Covers Phase 03 / Category C (Items 01 through 04).

import unittest
import std/options
import http_logviewer/core/types
import http_logviewer/enrichment/[geoip, flags, bogon]

suite "GeoIP Enrichment - RFC 1918 Private IPv4 Ranges (Phase 03 / Category C / Item 01)":
  test "Item 01: 10.0.0.0/8 exact boundary detection":
    check not isRfc1918Private("9.255.255.255")
    check isRfc1918Private("10.0.0.0")
    check isRfc1918Private("10.0.0.1")
    check isRfc1918Private("10.123.45.67")
    check isRfc1918Private("10.255.255.254")
    check isRfc1918Private("10.255.255.255")
    check not isRfc1918Private("11.0.0.0")

  test "Item 01: 172.16.0.0/12 exact boundary detection":
    check not isRfc1918Private("172.15.255.255")
    check isRfc1918Private("172.16.0.0")
    check isRfc1918Private("172.16.0.1")
    check isRfc1918Private("172.20.50.100")
    check isRfc1918Private("172.31.255.254")
    check isRfc1918Private("172.31.255.255")
    check not isRfc1918Private("172.32.0.0")
    check not isRfc1918Private("172.32.0.1")

  test "Item 01: 192.168.0.0/16 exact boundary detection":
    check not isRfc1918Private("192.167.255.255")
    check isRfc1918Private("192.168.0.0")
    check isRfc1918Private("192.168.0.1")
    check isRfc1918Private("192.168.1.1")
    check isRfc1918Private("192.168.100.200")
    check isRfc1918Private("192.168.255.254")
    check isRfc1918Private("192.168.255.255")
    check not isRfc1918Private("192.169.0.0")

  test "Item 01: IPv4-mapped IPv6 RFC 1918 addresses":
    check isRfc1918Private("::ffff:10.0.0.1")
    check isRfc1918Private("::ffff:172.20.1.1")
    check isRfc1918Private("::ffff:192.168.1.50")
    check isRfc1918Private("[::ffff:192.168.1.1]")
    check not isRfc1918Private("::ffff:8.8.8.8")
    check not isRfc1918Private("::ffff:1.1.1.1")

  test "Item 01: Subnet classification for RFC 1918 addresses":
    check classifyIpSubnet("10.0.0.1") == SubnetPrivateRfc1918
    check classifyIpSubnet("172.16.5.1") == SubnetPrivateRfc1918
    check classifyIpSubnet("192.168.1.1") == SubnetPrivateRfc1918
    check classifyIpSubnet("::ffff:10.5.5.5") == SubnetPrivateRfc1918
    check subnetDescription(SubnetPrivateRfc1918) == "RFC 1918 Private LAN"
    check isPrivateIp("10.0.0.1")
    check isPrivateIp("172.16.0.1")
    check isPrivateIp("192.168.1.1")

suite "GeoIP Enrichment - Loopback and Link-Local Ranges (Phase 03 / Category C / Item 02)":
  test "Item 02: IPv4 127.0.0.0/8 loopback detection and boundaries":
    check not isLoopbackIp("126.255.255.255")
    check isLoopbackIp("127.0.0.0")
    check isLoopbackIp("127.0.0.1")
    check isLoopbackIp("127.0.0.2")
    check isLoopbackIp("127.1.2.3")
    check isLoopbackIp("127.255.255.254")
    check isLoopbackIp("127.255.255.255")
    check not isLoopbackIp("128.0.0.1")
    check classifyIpSubnet("127.0.0.1") == SubnetLoopback

  test "Item 02: IPv6 ::1 loopback and localhost aliases":
    check isLoopbackIp("::1")
    check isLoopbackIp("[::1]")
    check isLoopbackIp("0:0:0:0:0:0:0:1")
    check isLoopbackIp("localhost")
    check isLoopbackIp("::ffff:127.0.0.1")
    check not isLoopbackIp("::2")
    check not isLoopbackIp("::")
    check classifyIpSubnet("::1") == SubnetLoopback
    check classifyIpSubnet("localhost") == SubnetLoopback
    check subnetDescription(SubnetLoopback) == "Loopback / Host"

  test "Item 02: IPv4 169.254.0.0/16 link-local range detection":
    check not isLinkLocalIp("169.253.255.255")
    check isLinkLocalIp("169.254.0.0")
    check isLinkLocalIp("169.254.0.1")
    check isLinkLocalIp("169.254.1.1")
    check isLinkLocalIp("169.254.123.45")
    check isLinkLocalIp("169.254.255.254")
    check isLinkLocalIp("169.254.255.255")
    check not isLinkLocalIp("169.255.0.0")
    check classifyIpSubnet("169.254.1.1") == SubnetLinkLocal

  test "Item 02: IPv6 fe80::/10 link-local range detection":
    check isLinkLocalIp("fe80::1")
    check isLinkLocalIp("fe80::abcd:ef01:2345:6789")
    check isLinkLocalIp("[fe80::1]")
    check isLinkLocalIp("fe80::1%eth0")
    check isLinkLocalIp("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    check not isLinkLocalIp("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    check not isLinkLocalIp("fec0::1")
    check classifyIpSubnet("fe80::1") == SubnetLinkLocal
    check subnetDescription(SubnetLinkLocal) == "Link-Local / Autoconf"

suite "GeoIP Enrichment - Local Traffic Marker and Icon (Phase 03 / Category C / Item 03)":
  test "Item 03: Standard distinct marker and icon for local/internal traffic":
    let markerEmoji = formatLocalTrafficMarker("192.168.1.1", useEmoji = true)
    check markerEmoji == "🏠 Local / Private LAN"

    let markerAscii = formatLocalTrafficMarker("192.168.1.1", useEmoji = false)
    check markerAscii == "[LAN] Local / Private LAN"

    let badgeEmoji = formatPrivateIpBadge("10.0.0.1", useEmoji = true)
    check badgeEmoji == "🏠 Local / Private LAN"

    let badgeAscii = formatPrivateIpBadge("10.0.0.1", useEmoji = false)
    check badgeAscii == "[LAN] Local / Private LAN"

  test "Item 03: Detailed marker with subnet topology description":
    let detailedRfc = formatLocalTrafficMarker("10.0.0.1", useEmoji = true, detailed = true)
    check detailedRfc == "🏠 Local / Private LAN (RFC 1918 Private LAN)"

    let detailedLoopback = formatLocalTrafficMarker("127.0.0.1", useEmoji = true, detailed = true)
    check detailedLoopback == "🏠 Local / Private LAN (Loopback / Host)"

    let detailedLinkLocal = formatLocalTrafficMarker("169.254.1.1", useEmoji = true, detailed = true)
    check detailedLinkLocal == "🏠 Local / Private LAN (Link-Local / Autoconf)"

    let detailedAscii = formatLocalTrafficMarker("fe80::1", useEmoji = false, detailed = true)
    check detailedAscii == "[LAN] Local / Private LAN (Link-Local / Autoconf)"

  test "Item 03: makeEnrichedPrivateLocation annotates subnet kind":
    let locRfc = makeEnrichedPrivateLocation("192.168.1.100")
    check locRfc.countryCode == "LO"
    check locRfc.flagEmoji == "🏠"
    check locRfc.isPrivate == true
    check locRfc.city == some("RFC 1918 Private LAN")

    let locLoop = makeEnrichedPrivateLocation("::1")
    check locLoop.countryCode == "LO"
    check locLoop.flagEmoji == "🏠"
    check locLoop.isPrivate == true
    check locLoop.city == some("Loopback / Host")

  test "Item 03: FormatCountryBadge and flag emoji integration for LO":
    check isoToFlagEmoji("LO") == "🏠"
    check flagTerminalFallback("LO") == "[LAN]"
    check formatCountryBadge("LO", true) == "🏠 LO"
    check formatCountryBadge("LO", false) == "[LAN] LO"

suite "GeoIP Enrichment - Multicast Subnets (Phase 03 / Category C / Item 04)":
  test "Item 04: IPv4 224.0.0.0/4 multicast range detection and boundaries":
    check not isMulticastIp("223.255.255.255")
    check isMulticastIp("224.0.0.0")
    check isMulticastIp("224.0.0.1")
    check isMulticastIp("224.0.1.1")
    check isMulticastIp("232.0.0.1")
    check isMulticastIp("239.255.255.254")
    check isMulticastIp("239.255.255.255")
    check not isMulticastIp("240.0.0.0")
    check classifyIpSubnet("224.0.0.1") == SubnetMulticast
    check classifyIpSubnet("239.1.2.3") == SubnetMulticast
    check subnetDescription(SubnetMulticast) == "Multicast Group"

  test "Item 04: IPv6 ff00::/8 multicast range detection":
    check isMulticastIp("ff02::1")
    check isMulticastIp("ff02::2")
    check isMulticastIp("ff05::1:3")
    check isMulticastIp("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    check not isMulticastIp("fe80::1")
    check not isMulticastIp("2001:4860::8888")
    check classifyIpSubnet("ff02::1") == SubnetMulticast

suite "GeoIP Enrichment - Carrier-Grade NAT (CGNAT) (Phase 03 / Category C / Item 04)":
  test "Item 04: IPv4 100.64.0.0/10 CGNAT range detection and exact boundaries":
    check not isCgnatIp("100.63.255.255")
    check isCgnatIp("100.64.0.0")
    check isCgnatIp("100.64.0.1")
    check isCgnatIp("100.80.50.25")
    check isCgnatIp("100.127.255.254")
    check isCgnatIp("100.127.255.255")
    check not isCgnatIp("100.128.0.0")
    check not isCgnatIp("100.128.0.1")
    check classifyIpSubnet("100.64.0.1") == SubnetCarrierGradeNat
    check classifyIpSubnet("100.100.100.100") == SubnetCarrierGradeNat
    check subnetDescription(SubnetCarrierGradeNat) == "Carrier-Grade NAT (CGNAT)"

suite "GeoIP Enrichment - Bogon, Reserved, and Documentation Subnets (Phase 03 / Category C / Item 04)":
  test "Item 04: Current network (0.0.0.0/8) and broadcast (255.255.255.255)":
    check isBogonIp("0.0.0.0")
    check isBogonIp("0.0.0.1")
    check isBogonIp("0.255.255.255")
    check isBogonIp("255.255.255.255")
    check classifyIpSubnet("255.255.255.255") == SubnetBroadcast
    check subnetDescription(SubnetBroadcast) == "Limited Broadcast"

  test "Item 04: Reserved class E space (240.0.0.0/4)":
    check not isBogonIp("239.255.255.255") # Multicast, not bogon reserved
    check isBogonIp("240.0.0.0")
    check isBogonIp("240.0.0.1")
    check isBogonIp("250.1.2.3")
    check isBogonIp("255.255.255.254")
    check classifyIpSubnet("240.0.0.1") == SubnetBogonReserved
    check subnetDescription(SubnetBogonReserved) == "Reserved / Bogon Range"

  test "Item 04: Documentation subnets TEST-NET-1, 2, 3 and 2001:db8::/32":
    check isDocumentationIp("192.0.2.1")      # TEST-NET-1
    check isDocumentationIp("198.51.100.50")  # TEST-NET-2
    check isDocumentationIp("203.0.113.199")  # TEST-NET-3
    check isDocumentationIp("2001:db8::1")    # IPv6 Documentation
    check isDocumentationIp("2001:0db8:85a3::8a2e:370:7334")
    check not isDocumentationIp("8.8.8.8")
    check not isDocumentationIp("2001:4860::8888")
    check classifyIpSubnet("192.0.2.1") == SubnetDocumentation
    check classifyIpSubnet("198.51.100.1") == SubnetDocumentation
    check classifyIpSubnet("203.0.113.1") == SubnetDocumentation
    check classifyIpSubnet("2001:db8::1") == SubnetDocumentation
    check subnetDescription(SubnetDocumentation) == "Documentation / Test Net"

  test "Item 04: Benchmarking, 6to4 relay, discard-only, and IPv6 unspecified":
    check isBogonIp("198.18.0.1")       # Benchmarking RFC 2544
    check isBogonIp("198.19.255.254")
    check isBogonIp("192.88.99.1")      # 6to4 Relay Anycast
    check isBogonIp("::")               # IPv6 Unspecified
    check isBogonIp("100::1")           # Discard-only RFC 6666
    check isBogonIp("2001:2::1")        # IPv6 Benchmarking RFC 5180

suite "GeoIP Enrichment - IPv6 Unique Local Address (ULA) (Phase 03 / Category C / Item 04)":
  test "Item 04: IPv6 fc00::/7 ULA detection":
    check isUniqueLocalIp("fc00::1")
    check isUniqueLocalIp("fd00::1")
    check isUniqueLocalIp("fd12:3456:789a::1")
    check not isUniqueLocalIp("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
    check not isUniqueLocalIp("fe00::1")
    check classifyIpSubnet("fd12:3456:789a::1") == SubnetUniqueLocalIpv6
    check subnetDescription(SubnetUniqueLocalIpv6) == "IPv6 Unique Local (ULA)"

suite "GeoIP Enrichment - Comprehensive Subnet Classification & Diagnostics (Phase 03 / Category C / Item 04)":
  test "Item 04: Public routable addresses classified as SubnetPublic":
    check classifyIpSubnet("8.8.8.8") == SubnetPublic
    check classifyIpSubnet("1.1.1.1") == SubnetPublic
    check classifyIpSubnet("142.250.180.206") == SubnetPublic
    check classifyIpSubnet("2001:4860:4860::8888") == SubnetPublic
    check subnetDescription(SubnetPublic) == "Public Internet"

  test "Item 04: Invalid and malformed IP strings classified as SubnetInvalid":
    check classifyIpSubnet("") == SubnetInvalid
    check classifyIpSubnet("invalid-ip") == SubnetInvalid
    check classifyIpSubnet("999.999.999.999") == SubnetInvalid
    check classifyIpSubnet("::gggg") == SubnetInvalid
    check subnetDescription(SubnetInvalid) == "Invalid IP Address"

suite "GeoIP Enrichment - Private and Bogon Integration with GeoIpEngine (Phase 03 / Category C / Item 04)":
  test "Item 04: GeoIpEngine intercepts private IPs without querying external DB":
    let engine = newGeoIpEngine()

    let testIps = [
      "10.10.10.10",
      "172.25.1.1",
      "192.168.10.1",
      "127.0.0.1",
      "169.254.10.20",
      "100.64.1.1",
      "::1",
      "fe80::1",
      "fd00::1234",
      "224.0.0.251",
      "255.255.255.255"
    ]

    for ip in testIps:
      check isPrivateIp(ip)
      let loc = engine.lookup(ip)
      check loc.isPrivate == true
      check loc.countryCode == "LO"
      check loc.flagEmoji == "🏠"
      check loc.countryName == "Local / Private Network"

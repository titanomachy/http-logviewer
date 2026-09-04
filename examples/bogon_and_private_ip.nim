# Example: Bogon, Private, and Loopback IP Subnet Detection & Classification
# Demonstrates RFC 1918 private subnets, loopback/localhost, link-local, carrier-grade NAT,
# multicast, bogon/reserved networks, distinct local traffic markers (🏠 Local / Private LAN),
# and GeoIpEngine integration.
#
# Compile and run with:
#   nim r --path:src examples/bogon_and_private_ip.nim

import std/[strutils]
import http_logviewer/core/types
import http_logviewer/enrichment/[geoip, flags, bogon]

proc main() =
  echo "=== http_logviewer: Bogon, Private & Loopback IP Subnet Handling (Phase 03 / Category C) ==="
  echo ""

  # 1. RFC 1918 Private IPv4 Ranges (Item 01)
  echo "[1] RFC 1918 Private IPv4 Range Detection (Item 01):"
  let rfcIps = [
    ("10.0.0.1", "10.0.0.0/8 Private Network"),
    ("10.255.255.254", "10.0.0.0/8 Upper Boundary"),
    ("172.16.0.1", "172.16.0.0/12 Lower Boundary"),
    ("172.24.10.50", "172.16.0.0/12 Mid Range"),
    ("172.31.255.254", "172.16.0.0/12 Upper Boundary"),
    ("192.168.1.1", "192.168.0.0/16 Common Gateway"),
    ("192.168.100.200", "192.168.0.0/16 Host"),
    ("::ffff:192.168.1.1", "IPv4-Mapped IPv6 RFC 1918")
  ]
  for (ip, label) in rfcIps:
    let isRfc = isRfc1918Private(ip)
    let kind = classifyIpSubnet(ip)
    echo "  IP: ", ip.alignLeft(22), " -> RFC 1918: ", isRfc,
         " | Kind: ", subnetDescription(kind), " (", label, ")"
  echo ""

  # 2. Loopback and Link-Local Ranges (Item 02)
  echo "[2] Loopback and Link-Local Range Detection (Item 02):"
  let localIps = [
    ("127.0.0.1", "IPv4 Loopback (localhost)"),
    ("127.1.2.3", "127.0.0.0/8 Loopback Range"),
    ("::1", "IPv6 Loopback"),
    ("localhost", "Standard Localhost Alias"),
    ("::ffff:127.0.0.1", "IPv4-Mapped Loopback"),
    ("169.254.1.1", "IPv4 Link-Local (RFC 3927)"),
    ("fe80::1", "IPv6 Link-Local Unicast (fe80::/10)"),
    ("fe80::1%eth0", "IPv6 Link-Local Scoped with Interface")
  ]
  for (ip, label) in localIps:
    let isLoop = isLoopbackIp(ip)
    let isLink = isLinkLocalIp(ip)
    let kind = classifyIpSubnet(ip)
    echo "  IP: ", ip.alignLeft(22), " -> Loopback: ", isLoop,
         " | LinkLocal: ", isLink, " | Classification: ", subnetDescription(kind)
  echo ""

  # 3. Carrier-Grade NAT, Multicast, ULA & Bogon Subnets (Item 04)
  echo "[3] Advanced Subnet & Topology Classification (CGNAT, Multicast, ULA, Bogon):"
  let specializedIps = [
    ("100.64.0.1", "Carrier-Grade NAT (RFC 6598)"),
    ("100.127.255.254", "CGNAT Upper Boundary"),
    ("224.0.0.1", "IPv4 Multicast Group"),
    ("ff02::1", "IPv6 Multicast All-Nodes"),
    ("fc00::1", "IPv6 Unique Local Address (ULA)"),
    ("fd12:3456:789a::1", "IPv6 ULA Global ID"),
    ("0.0.0.0", "Current Network / Default Route"),
    ("240.0.0.1", "Class E Reserved / Bogon"),
    ("255.255.255.255", "Limited Broadcast"),
    ("192.0.2.1", "TEST-NET-1 Documentation"),
    ("198.51.100.1", "TEST-NET-2 Documentation"),
    ("203.0.113.1", "TEST-NET-3 Documentation"),
    ("2001:db8::1", "IPv6 Documentation Prefix"),
    ("8.8.8.8", "Public Routable Internet Address")
  ]
  for (ip, label) in specializedIps:
    let kind = classifyIpSubnet(ip)
    let isPriv = isPrivateIp(ip)
    let isBogon = isBogonIp(ip)
    echo "  IP: ", ip.alignLeft(22), " -> ", subnetDescription(kind).alignLeft(28),
         " | Private: ", isPriv, " | Bogon: ", isBogon
  echo ""

  # 4. Distinct Local Traffic Markers & Badges (Item 03)
  echo "[4] Distinct Local / Internal Traffic Markers & Badges (Item 03):"
  let sampleInternal = ["127.0.0.1", "10.0.0.1", "172.16.5.1", "192.168.1.100", "169.254.1.1", "fe80::1"]
  echo "  " & "-".repeat(78)
  echo "  INTERNAL IP           | EMOJI MARKER             | DETAILED TOPOLOGY MARKER"
  echo "  " & "-".repeat(78)
  for ip in sampleInternal:
    let emojiMarker = formatLocalTrafficMarker(ip, useEmoji = true).alignLeft(24)
    let detailedMarker = formatLocalTrafficMarker(ip, useEmoji = true, detailed = true)
    echo "  ", ip.alignLeft(21), " | ", emojiMarker, " | ", detailedMarker
  echo "  " & "-".repeat(78)
  echo ""
  echo "  Fallback ASCII badges (for NO_EMOJI=1 / dumb terminals):"
  for ip in ["127.0.0.1", "192.168.1.1"]:
    echo "    ", ip.alignLeft(15), " -> ", formatLocalTrafficMarker(ip, useEmoji = false)
    echo "    ", ip.alignLeft(15), " -> ", formatPrivateIpBadge(ip, useEmoji = false)
  echo ""

  # 5. GeoIpEngine Integration (Zero DB Overhead for Local Traffic)
  echo "[5] GeoIpEngine Seamless Integration (Instant Resolution with Zero DB Lookups):"
  let engine = newGeoIpEngine()
  let queryIps = ["192.168.1.1", "10.1.2.3", "127.0.0.1", "8.8.8.8", "78.46.100.2"]
  for ip in queryIps:
    let loc = engine.lookup(ip)
    let badge = formatCountryBadge(loc.countryCode, true)
    echo "  IP: ", ip.alignLeft(16), " -> Badge: ", badge,
         " | Code: ", loc.countryCode, " | Private: ", loc.isPrivate,
         " | Name: ", loc.countryName
  echo ""
  echo "=== All Phase 03 Category C capabilities operational! ==="

when isMainModule:
  main()

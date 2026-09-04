## Bogon, private, and loopback IP subnet detection and classification module for http_logviewer.
## Implements RFC 1918 private IPv4 ranges, RFC 3927 link-local, RFC 1122 loopback,
## RFC 6598 carrier-grade NAT, RFC 4193 unique local addresses (ULA), and unroutable bogon ranges.

import std/[strutils, parseutils, options]
import ../core/types

type
  ## Classification of IP addresses by network topology and RFC allocation
  IpSubnetKind* = enum
    SubnetPublic,           ## Routable public internet address
    SubnetPrivateRfc1918,   ## RFC 1918 private address (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    SubnetLoopback,         ## Loopback address (127.0.0.0/8, ::1, localhost)
    SubnetLinkLocal,        ## Link-local autoconfiguration (169.254.0.0/16, fe80::/10)
    SubnetUniqueLocalIpv6,  ## IPv6 Unique Local Address (fc00::/7)
    SubnetCarrierGradeNat,  ## Carrier-Grade NAT / Shared Address Space (100.64.0.0/10, RFC 6598)
    SubnetMulticast,        ## Multicast address space (224.0.0.0/4, ff00::/8)
    SubnetBroadcast,        ## Limited broadcast (255.255.255.255)
    SubnetDocumentation,    ## Documentation and test networks (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32)
    SubnetBogonReserved,    ## Reserved for future use, current network, or IETF protocol (0.0.0.0/8, 240.0.0.0/4)
    SubnetInvalid           ## Malformed or unparseable IP address string

# ==============================================================================
# IP Address Parsing Utilities
# ==============================================================================

func stripIpv4MappedPrefix*(ip: string): string =
  ## Strips IPv4-mapped IPv6 prefix "::ffff:" if present.
  ## Example: "::ffff:192.168.1.1" -> "192.168.1.1".
  let s = ip.strip()
  let lower = s.toLowerAscii()
  if lower.startsWith("::ffff:") and s.len > 7:
    let candidate = s[7..^1]
    if candidate.find('.') >= 0:
      return candidate
  elif lower.startsWith("[::ffff:") and lower.endsWith("]"):
    let inner = s[8..^2]
    if inner.find('.') >= 0:
      return inner
  return s

func parseIpv4Octets*(ip: string, octets: var array[4, int]): bool =
  ## Parses standard IPv4 decimal dotted quad "A.B.C.D". Returns false if malformed.
  let cleaned = stripIpv4MappedPrefix(ip)
  var idx = 0
  for i in 0..3:
    var val = 0
    let parsed = parseutils.parseInt(cleaned, val, idx)
    if parsed <= 0 or val < 0 or val > 255:
      return false
    octets[i] = val
    idx += parsed
    if i < 3:
      if idx >= cleaned.len or cleaned[idx] != '.':
        return false
      inc idx
  return idx == cleaned.len

func parseIpv4ToUint32*(ip: string, ipNum: var uint32): bool =
  ## Converts an IPv4 string into a big-endian uint32.
  ## Handles IPv4-mapped IPv6 addresses (e.g. "::ffff:192.168.1.1").
  var octets: array[4, int]
  if not parseIpv4Octets(ip, octets):
    return false
  ipNum = (uint32(octets[0]) shl 24) or
          (uint32(octets[1]) shl 16) or
          (uint32(octets[2]) shl 8) or
          uint32(octets[3])
  return true

func parseIpv6ToBytes*(ip: string, bytes: var array[16, byte]): bool =
  ## Parses standard IPv6 hex representations including "::" shorthand.
  ## Also handles bracketed notations like `"[2001:db8::1]"`.
  var raw = ip.strip()
  if raw.startsWith('[') and raw.endsWith(']'):
    raw = raw[1..^2]

  let pctIdx = raw.find('%')
  if pctIdx >= 0:
    raw = raw[0..<pctIdx]

  if raw.len == 0 or raw.len > 45:
    return false

  # Check for embedded IPv4-mapped in full hex notation
  let lower = raw.toLowerAscii()
  if lower.startsWith("::ffff:") and raw.find('.') >= 0:
    let v4Part = raw[7..^1]
    var octets: array[4, int]
    if parseIpv4Octets(v4Part, octets):
      for i in 0..9: bytes[i] = 0'u8
      bytes[10] = 0xFF'u8
      bytes[11] = 0xFF'u8
      bytes[12] = byte(octets[0])
      bytes[13] = byte(octets[1])
      bytes[14] = byte(octets[2])
      bytes[15] = byte(octets[3])
      return true

  # Clear output bytes
  for i in 0..15: bytes[i] = 0'u8

  var parts = raw.split("::")
  if parts.len > 2:
    return false # Multiple "::" not allowed

  var headWords: seq[uint16] = @[]
  var tailWords: seq[uint16] = @[]

  if parts[0].len > 0:
    for token in parts[0].split(':'):
      if token.len == 0: return false
      var val: int
      if parseutils.parseHex(token, val) == 0 or val < 0 or val > 0xFFFF:
        return false
      headWords.add(uint16(val))

  if parts.len == 2 and parts[1].len > 0:
    for token in parts[1].split(':'):
      if token.len == 0: return false
      var val: int
      if parseutils.parseHex(token, val) == 0 or val < 0 or val > 0xFFFF:
        return false
      tailWords.add(uint16(val))

  let totalWords = headWords.len + tailWords.len
  if parts.len == 1:
    if totalWords != 8: return false
  else:
    if totalWords > 7: return false

  var fullWords: array[8, uint16]
  for i in 0..<headWords.len:
    fullWords[i] = headWords[i]

  let fillCount = 8 - totalWords
  for i in 0..<tailWords.len:
    fullWords[headWords.len + fillCount + i] = tailWords[i]

  for i in 0..7:
    bytes[i * 2] = byte((fullWords[i] shr 8) and 0xFF)
    bytes[i * 2 + 1] = byte(fullWords[i] and 0xFF)

  return true

# ==============================================================================
# Subnet & Topology Predicates
# ==============================================================================

func isRfc1918Private*(ip: string): bool =
  ## Checks whether the given IP address falls within the RFC 1918 private IPv4 ranges:
  ## - 10.0.0.0/8     (10.0.0.0 - 10.255.255.255)
  ## - 172.16.0.0/12  (172.16.0.0 - 172.31.255.255)
  ## - 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
  ## Also handles IPv4-mapped IPv6 notations (e.g. "::ffff:192.168.1.1").
  var ipNum: uint32
  if not parseIpv4ToUint32(ip, ipNum):
    return false

  # 10.0.0.0/8 (0x0A000000)
  if (ipNum and 0xFF000000'u32) == 0x0A000000'u32:
    return true
  # 172.16.0.0/12 (0xAC100000)
  if (ipNum and 0xFFF00000'u32) == 0xAC100000'u32:
    return true
  # 192.168.0.0/16 (0xC0A80000)
  if (ipNum and 0xFFFF0000'u32) == 0xC0A80000'u32:
    return true

  return false

func isRfc1918Ip*(ip: string): bool {.inline.} =
  ## Alias for `isRfc1918Private`.
  isRfc1918Private(ip)

func isLoopbackIp*(ip: string): bool =
  ## Checks whether the given IP address is a loopback address:
  ## - 127.0.0.0/8 IPv4 loopback (RFC 1122)
  ## - ::1 IPv6 loopback (RFC 4291)
  ## - "localhost" string alias
  ## - IPv4-mapped IPv6 loopback (::ffff:127.0.0.1)
  let cleaned = ip.strip()
  if cleaned.len == 0:
    return false

  let lower = cleaned.toLowerAscii()
  if lower == "localhost" or lower == "127.0.0.1" or lower == "::1":
    return true

  var ipNum: uint32
  if parseIpv4ToUint32(cleaned, ipNum):
    return (ipNum and 0xFF000000'u32) == 0x7F000000'u32

  var v6Bytes: array[16, byte]
  if parseIpv6ToBytes(cleaned, v6Bytes):
    var isZero = true
    for i in 0..14:
      if v6Bytes[i] != 0'u8: isZero = false
    return isZero and v6Bytes[15] == 1'u8

  return false

func isLinkLocalIp*(ip: string): bool =
  ## Checks whether the given IP address is a link-local address:
  ## - 169.254.0.0/16 IPv4 link-local (RFC 3927)
  ## - fe80::/10 IPv6 link-local unicast (RFC 4291)
  var ipNum: uint32
  if parseIpv4ToUint32(ip, ipNum):
    return (ipNum and 0xFFFF0000'u32) == 0xA9FE0000'u32

  var v6Bytes: array[16, byte]
  if parseIpv6ToBytes(ip, v6Bytes):
    # fe80::/10 -> first byte is 0xFE, top 2 bits of second byte are 10 (0x80)
    return v6Bytes[0] == 0xFE'u8 and (v6Bytes[1] and 0xC0'u8) == 0x80'u8

  return false

func isUniqueLocalIp*(ip: string): bool =
  ## Checks whether the given IPv6 address is a Unique Local Address (ULA):
  ## - fc00::/7 (RFC 4193, covers fc00::/8 and fd00::/8)
  var v6Bytes: array[16, byte]
  if parseIpv6ToBytes(ip, v6Bytes):
    return (v6Bytes[0] and 0xFE'u8) == 0xFC'u8
  return false

func isCgnatIp*(ip: string): bool =
  ## Checks whether the given IP address belongs to Carrier-Grade NAT (CGNAT) / Shared Address Space:
  ## - 100.64.0.0/10 (RFC 6598, 100.64.0.0 - 100.127.255.255)
  var ipNum: uint32
  if parseIpv4ToUint32(ip, ipNum):
    return (ipNum and 0xFFC00000'u32) == 0x64400000'u32
  return false

func isMulticastIp*(ip: string): bool =
  ## Checks whether the given IP address is a multicast address:
  ## - 224.0.0.0/4 IPv4 multicast (RFC 5771)
  ## - ff00::/8 IPv6 multicast (RFC 4291)
  var ipNum: uint32
  if parseIpv4ToUint32(ip, ipNum):
    return (ipNum and 0xF0000000'u32) == 0xE0000000'u32

  var v6Bytes: array[16, byte]
  if parseIpv6ToBytes(ip, v6Bytes):
    return v6Bytes[0] == 0xFF'u8

  return false

func isDocumentationIp*(ip: string): bool =
  ## Checks whether the given IP address is allocated for documentation or testing (RFC 5737, RFC 3849):
  ## - 192.0.2.0/24 (TEST-NET-1)
  ## - 198.51.100.0/24 (TEST-NET-2)
  ## - 203.0.113.0/24 (TEST-NET-3)
  ## - 2001:db8::/32 (IPv6 Documentation)
  var ipNum: uint32
  if parseIpv4ToUint32(ip, ipNum):
    # 192.0.2.0/24 (0xC0000200)
    if (ipNum and 0xFFFFFF00'u32) == 0xC0000200'u32: return true
    # 198.51.100.0/24 (0xC6336400)
    if (ipNum and 0xFFFFFF00'u32) == 0xC6336400'u32: return true
    # 203.0.113.0/24 (0xCB007100)
    if (ipNum and 0xFFFFFF00'u32) == 0xCB007100'u32: return true
    return false

  var v6Bytes: array[16, byte]
  if parseIpv6ToBytes(ip, v6Bytes):
    # 2001:0db8::/32 -> bytes[0..3] == [0x20, 0x01, 0x0D, 0xB8]
    return v6Bytes[0] == 0x20'u8 and v6Bytes[1] == 0x01'u8 and
           v6Bytes[2] == 0x0D'u8 and v6Bytes[3] == 0xB8'u8

  return false

func isBogonIp*(ip: string): bool =
  ## Checks whether the given IP address is a bogon, reserved, or unroutable address:
  ## Includes current network (0.0.0.0/8), broadcast (255.255.255.255), reserved (240.0.0.0/4),
  ## documentation networks (TEST-NET-1/2/3, 2001:db8::/32), benchmarking (198.18.0.0/15, 2001:2::/48),
  ## 6to4 relay anycast (192.88.99.0/24), or IPv6 unspecified (::/128).
  let cleaned = ip.strip()
  if cleaned.len == 0:
    return true

  if cleaned == "::" or cleaned == "0.0.0.0":
    return true

  var ipNum: uint32
  if parseIpv4ToUint32(cleaned, ipNum):
    # 0.0.0.0/8 Current network
    if (ipNum and 0xFF000000'u32) == 0x00000000'u32: return true
    # 192.88.99.0/24 6to4 Relay Anycast (RFC 3068 / RFC 7526)
    if (ipNum and 0xFFFFFF00'u32) == 0xC0586300'u32: return true
    # 198.18.0.0/15 Benchmarking (RFC 2544)
    if (ipNum and 0xFFFE0000'u32) == 0xC6120000'u32: return true
    # Documentation ranges
    if isDocumentationIp(cleaned): return true
    # 240.0.0.0/4 Reserved (Class E)
    if (ipNum and 0xF0000000'u32) == 0xF0000000'u32: return true
    # 255.255.255.255 Broadcast
    if ipNum == 0xFFFFFFFF'u32: return true
    return false

  var v6Bytes: array[16, byte]
  if parseIpv6ToBytes(cleaned, v6Bytes):
    # ::/128 Unspecified
    var isAllZero = true
    for b in v6Bytes:
      if b != 0'u8: isAllZero = false
    if isAllZero: return true

    # 100::/64 Discard-only (RFC 6666)
    if v6Bytes[0] == 0x01'u8 and v6Bytes[1] == 0x00'u8:
      var restZero = true
      for i in 2..7:
        if v6Bytes[i] != 0'u8: restZero = false
      if restZero: return true

    # 2001:2::/48 Benchmarking
    if v6Bytes[0] == 0x20'u8 and v6Bytes[1] == 0x01'u8 and
       v6Bytes[2] == 0x00'u8 and v6Bytes[3] == 0x02'u8 and
       v6Bytes[4] == 0x00'u8 and v6Bytes[5] == 0x00'u8:
      return true

    # Documentation 2001:db8::/32
    if isDocumentationIp(cleaned): return true

  return false

func isPrivateIp*(ip: string): bool =
  ## Returns true if the IP belongs to RFC 1918 private ranges, Loopback, Link-Local,
  ## Carrier-Grade NAT (CGNAT), IPv6 Unique Local (ULA), Multicast, Broadcast, or Bogon reserved subnets.
  let cleaned = ip.strip()
  if cleaned.len == 0:
    return false

  let lower = cleaned.toLowerAscii()
  if lower == "localhost" or lower == "127.0.0.1" or lower == "::1" or lower == "::":
    return true

  if isRfc1918Private(cleaned):
    return true
  if isLoopbackIp(cleaned):
    return true
  if isLinkLocalIp(cleaned):
    return true
  if isCgnatIp(cleaned):
    return true
  if isUniqueLocalIp(cleaned):
    return true
  if isMulticastIp(cleaned):
    return true

  # Check bogon unroutable ranges (0.0.0.0/8, 240.0.0.0/4, 255.255.255.255)
  var ipNum: uint32
  if parseIpv4ToUint32(cleaned, ipNum):
    # 0.0.0.0/8
    if (ipNum and 0xFF000000'u32) == 0x00000000'u32: return true
    # 240.0.0.0/4 Reserved
    if (ipNum and 0xF0000000'u32) == 0xF0000000'u32: return true
    # Broadcast
    if ipNum == 0xFFFFFFFF'u32: return true

  return false

# ==============================================================================
# Comprehensive IP Subnet Classifier
# ==============================================================================

func classifyIpSubnet*(ip: string): IpSubnetKind =
  ## Classifies an IP address into its architectural subnet allocation kind.
  let cleaned = ip.strip()
  if cleaned.len == 0:
    return SubnetInvalid

  var ipNum: uint32
  let isV4 = parseIpv4ToUint32(cleaned, ipNum)
  var v6Bytes: array[16, byte]
  let isV6 = if not isV4: parseIpv6ToBytes(cleaned, v6Bytes) else: false

  if not isV4 and not isV6:
    if cleaned.toLowerAscii() == "localhost":
      return SubnetLoopback
    return SubnetInvalid

  if isLoopbackIp(cleaned):
    return SubnetLoopback
  if isRfc1918Private(cleaned):
    return SubnetPrivateRfc1918
  if isLinkLocalIp(cleaned):
    return SubnetLinkLocal
  if isCgnatIp(cleaned):
    return SubnetCarrierGradeNat
  if isUniqueLocalIp(cleaned):
    return SubnetUniqueLocalIpv6
  if isMulticastIp(cleaned):
    return SubnetMulticast
  if isV4 and ipNum == 0xFFFFFFFF'u32:
    return SubnetBroadcast
  if isDocumentationIp(cleaned):
    return SubnetDocumentation
  if isBogonIp(cleaned):
    return SubnetBogonReserved

  return SubnetPublic

func subnetDescription*(kind: IpSubnetKind): string =
  ## Returns human-readable description for an IP subnet kind.
  case kind
  of SubnetPublic: "Public Internet"
  of SubnetPrivateRfc1918: "RFC 1918 Private LAN"
  of SubnetLoopback: "Loopback / Host"
  of SubnetLinkLocal: "Link-Local / Autoconf"
  of SubnetUniqueLocalIpv6: "IPv6 Unique Local (ULA)"
  of SubnetCarrierGradeNat: "Carrier-Grade NAT (CGNAT)"
  of SubnetMulticast: "Multicast Group"
  of SubnetBroadcast: "Limited Broadcast"
  of SubnetDocumentation: "Documentation / Test Net"
  of SubnetBogonReserved: "Reserved / Bogon Range"
  of SubnetInvalid: "Invalid IP Address"

func makePrivateLocation*(ip: string): GeoLocation =
  ## Returns standard GeoLocation representing a private, local, or loopback IP.
  ## Displays distinct icon `🏠` and `Local / Private LAN` description as specified in Phase 03.
  initGeoLocation(
    ip = ip,
    countryCode = "LO",
    countryName = "Local / Private Network",
    flagEmoji = "🏠",
    isPrivate = true
  )

func makeUnknownLocation*(ip: string): GeoLocation =
  ## Returns standard GeoLocation for unmapped or unknown public IPs.
  initGeoLocation(
    ip = ip,
    countryCode = "XX",
    countryName = "Unknown Country",
    flagEmoji = "🌐",
    isPrivate = false
  )

func formatPrivateIpBadge*(ip: string, useEmoji: bool = true): string =
  ## Formats a private IP into a distinct marker badge suitable for terminal display.
  ## Example: "🏠 Local / Private LAN" or `"[LAN] Local / Private LAN"`.
  if useEmoji:
    "🏠 Local / Private LAN"
  else:
    "[LAN] Local / Private LAN"

func formatLocalTrafficMarker*(ip: string, useEmoji: bool = true, detailed: bool = false): string =
  ## Formats a distinct marker and icon for local/internal traffic.
  ## Standard marker: "🏠 Local / Private LAN" (or `"[LAN] Local / Private LAN"`).
  ## Detailed marker: "🏠 Local / Private LAN (RFC 1918 Private LAN)".
  let icon = if useEmoji: "🏠 " else: "[LAN] "
  if detailed:
    let kind = classifyIpSubnet(ip)
    icon & "Local / Private LAN (" & subnetDescription(kind) & ")"
  else:
    icon & "Local / Private LAN"

func makeEnrichedPrivateLocation*(ip: string): GeoLocation =
  ## Returns standard GeoLocation representing a private, local, or loopback IP,
  ## annotating the specific subnet kind in the city field.
  let kind = classifyIpSubnet(ip)
  initGeoLocation(
    ip = ip,
    countryCode = "LO",
    countryName = "Local / Private Network",
    flagEmoji = "🏠",
    isPrivate = true,
    city = some(subnetDescription(kind))
  )

## Geolocation and metadata enrichment module for http_logviewer.
## Provides GeoIpProvider interface, offline MaxMind MMDB parser,
## fallback offline CIDR-to-Country database, LRU memory cache, and automatic database discovery.

import std/[strutils, os, tables, options]
import ../core/[types, errors]
import flags, bogon

export flags
export bogon

# ==============================================================================
# GeoIpProvider Interface (Phase 03 / Category A / Item 01)
# ==============================================================================

type
  GeoIpProvider* = ref object of RootObj
    ## Abstract base class defining the GeoIP provider interface.

method lookup*(provider: GeoIpProvider, ip: string): GeoLocation {.base.} =
  ## Resolves the given IP address string into a GeoLocation record.
  ## Base implementation handles private IPs and defaults to Unknown.
  if isPrivateIp(ip):
    return makePrivateLocation(ip)
  return makeUnknownLocation(ip)

# ==============================================================================
# Fallback CIDR-to-Country Lookup Engine (Phase 03 / Category A / Item 03)
# ==============================================================================

type
  Ipv4CidrRange = object
    network: uint32
    mask: uint32
    countryCode: string
    countryName: string

  Ipv6CidrRange = object
    network: array[16, byte]
    prefixLen: int
    countryCode: string
    countryName: string

  CidrGeoIpProvider* = ref object of GeoIpProvider
    ipv4Ranges: seq[Ipv4CidrRange]
    ipv6Ranges: seq[Ipv6CidrRange]

proc cidrMask(prefix: int): uint32 =
  if prefix <= 0: 0'u32
  elif prefix >= 32: 0xFFFFFFFF'u32
  else: not ((1'u32 shl uint32(32 - prefix)) - 1'u32)

proc addIpv4Cidr*(p: CidrGeoIpProvider, cidrStr: string, code: string, name: string = "") =
  let slashIdx = cidrStr.find('/')
  var ipPart = cidrStr
  var prefix = 32
  if slashIdx >= 0:
    ipPart = cidrStr[0 ..< slashIdx]
    prefix = parseInt(cidrStr[(slashIdx + 1) .. ^1])
  var ipNum: uint32
  if parseIpv4ToUint32(ipPart, ipNum):
    let mask = cidrMask(prefix)
    let net = ipNum and mask
    let countryName = if name.len > 0: name else: getCountryName(code)
    p.ipv4Ranges.add(Ipv4CidrRange(network: net, mask: mask, countryCode: code, countryName: countryName))

proc addIpv6Cidr*(p: CidrGeoIpProvider, cidrStr: string, code: string, name: string = "") =
  let slashIdx = cidrStr.find('/')
  var ipPart = cidrStr
  var prefix = 128
  if slashIdx >= 0:
    ipPart = cidrStr[0 ..< slashIdx]
    prefix = parseInt(cidrStr[(slashIdx + 1) .. ^1])
  var bytes: array[16, byte]
  if parseIpv6ToBytes(ipPart, bytes):
    let countryName = if name.len > 0: name else: getCountryName(code)
    p.ipv6Ranges.add(Ipv6CidrRange(network: bytes, prefixLen: prefix, countryCode: code, countryName: countryName))

proc newCidrGeoIpProvider*(): CidrGeoIpProvider =
  ## Initializes a CidrGeoIpProvider populated with major public IP ranges
  ## (Google, Cloudflare, Quad9, AWS, Azure, Hetzner, OVH, DigitalOcean, CN, NL, RU, JP, etc.).
  result = CidrGeoIpProvider(ipv4Ranges: @[], ipv6Ranges: @[])

  # Google
  result.addIpv4Cidr("8.8.8.0/24", "US", "United States")
  result.addIpv4Cidr("8.8.4.0/24", "US", "United States")
  result.addIpv4Cidr("34.64.0.0/11", "US", "United States")
  result.addIpv4Cidr("35.184.0.0/13", "US", "United States")
  result.addIpv4Cidr("172.217.0.0/16", "US", "United States")
  result.addIpv4Cidr("142.250.0.0/15", "US", "United States")
  result.addIpv4Cidr("216.58.192.0/19", "US", "United States")
  result.addIpv6Cidr("2001:4860::/32", "US", "United States")
  result.addIpv6Cidr("2a00:1450::/32", "US", "United States")

  # Cloudflare
  result.addIpv4Cidr("1.1.1.0/24", "US", "United States")
  result.addIpv4Cidr("1.0.0.0/24", "US", "United States")
  result.addIpv4Cidr("104.16.0.0/12", "US", "United States")
  result.addIpv4Cidr("104.24.0.0/14", "US", "United States")
  result.addIpv4Cidr("172.64.0.0/13", "US", "United States")
  result.addIpv4Cidr("162.158.0.0/15", "US", "United States")
  result.addIpv6Cidr("2606:4700::/32", "US", "United States")
  result.addIpv6Cidr("2400:cb00::/32", "US", "United States")

  # Quad9 & OpenDNS
  result.addIpv4Cidr("9.9.9.0/24", "US", "United States")
  result.addIpv4Cidr("149.112.112.0/24", "US", "United States")
  result.addIpv4Cidr("208.67.220.0/22", "US", "United States")
  result.addIpv4Cidr("208.67.222.0/22", "US", "United States")

  # Amazon Web Services (AWS)
  result.addIpv4Cidr("52.0.0.0/11", "US", "United States")
  result.addIpv4Cidr("54.0.0.0/12", "US", "United States")
  result.addIpv4Cidr("3.0.0.0/9", "US", "United States")
  result.addIpv4Cidr("18.128.0.0/9", "US", "United States")
  result.addIpv4Cidr("44.192.0.0/10", "US", "United States")

  # Microsoft Azure
  result.addIpv4Cidr("13.64.0.0/11", "US", "United States")
  result.addIpv4Cidr("20.0.0.0/11", "US", "United States")
  result.addIpv4Cidr("40.74.0.0/15", "US", "United States")
  result.addIpv4Cidr("52.96.0.0/12", "US", "United States")

  # DigitalOcean
  result.addIpv4Cidr("104.131.0.0/16", "US", "United States")
  result.addIpv4Cidr("138.68.0.0/16", "US", "United States")
  result.addIpv4Cidr("159.89.0.0/16", "US", "United States")
  result.addIpv4Cidr("165.22.0.0/16", "US", "United States")
  result.addIpv4Cidr("167.99.0.0/16", "US", "United States")
  result.addIpv4Cidr("206.189.0.0/16", "US", "United States")
  result.addIpv6Cidr("2400:6180::/32", "US", "United States")

  # Hetzner & Germany
  result.addIpv4Cidr("78.46.0.0/15", "DE", "Germany")
  result.addIpv4Cidr("88.198.0.0/16", "DE", "Germany")
  result.addIpv4Cidr("136.243.0.0/16", "DE", "Germany")
  result.addIpv4Cidr("144.76.0.0/16", "DE", "Germany")
  result.addIpv4Cidr("159.69.0.0/16", "DE", "Germany")
  result.addIpv4Cidr("168.119.0.0/16", "DE", "Germany")
  result.addIpv4Cidr("194.26.29.0/24", "DE", "Germany")
  result.addIpv4Cidr("195.201.0.0/16", "DE", "Germany")
  result.addIpv6Cidr("2a01:4f8::/32", "DE", "Germany")

  # OVH (France)
  result.addIpv4Cidr("51.254.0.0/15", "FR", "France")
  result.addIpv4Cidr("178.32.0.0/15", "FR", "France")
  result.addIpv4Cidr("188.165.0.0/16", "FR", "France")
  result.addIpv4Cidr("198.27.64.0/18", "FR", "France")
  result.addIpv4Cidr("217.182.0.0/16", "FR", "France")
  result.addIpv6Cidr("2001:41d0::/32", "FR", "France")

  # Netherlands (NL)
  result.addIpv4Cidr("45.154.255.0/24", "NL", "Netherlands")
  result.addIpv4Cidr("82.168.0.0/14", "NL", "Netherlands")
  result.addIpv4Cidr("84.80.0.0/13", "NL", "Netherlands")
  result.addIpv4Cidr("86.80.0.0/12", "NL", "Netherlands")
  result.addIpv4Cidr("145.0.0.0/16", "NL", "Netherlands")
  result.addIpv4Cidr("185.220.101.0/24", "NL", "Netherlands")
  result.addIpv6Cidr("2001:67c::/32", "NL", "Netherlands")

  # United Kingdom (GB)
  result.addIpv4Cidr("81.128.0.0/11", "GB", "United Kingdom")
  result.addIpv4Cidr("82.0.0.0/11", "GB", "United Kingdom")
  result.addIpv4Cidr("86.0.0.0/12", "GB", "United Kingdom")

  # China (CN)
  result.addIpv4Cidr("1.2.0.0/16", "CN", "China")
  result.addIpv4Cidr("14.128.0.0/10", "CN", "China")
  result.addIpv4Cidr("27.0.0.0/12", "CN", "China")
  result.addIpv4Cidr("114.114.114.0/24", "CN", "China")
  result.addIpv4Cidr("202.96.0.0/12", "CN", "China")
  result.addIpv4Cidr("220.181.0.0/16", "CN", "China")

  # Russian Federation (RU)
  result.addIpv4Cidr("87.250.250.0/24", "RU", "Russian Federation")
  result.addIpv4Cidr("93.158.134.0/24", "RU", "Russian Federation")
  result.addIpv4Cidr("178.154.131.0/24", "RU", "Russian Federation")
  result.addIpv4Cidr("193.32.161.0/24", "RU", "Russian Federation")
  result.addIpv4Cidr("213.180.193.0/24", "RU", "Russian Federation")
  result.addIpv6Cidr("2a02:6b8::/32", "RU", "Russian Federation")

  # Japan (JP)
  result.addIpv4Cidr("133.0.0.0/10", "JP", "Japan")
  result.addIpv4Cidr("150.0.0.0/10", "JP", "Japan")
  result.addIpv4Cidr("163.0.0.0/10", "JP", "Japan")
  result.addIpv4Cidr("210.140.0.0/16", "JP", "Japan")
  result.addIpv6Cidr("2400:8900::/32", "JP", "Japan")

  # Brazil (BR)
  result.addIpv4Cidr("177.0.0.0/11", "BR", "Brazil")
  result.addIpv4Cidr("186.192.0.0/11", "BR", "Brazil")
  result.addIpv4Cidr("191.160.0.0/11", "BR", "Brazil")

  # India (IN)
  result.addIpv4Cidr("103.0.0.0/10", "IN", "India")
  result.addIpv4Cidr("117.192.0.0/10", "IN", "India")
  result.addIpv4Cidr("122.160.0.0/11", "IN", "India")

  # Australia (AU)
  result.addIpv4Cidr("139.130.0.0/16", "AU", "Australia")
  result.addIpv4Cidr("144.130.0.0/15", "AU", "Australia")
  result.addIpv4Cidr("203.0.0.0/11", "AU", "Australia")

  # Canada (CA)
  result.addIpv4Cidr("142.150.0.0/16", "CA", "Canada")
  result.addIpv4Cidr("198.168.0.0/16", "CA", "Canada")
  result.addIpv4Cidr("24.222.0.0/15", "CA", "Canada")

method lookup*(provider: CidrGeoIpProvider, ip: string): GeoLocation =
  ## Queries the embedded CIDR database. Returns enriched GeoLocation or Unknown.
  if isPrivateIp(ip):
    return makePrivateLocation(ip)

  var ipNum: uint32
  if parseIpv4ToUint32(ip, ipNum):
    for entry in provider.ipv4Ranges:
      if (ipNum and entry.mask) == entry.network:
        return initGeoLocation(
          ip = ip,
          countryCode = entry.countryCode,
          countryName = entry.countryName,
          flagEmoji = isoToFlagEmoji(entry.countryCode),
          isPrivate = false
        )
    return makeUnknownLocation(ip)

  var v6Bytes: array[16, byte]
  if parseIpv6ToBytes(ip, v6Bytes):
    for entry in provider.ipv6Ranges:
      var matches = true
      let fullBytes = entry.prefixLen div 8
      let remBits = entry.prefixLen mod 8
      for i in 0..<fullBytes:
        if v6Bytes[i] != entry.network[i]:
          matches = false
          break
      if matches and remBits > 0 and fullBytes < 16:
        let mask = byte(0xFF'u8 shl uint32(8 - remBits))
        if (v6Bytes[fullBytes] and mask) != (entry.network[fullBytes] and mask):
          matches = false
      if matches:
        return initGeoLocation(
          ip = ip,
          countryCode = entry.countryCode,
          countryName = entry.countryName,
          flagEmoji = isoToFlagEmoji(entry.countryCode),
          isPrivate = false
        )
    return makeUnknownLocation(ip)

  return makeUnknownLocation(ip)

# ==============================================================================
# Pure Nim MaxMind MMDB Binary Parser (Phase 03 / Category A / Item 02)
# ==============================================================================

type
  MmdbValueKind* = enum
    mvkNone, mvkString, mvkInt, mvkFloat, mvkBool, mvkMap, mvkArray

  MmdbValue* = ref object
    case kind*: MmdbValueKind
    of mvkNone: discard
    of mvkString: strVal*: string
    of mvkInt: intVal*: int64
    of mvkFloat: floatVal*: float64
    of mvkBool: boolVal*: bool
    of mvkMap: mapVal*: Table[string, MmdbValue]
    of mvkArray: arrVal*: seq[MmdbValue]

proc getStr*(v: MmdbValue, defaultVal: string = ""): string =
  if v != nil:
    case v.kind
    of mvkString: return v.strVal
    else: return defaultVal
  return defaultVal

proc getInt*(v: MmdbValue, defaultVal: int64 = 0): int64 =
  if v != nil:
    case v.kind
    of mvkInt: return v.intVal
    else: return defaultVal
  return defaultVal

proc hasKey*(v: MmdbValue, key: string): bool =
  if v != nil:
    case v.kind
    of mvkMap: return v.mapVal.hasKey(key)
    else: return false
  return false

proc `[]`*(v: MmdbValue, key: string): MmdbValue =
  if v != nil:
    case v.kind
    of mvkMap:
      if v.mapVal.hasKey(key):
        return v.mapVal[key]
    else: discard
  return nil


type
  MmdbGeoIpProvider* = ref object of GeoIpProvider
    filePath*: string
    data: string
    nodeCount*: int
    recordSize*: int
    ipVersion*: int
    databaseType*: string
    nodeByteSize*: int
    treeSize*: int
    dataSectionStart*: int
    metadataStart*: int
    ipv4StartNode*: int
    fallbackCidr*: CidrGeoIpProvider

proc readNode(p: MmdbGeoIpProvider, nodeIndex: int, isRight: bool): int =
  let nodeOffset = nodeIndex * p.nodeByteSize
  case p.recordSize
  of 24:
    if not isRight:
      let b0 = ord(p.data[nodeOffset])
      let b1 = ord(p.data[nodeOffset + 1])
      let b2 = ord(p.data[nodeOffset + 2])
      result = (b0 shl 16) or (b1 shl 8) or b2
    else:
      let b3 = ord(p.data[nodeOffset + 3])
      let b4 = ord(p.data[nodeOffset + 4])
      let b5 = ord(p.data[nodeOffset + 5])
      result = (b3 shl 16) or (b4 shl 8) or b5
  of 28:
    let b0 = ord(p.data[nodeOffset])
    let b1 = ord(p.data[nodeOffset + 1])
    let b2 = ord(p.data[nodeOffset + 2])
    let b3 = ord(p.data[nodeOffset + 3])
    let b4 = ord(p.data[nodeOffset + 4])
    let b5 = ord(p.data[nodeOffset + 5])
    let b6 = ord(p.data[nodeOffset + 6])
    if not isRight:
      result = ((b3 and 0xF0) shl 20) or (b0 shl 16) or (b1 shl 8) or b2
    else:
      result = ((b3 and 0x0F) shl 24) or (b4 shl 16) or (b5 shl 8) or b6
  of 32:
    if not isRight:
      let b0 = ord(p.data[nodeOffset])
      let b1 = ord(p.data[nodeOffset + 1])
      let b2 = ord(p.data[nodeOffset + 2])
      let b3 = ord(p.data[nodeOffset + 3])
      result = (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
    else:
      let b4 = ord(p.data[nodeOffset + 4])
      let b5 = ord(p.data[nodeOffset + 5])
      let b6 = ord(p.data[nodeOffset + 6])
      let b7 = ord(p.data[nodeOffset + 7])
      result = (b4 shl 24) or (b5 shl 16) or (b6 shl 8) or b7
  else:
    result = 0

proc decodeValue(p: MmdbGeoIpProvider, offset: var int): MmdbValue =
  if offset >= p.data.len:
    return MmdbValue(kind: mvkNone)

  let ctrl = ord(p.data[offset])
  inc offset
  let rawType = (ctrl shr 5) and 0x07

  if rawType == 1: # Pointer
    let ptrSize = (ctrl shr 3) and 0x03
    let valBits = ctrl and 0x07
    var ptrOffset = 0
    case ptrSize
    of 0:
      if offset >= p.data.len: return MmdbValue(kind: mvkNone)
      let b = ord(p.data[offset])
      inc offset
      ptrOffset = (valBits shl 8) or b
    of 1:
      if offset + 1 >= p.data.len: return MmdbValue(kind: mvkNone)
      let b0 = ord(p.data[offset])
      let b1 = ord(p.data[offset + 1])
      offset += 2
      ptrOffset = 2048 + (valBits shl 16) or (b0 shl 8) or b1
    of 2:
      if offset + 2 >= p.data.len: return MmdbValue(kind: mvkNone)
      let b0 = ord(p.data[offset])
      let b1 = ord(p.data[offset + 1])
      let b2 = ord(p.data[offset + 2])
      offset += 3
      ptrOffset = 2048 + 524288 + (valBits shl 24) or (b0 shl 16) or (b1 shl 8) or b2
    of 3:
      if offset + 3 >= p.data.len: return MmdbValue(kind: mvkNone)
      let b0 = ord(p.data[offset])
      let b1 = ord(p.data[offset + 1])
      let b2 = ord(p.data[offset + 2])
      let b3 = ord(p.data[offset + 3])
      offset += 4
      ptrOffset = (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
    else: discard
    var target = p.dataSectionStart + ptrOffset
    return p.decodeValue(target)

  var typeNum = rawType
  var size = ctrl and 0x1F
  if typeNum == 0:
    if offset >= p.data.len: return MmdbValue(kind: mvkNone)
    typeNum = ord(p.data[offset]) + 7
    inc offset

  if size == 29:
    if offset >= p.data.len: return MmdbValue(kind: mvkNone)
    size = 29 + ord(p.data[offset])
    inc offset
  elif size == 30:
    if offset + 1 >= p.data.len: return MmdbValue(kind: mvkNone)
    let b0 = ord(p.data[offset])
    let b1 = ord(p.data[offset + 1])
    offset += 2
    size = 285 + (b0 shl 8) or b1
  elif size == 31:
    if offset + 2 >= p.data.len: return MmdbValue(kind: mvkNone)
    let b0 = ord(p.data[offset])
    let b1 = ord(p.data[offset + 1])
    let b2 = ord(p.data[offset + 2])
    offset += 3
    size = 65821 + (b0 shl 16) or (b1 shl 8) or b2

  case typeNum
  of 2, 4: # String or bytes
    if offset + size > p.data.len: return MmdbValue(kind: mvkNone)
    let s = p.data[offset ..< (offset + size)]
    offset += size
    return MmdbValue(kind: mvkString, strVal: s)
  of 3: # Double
    offset += min(size, 8)
    return MmdbValue(kind: mvkFloat, floatVal: 0.0)
  of 5, 6, 8, 9: # Integers
    var num = 0'i64
    for i in 0..<size:
      if offset + i < p.data.len:
        num = (num shl 8) or int64(ord(p.data[offset + i]))
    offset += size
    return MmdbValue(kind: mvkInt, intVal: num)
  of 7: # Map
    var tbl = initTable[string, MmdbValue]()
    for _ in 0..<size:
      let keyVal = p.decodeValue(offset)
      let val = p.decodeValue(offset)
      let keyStr = keyVal.getStr()
      if keyStr.len > 0:
        tbl[keyStr] = val
    return MmdbValue(kind: mvkMap, mapVal: tbl)
  of 11: # Array
    var arr = newSeq[MmdbValue](size)
    for i in 0..<size:
      arr[i] = p.decodeValue(offset)
    return MmdbValue(kind: mvkArray, arrVal: arr)
  of 14: # Boolean
    return MmdbValue(kind: mvkBool, boolVal: (size != 0))
  else:
    offset += size
    return MmdbValue(kind: mvkNone)

proc parseMmdbBinary*(raw: string, filePath: string = ""): MmdbGeoIpProvider =
  ## Parses in-memory MMDB binary data. Raises GeoIpError on format violation.
  let marker = "\xAB\xCD\xEFMaxMind.com"
  let idx = raw.rfind(marker)
  if idx < 0:
    raise newException(GeoIpError, "Invalid MaxMind DB format: metadata marker not found")

  let provider = MmdbGeoIpProvider(
    filePath: filePath,
    data: raw,
    metadataStart: idx + marker.len,
    fallbackCidr: newCidrGeoIpProvider()
  )

  var metaOffset = provider.metadataStart
  provider.dataSectionStart = 0
  let metaVal = provider.decodeValue(metaOffset)
  if metaVal.kind != mvkMap:
    raise newException(GeoIpError, "Invalid MaxMind DB metadata structure")

  if metaVal.hasKey("node_count"):
    provider.nodeCount = int(metaVal["node_count"].getInt())
  if metaVal.hasKey("record_size"):
    provider.recordSize = int(metaVal["record_size"].getInt())
  if metaVal.hasKey("ip_version"):
    provider.ipVersion = int(metaVal["ip_version"].getInt())
  if metaVal.hasKey("database_type"):
    provider.databaseType = metaVal["database_type"].getStr()

  if provider.recordSize notin [24, 28, 32]:
    raise newException(GeoIpError, "Unsupported MMDB record size: " & $provider.recordSize)

  provider.nodeByteSize = (provider.recordSize * 2) div 8
  provider.treeSize = provider.nodeCount * provider.nodeByteSize
  provider.dataSectionStart = provider.treeSize + 16

  if provider.dataSectionStart > provider.data.len:
    raise newException(GeoIpError, "Corrupt MMDB: tree size exceeds file bounds")

  # Calculate IPv4 start node for IPv6 trees by traversing 96 zero bits
  provider.ipv4StartNode = 0
  if provider.ipVersion == 6:
    var node = 0
    for _ in 0..<96:
      let nextNode = provider.readNode(node, false)
      if nextNode >= provider.nodeCount:
        break
      node = nextNode
    provider.ipv4StartNode = node

  return provider

proc openMmdbFile*(filePath: string): MmdbGeoIpProvider =
  ## Opens an MMDB file from disk and initializes an MmdbGeoIpProvider.
  if not fileExists(filePath):
    raise newException(GeoIpError, "GeoIP MMDB database file not found: " & filePath)
  try:
    let content = readFile(filePath)
    result = parseMmdbBinary(content, filePath)
  except CatchableError as e:
    raise newException(GeoIpError, "Failed to open or parse MMDB database " & filePath & ": " & e.msg)

proc lookupDataRecord(p: MmdbGeoIpProvider, bits: openArray[int], startNode: int = 0): Option[MmdbValue] =
  var node = startNode
  for b in bits:
    let isRight = (b == 1)
    let nextVal = p.readNode(node, isRight)
    if nextVal < p.nodeCount:
      node = nextVal
    elif nextVal == p.nodeCount:
      return none(MmdbValue)
    else:
      let dataOffset = nextVal - p.nodeCount - 16
      var offset = p.dataSectionStart + dataOffset
      let val = p.decodeValue(offset)
      return some(val)
  return none(MmdbValue)

proc extractCountryIso(val: MmdbValue): string =
  ## Traverses MMDB data map extracting ISO country code from country/registered_country maps.
  if val == nil: return ""
  if val.hasKey("country"):
    let c = val["country"]
    if c.hasKey("iso_code"):
      return c["iso_code"].getStr()
  if val.hasKey("registered_country"):
    let c = val["registered_country"]
    if c.hasKey("iso_code"):
      return c["iso_code"].getStr()
  if val.hasKey("represented_country"):
    let c = val["represented_country"]
    if c.hasKey("iso_code"):
      return c["iso_code"].getStr()
  if val.hasKey("iso_code"):
    return val["iso_code"].getStr()
  return ""

proc extractCityName(val: MmdbValue): Option[string] =
  ## Extracts city name in English if present in MMDB record.
  if val != nil and val.hasKey("city"):
    let c = val["city"]
    if c.hasKey("names"):
      let names = c["names"]
      if names.hasKey("en"):
        return some(names["en"].getStr())
  return none(string)

method lookup*(provider: MmdbGeoIpProvider, ip: string): GeoLocation =
  ## Queries the binary MMDB tree for the given IP address, with fallback to CIDR table.
  if isPrivateIp(ip):
    return makePrivateLocation(ip)

  var ipNum: uint32
  if parseIpv4ToUint32(ip, ipNum):
    var bits: array[32, int]
    for i in 0..31:
      bits[i] = int((ipNum shr (31 - i)) and 1'u32)

    let startNode = if provider.ipVersion == 6: provider.ipv4StartNode else: 0
    let recOpt = provider.lookupDataRecord(bits, startNode)
    if recOpt.isSome:
      let iso = extractCountryIso(recOpt.get())
      if iso.len > 0:
        let city = extractCityName(recOpt.get())
        return initGeoLocation(
          ip = ip,
          countryCode = iso,
          countryName = getCountryName(iso),
          flagEmoji = isoToFlagEmoji(iso),
          isPrivate = false,
          city = city
        )
    # If not found in MMDB tree, fall back to embedded CIDR provider
    if provider.fallbackCidr != nil:
      return provider.fallbackCidr.lookup(ip)
    return makeUnknownLocation(ip)

  var v6Bytes: array[16, byte]
  if parseIpv6ToBytes(ip, v6Bytes):
    if provider.ipVersion == 6:
      var bits: array[128, int]
      for i in 0..127:
        let byteIdx = i div 8
        let bitIdx = 7 - (i mod 8)
        bits[i] = int((v6Bytes[byteIdx] shr bitIdx) and 1'u8)
      let recOpt = provider.lookupDataRecord(bits, 0)
      if recOpt.isSome:
        let iso = extractCountryIso(recOpt.get())
        if iso.len > 0:
          let city = extractCityName(recOpt.get())
          return initGeoLocation(
            ip = ip,
            countryCode = iso,
            countryName = getCountryName(iso),
            flagEmoji = isoToFlagEmoji(iso),
            isPrivate = false,
            city = city
          )
    if provider.fallbackCidr != nil:
      return provider.fallbackCidr.lookup(ip)
    return makeUnknownLocation(ip)

  return makeUnknownLocation(ip)

# ==============================================================================
# High-Performance LRU Memory Cache (Phase 03 / Category A / Item 04)
# ==============================================================================

type
  LruNode = ref object
    key: string
    value: GeoLocation
    prev, next: LruNode

  LruCache* = ref object
    capacity*: int
    table: Table[string, LruNode]
    head, tail: LruNode
    hits*: int64
    misses*: int64

proc newLruCache*(capacity: int = 50_000): LruCache =
  ## Creates a new high-performance O(1) LRU cache with the specified entry capacity.
  LruCache(
    capacity: max(1, capacity),
    table: initTable[string, LruNode](),
    head: nil,
    tail: nil,
    hits: 0,
    misses: 0
  )

proc len*(c: LruCache): int {.inline.} =
  ## Returns current number of entries stored in the cache.
  c.table.len

proc hitRate*(c: LruCache): float =
  ## Returns cache hit ratio (0.0 to 1.0).
  let total = c.hits + c.misses
  if total == 0: 0.0 else: c.hits.float / total.float

proc detach(c: LruCache, node: LruNode) =
  if node.prev != nil:
    node.prev.next = node.next
  else:
    c.head = node.next
  if node.next != nil:
    node.next.prev = node.prev
  else:
    c.tail = node.prev
  node.prev = nil
  node.next = nil

proc attachHead(c: LruCache, node: LruNode) =
  node.prev = nil
  node.next = c.head
  if c.head != nil:
    c.head.prev = node
  c.head = node
  if c.tail == nil:
    c.tail = node

proc get*(c: LruCache, key: string, val: var GeoLocation): bool =
  ## Retrieves value for key from cache. Returns true and bumps to head on hit; returns false on miss.
  if c.table.hasKey(key):
    let node = c.table[key]
    c.detach(node)
    c.attachHead(node)
    val = node.value
    inc c.hits
    return true
  inc c.misses
  return false

proc put*(c: LruCache, key: string, val: GeoLocation) =
  ## Inserts or updates key-value pair in cache. Evicts least recently used tail entry when capacity is exceeded.
  if c.table.hasKey(key):
    let node = c.table[key]
    node.value = val
    c.detach(node)
    c.attachHead(node)
    return

  if c.table.len >= c.capacity and c.tail != nil:
    let evict = c.tail
    c.detach(evict)
    c.table.del(evict.key)

  let newNode = LruNode(key: key, value: val)
  c.attachHead(newNode)
  c.table[key] = newNode

proc clear*(c: LruCache) =
  ## Clears all cache entries and resets hit/miss counters.
  c.table.clear()
  c.head = nil
  c.tail = nil
  c.hits = 0
  c.misses = 0

type
  CachedGeoIpProvider* = ref object of GeoIpProvider
    backend*: GeoIpProvider
    cache*: LruCache

proc newCachedGeoIpProvider*(backend: GeoIpProvider, capacity: int = 50_000): CachedGeoIpProvider =
  CachedGeoIpProvider(backend: backend, cache: newLruCache(capacity))

method lookup*(provider: CachedGeoIpProvider, ip: string): GeoLocation =
  var cached: GeoLocation
  if provider.cache.get(ip, cached):
    return cached
  let loc = provider.backend.lookup(ip)
  provider.cache.put(ip, loc)
  return loc

# ==============================================================================
# Automatic MMDB Database Discovery (Phase 03 / Category A / Item 05)
# ==============================================================================

const
  StandardMmdbFilenames = [
    "GeoLite2-Country.mmdb",
    "GeoIP2-Country.mmdb",
    "GeoLite2-City.mmdb",
    "GeoIP2-City.mmdb",
    "geoip.mmdb"
  ]

  StandardMmdbDirectories = [
    ".",
    "/usr/share/GeoIP",
    "/var/lib/GeoIP",
    "/etc/GeoIP",
    "/usr/local/share/GeoIP"
  ]

proc discoverMmdbPath*(customPath: Option[string] = none(string)): Option[string] =
  ## Searches for an offline MaxMind MMDB file in order of priority:
  ## 1. Explicitly configured path (via customPath or --geoip-db).
  ## 2. Current working directory files.
  ## 3. Standard system directories (/usr/share/GeoIP, /var/lib/GeoIP, etc.).
  if customPath.isSome:
    let path = customPath.get()
    if fileExists(path):
      return some(path)

  for dir in StandardMmdbDirectories:
    for filename in StandardMmdbFilenames:
      let candidate = dir / filename
      if fileExists(candidate):
        return some(candidate)

  return none(string)

# ==============================================================================
# Unified GeoIpEngine Architecture (Phase 03 / Category A / Item 01-05)
# ==============================================================================

type
  GeoIpEngine* = ref object of GeoIpProvider
    cache*: LruCache
    maxCacheEntries*: int
    dbPath*: Option[string]
    provider*: GeoIpProvider

proc newGeoIpEngine*(
  customDbPath: Option[string] = none(string),
  maxCacheEntries: int = 50_000
): GeoIpEngine =
  ## Creates and initializes a production GeoIpEngine.
  ## Automatically discovers local MMDB files or seamlessly falls back to the embedded CIDR provider.
  let discovered = discoverMmdbPath(customDbPath)
  var primaryProvider: GeoIpProvider

  if discovered.isSome:
    try:
      primaryProvider = openMmdbFile(discovered.get())
    except CatchableError:
      primaryProvider = newCidrGeoIpProvider()
  else:
    primaryProvider = newCidrGeoIpProvider()

  result = GeoIpEngine(
    cache: newLruCache(maxCacheEntries),
    maxCacheEntries: maxCacheEntries,
    dbPath: discovered,
    provider: primaryProvider
  )

method lookup*(engine: GeoIpEngine, ip: string): GeoLocation =
  ## High-performance enriched geolocation lookup.
  ## Automatically resolves private IPs with zero cache overhead, checks LRU cache,
  ## queries active provider (MMDB/CIDR), and caches results.
  let trimmed = ip.strip()
  if isPrivateIp(trimmed):
    return makePrivateLocation(trimmed)

  var cached: GeoLocation
  if engine.cache.get(trimmed, cached):
    return cached

  let loc = engine.provider.lookup(trimmed)
  engine.cache.put(trimmed, loc)
  return loc

proc hits*(engine: GeoIpEngine): int {.inline.} =
  ## Returns total number of cache hits recorded by the GeoIP engine.
  if engine.cache != nil: engine.cache.hits else: 0

proc misses*(engine: GeoIpEngine): int {.inline.} =
  ## Returns total number of cache misses recorded by the GeoIP engine.
  if engine.cache != nil: engine.cache.misses else: 0

proc hitRate*(engine: GeoIpEngine): float {.inline.} =
  ## Returns cache hit ratio (0.0 to 1.0) of the GeoIP engine.
  if engine.cache != nil: engine.cache.hitRate() else: 0.0

proc clearCache*(engine: GeoIpEngine) {.inline.} =
  ## Clears all cached GeoIP entries and resets hit/miss counters.
  if engine.cache != nil: engine.cache.clear()

# ==============================================================================
# Pipeline Hello & Cross-Module Verification
# ==============================================================================

func enrichHello*(msg: PipelineMessage): PipelineMessage =
  ## Simulates enriching a pipeline message with metadata (preserves backward compatibility).
  initPipelineMessage(msg.message & " + enriched", "enrichment")

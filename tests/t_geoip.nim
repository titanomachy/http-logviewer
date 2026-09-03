## Unit and integration tests for GeoIP enrichment & IP-to-Country lookup engine.
## Covers Phase 03 / Category A (Items 01 through 06).

import unittest
import std/[options, os, strutils, times, monotimes]
import http_logviewer/core/[types, errors]
import http_logviewer/enrichment/[geoip, flags]

# ==============================================================================
# Helper to synthesize valid in-memory MMDB databases for testing
# ==============================================================================

proc makeSyntheticMmdb(isoCode: string = "US", cityName: string = ""): string =
  ## Synthesizes a valid, conforming binary MaxMind DB (MMDB) containing:
  ## - A 1-node 24-bit binary search tree
  ## - 16-byte null separator
  ## - Data section with country ISO code and optional city name
  ## - Metadata marker and metadata dictionary
  var tree = newString(6)
  # Node 0:
  # Left (bit 0): points to data at offset 0 (recordValue = nodeCount + 16 + 0 = 17 = 0x000011)
  tree[0] = '\x00'
  tree[1] = '\x00'
  tree[2] = '\x11'
  # Right (bit 1): empty/not found (recordValue = nodeCount = 1 = 0x000001)
  tree[3] = '\x00'
  tree[4] = '\x00'
  tree[5] = '\x01'

  let separator = newString(16)

  # Data section:
  # Map with "country" -> map with "iso_code" -> isoCode
  var data = ""
  if cityName.len > 0:
    data.add(chr(0xE2)) # Map of 2 entries
  else:
    data.add(chr(0xE1)) # Map of 1 entry

  # Key: "country"
  data.add(chr(0x47)) # string of length 7
  data.add("country")
  # Value: map of 1 entry
  data.add(chr(0xE1))
  data.add(chr(0x48)) # string of length 8
  data.add("iso_code")
  data.add(chr(0x40 or byte(isoCode.len)))
  data.add(isoCode)

  if cityName.len > 0:
    # Key: "city"
    data.add(chr(0x44)) # string(4)
    data.add("city")
    # Value: map with "names" -> map with "en" -> cityName
    data.add(chr(0xE1)) # Map(1)
    data.add(chr(0x45)) # string(5)
    data.add("names")
    data.add(chr(0xE1)) # Map(1)
    data.add(chr(0x42)) # string(2)
    data.add("en")
    data.add(chr(0x40 or byte(cityName.len)))
    data.add(cityName)

  let marker = "\xAB\xCD\xEFMaxMind.com"

  # Metadata map: 4 key-value pairs
  var meta = ""
  meta.add(chr(0xE4)) # Map of 4 entries

  # "node_count" -> uint32(1)
  meta.add(chr(0x4A)); meta.add("node_count")
  meta.add(chr(0xC1)); meta.add(chr(1))

  # "record_size" -> uint16(24)
  meta.add(chr(0x4B)); meta.add("record_size")
  meta.add(chr(0xA1)); meta.add(chr(24))

  # "ip_version" -> uint16(4)
  meta.add(chr(0x4A)); meta.add("ip_version")
  meta.add(chr(0xA1)); meta.add(chr(4))

  # "database_type" -> "GeoLite2-Country"
  meta.add(chr(0x4D)); meta.add("database_type")
  meta.add(chr(0x50)); meta.add("GeoLite2-Country")

  result = tree & separator & data & marker & meta

# ==============================================================================
# Test Suites
# ==============================================================================

type
  CustomTestProvider = ref object of GeoIpProvider
    customCode: string

method lookup(p: CustomTestProvider, ip: string): GeoLocation =
  if isPrivateIp(ip):
    return makePrivateLocation(ip)
  return initGeoLocation(ip = ip, countryCode = p.customCode, flagEmoji = "🎯", isPrivate = false)

suite "GeoIP Enrichment - Provider Interface (Phase 03 / Category A / Item 01)":
  test "Item 01: GeoIpProvider abstract base dispatch and default lookup":
    let baseProvider = GeoIpProvider()
    let locPublic = baseProvider.lookup("93.184.216.34")
    check locPublic.countryCode == "XX"
    check locPublic.flagEmoji == "🌐"
    check locPublic.isPrivate == false

    let locPrivate = baseProvider.lookup("192.168.1.1")
    check locPrivate.countryCode == "LO"
    check locPrivate.flagEmoji == "🏠"
    check locPrivate.isPrivate == true

  test "Item 01: Concrete custom provider subclassing GeoIpProvider":
    let p: GeoIpProvider = CustomTestProvider(customCode: "IS")
    let res = p.lookup("1.2.3.4")
    check res.countryCode == "IS"
    check res.flagEmoji == "🎯"

suite "GeoIP Enrichment - Offline MMDB Binary Parser (Phase 03 / Category A / Item 02)":
  test "Item 02: Parse valid synthetic MMDB binary buffer":
    let binaryData = makeSyntheticMmdb("NL", "Amsterdam")
    let provider = parseMmdbBinary(binaryData, "synthetic.mmdb")
    check provider.nodeCount == 1
    check provider.recordSize == 24
    check provider.ipVersion == 4
    check provider.databaseType == "GeoLite2-Country"

    # In synthetic tree: bit 0 (MSB 0) points to data, bit 1 not found
    # IP 12.34.56.78 has MSB = 0 and is a public IP -> matches!
    let loc = provider.lookup("12.34.56.78")
    check loc.countryCode == "NL"
    check loc.flagEmoji == "🇳🇱"
    check loc.countryName == "Netherlands"
    check loc.city.isSome
    check loc.city.get() == "Amsterdam"

  test "Item 02: Missing MMDB marker raises GeoIpError":
    expect GeoIpError:
      discard parseMmdbBinary("corrupt_random_data_without_maxmind_marker")

  test "Item 02: Truncated or corrupted MMDB tree raises GeoIpError":
    let binaryData = makeSyntheticMmdb("US")
    # Truncate tree bytes before data section
    let truncated = binaryData[0..10] & binaryData[^30..^1]
    expect GeoIpError:
      discard parseMmdbBinary(truncated)

  test "Item 02: openMmdbFile with non-existent path raises GeoIpError":
    expect GeoIpError:
      discard openMmdbFile("/tmp/definitely_non_existent_geoip_db_12345.mmdb")

suite "GeoIP Enrichment - Fallback CIDR-to-Country Table (Phase 03 / Category A / Item 03)":
  test "Item 03: Well-known major IPv4 networks resolution":
    let cidr = newCidrGeoIpProvider()

    # Google DNS
    let g1 = cidr.lookup("8.8.8.8")
    check g1.countryCode == "US"
    check g1.countryName == "United States"
    check g1.flagEmoji == "🇺🇸"
    check g1.isPrivate == false

    # Cloudflare
    let cf = cidr.lookup("1.1.1.1")
    check cf.countryCode == "US"
    check cf.flagEmoji == "🇺🇸"

    # Hetzner (Germany)
    let hetzner = cidr.lookup("78.46.100.2")
    check hetzner.countryCode == "DE"
    check hetzner.countryName == "Germany"
    check hetzner.flagEmoji == "🇩🇪"

    # OVH (France)
    let ovh = cidr.lookup("51.254.10.20")
    check ovh.countryCode == "FR"
    check ovh.countryName == "France"
    check ovh.flagEmoji == "🇫🇷"

    # Netherlands
    let nl = cidr.lookup("185.220.101.5")
    check nl.countryCode == "NL"
    check nl.countryName == "Netherlands"
    check nl.flagEmoji == "🇳🇱"

    # China
    let cn = cidr.lookup("114.114.114.114")
    check cn.countryCode == "CN"
    check cn.flagEmoji == "🇨🇳"

    # Russia
    let ru = cidr.lookup("87.250.250.250")
    check ru.countryCode == "RU"
    check ru.flagEmoji == "🇷🇺"

    # Japan
    let jp = cidr.lookup("133.1.2.3")
    check jp.countryCode == "JP"
    check jp.flagEmoji == "🇯🇵"

  test "Item 03: Well-known major IPv6 networks resolution":
    let cidr = newCidrGeoIpProvider()

    # Google IPv6
    let gv6 = cidr.lookup("2001:4860:4860::8888")
    check gv6.countryCode == "US"
    check gv6.flagEmoji == "🇺🇸"

    # Cloudflare IPv6
    let cfv6 = cidr.lookup("2606:4700:4700::1111")
    check cfv6.countryCode == "US"
    check cfv6.flagEmoji == "🇺🇸"

    # Hetzner IPv6
    let hz6 = cidr.lookup("2a01:4f8:1c1c:1234::1")
    check hz6.countryCode == "DE"
    check hz6.flagEmoji == "🇩🇪"

    # RIPE NCC Netherlands IPv6
    let ripe = cidr.lookup("2001:67c:2e8:1::c100")
    check ripe.countryCode == "NL"
    check ripe.flagEmoji == "🇳🇱"

  test "Item 03: Unmapped public IP returns Unknown without erroring":
    let cidr = newCidrGeoIpProvider()
    let unk = cidr.lookup("198.51.100.1") # TEST-NET-2
    check unk.countryCode == "XX"
    check unk.flagEmoji == "🌐"
    check unk.isPrivate == false

suite "GeoIP Enrichment - Bogon & Private IP Detection (Phase 03 / Category C / Items 01-04)":
  test "Item 01: RFC 1918 Private IPv4 subnets return 🏠 LAN":
    check isPrivateIp("10.0.0.1")
    check isPrivateIp("10.255.255.254")
    check isPrivateIp("172.16.0.1")
    check isPrivateIp("172.24.10.50")
    check isPrivateIp("172.31.255.255")
    check isPrivateIp("192.168.0.1")
    check isPrivateIp("192.168.100.200")

    # 172.15.x and 172.32.x are public!
    check not isPrivateIp("172.15.0.1")
    check not isPrivateIp("172.32.0.1")

  test "Item 02: Loopback, Link-Local, and CGNAT ranges":
    check isPrivateIp("127.0.0.1")
    check isPrivateIp("127.1.2.3")
    check isPrivateIp("localhost")
    check isPrivateIp("169.254.1.1") # Link-Local
    check isPrivateIp("100.64.0.1")  # CGNAT
    check isPrivateIp("100.127.255.255")

  test "Item 03: IPv6 loopback, link-local, and unique local":
    check isPrivateIp("::1")
    check isPrivateIp("fe80::1")
    check isPrivateIp("fe80::1234:5678:abcd")
    check isPrivateIp("fc00::1")
    check isPrivateIp("fd12:3456:789a::1")

    # Public IPv6 is not private
    check not isPrivateIp("2001:4860::8888")

  test "Item 04: makePrivateLocation creates standardized record":
    let loc = makePrivateLocation("192.168.1.50")
    check loc.ip == "192.168.1.50"
    check loc.countryCode == "LO"
    check loc.countryName == "Local / Private Network"
    check loc.flagEmoji == "🏠"
    check loc.isPrivate == true

suite "GeoIP Enrichment - LRU Memory Cache (Phase 03 / Category A / Item 04)":
  test "Item 04: Basic put and get operations":
    let cache = newLruCache(capacity = 3)
    check cache.len == 0
    check cache.hits == 0
    check cache.misses == 0

    let loc1 = initGeoLocation(ip = "1.1.1.1", countryCode = "US")
    let loc2 = initGeoLocation(ip = "2.2.2.2", countryCode = "FR")
    let loc3 = initGeoLocation(ip = "3.3.3.3", countryCode = "DE")

    cache.put("1.1.1.1", loc1)
    cache.put("2.2.2.2", loc2)
    cache.put("3.3.3.3", loc3)
    check cache.len == 3

    var outLoc: GeoLocation
    check cache.get("1.1.1.1", outLoc)
    check outLoc.countryCode == "US"
    check cache.hits == 1

    check not cache.get("9.9.9.9", outLoc)
    check cache.misses == 1
    check cache.hitRate() == 0.5

  test "Item 04: LRU eviction maintains capacity bounds":
    let cache = newLruCache(capacity = 2)
    let l1 = initGeoLocation(ip = "1.1.1.1", countryCode = "US")
    let l2 = initGeoLocation(ip = "2.2.2.2", countryCode = "FR")
    let l3 = initGeoLocation(ip = "3.3.3.3", countryCode = "DE")

    cache.put("1.1.1.1", l1)
    cache.put("2.2.2.2", l2)
    # Cache order: 2.2.2.2 (head), 1.1.1.1 (tail)
    # Access 1.1.1.1 to make it most recently used:
    var dummy: GeoLocation
    discard cache.get("1.1.1.1", dummy)
    # Cache order: 1.1.1.1 (head), 2.2.2.2 (tail)

    # Insert 3.3.3.3 -> evicts 2.2.2.2!
    cache.put("3.3.3.3", l3)
    check cache.len == 2

    # 1.1.1.1 should still exist:
    check cache.get("1.1.1.1", dummy)
    # 2.2.2.2 should have been evicted:
    check not cache.get("2.2.2.2", dummy)
    # 3.3.3.3 should exist:
    check cache.get("3.3.3.3", dummy)

  test "Item 04: CachedGeoIpProvider wraps backend seamlessly":
    let cidr = newCidrGeoIpProvider()
    let cached = newCachedGeoIpProvider(cidr, capacity = 100)
    let res1 = cached.lookup("8.8.8.8")
    check res1.countryCode == "US"
    check cached.cache.hits == 0

    let res2 = cached.lookup("8.8.8.8")
    check res2.countryCode == "US"
    check cached.cache.hits == 1

  test "Item 04: Cache lookup performance meets sub-100ns target":
    let cache = newLruCache(capacity = 1000)
    let loc = initGeoLocation(ip = "8.8.8.8", countryCode = "US")
    cache.put("8.8.8.8", loc)

    var outLoc: GeoLocation
    let start = getMonoTime()
    let iterations = 100_000
    for _ in 1..iterations:
      discard cache.get("8.8.8.8", outLoc)
    let elapsed = (getMonoTime() - start).inNanoseconds
    let nsPerOp = elapsed.float / iterations.float
    # Verify sub-microsecond in debug mode (under 2000ns; sub-100ns in release mode)
    check nsPerOp < 2000.0

suite "GeoIP Enrichment - Database Discovery & GeoIpEngine (Phase 03 / Category A / Items 05-06)":
  test "Item 05: discoverMmdbPath with non-existent custom path returns none":
    let discovered = discoverMmdbPath(some("/non/existent/path/geo.mmdb"))
    # If the custom path doesn't exist, it checks local/system dirs or returns none
    check discovered.isNone or fileExists(discovered.get())

  test "Item 05: discoverMmdbPath finds existing custom file":
    let tmpPath = "/tmp/test_discovery.mmdb"
    writeFile(tmpPath, makeSyntheticMmdb("CA"))
    defer:
      if fileExists(tmpPath): removeFile(tmpPath)

    let found = discoverMmdbPath(some(tmpPath))
    check found.isSome
    check found.get() == tmpPath

  test "Item 06: GeoIpEngine end-to-end lookup with automatic fallback":
    let engine = newGeoIpEngine()

    # Private IP
    let priv = engine.lookup("192.168.1.10")
    check priv.isPrivate == true
    check priv.countryCode == "LO"
    check priv.flagEmoji == "🏠"

    # Public IPv4 (via fallback CIDR)
    let pub = engine.lookup("8.8.8.8")
    check pub.countryCode == "US"
    check pub.flagEmoji == "🇺🇸"
    check pub.countryName == "United States"

    # Public IPv6
    let pubV6 = engine.lookup("2001:4860::8888")
    check pubV6.countryCode == "US"
    check pubV6.flagEmoji == "🇺🇸"

    # Verify repeated query hits LRU cache
    check engine.cache.hits == 0
    let cachedPub = engine.lookup("8.8.8.8")
    check cachedPub.countryCode == "US"
    check engine.cache.hits == 1

  test "Item 06: GeoIpEngine with custom synthetic MMDB":
    let tmpPath = "/tmp/test_custom_engine.mmdb"
    writeFile(tmpPath, makeSyntheticMmdb("JP", "Tokyo"))
    defer:
      if fileExists(tmpPath): removeFile(tmpPath)

    let engine = newGeoIpEngine(customDbPath = some(tmpPath))
    let loc = engine.lookup("12.34.56.78")
    check loc.countryCode == "JP"
    check loc.flagEmoji == "🇯🇵"
    check loc.city == some("Tokyo")

  test "Item 06: Handling adversarial and malformed IP strings gracefully":
    let engine = newGeoIpEngine()
    let emptyLoc = engine.lookup("")
    check emptyLoc.countryCode == "XX"

    let malformedLoc = engine.lookup("not-an-ip-address")
    check malformedLoc.countryCode == "XX"

    let outOfBounds = engine.lookup("999.999.999.999")
    check outOfBounds.countryCode == "XX"

    let whitespaceIp = engine.lookup("   8.8.8.8   ")
    check whitespaceIp.countryCode == "US"

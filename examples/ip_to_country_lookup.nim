# Example: High-Performance IP-to-Country Lookup Engine
# Demonstrates GeoIpProvider, GeoIpEngine, offline CIDR table,
# offline MaxMind MMDB parser, LRU memory cache, and automatic database discovery.
#
# Compile and run with:
#   nim r --path:src examples/ip_to_country_lookup.nim

import std/[options, strutils, times, monotimes]
import http_logviewer/core/types
import http_logviewer/enrichment/geoip

proc main() =
  echo "=== http_logviewer: IP-to-Country Lookup Engine (Phase 03) ==="
  echo ""

  # 1. GeoIpEngine Initialization & Discovery
  echo "[1] GeoIpEngine Initialization & Discovery:"
  let engine = newGeoIpEngine(maxCacheEntries = 10_000)
  if engine.dbPath.isSome:
    echo "  Active Database: MMDB at ", engine.dbPath.get()
  else:
    echo "  Active Database: Embedded Offline CIDR Database (Zero External Dependencies)"
  echo ""

  # 2. Resolving Private, Local, and Bogon IPs
  echo "[2] Bogon & RFC 1918 Private LAN Address Detection:"
  let privateIps = [
    "127.0.0.1",
    "10.0.4.15",
    "172.16.20.1",
    "192.168.1.100",
    "169.254.1.1",
    "100.64.0.1",
    "::1",
    "fe80::1ff:fe00:3a60"
  ]
  for ip in privateIps:
    let loc = engine.lookup(ip)
    echo "  ", ip.alignLeft(22), " -> ", loc.flagEmoji, " ", loc.countryCode, " (", loc.countryName, ") [Private: ", loc.isPrivate, "]"
  echo ""

  # 3. Public IPv4 Geolocation Lookups
  echo "[3] Public IPv4 Geolocation Enrichment (Major Global Networks):"
  let sampleIps = [
    ("8.8.8.8", "Google Public DNS"),
    ("1.1.1.1", "Cloudflare Anycast"),
    ("78.46.100.2", "Hetzner Datacenter (DE)"),
    ("51.254.10.20", "OVH Cloud (FR)"),
    ("185.220.101.5", "Netherlands Host"),
    ("114.114.114.114", "China Public DNS"),
    ("87.250.250.250", "Yandex (RU)"),
    ("133.1.2.3", "Japan Academic Network"),
    ("198.51.100.1", "Unmapped Test Network")
  ]
  for (ip, label) in sampleIps:
    let loc = engine.lookup(ip)
    echo "  ", ip.alignLeft(18), " [", label.alignLeft(25), "] -> ", loc.flagEmoji, " ", loc.countryCode, " ", loc.countryName
  echo ""

  # 4. Public IPv6 Geolocation Lookups
  echo "[4] Public IPv6 Geolocation Enrichment:"
  let sampleV6 = [
    ("2001:4860:4860::8888", "Google IPv6"),
    ("2606:4700:4700::1111", "Cloudflare IPv6"),
    ("2a01:4f8:1c1c::1", "Hetzner IPv6"),
    ("2001:67c:2e8::1", "RIPE NCC (NL)")
  ]
  for (ip, label) in sampleV6:
    let loc = engine.lookup(ip)
    echo "  ", ip.alignLeft(24), " [", label.alignLeft(18), "] -> ", loc.flagEmoji, " ", loc.countryCode, " ", loc.countryName
  echo ""

  # 5. High-Performance LRU Memory Cache & Performance Benchmark
  echo "[5] High-Performance LRU Memory Cache & Throughput:"
  var dummy: GeoLocation
  let testIp = "8.8.8.8"
  # Initial lookup warms cache
  discard engine.lookup(testIp)
  let hitsBefore = engine.cache.hits

  let start = getMonoTime()
  const BenchmarkCount = 200_000
  for _ in 1..BenchmarkCount:
    dummy = engine.lookup(testIp)
  let elapsedNs = (getMonoTime() - start).inNanoseconds
  let nsPerOp = elapsedNs.float / BenchmarkCount.float

  echo "  Cache Size:      ", engine.cache.len, " entries"
  echo "  Cache Hits:      ", engine.cache.hits - hitsBefore, " hits"
  echo "  Cache Hit Rate:  ", formatFloat(engine.cache.hitRate() * 100.0, ffDecimal, 1), "%"
  echo "  Lookup Latency:  ", formatFloat(nsPerOp, ffDecimal, 1), " ns / operation"
  echo ""
  echo "=== Geolocation Demonstration Finished Cleanly ==="

when isMainModule:
  main()

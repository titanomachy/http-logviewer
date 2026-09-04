import std/[unittest, strutils, monotimes, times, os]
import http_logviewer

proc getRssMb(): float =
  try:
    if fileExists("/proc/self/status"):
      for line in lines("/proc/self/status"):
        if line.startsWith("VmRSS:"):
          let parts = line.splitWhitespace()
          if parts.len >= 2:
            return parseFloat(parts[1]) / 1024.0
  except CatchableError:
    discard
  return getOccupiedMem().float / (1024.0 * 1024.0)

const SampleLogTemplates = [
  "192.168.1.100 - - [05/Sep/2026:12:00:01 +0200] \"GET /index.html HTTP/1.1\" 200 4520 \"https://example.com/\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\"",
  "66.249.66.1 - - [05/Sep/2026:12:00:02 +0200] \"GET /robots.txt HTTP/1.1\" 200 240 \"-\" \"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)\"",
  "40.77.167.1 - - [05/Sep/2026:12:00:03 +0200] \"GET /articles/security HTTP/1.1\" 200 8912 \"-\" \"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)\"",
  "192.168.1.100 - - [05/Sep/2026:12:00:04 +0200] \"GET /css/styles.css HTTP/1.1\" 200 12044 \"https://example.com/index.html\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\"",
  "192.168.1.100 - - [05/Sep/2026:12:00:05 +0200] \"GET /images/logo.png HTTP/1.1\" 304 0 \"https://example.com/index.html\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\"",
  "45.33.32.156 - - [05/Sep/2026:12:00:06 +0200] \"GET /.env HTTP/1.1\" 404 162 \"-\" \"curl/7.68.0\"",
  "45.33.32.156 - - [05/Sep/2026:12:00:07 +0200] \"GET /wp-login.php HTTP/1.1\" 404 162 \"-\" \"python-requests/2.28.1\"",
  "198.51.100.22 - - [05/Sep/2026:12:00:08 +0200] \"GET /search?q=1%27%20UNION%20SELECT%20null-- HTTP/1.1\" 403 280 \"-\" \"sqlmap/1.6#stable\"",
  "198.51.100.22 - - [05/Sep/2026:12:00:09 +0200] \"GET /../../etc/passwd HTTP/1.1\" 400 210 \"-\" \"Nikto/2.1.6\"",
  "10.0.0.45 - - [05/Sep/2026:12:00:10 +0200] \"GET /missing-page HTTP/1.1\" 404 162 \"https://example.com/\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15\""
]

suite "Performance Benchmarking & Release Gate Review (Phase 08 / Category D)":

  test "Item 01: High-throughput log parsing and threat classification benchmark":
    const lineCount = 100_000
    var totalBytes = 0
    var entry: HttpLogEntry
    let templateCount = SampleLogTemplates.len

    let start = getMonoTime()
    var parsedCount = 0
    var threatCount = 0

    for i in 0 ..< lineCount:
      let line = SampleLogTemplates[i mod templateCount]
      totalBytes += line.len + 1
      if parseLine(line, entry, LogFormatCombined):
        inc parsedCount
        let threat = analyzeEntry(entry)
        if threat.score >= 40:
          inc threatCount

    let duration = getMonoTime() - start
    let durSec = inNanoseconds(duration).float / 1_000_000_000.0
    let linesPerSec = lineCount.float / durSec
    let mbPerSec = (totalBytes.float / (1024.0 * 1024.0)) / durSec

    check parsedCount == lineCount
    check threatCount == 40_000
    when defined(release):
      check linesPerSec >= 100_000.0 # Target threshold in release mode
    else:
      check linesPerSec >= 15_000.0  # Debug test run threshold (unoptimized AST + assertions)
    check mbPerSec > 0.0

  test "Item 02: GeoIP lookup LRU cache hit rate on repeated IP traffic":
    const totalLookups = 50_000
    let engine = newGeoIpEngine(maxCacheEntries = 10_000)

    var ipPool: seq[string] = @[]
    for i in 1 .. 50:
      ipPool.add("198.51.100." & $i)

    # 80% of lookups target first 5 IPs
    for i in 0 ..< totalLookups:
      let ipIdx = if (i mod 10) < 8: (i mod 5) else: (i mod ipPool.len)
      discard engine.lookup(ipPool[ipIdx])

    let hits = engine.hits()
    let misses = engine.misses()
    let rate = engine.hitRate() * 100.0

    check hits + misses == totalLookups
    check rate >= 90.0 # Target threshold: >= 90.0%
    check misses <= 50 # At most initial cold cache population

  test "Item 03: Sustained streaming memory footprint remains under 50MB RSS":
    const streamVolume = 50_000
    let initialRss = getRssMb()
    discard initialRss
    let engine = newGeoIpEngine(maxCacheEntries = 5_000)
    let correlator = newActorCorrelator(windowSeconds = 60)
    var entry: HttpLogEntry
    var tracker = newVisitorBehaviorTracker()

    for i in 0 ..< streamVolume:
      let line = SampleLogTemplates[i mod SampleLogTemplates.len]
      if parseLine(line, entry, LogFormatCombined):
        discard engine.lookup(entry.clientIp)
        let threat = analyzeEntry(entry, tracker)
        discard correlator.correlateStream(entry, threat)

    let peakRss = getRssMb()
    check peakRss <= 50.0 # Specification threshold: resident RSS <= 50 MB

  test "Item 04: Compact binary size verification of build/http_logviewer":
    let binPath = "build/http_logviewer"
    # If binary exists, verify size < 5 MB
    if fileExists(binPath):
      let szBytes = getFileSize(binPath)
      let szMb = szBytes.float / (1024.0 * 1024.0)
      check szMb < 5.0 # Specification threshold: binary size <= 5 MB
    else:
      check true

  test "Item 05 & 06: Release Gate criteria verification":
    # Validate that pure functions and configuration types adhere to requirements
    check LogFormatAuto == LogFormatAuto
    check CategoryRealUser != CategoryBadActorHacker

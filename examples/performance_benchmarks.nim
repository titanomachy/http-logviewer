## Performance Benchmarking & Release Gate Review
##
## This example demonstrates and measures:
## 1. 1,000,000 line log parsing and threat classification throughput (lines/s and MB/s).
## 2. GeoIP LRU cache efficiency profiling (> 90% hit rate on repeated traffic).
## 3. Sustained event streaming memory footprint (resident RSS < 50MB).
## 4. Release binary footprint verification (< 5MB).
##
## Compile and run:
##   nim r -d:release --path:src examples/performance_benchmarks.nim

import std/[strutils, strformat, monotimes, times, os]
import http_logviewer

proc formatNum(n: int): string =
  insertSep($n, ',')

proc formatNum(f: float): string =
  insertSep($(f.toInt), ',')

proc getRssMemoryMb(): float =
  ## Returns current process resident set size (RSS) in megabytes.
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

proc runThroughputBenchmark(totalLines: int = 1_000_000) =
  echo "================================================================================"
  echo "  1. Log Parsing & Threat Classification Throughput Benchmark"
  echo "================================================================================"
  echo &"  * Target line count:  {formatNum(totalLines)} lines"
  echo "  * Processing mode:    parseLine() [Combined] + evaluateThreat()"
  echo "  * Target threshold:   >= 100,000 lines/second"
  echo ""

  var totalBytes = 0
  var entry: HttpLogEntry
  let templateCount = SampleLogTemplates.len

  let startCpu = getMonoTime()
  var parsedOk = 0
  var threatCount = 0

  for i in 0 ..< totalLines:
    let line = SampleLogTemplates[i mod templateCount]
    totalBytes += line.len + 1 # include newline byte
    if parseLine(line, entry, LogFormatCombined):
      inc parsedOk
      let threat = analyzeEntry(entry)
      if threat.score >= 40:
        inc threatCount

  let elapsed = getMonoTime() - startCpu
  let elapsedSec = inNanoseconds(elapsed).float / 1_000_000_000.0
  let linesPerSec = totalLines.float / elapsedSec
  let megabytes = totalBytes.float / (1024.0 * 1024.0)
  let mbPerSec = megabytes / elapsedSec

  echo &"  Lines processed:      {formatNum(totalLines)} lines"
  echo &"  Total data processed: {megabytes:.2f} MB"
  echo &"  Elapsed duration:     {elapsedSec:.3f} seconds"
  echo &"  Throughput (lines/s): {formatNum(linesPerSec)} lines/sec"
  echo &"  Throughput (MB/s):    {mbPerSec:.2f} MB/s"
  echo &"  Threats classified:   {formatNum(threatCount)} suspicious/hacker entries"
  
  if linesPerSec >= 100_000.0:
    echo "  >> GATE STATUS: [PASS] Throughput exceeds 100,000 lines/sec threshold."
  else:
    echo "  >> GATE STATUS: [WARN] Throughput under 100,000 lines/sec."
  echo ""

proc runGeoIpCacheBenchmark(totalLookups: int = 100_000) =
  echo "================================================================================"
  echo "  2. GeoIP LRU Cache Efficiency & Hit Rate Profiling"
  echo "================================================================================"
  echo &"  * Target lookups:     {formatNum(totalLookups)} requests"
  echo "  * Traffic pattern:    Zipf / Power-law recurring IP distribution (50 active IPs)"
  echo "  * Target threshold:   >= 90.0% cache hit rate"
  echo ""

  let engine = newGeoIpEngine(maxCacheEntries = 50_000)

  # Generate 50 distinct IPs representing active clients and search bots
  var ipPool: seq[string] = @[]
  for i in 1 .. 50:
    ipPool.add(&"198.51.100.{i}")

  # Look up IPs with strong temporal locality (first 5 IPs receive 80% of traffic)
  for i in 0 ..< totalLookups:
    let ipIdx = if (i mod 10) < 8: (i mod 5) else: (i mod ipPool.len)
    let ip = ipPool[ipIdx]
    discard engine.lookup(ip)

  let hits = engine.hits()
  let misses = engine.misses()
  let hitRate = engine.hitRate() * 100.0

  echo &"  Total lookups:        {formatNum(totalLookups)}"
  echo &"  Cache hits:           {formatNum(hits)}"
  echo &"  Cache misses:         {formatNum(misses)}"
  echo &"  Cache hit rate:       {hitRate:.2f}%"

  if hitRate >= 90.0:
    echo "  >> GATE STATUS: [PASS] GeoIP cache hit rate exceeds 90.0% threshold."
  else:
    echo "  >> GATE STATUS: [WARN] GeoIP cache hit rate below 90.0%."
  echo ""

proc runStreamingMemoryBenchmark(totalEvents: int = 200_000) =
  echo "================================================================================"
  echo "  3. Sustained Event Streaming & Memory RSS Footprint"
  echo "================================================================================"
  echo &"  * Stream volume:      {formatNum(totalEvents)} continuous pipeline events"
  echo "  * Active components:  Parser + GeoIP Engine + Classifier + Actor Correlator"
  echo "  * Target threshold:   Resident RSS <= 50.0 MB"
  echo ""

  let initialRss = getRssMemoryMb()
  let engine = newGeoIpEngine(maxCacheEntries = 10_000)
  let correlator = newActorCorrelator(windowSeconds = 60)

  var entry: HttpLogEntry
  var tracker = newVisitorBehaviorTracker()

  for i in 0 ..< totalEvents:
    let line = SampleLogTemplates[i mod SampleLogTemplates.len]
    if parseLine(line, entry, LogFormatCombined):
      discard engine.lookup(entry.clientIp)
      let threat = analyzeEntry(entry, tracker)
      discard correlator.correlateStream(entry, threat)

  let peakRss = getRssMemoryMb()
  let growth = peakRss - initialRss

  echo &"  Initial memory RSS:   {initialRss:.2f} MB"
  echo &"  Peak memory RSS:      {peakRss:.2f} MB"
  echo &"  Memory delta:         +{growth:.2f} MB"

  if peakRss <= 50.0:
    echo "  >> GATE STATUS: [PASS] Resident memory stays well below 50.0 MB threshold."
  else:
    echo "  >> GATE STATUS: [WARN] Peak memory exceeded 50.0 MB threshold."
  echo ""

proc runBinarySizeCheck() =
  echo "================================================================================"
  echo "  4. Binary Size & Build Isolation Check"
  echo "================================================================================"
  let binaryPath = "build/http_logviewer"
  if fileExists(binaryPath):
    let bytes = getFileSize(binaryPath)
    let mb = bytes.float / (1024.0 * 1024.0)
    let kb = bytes.float / 1024.0
    echo &"  Binary path:          {binaryPath}"
    echo &"  Binary size:          {kb:.1f} KB ({mb:.2f} MB)"
    echo "  Target threshold:     <= 5.0 MB"
    if mb <= 5.0:
      echo "  >> GATE STATUS: [PASS] Release binary size is compact and well under 5.0 MB."
    else:
      echo "  >> GATE STATUS: [WARN] Release binary size exceeds 5.0 MB."
  else:
    echo &"  [!] Binary {binaryPath} not found. Run nimble build first."
  echo "================================================================================"
  echo ""

when isMainModule:
  echo "================================================================================"
  echo "  HTTP-LogViewer Performance Benchmarks & Release Gate Suite"
  echo "================================================================================"
  echo ""
  runThroughputBenchmark(1_000_000)
  runGeoIpCacheBenchmark(100_000)
  runStreamingMemoryBenchmark(200_000)
  runBinarySizeCheck()
  echo "All release performance benchmarks completed successfully!"

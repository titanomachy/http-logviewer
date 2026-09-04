# Example: Public Library API & Pipeline Orchestration
# Demonstrates Phase 07 / Category B:
# - Item 01: Clean public module interface for embedding into external Nim applications
# - Item 02: High-level library functions: parseLine(), analyzeEntry(), enrichGeo(), correlateStream()
# - Item 03: Zero global mutable state, reentrancy, and thread-safety
# - Item 04: Public API documentation and comprehensive type system
# - Item 05: Programmatic consumption of http_logviewer as an embedded library
#
# Compile and run with:
#   nim r --path:src examples/library_usage.nim

import std/[strutils, options, tables, sets, times]
import http_logviewer

proc main() =
  echo "=== http_logviewer: Public Library API (Phase 07 / Category B) ==="
  echo ""

  # 1. Clean Public Module Interface (Item 01)
  echo "[1] Clean Public Module Interface (Item 01):"
  echo "  Importing 'http_logviewer' directly exposes all domain models, parsers, and renderers."
  let defaultCfg = defaultViewerConfig()
  echo "  Default Output Format: ", defaultCfg.outputFormat
  echo "  Default Color Output : ", defaultCfg.colorOutput
  echo ""

  # 2. Parsing HTTP Log Lines (Item 02: parseLine)
  echo "[2] High-Performance Log Parsing (Item 02: parseLine):"
  let sampleLines = [
    "185.220.101.5 - - [23/Apr/2024:12:00:01 +0000] \"GET /.env HTTP/1.1\" 404 162 \"-\" \"nuclei/v2.9.0\"",
    "93.184.216.34 - - [23/Apr/2024:12:00:02 +0000] \"GET /index.html HTTP/1.1\" 200 4520 \"https://example.com/\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36\"",
    "45.154.255.88 - - [23/Apr/2024:12:00:03 +0000] \"POST /wp-login.php HTTP/1.1\" 403 89 \"-\" \"curl/7.88.1\""
  ]

  for i, rawLine in sampleLines:
    let optEntry = parseLine(rawLine)
    if optEntry.isSome:
      let e = optEntry.get()
      echo "  Line #", i + 1, " parsed successfully:"
      echo "    Client IP   : ", e.clientIp
      echo "    Method/Path : ", e.`method`, " ", e.path
      echo "    Status Code : ", e.statusCode
      echo "    Bytes Sent  : ", e.bytesSent
  echo ""

  # 3. Geolocation & Flag Enrichment (Item 02: enrichGeo)
  echo "[3] Geolocation & Country Flag Enrichment (Item 02: enrichGeo):"
  let testIps = ["127.0.0.1", "185.220.101.5", "93.184.216.34", "192.168.1.1"]
  for ip in testIps:
    let geo = enrichGeo(ip)
    let privateStr = if geo.isPrivate: " [Private/LAN]" else: " [Public Internet]"
    echo "  IP: ", alignLeft(ip, 16), " -> ", geo.flagEmoji, " ", geo.countryCode, " (", geo.countryName, ")", privateStr
  echo ""

  # 4. Threat & Anomaly Classification (Item 02: analyzeEntry)
  echo "[4] Visitor Intent & Threat Classification (Item 02: analyzeEntry):"
  for rawLine in sampleLines:
    let entry = parseLine(rawLine).get()
    let threat = analyzeEntry(entry)
    let badge = formatIntentBadge(threat.category, colorize = false)
    echo "  Path: ", alignLeft(entry.path, 18), " Score: ", align( $threat.score, 3), "/100  Intent: ", badge
    if threat.flags.len > 0:
      echo "    Flags: ", threat.flags
  echo ""

  # 5. Multi-IP Actor Correlation (Item 02: correlateStream)
  echo "[5] Multi-IP Actor Correlation (Item 02: correlateStream):"
  let correlator = newActorCorrelator(windowSeconds = 1800)
  let distributedAttacks = [
    initHttpLogEntry(clientIp = "198.51.100.10", path = "/.env", statusCode = 404, userAgent = "Masscan/1.3.2", timestamp = now()),
    initHttpLogEntry(clientIp = "198.51.100.11", path = "/.env", statusCode = 404, userAgent = "Masscan/1.3.2", timestamp = now()),
    initHttpLogEntry(clientIp = "198.51.100.12", path = "/.env", statusCode = 404, userAgent = "Masscan/1.3.2", timestamp = now())
  ]

  for entry in distributedAttacks:
    let threat = analyzeEntry(entry)
    let clusterId = correlateStream(correlator, entry, threat)
    echo "  Correlating IP ", entry.clientIp, " -> Cluster ID: ", (if clusterId.isSome: clusterId.get() else: "none")

  echo "  Discovered Clusters: ", correlator.clusters.len
  for cid, cluster in correlator.clusters:
    echo "    Cluster ", cid, ": ", cluster.ips.len, " unique IPs, ", cluster.entries.len, " probes, risk: ", cluster.aggregateRisk, "/100"
  echo ""

  # 6. All-in-One Convenience Pipeline (enrichAndAnalyze)
  echo "[6] All-in-One Convenience Pipeline (enrichAndAnalyze):"
  let testLogLine = "185.220.101.5 - - [23/Apr/2024:12:05:00 +0000] \"GET /wp-config.php.bak HTTP/1.1\" 404 162 \"-\" \"Go-http-client/1.1\""
  let optRecord = enrichAndAnalyze(testLogLine, correlator = correlator)
  if optRecord.isSome:
    let rec = optRecord.get()
    echo "  Rendered Stream Line (Monochrome):"
    echo "  ", renderStreamLine(rec, colorize = false)
    echo "  Rendered Stream Line (ANSI Badges):"
    echo "  ", renderStreamLine(rec, colorize = true)
  echo ""

  # 7. Zero Global State & Reentrancy Demonstration (Item 03)
  echo "[7] Zero Global State & Reentrancy (Item 03):"
  let isolatedCorrelatorA = newActorCorrelator()
  let isolatedCorrelatorB = newActorCorrelator()
  echo "  Correlator A initialized with ", isolatedCorrelatorA.clusters.len, " clusters."
  echo "  Correlator B initialized with ", isolatedCorrelatorB.clusters.len, " clusters."
  echo "  Library procedures operate strictly on isolated data structures."
  echo ""

  echo "=== Programmatic Library Consumption Complete ==="

when isMainModule:
  main()

## Test suite for Phase 07 / Category B: Public Library API & Pipeline Orchestration.

import unittest
import std/[strutils, options, tables, times]
import http_logviewer

suite "Public Library API - Module Interface & Clean Embedding (Phase 07 / Category B / Item 01)":
  test "Item 01: Core types and models accessible directly via http_logviewer root import":
    # Verify core type declarations are accessible without deep submodule imports
    var entry = initHttpLogEntry(
      clientIp = "93.184.216.34",
      timestamp = now(),
      `method` = HttpGet,
      path = "/index.html",
      statusCode = 200,
      bytesSent = 1024,
      referer = "https://example.com",
      userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
      rawLine = "raw"
    )
    check entry.clientIp == "93.184.216.34"
    check entry.`method` == HttpGet
    check entry.statusCode == 200

    # Verify threat models and enums are exposed
    check CategoryRealUser is ActorCategory
    check CategoryBadActorHacker is ActorCategory
    check ThreatSensitiveFile is ThreatFlag

    # Verify configuration types are exposed
    let cfg = defaultViewerConfig()
    check cfg.colorOutput == true
    check cfg.outputFormat == FormatStreamTable

    # Verify enrichment types are exposed
    let geo = GeoLocation(
      ip: "127.0.0.1",
      countryCode: "LO",
      countryName: "Local Network",
      flagEmoji: "🏠",
      isPrivate: true
    )
    check geo.isPrivate == true

  test "Item 01: Renderer formatters and badges accessible via root import":
    let codeBadge = formatStatusCode(404, colorize = false)
    check "404" in codeBadge

    let intentBadge = formatIntentBadge(CategoryBadActorHacker, colorize = false)
    check "HACKER" in intentBadge

    let ticker = initStatusTicker()
    check ticker.totalLines == 0

suite "Public Library API - High-Level Procedures (Phase 07 / Category B / Item 02)":
  test "Item 02: parseLine parses CLF, Combined, and JSON lines":
    # CLF line
    let clfLine = "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif HTTP/1.0\" 200 2326"
    let optClf = parseLine(clfLine)
    check optClf.isSome
    let entryClf = optClf.get()
    check entryClf.clientIp == "127.0.0.1"
    check entryClf.`method` == HttpGet
    check entryClf.path == "/apache_pb.gif"
    check entryClf.statusCode == 200
    check entryClf.bytesSent == 2326

    # Combined line
    let combinedLine = "192.168.1.100 - - [23/Apr/2024:08:14:22 +0000] \"POST /api/v1/login HTTP/1.1\" 401 128 \"https://app.example.com/\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\""
    let optCombined = parseLine(combinedLine)
    check optCombined.isSome
    let entryCombined = optCombined.get()
    check entryCombined.clientIp == "192.168.1.100"
    check entryCombined.`method` == HttpPost
    check entryCombined.path == "/api/v1/login"
    check entryCombined.statusCode == 401
    check entryCombined.bytesSent == 128
    check entryCombined.referer == "https://app.example.com/"
    check entryCombined.userAgent == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

    # JSON line
    let jsonLine = "{\"remote_addr\": \"203.0.113.195\", \"time_local\": \"23/Apr/2024:09:12:01 +0000\", \"request\": \"GET /admin HTTP/1.1\", \"status\": 403, \"body_bytes_sent\": 512, \"http_referer\": \"-\", \"http_user_agent\": \"curl/7.68.0\"}"
    let optJson = parseLine(jsonLine)
    check optJson.isSome
    let entryJson = optJson.get()
    check entryJson.clientIp == "203.0.113.195"
    check entryJson.statusCode == 403
    check entryJson.path == "/admin"

    # In-place parseLine overload
    var inPlaceEntry: HttpLogEntry
    let ok = parseLine(combinedLine, inPlaceEntry)
    check ok == true
    check inPlaceEntry.statusCode == 401

    # Malformed line returns none
    let optBad = parseLine("this is not a valid http log line")
    check optBad.isNone

    var badInPlace: HttpLogEntry
    check parseLine("", badInPlace) == false

  test "Item 02: enrichGeo and enrichWithGeo resolve IP metadata and private IPs":
    # Private / Local IPs
    let localGeo = enrichGeo("127.0.0.1")
    check localGeo.isPrivate == true
    check localGeo.countryCode == "LO"
    check localGeo.flagEmoji == "🏠"

    let rfc1918 = enrichGeo("192.168.1.50")
    check rfc1918.isPrivate == true
    check rfc1918.flagEmoji == "🏠"

    # Spec 07 alias enrichWithGeo
    let aliasGeo = enrichWithGeo("10.0.0.1")
    check aliasGeo.isPrivate == true

    # Pre-instantiated GeoIpEngine overload
    let engine = newGeoIpEngine()
    let engineGeo = enrichGeo(engine, "172.16.0.1")
    check engineGeo.isPrivate == true
    let aliasEngineGeo = enrichWithGeo(engine, "127.0.0.1")
    check aliasEngineGeo.isPrivate == true

  test "Item 02: analyzeEntry and analyzeRequest evaluate threats accurately":
    # Benign real user request
    let benignEntry = initHttpLogEntry(
      clientIp = "93.184.216.34",
      `method` = HttpGet,
      path = "/index.html",
      statusCode = 200,
      userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    )
    let benignThreat = analyzeEntry(benignEntry)
    check benignThreat.category == CategoryRealUser
    check benignThreat.score < 25
    check benignThreat.isHacker == false

    # Spec 07 alias analyzeRequest
    let aliasThreat = analyzeRequest(benignEntry)
    check aliasThreat.category == CategoryRealUser

    # Malicious hacker attack probe (.env)
    let attackEntry = initHttpLogEntry(
      clientIp = "185.220.101.5",
      `method` = HttpGet,
      path = "/.env",
      statusCode = 404,
      userAgent = "curl/7.88.1"
    )
    let attackThreat = analyzeEntry(attackEntry)
    check attackThreat.score >= 50
    check attackThreat.category in {CategoryBadActorHacker, CategorySuspicious}
    check attackThreat.isHacker == true
    check ThreatSensitiveFile in attackThreat.flags

    # Offensive scanner tool (sqlmap)
    let sqlmapEntry = initHttpLogEntry(
      clientIp = "45.154.255.88",
      `method` = HttpGet,
      path = "/products.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users",
      statusCode = 500,
      userAgent = "sqlmap/1.7.2#stable"
    )
    let sqlmapThreat = analyzeEntry(sqlmapEntry)
    check sqlmapThreat.score >= 80
    check sqlmapThreat.isHacker == true
    check ThreatSqlInjection in sqlmapThreat.flags

  test "Item 02: correlateStream and correlateEvent cluster multi-IP probes":
    let correlator = newActorCorrelator(windowSeconds = 1800)
    let entry1 = initHttpLogEntry(
      clientIp = "198.51.100.1",
      path = "/wp-login.php",
      statusCode = 404,
      userAgent = "WPScan v3.8.22",
      timestamp = now()
    )
    let threat1 = analyzeEntry(entry1)
    let clusterId1 = correlateStream(correlator, entry1, threat1)
    check clusterId1.isSome

    # Second request from a different IP in the same attack pattern
    let entry2 = initHttpLogEntry(
      clientIp = "198.51.100.2",
      path = "/wp-login.php",
      statusCode = 404,
      userAgent = "WPScan v3.8.22",
      timestamp = now()
    )
    let threat2 = analyzeEntry(entry2)
    let clusterId2 = correlateEvent(correlator, entry2, threat2)
    check clusterId2.isSome
    check clusterId2.get() == clusterId1.get()
    check correlator.clusters.len >= 1

    # Batch correlateStream overload
    let batchEntries = @[entry1, entry2]
    let batchClusters = correlateStream(batchEntries, windowSeconds = 1800)
    check batchClusters.len >= 1

  test "Item 02: enrichAndAnalyze provides an end-to-end convenience pipeline":
    let rawLine = "185.220.101.5 - - [23/Apr/2024:12:00:00 +0000] \"GET /.git/config HTTP/1.1\" 404 162 \"-\" \"nuclei/v2.9.0\""
    let correlator = newActorCorrelator()
    let optRecord = enrichAndAnalyze(rawLine, correlator = correlator)
    check optRecord.isSome
    let record = optRecord.get()
    check record.entry.clientIp == "185.220.101.5"
    check record.entry.statusCode == 404
    check record.threat.isHacker == true
    check record.clusterId.isSome

    # Unparseable line returns none
    let badRecord = enrichAndAnalyze("random garbage string")
    check badRecord.isNone

suite "Public Library API - Reentrancy & Zero Global State (Phase 07 / Category B / Item 03)":
  test "Item 03: Multiple independent correlator instances do not cross-contaminate state":
    let correlatorA = newActorCorrelator(windowSeconds = 300)
    let correlatorB = newActorCorrelator(windowSeconds = 300)

    let entryA = initHttpLogEntry(
      clientIp = "103.21.244.1",
      path = "/administrator/index.php",
      statusCode = 404,
      userAgent = "Nikto/2.1.6",
      timestamp = now()
    )
    let threatA = analyzeEntry(entryA)
    let cidA = correlateStream(correlatorA, entryA, threatA)
    check cidA.isSome

    # Verify correlatorB is untouched and contains 0 clusters
    check correlatorA.clusters.len == 1
    check correlatorB.clusters.len == 0

  test "Item 03: Deterministic and reentrant evaluation without mutable side effects":
    let entry = initHttpLogEntry(
      clientIp = "192.0.2.1",
      path = "/.env",
      statusCode = 404,
      userAgent = "curl/7.88.1"
    )
    # Repeated invocations produce identical results
    let threatFirst = analyzeEntry(entry)
    let threatSecond = analyzeEntry(entry)
    check threatFirst.score == threatSecond.score
    check threatFirst.category == threatSecond.category
    check threatFirst.flags == threatSecond.flags

suite "Public Library API - Programmatic Consumption Verification (Phase 07 / Category B / Item 05)":
  test "Item 05: Third-party simulation consuming all library procs":
    let logLine = "127.0.0.1 - - [23/Apr/2024:14:22:10 +0000] \"GET /index.html HTTP/1.1\" 200 4520 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36\""
    let parsed = parseLine(logLine)
    check parsed.isSome
    let entry = parsed.get()

    let geo = enrichGeo(entry.clientIp)
    check geo.isPrivate == true

    let threat = analyzeEntry(entry)
    check threat.category == CategoryRealUser

    let correlator = newActorCorrelator()
    let clusterId = correlateStream(correlator, entry, threat)
    check clusterId.isNone # Innocent user is not clustered as attacker

    let record = initEnrichedLogRecord(entry, geo, threat, clusterId)
    let streamText = renderStreamLine(record, colorize = false)
    check "200" in streamText
    check "/index.html" in streamText

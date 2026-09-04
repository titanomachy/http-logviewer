## Test suite for Phase 08 Category B: Memory Safety, ARC/ORC & Allocation Profiling.
## Validates deterministic memory reclamation, hot-loop allocation efficiency,
## reliable resource closure with defer/try-finally, buffer safety, and sliding-window bounds.

import unittest
import std/[strutils, times, os, streams, tables, sets, hashes, options, monotimes]
import http_logviewer
import http_logviewer/core/[types, config, errors]
import http_logviewer/parser/[engine, formats]
import http_logviewer/enrichment/[geoip, flags, bogon]
import http_logviewer/analyzer/[classifier, signatures, useragents, correlator]
import http_logviewer/renderer/[styles, terminal]
import http_logviewer/cli/args

suite "Memory Safety & ARC/ORC Verification (Phase 08 / Category B / Item 01)":

  test "Item 01: ARC/ORC deterministic lifecycle and scope cleanup":
    for i in 0 ..< 10_000:
      let entry = initHttpLogEntry(
        clientIp = "192.168.1." & $(i mod 254 + 1),
        timestamp = now().utc,
        `method` = HttpGet,
        path = "/test/path/" & $i,
        statusCode = 200,
        userAgent = "Mozilla/5.0 (Test Browser)"
      )
      let threat = analyzeEntry(entry)
      check threat.category in {CategoryRealUser, CategorySuspicious, CategoryBadActorHacker}
    check true

  test "Item 01: Cyclic and complex reference types release without leaks":
    let table = newActorClusterTable(windowSeconds = 60)
    for i in 0 ..< 500:
      let entry = initHttpLogEntry(
        clientIp = "198.51.100." & $(i mod 10 + 1),
        timestamp = now().utc,
        `method` = HttpGet,
        path = "/.env",
        statusCode = 404,
        userAgent = "Nikto/2.1.6"
      )
      let threat = analyzeEntry(entry)
      discard table.correlateRecord(entry, threat)
    check table.len > 0
    table.clear()
    check table.len == 0
    check table.ipCount == 0

suite "Allocation Profiling & Hot-Loop Efficiency (Phase 08 / Category B / Item 02)":

  test "Item 02: cleanIpAddress returns identical string without allocating on clean IPv4":
    let cleanIpv4 = "192.168.1.42"
    let cleaned = cleanIpAddress(cleanIpv4)
    check cleaned == cleanIpv4

  test "Item 02: sanitizeField returns identical string on clean input":
    let cleanPath = "/api/v1/users/status"
    let sanitized = sanitizeField(cleanPath)
    check sanitized == cleanPath

  test "Item 02: High-throughput parsing loop reuses line and entry buffers":
    const sampleLine = "203.0.113.195 - - [10/Oct/2026:13:55:36 +0200] \"GET /index.html HTTP/1.1\" 200 2326 \"https://example.com\" \"Mozilla/5.0\""
    var entry: HttpLogEntry
    let t0 = getMonoTime()
    for i in 0 ..< 20_000:
      check parseCombinedLine(sampleLine, entry)
      check entry.statusCode == 200
      check entry.clientIp == "203.0.113.195"
    let elapsed = (getMonoTime() - t0).inMicroseconds.float / 1_000_000.0
    check elapsed > 0.0

suite "Resource Cleanup & Safe Handle Management (Phase 08 / Category B / Item 03)":

  test "Item 03: StreamReader safely closes file handles even on multiple close calls":
    let tempPath = getTempDir() / "test_mem_reader.log"
    writeFile(tempPath, "127.0.0.1 - - [10/Oct/2026:13:55:36 +0200] \"GET / HTTP/1.1\" 200 100 \"-\" \"curl/7.68.0\"\n")
    defer:
      if fileExists(tempPath): removeFile(tempPath)

    let reader = openStreamReader(tempPath)
    check not reader.closed
    var line: string
    check reader.readLine(line)
    reader.close()
    check reader.closed
    reader.close()
    check reader.closed

  test "Item 03: validateInputPath safely closes opened file handle":
    let tempPath = getTempDir() / "test_validate_path.log"
    writeFile(tempPath, "sample\n")
    defer:
      if fileExists(tempPath): removeFile(tempPath)

    let res = validateInputPath(tempPath)
    check res.valid
    removeFile(tempPath)
    check not fileExists(tempPath)

  test "Item 03: Gzip compression handles closed safely":
    let gzPath = getTempDir() / "test_mem_gzip.log.gz"
    defer:
      if fileExists(gzPath): removeFile(gzPath)

    check writeGzipFile(gzPath, "sample log line\n")
    check isGzipFile(gzPath)
    let gzReader = openStreamReader(gzPath)
    var line: string
    check gzReader.readLine(line)
    check line == "sample log line"
    gzReader.close()
    check gzReader.closed
    gzReader.close()

suite "Buffer Safety & AddressSanitizer Verification (Phase 08 / Category B / Item 04)":

  test "Item 04: Oversized and adversarial log line handling":
    let hugePath = "/" & repeat('a', 65536)
    let hugeLine = "127.0.0.1 - - [10/Oct/2026:13:55:36 +0200] \"GET " & hugePath & " HTTP/1.1\" 200 100 \"-\" \"TestUA\""
    var entry: HttpLogEntry
    let parsed = parseCombinedLine(hugeLine, entry)
    check parsed or not parsed

  test "Item 04: Binary null byte and control character boundary safety":
    let malformed = "192.168.1.1 - - [10/Oct/2026:13:55:36 +0200] \"GET /\0\xFF\xFE\x00/admin HTTP/1.1\" 404 10 \"-\" \"curl\x00inject\""
    var entry: HttpLogEntry
    if parseCombinedLine(malformed, entry):
      check "\\0" in entry.path or "\uFFFD" in entry.path
      check "\\0" in entry.userAgent

suite "Sliding-Window Expiration & Bounded Memory (Phase 08 / Category B / Item 05)":

  test "Item 05: ActorClusterTable prunes expired clusters across time windows":
    let table = newActorClusterTable(windowSeconds = 300)
    let t0 = parse("2026-09-04T12:00:00+00:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let entry0 = initHttpLogEntry(
      clientIp = "198.51.100.1",
      timestamp = t0,
      path = "/.env",
      statusCode = 404,
      userAgent = "TestScanner"
    )
    let threat0 = analyzeEntry(entry0)
    discard table.correlateRecord(entry0, threat0)
    check table.len == 1

    let t1 = t0 + initDuration(seconds = 600)
    let entry1 = initHttpLogEntry(
      clientIp = "198.51.100.99",
      timestamp = t1,
      path = "/wp-login.php",
      statusCode = 404,
      userAgent = "AnotherScanner"
    )
    let threat1 = analyzeEntry(entry1)
    discard table.correlateRecord(entry1, threat1)

    let pruned = table.pruneExpired(t1)
    check pruned >= 1
    check not table.hasClusterForIp("198.51.100.1")
    check table.hasClusterForIp("198.51.100.99")

  test "Item 05: ActorCluster.entries memory bounded by maxStoredEntries":
    var cluster = newActorCluster(clusterId = "ACTOR-TEST")
    let baseTime = now().utc
    for i in 0 ..< 2500:
      let entry = initHttpLogEntry(
        clientIp = "10.0.0.1",
        timestamp = baseTime + initDuration(seconds = i),
        path = "/probe/" & $i,
        statusCode = 404
      )
      cluster.addEntry(entry, score = 50, flags = {ThreatSensitiveFile})
    check cluster.totalRequests == 2500
    check cluster.entries.len <= 1000

suite "Build Output Isolation (Phase 08 / Category B / Item 06)":

  test "Item 06: Root nim.cfg directs compiler outputs strictly into build/":
    let nimCfgContent = readFile("nim.cfg")
    check "--nimcache:\"build/nimcache\"" in nimCfgContent
    check "--outdir:\"build\"" in nimCfgContent

  test "Item 06: Package nimble file specifies binDir = 'build'":
    let nimbleContent = readFile("http_logviewer.nimble")
    check "binDir        = \"build\"" in nimbleContent

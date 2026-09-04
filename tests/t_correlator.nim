## Unit tests for Multi-IP Actor Grouping and Correlation Engine.
## Tests Phase 05 / Category A & Category B: Actor Fingerprints & Probe Sequence Correlation.

import std/[unittest, strutils, times, options, json, sets, tables, hashes, os]
import http_logviewer/core/types
import http_logviewer/analyzer/correlator
import http_logviewer/analyzer/classifier
import http_logviewer/parser/formats

suite "Actor Fingerprint Synthesis - User-Agent, Signature & Accept Header (Phase 05 / Category A / Item 01)":
  test "Item 01: normalizeUserAgent normalizes whitespace and casing":
    check normalizeUserAgent("  Mozilla/5.0  (Windows NT 10.0; Win64; x64)  ") == "mozilla/5.0 (windows nt 10.0; win64; x64)"
    check normalizeUserAgent("sqlmap/1.7#stable   (https://sqlmap.org)") == "sqlmap/1.7#stable (https://sqlmap.org)"
    check normalizeUserAgent("   \t  \n  ") == ""
    check normalizeUserAgent("") == ""

  test "Item 01: normalizeAcceptHeader sorts and formats MIME types":
    check normalizeAcceptHeader("text/html, application/xhtml+xml, application/xml;q=0.9") == "application/xhtml+xml,application/xml;q=0.9,text/html"
    check normalizeAcceptHeader("*/*, text/html") == "*/*,text/html"
    check normalizeAcceptHeader("   ") == ""

  test "Item 01: generateProbeFingerprint produces identical hash across distinct IPs":
    let entryIp1 = initHttpLogEntry(
      clientIp = "198.51.100.1",
      path = "/.env",
      `method` = HttpGet,
      statusCode = 404,
      userAgent = "Custom-Exploit-Bot/1.0"
    )
    let entryIp2 = initHttpLogEntry(
      clientIp = "203.0.113.88",
      path = "/.env",
      `method` = HttpGet,
      statusCode = 404,
      userAgent = "Custom-Exploit-Bot/1.0"
    )
    let threat = initThreatProfile(
      score = 85,
      category = CategoryBadActorHacker,
      flags = {ThreatSensitiveFile},
      matchedSignatures = @["SensitiveFile:DotEnv"]
    )
    let fp1 = generateProbeFingerprint(entryIp1, threat, "text/html, */*")
    let fp2 = generateProbeFingerprint(entryIp2, threat, "*/*, text/html")
    check fp1 == fp2

  test "Item 01: generateActorFingerprint constructs structured fingerprint record":
    let entry = initHttpLogEntry(
      clientIp = "185.220.101.5",
      path = "/wp-login.php",
      `method` = HttpPost,
      statusCode = 404,
      userAgent = "WP-Scan-Distributed/2.4"
    )
    let threat = initThreatProfile(
      score = 70,
      category = CategoryBadActorHacker,
      flags = {ThreatCmsExploit},
      matchedSignatures = @["CmsExploit:WpLogin"]
    )
    let afp = generateActorFingerprint(entry, threat, "text/html")
    check afp.normalizedUa == "wp-scan-distributed/2.4"
    check afp.matchedSignatures == @["CmsExploit:WpLogin"]
    check afp.pathPattern == "/wp-login.php"
    check afp.hashHex.len == 16
    let jsonNode = %afp
    check jsonNode["hashHex"].getStr() == afp.hashHex
    check jsonNode["normalizedUa"].getStr() == "wp-scan-distributed/2.4"
    check ($afp).contains("wp-scan-distributed/2.4")

suite "Actor Fingerprint Synthesis - URL Path Sequence Hasher (Phase 05 / Category A / Item 02)":
  test "Item 02: normalizePathPattern masks dynamic IDs, UUIDs, and hashes":
    check normalizePathPattern("/users/12345/profile") == "/users/{id}/profile"
    check normalizePathPattern("/orders/0/items/999") == "/orders/{id}/items/{id}"
    check normalizePathPattern("/items/123e4567-e89b-12d3-a456-426614174000") == "/items/{uuid}"
    check normalizePathPattern("/blobs/a1b2c3d4e5f60718293a4b5c6d7e8f90") == "/blobs/{hash}"
    check normalizePathPattern("/.env?id=1") == "/.env"
    check normalizePathPattern("/WP-ADMIN/Setup.php") == "/wp-admin/setup.php"
    check normalizePathPattern("") == "/"

  test "Item 02: hashPathSequence creates distinct order-sensitive signatures":
    let seqA = @["/.env", "/wp-login.php", "/xmlrpc.php"]
    let seqB = @["/wp-login.php", "/.env", "/xmlrpc.php"]
    let hashA = hashPathSequence(seqA)
    let hashB = hashPathSequence(seqB)
    check hashA != hashB

  test "Item 02: hashPathSequence normalizes dynamic identifiers across identical attack sequences":
    let seqA = @["/api/users/123/delete", "/api/orders/456/status"]
    let seqB = @["/api/users/9999/delete", "/api/orders/77/status"]
    check hashPathSequence(seqA) == hashPathSequence(seqB)

  test "Item 02: formatPathSequence creates readable breadcrumb strings":
    let paths = @["/.env", "/wp-config.php.bak", "/actuator/env"]
    check formatPathSequence(paths) == "/.env -> /wp-config.php.bak -> /actuator/env"

  test "Item 02: ProbeSequenceTracker bounds history and maintains sequence hash":
    var tracker = initProbeSequenceTracker(maxHistory = 3)
    tracker.addPath("/probe1")
    tracker.addPath("/probe2")
    tracker.addPath("/probe3")
    check tracker.len == 3
    let hash3 = tracker.sequenceHash()

    tracker.addPath("/probe4")
    check tracker.len == 3
    # /probe1 was evicted, so sequence is /probe2 -> /probe3 -> /probe4
    check tracker.formatSequence() == "/probe2 -> /probe3 -> /probe4"
    check tracker.sequenceHash() != hash3

suite "Actor Fingerprint Synthesis - Query Parameter Normalization (Phase 05 / Category A / Item 03)":
  test "Item 03: isCacheBusterKey identifies standard ephemeral keys":
    check isCacheBusterKey("_")
    check isCacheBusterKey("cb")
    check isCacheBusterKey("nocache")
    check isCacheBusterKey("timestamp")
    check isCacheBusterKey("RAND")
    check not isCacheBusterKey("username")
    check not isCacheBusterKey("id")

  test "Item 03: normalizeQueryParams strips cache busters and sorts parameters":
    check normalizeQueryParams("?b=2&_=1719283749182&a=1&cb=xyz99") == "a=1&b=2"
    check normalizeQueryParams("rand=849102&timestamp=1700000000") == ""
    check normalizeQueryParams("action=delete;id=42;_t=999999") == "action=delete&id=42"
    check normalizeQueryParams("") == ""
    check normalizeQueryParams("?") == ""

  test "Item 03: normalizeUrl canonicalizes paths with varying cache-busters and parameter orders":
    let url1 = "/api/v1/search?q=exploit&_=1692837482"
    let url2 = "/api/v1/search?cb=random123&q=exploit"
    let url3 = "/api/v1/search?q=exploit"
    check normalizeUrl(url1) == "/api/v1/search?q=exploit"
    check normalizeUrl(url2) == "/api/v1/search?q=exploit"
    check normalizeUrl(url3) == "/api/v1/search?q=exploit"
    check hashQueryNormalizedUrl(url1) == hashQueryNormalizedUrl(url2)
    check hashQueryNormalizedUrl(url2) == hashQueryNormalizedUrl(url3)

suite "Actor Fingerprint Synthesis - Jaccard Similarity Scoring (Phase 05 / Category A / Item 04)":
  test "Item 04: jaccardSimilarity returns precise set overlap":
    var setA = initHashSet[string]()
    var setB = initHashSet[string]()
    check jaccardSimilarity(setA, setB) == 1.0

    for item in ["a", "b", "c"]: setA.incl(item)
    for item in ["b", "c", "d", "e"]: setB.incl(item)
    # Intersection = {b, c} (len 2), Union = {a, b, c, d, e} (len 5) => 2/5 = 0.4
    check abs(jaccardSimilarity(setA, setB) - 0.40) < 0.0001

    var setC = initHashSet[string]()
    for item in ["x", "y", "z"]: setC.incl(item)
    check jaccardSimilarity(setA, setC) == 0.0

  test "Item 04: pathSetSimilarity normalizes structural dynamic paths":
    let pathsA = ["/users/1/edit", "/orders/99", "/.env"]
    let pathsB = ["/users/999/edit", "/orders/12", "/wp-login.php"]
    # Normalized:
    # A: /users/{id}/edit, /orders/{id}, /.env (len 3)
    # B: /users/{id}/edit, /orders/{id}, /wp-login.php (len 3)
    # Intersection: {/users/{id}/edit, /orders/{id}} (len 2)
    # Union: {/users/{id}/edit, /orders/{id}, /.env, /wp-login.php} (len 4)
    # Jaccard = 2/4 = 0.50
    check abs(pathSetSimilarity(pathsA, pathsB) - 0.50) < 0.0001
    check isPathSimilarityAbove(pathsA, pathsB, 0.40)
    check not isPathSimilarityAbove(pathsA, pathsB, 0.60)

  test "Item 04: fingerprintSimilarity calculates composite actor correlation":
    let entryA = initHttpLogEntry(clientIp = "1.1.1.1", path = "/.env", userAgent = "BotNet/1.0")
    let entryB = initHttpLogEntry(clientIp = "2.2.2.2", path = "/.env", userAgent = "BotNet/1.0")
    let threat = initThreatProfile(score = 90, matchedSignatures = @["SensitiveFile:DotEnv"])
    let fpA = generateActorFingerprint(entryA, threat)
    let fpB = generateActorFingerprint(entryB, threat)
    check fingerprintSimilarity(fpA, fpB) == 1.0

suite "Actor Fingerprint Synthesis - Session & Token Extraction (Phase 05 / Category A / Item 05)":
  test "Item 05: extractTokensFromUrl extracts session and tracking keys":
    let url = "/admin/login?phpsessid=s3cr3ts3ss10n&token=botnet_runner_42&other=ignore"
    let tokens = extractTokensFromUrl(url)
    check tokens.len == 2
    check tokens[0].key.toLowerAscii() == "phpsessid"
    check tokens[0].value == "s3cr3ts3ss10n"
    check tokens[1].key.toLowerAscii() == "token"
    check tokens[1].value == "botnet_runner_42"

  test "Item 05: extractTokensFromRawLine finds session cookies in raw logs":
    let raw = "192.0.2.1 - - [01/Jan/2026:12:00:00 +0000] \"GET /api HTTP/1.1\" 200 123 \"-\" \"curl\" \"PHPSESSID=session998877; api_key=key_alpha_1\""
    let tokens = extractTokensFromRawLine(raw)
    check tokens.len >= 2
    var foundPhp = false
    var foundKey = false
    for t in tokens:
      if t.key.toLowerAscii() == "phpsessid" and t.value == "session998877":
        foundPhp = true
      if t.key.toLowerAscii() == "api_key" and t.value == "key_alpha_1":
        foundKey = true
    check foundPhp
    check foundKey

  test "Item 05: hasSharedSessionToken links disparate IPs sharing tokens":
    let entry1 = initHttpLogEntry(
      clientIp = "198.51.100.5",
      path = "/search?token=distributed_cluster_xyz&q=test",
      `method` = HttpGet
    )
    let entry2 = initHttpLogEntry(
      clientIp = "203.0.113.99",
      path = "/checkout?token=distributed_cluster_xyz&step=1",
      `method` = HttpPost
    )
    let entry3 = initHttpLogEntry(
      clientIp = "192.0.2.77",
      path = "/search?token=unrelated_token&q=test",
      `method` = HttpGet
    )
    check hasSharedSessionToken(entry1, entry2)
    check getSharedSessionTokens(entry1, entry2) == @["token=distributed_cluster_xyz"]
    check not hasSharedSessionToken(entry1, entry3)

suite "Actor Fingerprint Synthesis - Multi-IP Validation (Phase 05 / Category A / Item 06)":
  test "Item 06: Identical probe across 4 distinct IPs produces identical fingerprint":
    let ips = ["185.220.101.5", "45.154.255.12", "194.26.29.40", "91.240.118.82"]
    let threat = initThreatProfile(
      score = 85,
      category = CategoryBadActorHacker,
      flags = {ThreatSensitiveFile},
      matchedSignatures = @["SensitiveFile:DotEnv"]
    )
    var fingerprints: seq[ActorFingerprint] = @[]
    for ip in ips:
      let entry = initHttpLogEntry(
        clientIp = ip,
        path = "/.env",
        `method` = HttpGet,
        statusCode = 404,
        userAgent = "Masscan/1.3.2 (https://github.com/robertdavidgraham/masscan)"
      )
      let fp = generateActorFingerprint(entry, threat, "*/*")
      fingerprints.add(fp)

    check fingerprints.len == 4
    for i in 1 ..< fingerprints.len:
      check fingerprints[i].rawHash == fingerprints[0].rawHash
      check fingerprints[i].hashHex == fingerprints[0].hashHex
      check fingerprints[i] == fingerprints[0]

  test "Item 06: Rotating IPs with cache-busting and parameter shuffling correlate 100%":
    let node1 = initHttpLogEntry(
      clientIp = "198.51.100.10",
      path = "/wp-login.php?action=login&_=171928374",
      `method` = HttpPost,
      userAgent = "WP-Scan-Campaign-2026"
    )
    let node2 = initHttpLogEntry(
      clientIp = "203.0.113.55",
      path = "/wp-login.php?cb=998877&action=login",
      `method` = HttpPost,
      userAgent = "WP-Scan-Campaign-2026"
    )
    let threat = initThreatProfile(
      score = 75,
      category = CategoryBadActorHacker,
      flags = {ThreatCmsExploit},
      matchedSignatures = @["CmsExploit:WpLogin"]
    )
    let fp1 = generateActorFingerprint(node1, threat)
    let fp2 = generateActorFingerprint(node2, threat)
    check fp1.rawHash == fp2.rawHash
    check fp1.hashHex == fp2.hashHex
    check fp1.pathPattern == fp2.pathPattern

  test "Item 06: Synchronized probe sequence across 5 distinct nodes produces matching sequence signature":
    let nodeIps = ["103.21.244.2", "141.101.120.15", "173.245.48.8", "190.93.240.1", "198.41.128.5"]
    let attackSequence = @["/.env", "/wp-config.php", "/xmlrpc.php", "/actuator/env"]
    let expectedHash = hashPathSequence(attackSequence)

    for ip in nodeIps:
      var tracker = initProbeSequenceTracker(maxHistory = 10)
      for p in attackSequence:
        tracker.addPath(p)
      check tracker.sequenceHash() == expectedHash

  test "Item 06: Dissimilar traffic from different IPs maintains distinct fingerprints":
    let hackerEntry = initHttpLogEntry(
      clientIp = "185.220.101.5",
      path = "/.env",
      `method` = HttpGet,
      userAgent = "sqlmap/1.7"
    )
    let hackerThreat = initThreatProfile(
      score = 90,
      category = CategoryBadActorHacker,
      flags = {ThreatSensitiveFile},
      matchedSignatures = @["SensitiveFile:DotEnv"]
    )
    let humanEntry = initHttpLogEntry(
      clientIp = "192.0.2.1",
      path = "/index.html",
      `method` = HttpGet,
      userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )
    let humanThreat = initThreatProfile(
      score = 0,
      category = CategoryRealUser
    )
    let fpHacker = generateActorFingerprint(hackerEntry, hackerThreat)
    let fpHuman = generateActorFingerprint(humanEntry, humanThreat)
    check fpHacker.rawHash != fpHuman.rawHash
    check fingerprintSimilarity(fpHacker, fpHuman) < 0.20

suite "Sliding Time Window Tracker (Phase 05 / Category B / Item 01)":
  test "Item 01: initSlidingWindowTracker configures custom and default windows":
    let trackerDefault = initSlidingWindowTracker()
    check trackerDefault.windowSeconds == 1800
    check trackerDefault.windowMinutes == 30.0
    check trackerDefault.windowDuration.inSeconds == 1800

    let tracker5m = initSlidingWindowTracker(300)
    check tracker5m.windowSeconds == 300
    check tracker5m.windowMinutes == 5.0
    check tracker5m.windowDuration.inSeconds == 300

    let tracker60m = initSlidingWindowTracker(3600)
    check tracker60m.windowSeconds == 3600
    check tracker60m.windowMinutes == 60.0

  test "Item 01: isWithinWindow evaluates temporal proximity":
    let tracker = initSlidingWindowTracker(1800)
    let t0 = parse("2026-09-04T02:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let t10m = parse("2026-09-04T02:10:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let t40m = parse("2026-09-04T02:40:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")

    check tracker.isWithinWindow(t0, t10m)
    check not tracker.isWithinWindow(t0, t40m)

  test "Item 01: isExpired identifies stale clusters against currentTime":
    let tracker = initSlidingWindowTracker(1800)
    let lastSeen = parse("2026-09-04T02:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let curActive = parse("2026-09-04T02:25:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let curExpired = parse("2026-09-04T02:35:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")

    check not tracker.isExpired(lastSeen, curActive)
    check tracker.isExpired(lastSeen, curExpired)

  test "Item 01: pruneExpired purges stale clusters and maps":
    let table = newActorClusterTable(windowSeconds = 600)
    let t0 = parse("2026-09-04T02:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let t5m = parse("2026-09-04T02:05:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let t20m = parse("2026-09-04T02:20:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")

    let entryOld = initHttpLogEntry(clientIp = "192.0.2.1", path = "/.env", timestamp = t0, userAgent = "OldBot")
    let entryRecent = initHttpLogEntry(clientIp = "198.51.100.1", path = "/backup.sql", timestamp = t5m, userAgent = "RecentBot")
    let threatOld = initThreatProfile(score = 80, category = CategoryBadActorHacker, matchedSignatures = @["SensitiveFile:DotEnv"])
    let threatRecent = initThreatProfile(score = 80, category = CategoryBadActorHacker, matchedSignatures = @["SensitiveFile:Database"])

    let cidOld = table.correlateRecord(entryOld, threatOld)
    let cidRecent = table.correlateRecord(entryRecent, threatRecent)
    check cidOld.isSome
    check cidRecent.isSome
    check table.len == 2

    let pruned = table.pruneExpired(t20m)
    check pruned == 2
    check table.len == 0
    check not table.hasClusterForIp("192.0.2.1")
    check not table.hasClusterForIp("198.51.100.1")

suite "Multi-IP Probe Sequence Correlation (Phase 05 / Category B / Item 02)":
  test "Item 02: Disparate IPs executing identical attack sequence correlate into single cluster":
    let table = newActorClusterTable(windowSeconds = 1800)
    let t0 = parse("2026-09-04T02:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let t1 = parse("2026-09-04T02:02:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let t2 = parse("2026-09-04T02:04:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")

    let threats = [
      initThreatProfile(score = 80, category = CategoryBadActorHacker, matchedSignatures = @["SensitiveFile:DotEnv"]),
      initThreatProfile(score = 75, category = CategoryBadActorHacker, matchedSignatures = @["CmsExploit:WpLogin"])
    ]

    let n1_1 = initHttpLogEntry(clientIp = "198.51.100.1", path = "/.env", timestamp = t0, userAgent = "Dist-Bot/1.0")
    let n1_2 = initHttpLogEntry(clientIp = "198.51.100.1", path = "/wp-login.php", timestamp = t0, userAgent = "Dist-Bot/1.0")
    let cid1 = table.correlateRecord(n1_1, threats[0])
    discard table.correlateRecord(n1_2, threats[1])

    let n2_1 = initHttpLogEntry(clientIp = "203.0.113.88", path = "/.env", timestamp = t1, userAgent = "Dist-Bot/1.0")
    let n2_2 = initHttpLogEntry(clientIp = "203.0.113.88", path = "/wp-login.php", timestamp = t1, userAgent = "Dist-Bot/1.0")
    let cid2 = table.correlateRecord(n2_1, threats[0])
    discard table.correlateRecord(n2_2, threats[1])

    let n3_1 = initHttpLogEntry(clientIp = "192.0.2.44", path = "/.env", timestamp = t2, userAgent = "Dist-Bot/1.0")
    let n3_2 = initHttpLogEntry(clientIp = "192.0.2.44", path = "/wp-login.php", timestamp = t2, userAgent = "Dist-Bot/1.0")
    let cid3 = table.correlateRecord(n3_1, threats[0])
    discard table.correlateRecord(n3_2, threats[1])

    check cid1.isSome
    check cid2.isSome
    check cid3.isSome
    check cid1.get() == cid2.get()
    check cid2.get() == cid3.get()

    let cluster = table.getCluster(cid1.get()).get()
    check cluster.ips.len == 3
    check cluster.totalRequests == 6
    check cluster.ips.contains("198.51.100.1")
    check cluster.ips.contains("203.0.113.88")
    check cluster.ips.contains("192.0.2.44")

  test "Item 02: Late probe arriving outside correlation window creates new cluster":
    let table = newActorClusterTable(windowSeconds = 600)
    let t0 = parse("2026-09-04T02:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let tLate = parse("2026-09-04T05:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let threat = initThreatProfile(score = 80, category = CategoryBadActorHacker)

    let entry1 = initHttpLogEntry(clientIp = "1.1.1.1", path = "/.env", timestamp = t0, userAgent = "Bot/1.0")
    let cid1 = table.correlateRecord(entry1, threat)

    let entry2 = initHttpLogEntry(clientIp = "2.2.2.2", path = "/.env", timestamp = tLate, userAgent = "Bot/1.0")
    let cid2 = table.correlateRecord(entry2, threat)

    check cid1.isSome
    check cid2.isSome
    check cid1.get() != cid2.get()

suite "Residential Proxy Rotation Detection (Phase 05 / Category B / Item 03)":
  test "Item 03: Consecutive probes from distinct IPs within threshold flag proxy rotation":
    let table = newActorClusterTable(windowSeconds = 1800, proxyRotationThresholdSec = 10)
    let t0 = parse("2026-09-04T02:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let t1 = parse("2026-09-04T02:00:02+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let threat = initThreatProfile(score = 85, category = CategoryBadActorHacker, matchedSignatures = @["SensitiveFile:DotEnv"])

    let entryA = initHttpLogEntry(clientIp = "185.220.101.5", path = "/.env", timestamp = t0, userAgent = "ProxyBot/2.0")
    let entryB = initHttpLogEntry(clientIp = "45.154.255.12", path = "/.env", timestamp = t1, userAgent = "ProxyBot/2.0")

    let cidA = table.correlateRecord(entryA, threat)
    let cidB = table.correlateRecord(entryB, threat)

    check cidA.isSome
    check cidB.isSome
    check cidA.get() == cidB.get()

    let cluster = table.getCluster(cidA.get()).get()
    check cluster.proxyRotationDetected
    check cluster.isProxyRotating
    check cluster.proxyRotationCount >= 1

  test "Item 03: Probes from SAME IP do not trigger proxy rotation":
    let table = newActorClusterTable(windowSeconds = 1800, proxyRotationThresholdSec = 10)
    let t0 = parse("2026-09-04T02:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let t1 = parse("2026-09-04T02:00:02+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let threat = initThreatProfile(score = 85, category = CategoryBadActorHacker)

    let entryA = initHttpLogEntry(clientIp = "185.220.101.5", path = "/.env", timestamp = t0, userAgent = "SingleIpBot")
    let entryB = initHttpLogEntry(clientIp = "185.220.101.5", path = "/wp-login.php", timestamp = t1, userAgent = "SingleIpBot")

    let cidA = table.correlateRecord(entryA, threat)
    let cidB = table.correlateRecord(entryB, threat)

    let cluster = table.getCluster(cidA.get()).get()
    check not cluster.proxyRotationDetected
    check cluster.proxyRotationCount == 0

  test "Item 03: Probes from distinct IPs spaced far apart do not flag rotation":
    let table = newActorClusterTable(windowSeconds = 1800, proxyRotationThresholdSec = 10)
    let t0 = parse("2026-09-04T02:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let t60s = parse("2026-09-04T02:01:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let threat = initThreatProfile(score = 85, category = CategoryBadActorHacker)

    let entryA = initHttpLogEntry(clientIp = "10.0.0.1", path = "/.env", timestamp = t0, userAgent = "SlowBotA")
    let entryB = initHttpLogEntry(clientIp = "10.0.0.2", path = "/setup.php", timestamp = t60s, userAgent = "SlowBotB")

    discard table.correlateRecord(entryA, threat)
    let cidB = table.correlateRecord(entryB, threat)

    let clusterB = table.getCluster(cidB.get()).get()
    check not clusterB.proxyRotationDetected

suite "ActorClusterTable Dynamic IP Linking (Phase 05 / Category B / Item 04)":
  test "Item 04: linkIp and query methods manage dynamic mappings":
    let table = newActorClusterTable()
    let cluster = newActorCluster(clusterId = "ACTOR-TEST1", primaryUa = "TestUA")
    table.clusters["ACTOR-TEST1"] = cluster

    table.linkIp("192.168.1.50", cluster)
    table.linkIp("192.168.1.51", cluster)

    check table.hasClusterForIp("192.168.1.50")
    check table.hasClusterForIp("192.168.1.51")
    check not table.hasClusterForIp("192.168.1.99")

    let found = table.getClusterForIp("192.168.1.50")
    check found.isSome
    check found.get().clusterId == "ACTOR-TEST1"
    check found.get().ips.len == 2
    check table.ipCount == 2
    check table.len == 1

  test "Item 04: deleteCluster and clear clean up all auxiliary indexes":
    let table = newActorClusterTable()
    let c1 = newActorCluster(clusterId = "ACTOR-1")
    let c2 = newActorCluster(clusterId = "ACTOR-2")
    table.clusters["ACTOR-1"] = c1
    table.clusters["ACTOR-2"] = c2
    table.linkIp("1.1.1.1", c1)
    table.linkIp("2.2.2.2", c2)

    check table.len == 2
    check table.ipCount == 2

    table.deleteCluster("ACTOR-1")
    check table.len == 1
    check not table.hasClusterForIp("1.1.1.1")
    check table.hasClusterForIp("2.2.2.2")

    table.clear()
    check table.len == 0
    check table.ipCount == 0

suite "Cluster Risk Metrics Calculation (Phase 05 / Category B / Item 05)":
  test "Item 05: calculateClusterMetrics accurately computes risk posture":
    let tFirst = parse("2026-09-04T02:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let tLast = parse("2026-09-04T02:15:30+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")

    var ipSet = initHashSet[string]()
    ipSet.incl("1.1.1.1")
    ipSet.incl("2.2.2.2")
    ipSet.incl("3.3.3.3")

    let cluster = newActorCluster(
      clusterId = "ACTOR-METRIC1",
      primaryUa = "AttackerBot/1.0",
      ips = ipSet,
      totalRequests = 10,
      status404Count = 8,
      firstSeen = tFirst,
      lastSeen = tLast,
      highestThreatScore = 75,
      probedPaths = @["/.env", "/wp-login.php", "/xmlrpc.php"],
      proxyRotationDetected = true
    )

    let metrics = calculateClusterMetrics(cluster)
    check metrics.clusterId == "ACTOR-METRIC1"
    check metrics.totalRequests == 10
    check metrics.uniqueIps == 3
    check metrics.affectedTargets == 3
    check metrics.attackDurationSeconds == 930
    check metrics.status404Count == 8
    check abs(metrics.status404Ratio - 0.80) < 0.001
    check metrics.proxyRotationDetected
    check metrics.aggregateRisk == 100
    check metrics.severity == "Critical"

  test "Item 05: formatDuration formats time spans correctly":
    check formatDuration(initDuration(seconds = 45)) == "45s"
    check formatDuration(initDuration(minutes = 2, seconds = 15)) == "02m 15s"
    check formatDuration(initDuration(hours = 1, minutes = 10, seconds = 5)) == "01h 10m 05s"

  test "Item 05: ClusterRiskMetrics serializes to valid JSON and string representation":
    let metrics = ClusterRiskMetrics(
      clusterId: "ACTOR-JSON1",
      totalRequests: 5,
      uniqueIps: 2,
      affectedTargets: 3,
      attackDuration: initDuration(minutes = 10),
      attackDurationSeconds: 600,
      highestThreatScore: 60,
      aggregateRisk: 75,
      status404Count: 4,
      status404Ratio: 0.8,
      proxyRotationDetected: true,
      severity: "High"
    )
    let jsonNode = %metrics
    check jsonNode["clusterId"].getStr() == "ACTOR-JSON1"
    check jsonNode["totalRequests"].getInt() == 5
    check jsonNode["uniqueIps"].getInt() == 2
    check jsonNode["severity"].getStr() == "High"
    check ($metrics).contains("ACTOR-JSON1")
    check ($metrics).contains("ProxyRotation: true")

suite "5-Node Distributed Botnet Integration Test (Phase 05 / Category B / Item 06)":
  test "Item 06: Simulating a 5-node distributed botnet scanning an application":
    let table = newActorClusterTable(windowSeconds = 1800, proxyRotationThresholdSec = 10)

    let botnetNodes = [
      ("185.220.101.5",  "/.env",           parse("2026-09-04T02:10:01+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")),
      ("45.154.255.12",  "/.env",           parse("2026-09-04T02:10:03+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")),
      ("194.26.29.40",   "/wp-login.php",   parse("2026-09-04T02:10:05+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")),
      ("91.240.118.82",  "/xmlrpc.php",     parse("2026-09-04T02:10:07+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")),
      ("103.21.244.2",   "/actuator/env",   parse("2026-09-04T02:10:09+02:00", "yyyy-MM-dd'T'HH:mm:sszzz"))
    ]

    var clusterIds: seq[string] = @[]
    for (ip, targetPath, ts) in botnetNodes:
      let entry = initHttpLogEntry(
        clientIp = ip,
        timestamp = ts,
        path = targetPath,
        `method` = HttpGet,
        statusCode = 404,
        userAgent = "WP-Scan-Distributed/3.1 (Botnet-Fleet)"
      )
      let threat = evaluateThreat(entry)
      let cid = table.correlateRecord(entry, threat)
      check cid.isSome
      clusterIds.add(cid.get())

    check clusterIds.len == 5
    for i in 1 ..< clusterIds.len:
      check clusterIds[i] == clusterIds[0]

    let clusterId = clusterIds[0]
    let clusterOpt = table.getCluster(clusterId)
    check clusterOpt.isSome
    let cluster = clusterOpt.get()

    check cluster.ips.len == 5
    check cluster.totalRequests == 5
    check cluster.status404Count == 5
    check cluster.proxyRotationDetected

    let metrics = calculateClusterMetrics(cluster)
    check metrics.uniqueIps == 5
    check metrics.totalRequests == 5
    check metrics.affectedTargets == 4
    check metrics.proxyRotationDetected
    check metrics.severity == "Critical"
    check metrics.attackDurationSeconds == 8

  test "Item 06: Ingestion of tests/fixtures/distributed_botnet.log fixture verifies cluster grouping":
    let fixturePath = "tests/fixtures/distributed_botnet.log"
    check fileExists(fixturePath)

    let table = newActorClusterTable(windowSeconds = 1800, proxyRotationThresholdSec = 10)
    var lineCount = 0
    var assignedClusterId = ""

    for rawLine in lines(fixturePath):
      if rawLine.strip().len == 0: continue
      inc lineCount
      let entryOpt = parseCombinedLine(rawLine)
      check entryOpt.isSome
      let entry = entryOpt.get()
      let threat = evaluateThreat(entry)
      let cidOpt = table.correlateRecord(entry, threat)
      check cidOpt.isSome
      if assignedClusterId.len == 0:
        assignedClusterId = cidOpt.get()
      else:
        check cidOpt.get() == assignedClusterId

    check lineCount == 5
    check table.len == 1
    let cluster = table.getCluster(assignedClusterId).get()
    check cluster.ips.len == 5
    check cluster.proxyRotationDetected
    let metrics = calculateClusterMetrics(cluster)
    check metrics.uniqueIps == 5
    check metrics.severity == "Critical"

suite "Subnet CIDR Math & Subnet Grouping (Phase 05 / Category C / Item 01)":
  test "Item 01: ipv4ToSubnet formats /24 and arbitrary prefixes accurately":
    check ipv4ToSubnet("192.168.1.100") == "192.168.1.0/24"
    check ipv4ToSubnet("10.20.30.40:8080") == "10.20.30.0/24"
    check ipv4ToSubnet("172.16.5.9", 16) == "172.16.0.0/16"
    check ipv4ToSubnet("10.0.0.1", 8) == "10.0.0.0/8"
    check ipv4ToSubnet("invalid-ip") == ""

  test "Item 01: ipv6ToSubnet formats /64 and arbitrary prefixes":
    check ipv6ToSubnet("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3:0::/64"
    check ipv6ToSubnet("[2001:db8:abcd::1]:443") == "2001:db8:abcd:0::/64"
    check ipv6ToSubnet("invalid-ipv6") == ""

  test "Item 01: extractSubnetCidr handles both IPv4 and IPv6 automatically":
    check extractSubnetCidr("198.51.100.25") == "198.51.100.0/24"
    check extractSubnetCidr("2001:db8:abcd:ef01::2") == "2001:db8:abcd:ef01::/64"
    check extractSubnetCidr("") == ""

  test "Item 01: ipInSubnet evaluates network containment":
    check ipInSubnet("192.168.1.50", "192.168.1.0/24")
    check not ipInSubnet("192.168.2.50", "192.168.1.0/24")
    check ipInSubnet("10.0.5.99", "10.0.0.0/8")
    check ipInSubnet("2001:db8:85a3::1", "2001:db8:85a3::/64")
    check not ipInSubnet("2001:db8:9999::1", "2001:db8:85a3::/64")

  test "Item 01: Distinct IPs within same /24 subnet correlate into single cluster":
    let table = newActorClusterTable(windowSeconds = 1800)
    let t0 = parse("2026-09-04T05:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let t1 = parse("2026-09-04T05:02:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")

    let entry1 = initHttpLogEntry(
      clientIp = "198.51.100.10",
      timestamp = t0,
      path = "/.env",
      `method` = HttpGet,
      statusCode = 404,
      userAgent = "Subnet-Scanner/1.0"
    )
    let entry2 = initHttpLogEntry(
      clientIp = "198.51.100.88",
      timestamp = t1,
      path = "/wp-config.php",
      `method` = HttpGet,
      statusCode = 404,
      userAgent = "Subnet-Scanner/1.0"
    )

    let threat1 = evaluateThreat(entry1)
    let threat2 = evaluateThreat(entry2)
    let cid1 = table.correlateRecord(entry1, threat1)
    let cid2 = table.correlateRecord(entry2, threat2)

    check cid1.isSome
    check cid2.isSome
    check cid1.get() == cid2.get()

    let cluster = table.getCluster(cid1.get()).get()
    check cluster.ips.len == 2
    check cluster.subnets.contains("198.51.100.0/24")

suite "Datacenter & Hosting Provider Identification (Phase 05 / Category C / Item 02)":
  test "Item 02: Identify major hosting providers (DigitalOcean, OVH, Hetzner, AWS, Choopa)":
    # DigitalOcean
    let doInfo = identifyHostingProvider("159.65.10.20")
    check doInfo.provider == ProviderDigitalOcean
    check doInfo.providerName == "DigitalOcean"
    check doInfo.asn == "AS14061"
    check doInfo.isDatacenter
    check isKnownDatacenter("167.99.1.5")
    check isKnownDatacenter("138.68.50.2")

    # OVH
    let ovhInfo = identifyHostingProvider("198.27.70.1")
    check ovhInfo.provider == ProviderOVH
    check ovhInfo.providerName == "OVH"
    check ovhInfo.asn == "AS16276"
    check ovhInfo.isDatacenter
    check isKnownDatacenter("51.254.10.5")

    # Hetzner
    let hetznerInfo = identifyHostingProvider("78.46.100.1")
    check hetznerInfo.provider == ProviderHetzner
    check hetznerInfo.providerName == "Hetzner"
    check hetznerInfo.asn == "AS24940"
    check hetznerInfo.isDatacenter
    check isKnownDatacenter("136.243.5.10")
    check isKnownDatacenter("65.108.1.1")

    # AWS
    let awsInfo = identifyHostingProvider("3.5.10.20")
    check awsInfo.provider == ProviderAWS
    check awsInfo.providerName == "AWS"
    check awsInfo.asn == "AS16509"
    check awsInfo.isDatacenter
    check isKnownDatacenter("52.1.2.3")

    # Choopa / Vultr
    let choopaInfo = identifyHostingProvider("45.32.1.2")
    check choopaInfo.provider == ProviderChoopa
    check choopaInfo.providerName == "Choopa/Vultr"
    check choopaInfo.asn == "AS20473"
    check choopaInfo.isDatacenter
    check isKnownDatacenter("108.61.5.10")

  test "Item 02: Residential, private LAN, and unmapped IPs are not flagged as datacenters":
    check not isKnownDatacenter("192.168.1.1")
    check not isKnownDatacenter("10.0.0.1")
    check not isKnownDatacenter("127.0.0.1")
    check not isKnownDatacenter("::1")
    check not isKnownDatacenter("")

  test "Item 02: Cluster accumulates hosting provider telemetry and datacenter risk penalty":
    let table = newActorClusterTable(windowSeconds = 1800)
    let entry = initHttpLogEntry(
      clientIp = "136.243.5.10", # Hetzner
      timestamp = parse("2026-09-04T06:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz"),
      path = "/wp-login.php",
      `method` = HttpPost,
      statusCode = 404,
      userAgent = "Hetzner-Scanner/1.0"
    )
    let threat = evaluateThreat(entry)
    let cid = table.correlateRecord(entry, threat)
    check cid.isSome
    let cluster = table.getCluster(cid.get()).get()
    check cluster.hasDatacenterIps
    check cluster.hostingProviders.contains("Hetzner")

    let metrics = calculateClusterMetrics(cluster)
    check metrics.hasDatacenterIps
    check metrics.hostingProviders.contains("Hetzner")
    check metrics.aggregateRisk == min(100, threat.score + 10) # Datacenter penalty applied

suite "Synchronized Burst Request Detection (Phase 05 / Category C / Item 03)":
  test "Item 03: Distinct IPs within milliseconds trigger synchronized burst detection":
    let table = newActorClusterTable(windowSeconds = 1800, burstThresholdMs = 1000)
    let t0 = parse("2026-09-04T07:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    # 200 ms later:
    let t1 = t0 + initDuration(milliseconds = 200)

    let entry1 = initHttpLogEntry(
      clientIp = "192.0.2.1",
      timestamp = t0,
      path = "/.env",
      `method` = HttpGet,
      statusCode = 404,
      userAgent = "BurstBot/1.0"
    )
    let entry2 = initHttpLogEntry(
      clientIp = "192.0.2.2",
      timestamp = t1,
      path = "/.env",
      `method` = HttpGet,
      statusCode = 404,
      userAgent = "BurstBot/1.0"
    )

    let threat1 = evaluateThreat(entry1)
    let threat2 = evaluateThreat(entry2)
    let cid1 = table.correlateRecord(entry1, threat1)
    let cid2 = table.correlateRecord(entry2, threat2)

    check cid1.isSome
    check cid2.isSome
    check cid1.get() == cid2.get()

    let cluster = table.getCluster(cid1.get()).get()
    check cluster.synchronizedBurstDetected
    check cluster.synchronizedBurstCount >= 1
    check isSynchronizedBurst(cluster)

  test "Item 03: Probes spaced far apart do not flag synchronized burst":
    let table = newActorClusterTable(windowSeconds = 1800, burstThresholdMs = 500)
    let t0 = parse("2026-09-04T07:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let t1 = parse("2026-09-04T07:00:30+02:00", "yyyy-MM-dd'T'HH:mm:sszzz") # 30s apart

    let entry1 = initHttpLogEntry(
      clientIp = "192.0.2.10",
      timestamp = t0,
      path = "/probe",
      `method` = HttpGet,
      statusCode = 404
    )
    let entry2 = initHttpLogEntry(
      clientIp = "192.0.2.20",
      timestamp = t1,
      path = "/probe",
      `method` = HttpGet,
      statusCode = 404
    )
    let (isBurst, _) = table.detectSynchronizedBurst(entry2, 500)
    check not isBurst

suite "Human-Readable Cluster Tags (Phase 05 / Category C / Item 04)":
  test "Item 04: formatClusterTag produces standardized tags across threat types":
    var ipSet = initHashSet[string]()
    ipSet.incl("1.1.1.1")
    ipSet.incl("2.2.2.2")

    var provSet = initHashSet[string]()
    provSet.incl("DigitalOcean")

    var subSet = initHashSet[string]()
    subSet.incl("159.65.0.0/16")

    let clusterWp = newActorCluster(
      clusterId = "ACTOR-WP12",
      ips = ipSet,
      flags = {ThreatCmsExploit},
      hostingProviders = provSet,
      subnets = subSet
    )
    check formatClusterTag(clusterWp, 12) == "[Actor #12: 2 IPs (DigitalOcean /16) - WP-Scan Botnet]"

    let clusterEnv = newActorCluster(
      clusterId = "ACTOR-ENV1",
      ips = initHashSet[string](),
      flags = {ThreatSensitiveFile}
    )
    check formatClusterTag(clusterEnv, 1) == "[Actor #1: 1 IP - DotEnv/Config Scanner]"

    let clusterSqli = newActorCluster(
      clusterId = "ACTOR-SQL3",
      ips = ipSet,
      flags = {ThreatSqlInjection}
    )
    check formatClusterTag(clusterSqli, 3) == "[Actor #3: 2 IPs - SQLi Exploit Cluster]"

    let clusterBurst = newActorCluster(
      clusterId = "ACTOR-BST4",
      ips = ipSet,
      synchronizedBurstDetected = true
    )
    check formatClusterTag(clusterBurst, 4) == "[Actor #4: 2 IPs - Synchronized Burst Fleet]"

  test "Item 04: ClusterTag is preserved in ClusterRiskMetrics and JSON":
    var ipSet = initHashSet[string]()
    ipSet.incl("1.2.3.4")
    let cluster = newActorCluster(
      clusterId = "ACTOR-TAG1",
      ips = ipSet,
      clusterTag = "[Actor #9: 1 IP - DotEnv Probe]"
    )
    let metrics = calculateClusterMetrics(cluster)
    check metrics.clusterTag == "[Actor #9: 1 IP - DotEnv Probe]"
    check (%metrics)["clusterTag"].getStr() == "[Actor #9: 1 IP - DotEnv Probe]"
    check ($metrics).contains("[Actor #9: 1 IP - DotEnv Probe]")

suite "Subnet Math & Cluster Association Logic (Phase 05 / Category C / Item 05)":
  test "Item 05: parseCidr and CIDR boundary math":
    let (ip, prefix) = parseCidr("10.0.0.0/8")
    check ip == "10.0.0.0"
    check prefix == 8

    let (ip6, p6) = parseCidr("2001:db8::/32")
    check ip6 == "2001:db8::"
    check p6 == 32

    let (badIp, badP) = parseCidr("invalid")
    check badIp == "invalid"
    check badP == -1

  test "Item 05: Multi-subnet attack elevates cluster risk score":
    let cluster = newActorCluster(
      clusterId = "ACTOR-MULTI1",
      highestThreatScore = 50
    )
    cluster.ips.incl("1.1.1.1")
    cluster.ips.incl("2.2.2.2")
    cluster.subnets.incl("1.1.1.0/24")
    cluster.subnets.incl("2.2.2.0/24")

    let metrics = calculateClusterMetrics(cluster)
    # base 50 + multi-IP 10 + multi-subnet 5 = 65
    check metrics.aggregateRisk >= 65
    check metrics.subnets.len == 2

  test "Item 05: deleteCluster unmaps subnet indexes":
    let table = newActorClusterTable(windowSeconds = 1800)
    let entry = initHttpLogEntry(
      clientIp = "198.51.100.5",
      path = "/.env",
      `method` = HttpGet,
      statusCode = 404
    )
    let cid = table.correlateRecord(entry, evaluateThreat(entry)).get()
    check table.subnetToCluster.hasKey("198.51.100.0/24")

    table.deleteCluster(cid)
    check not table.subnetToCluster.hasKey("198.51.100.0/24")
    check table.len == 0






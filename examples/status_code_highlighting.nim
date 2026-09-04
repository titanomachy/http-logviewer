# Example: Background-Colored HTTP Status Highlighting & Terminal Layouts
# Demonstrates Phase 06 / Category A:
# - ANSI status code badge formatter for 2xx, 3xx, 401/403, 404, 5xx (Item 01)
# - Terminal color auto-detection (NO_COLOR, dumb terminals, TTY detection) (Item 02)
# - Monochromatic fallback mode when colors are suppressed (Item 03)
# - Visitor intent category badges ([REAL USER], [GOOD BOT], [SCRAPER], [HACKER]) (Item 04)
# - Country flag and ISO code aligned column formatting (Item 05)
# - Monospace visual string width calculation accounting for emojis and ANSI escapes (Item 06)
#
# Compile and run with:
#   nim r --path:src examples/status_code_highlighting.nim

import std/[strutils, times, options]
import http_logviewer/core/[types, config]
import http_logviewer/renderer/[styles, terminal]

proc main() =
  echo "=== http_logviewer: Status Code Highlighting & Terminal Layouts (Phase 06 / Category A) ==="
  echo ""

  # 1. Background-Colored HTTP Status Code Badges (Item 01)
  echo "[1] High-Contrast Background-Colored HTTP Status Badges (Item 01):"
  let sampleCodes = [200, 201, 301, 302, 400, 401, 403, 404, 500, 502, 503]
  for code in sampleCodes:
    let coloredBadge = formatStatusCode(code, colorize = true)
    let monoBadge = formatStatusCode(code, colorize = false)
    let desc = case code
               of 200: "OK / Success"
               of 201: "Created"
               of 301: "Moved Permanently"
               of 302: "Found / Redirect"
               of 400: "Bad Request"
               of 401: "Unauthorized"
               of 403: "Forbidden"
               of 404: "Not Found (Target Exploit / Probe)"
               of 500: "Internal Server Error"
               of 502: "Bad Gateway"
               of 503: "Service Unavailable"
               else: "Status Code"
    echo "  Status ", align($code, 3), " -> Badge: [", coloredBadge, "]  Mono: [", monoBadge, "]  (", desc, ")"
  echo ""

  # 2. Terminal Color Auto-Detection (Item 02)
  echo "[2] Terminal Color Auto-Detection & Environment Policies (Item 02):"
  echo "  Active TTY Detected:       ", detectColorSupport(none(bool))
  echo "  Auto Mode (TTY=true):      ", shouldColorize(ColorModeAuto, some(true))
  echo "  Auto Mode (TTY=false):     ", shouldColorize(ColorModeAuto, some(false))
  echo "  ColorModeAlways (forced):  ", shouldColorize(ColorModeAlways, some(false))
  echo "  ColorModeNever (suppressed):", shouldColorize(ColorModeNever, some(true))
  echo ""

  # 3. Monochromatic Fallback Mode (Item 03)
  echo "[3] Monochromatic Fallback Output (--no-color / piped redirection) (Item 03):"
  echo "  Raw 404 badge stripped:    \"", stripAnsi(formatStatusCode(404, true)), "\""
  echo "  Plain text 404 badge:      \"", formatStatusCode(404, false), "\""
  echo "  Plain text 200 badge:      \"", formatStatusCode(200, false), "\""
  echo "  Plain text 500 badge:      \"", formatStatusCode(500, false), "\""
  echo ""

  # 4. Intent Category Badges (Item 04)
  echo "[4] Visitor Intent Category Badges (Item 04):"
  let categories = [
    CategoryRealUser,
    CategoryVerifiedBot,
    CategoryFriendlyCrawler,
    CategoryCommercialBot,
    CategorySuspicious,
    CategoryBadActorHacker,
    CategoryUnknown
  ]
  for cat in categories:
    let colored = formatIntentBadge(cat, colorize = true)
    let mono = formatIntentBadge(cat, colorize = false)
    echo "  Category ", alignLeft($cat, 22), " -> ", colored, "  Mono: ", mono
  echo ""

  # 5. Country Flag & Code Column Alignment (Item 05)
  echo "[5] Country Flag & ISO Code Column Formatting (Item 05):"
  let geoSamples = [
    ("US", "🇺🇸", "United States"),
    ("DE", "🇩🇪", "Germany"),
    ("NL", "🇳🇱", "Netherlands"),
    ("JP", "🇯🇵", "Japan"),
    ("LO", "🏠", "Local LAN"),
    ("T1", "🧅", "Tor Exit Node"),
    ("XX", "🌐", "Unknown")
  ]
  for (cc, flag, name) in geoSamples:
    let colEmoji = formatCountryColumn(cc, flag, useEmoji = true, width = 7)
    let colAscii = formatCountryColumn(cc, flag, useEmoji = false, width = 7)
    echo "  Country: ", name.alignLeft(18), " Emoji Col: [", colEmoji, "] (width ", terminalDisplayWidth(colEmoji), ")  ASCII: [", colAscii, "]"
  echo ""

  # 6. Monospace Visual Width & Full Stream Line Integration (Item 06)
  echo "[6] Full Columnar Stream Line Rendering (Item 06):"
  echo "TIME      GEO    STATUS   INTENT        CLIENT IP        REQUEST                                   USER-AGENT"
  echo "------------------------------------------------------------------------------------------------------------------------"

  let demoRecords = [
    initEnrichedLogRecord(
      entry = initHttpLogEntry(
        clientIp = "172.56.21.89",
        timestamp = parse("2026-10-10 13:55:01", "yyyy-MM-dd HH:mm:ss"),
        `method` = HttpGet,
        path = "/blog/welcome",
        statusCode = 200,
        userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      ),
      geo = initGeoLocation(countryCode = "US", flagEmoji = "🇺🇸"),
      threat = initThreatProfile(score = 0, category = CategoryRealUser)
    ),
    initEnrichedLogRecord(
      entry = initHttpLogEntry(
        clientIp = "194.26.29.112",
        timestamp = parse("2026-10-10 13:55:02", "yyyy-MM-dd HH:mm:ss"),
        `method` = HttpGet,
        path = "/.env",
        statusCode = 404,
        userAgent = "python-requests/2.28.1"
      ),
      geo = initGeoLocation(countryCode = "DE", flagEmoji = "🇩🇪"),
      threat = initThreatProfile(score = 90, category = CategoryBadActorHacker)
    ),
    initEnrichedLogRecord(
      entry = initHttpLogEntry(
        clientIp = "45.154.255.8",
        timestamp = parse("2026-10-10 13:55:03", "yyyy-MM-dd HH:mm:ss"),
        `method` = HttpPost,
        path = "/wp-login.php",
        statusCode = 404,
        userAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
      ),
      geo = initGeoLocation(countryCode = "NL", flagEmoji = "🇳🇱"),
      threat = initThreatProfile(score = 95, category = CategoryBadActorHacker)
    ),
    initEnrichedLogRecord(
      entry = initHttpLogEntry(
        clientIp = "66.249.66.1",
        timestamp = parse("2026-10-10 13:55:04", "yyyy-MM-dd HH:mm:ss"),
        `method` = HttpGet,
        path = "/robots.txt",
        statusCode = 200,
        userAgent = "Googlebot/2.1 (+http://www.google.com/bot.html)"
      ),
      geo = initGeoLocation(countryCode = "US", flagEmoji = "🇺🇸"),
      threat = initThreatProfile(score = 0, category = CategoryVerifiedBot)
    ),
    initEnrichedLogRecord(
      entry = initHttpLogEntry(
        clientIp = "185.220.101.5",
        timestamp = parse("2026-10-10 13:55:05", "yyyy-MM-dd HH:mm:ss"),
        `method` = HttpGet,
        path = "/admin/config",
        statusCode = 403,
        userAgent = "curl/7.81.0"
      ),
      geo = initGeoLocation(countryCode = "DE", flagEmoji = "🇩🇪"),
      threat = initThreatProfile(score = 80, category = CategoryBadActorHacker)
    ),
    initEnrichedLogRecord(
      entry = initHttpLogEntry(
        clientIp = "192.168.1.50",
        timestamp = parse("2026-10-10 13:55:06", "yyyy-MM-dd HH:mm:ss"),
        `method` = HttpGet,
        path = "/api/v1/health",
        statusCode = 500,
        userAgent = "InternalMonitor/1.0"
      ),
      geo = initGeoLocation(countryCode = "LO", flagEmoji = "🏠", isPrivate = true),
      threat = initThreatProfile(score = 10, category = CategoryRealUser)
    )
  ]

  for rec in demoRecords:
    echo renderStreamLine(rec, colorize = true, useEmoji = true)

  echo ""
  echo "=== Monochromatic Mode Stream Line Preview ==="
  for rec in demoRecords:
    echo renderStreamLine(rec, colorize = false, useEmoji = false)

  echo ""
  echo "=== Demonstration Completed Successfully ==="

when isMainModule:
  main()

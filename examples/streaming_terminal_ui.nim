# Example: Streaming Log Output, Formatted Tables, Status Ticker & JSON Output
# Demonstrates Phase 06 / Category B:
# - Formatted stream line output and headers ([TIMESTAMP] [FLAG+CC] [STATUS_BADGE] [INTENT] [CLIENT_IP] [METHOD PATH] [USER_AGENT]) (Item 01)
# - Terminal width truncation and middle-ellipsis path shortening (Item 02)
# - Live status ticker and structured session summary banner (Item 03)
# - Suspicious URI parameter highlighting and attack payload diffing (Item 04)
# - JSON streaming output mode (NDJSON & pretty JSON for SIEM/jq) (Item 05)
# - Multi-column layout rendering across 80-column, 120-column, and ultra-wide viewports (Item 06)
#
# Compile and run with:
#   nim r --path:src examples/streaming_terminal_ui.nim

import std/times
import http_logviewer/core/types
import http_logviewer/renderer/terminal

proc createSampleRecords(): seq[EnrichedLogRecord] =
  result = @[
    initEnrichedLogRecord(
      entry = initHttpLogEntry(
        clientIp = "172.56.21.89",
        timestamp = parse("2026-10-10 13:55:01", "yyyy-MM-dd HH:mm:ss"),
        `method` = HttpGet,
        path = "/products/electronics/laptops?brand=thinkpad&model=x1-carbon-gen-10",
        statusCode = 200,
        bytesSent = 4520,
        userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
      ),
      geo = initGeoLocation(countryCode = "US", countryName = "United States", flagEmoji = "🇺🇸"),
      threat = initThreatProfile(score = 0, category = CategoryRealUser)
    ),
    initEnrichedLogRecord(
      entry = initHttpLogEntry(
        clientIp = "66.249.66.1",
        timestamp = parse("2026-10-10 13:55:02", "yyyy-MM-dd HH:mm:ss"),
        `method` = HttpGet,
        path = "/robots.txt",
        statusCode = 200,
        bytesSent = 512,
        userAgent = "Googlebot/2.1 (+http://www.google.com/bot.html)"
      ),
      geo = initGeoLocation(countryCode = "US", countryName = "United States", flagEmoji = "🇺🇸"),
      threat = initThreatProfile(score = 0, category = CategoryVerifiedBot)
    ),
    initEnrichedLogRecord(
      entry = initHttpLogEntry(
        clientIp = "194.26.29.112",
        timestamp = parse("2026-10-10 13:55:03", "yyyy-MM-dd HH:mm:ss"),
        `method` = HttpGet,
        path = "/.env",
        statusCode = 404,
        bytesSent = 162,
        userAgent = "python-requests/2.28.1"
      ),
      geo = initGeoLocation(countryCode = "DE", countryName = "Germany", flagEmoji = "🇩🇪"),
      threat = initThreatProfile(score = 90, category = CategoryBadActorHacker, flags = {ThreatSensitiveFile})
    ),
    initEnrichedLogRecord(
      entry = initHttpLogEntry(
        clientIp = "45.154.255.8",
        timestamp = parse("2026-10-10 13:55:04", "yyyy-MM-dd HH:mm:ss"),
        `method` = HttpPost,
        path = "/wp-login.php",
        statusCode = 404,
        bytesSent = 162,
        userAgent = "Mozilla/5.0 (compatible; EvilScanner/1.0)"
      ),
      geo = initGeoLocation(countryCode = "NL", countryName = "Netherlands", flagEmoji = "🇳🇱"),
      threat = initThreatProfile(score = 95, category = CategoryBadActorHacker, flags = {ThreatCmsExploit})
    ),
    initEnrichedLogRecord(
      entry = initHttpLogEntry(
        clientIp = "185.220.101.5",
        timestamp = parse("2026-10-10 13:55:05", "yyyy-MM-dd HH:mm:ss"),
        `method` = HttpGet,
        path = "/api/v1/search?q=laptops' UNION SELECT null,password,username FROM users--",
        statusCode = 403,
        bytesSent = 210,
        userAgent = "sqlmap/1.7#stable"
      ),
      geo = initGeoLocation(countryCode = "DE", countryName = "Germany", flagEmoji = "🇩🇪"),
      threat = initThreatProfile(score = 95, category = CategoryBadActorHacker, flags = {ThreatSqlInjection})
    ),
    initEnrichedLogRecord(
      entry = initHttpLogEntry(
        clientIp = "192.168.1.50",
        timestamp = parse("2026-10-10 13:55:06", "yyyy-MM-dd HH:mm:ss"),
        `method` = HttpGet,
        path = "/internal/metrics",
        statusCode = 500,
        bytesSent = 850,
        userAgent = "Prometheus/2.45.0"
      ),
      geo = initGeoLocation(countryCode = "LO", countryName = "Private LAN", flagEmoji = "🏠", isPrivate = true),
      threat = initThreatProfile(score = 10, category = CategoryRealUser)
    )
  ]

proc main() =
  echo "=== http_logviewer: Streaming Log Output & Formatted Tables (Phase 06 / Category B) ==="
  echo ""

  let records = createSampleRecords()

  # --------------------------------------------------------------------------
  # 1. Formatted Streaming Output with Header and Separator (Item 01)
  # --------------------------------------------------------------------------
  echo "[1] Formatted Stream Output with Header & Badges (Item 01):"
  let defaultOpts = StreamFormatOptions(
    colorize: true,
    useEmoji: true,
    includeUserAgent: true,
    maxWidth: 120,
    highlightSuspicious: true
  )

  echo renderStreamHeader(defaultOpts)
  echo renderStreamSeparator(defaultOpts)
  for r in records:
    echo renderStreamLine(r, defaultOpts)
  echo ""

  # --------------------------------------------------------------------------
  # 2. Terminal Width Truncation & Path Shortening (Item 02 & Item 06)
  # --------------------------------------------------------------------------
  echo "[2] Adaptive Display Width Truncation (Item 02 & Item 06):"
  let pathLong = "/v2/customer-dashboard/analytics/reports/monthly-summary-archive-export.json?range=all&format=full"
  echo "  Original Path (len ", pathLong.len, "): ", pathLong
  echo "  Shortened to 40 cols:              ", shortenPath(pathLong, 40)
  echo "  Shortened to 25 cols:              ", shortenPath(pathLong, 25)
  echo ""

  echo "  --- 80-Column Constrained View (User-Agent Suppressed) ---"
  let opts80 = StreamFormatOptions(
    colorize: true,
    useEmoji: true,
    includeUserAgent: true,
    maxWidth: 80,
    highlightSuspicious: true
  )
  echo renderStreamHeader(opts80)
  echo renderStreamSeparator(opts80)
  for r in records[0 .. 2]:
    echo renderStreamLine(r, opts80)
  echo ""

  echo "  --- 120-Column Standard Terminal View (User-Agent Included) ---"
  for r in records[0 .. 2]:
    echo renderStreamLine(r, defaultOpts)
  echo ""

  # --------------------------------------------------------------------------
  # 3. Suspicious URI Parameter Highlighting & Diffing (Item 04)
  # --------------------------------------------------------------------------
  echo "[3] Suspicious URI Parameter Highlighting & Diffing (Item 04):"
  let sqlPayload = "/search?category=shoes&q=' UNION SELECT username,password FROM accounts--"
  let lfiPayload = "/static/download.php?file=../../../../etc/shadow"
  let rcePayload = "/cgi-bin/test.sh?cmd=$(whoami);id"

  echo "  SQL Injection:   ", highlightSuspiciousUri(sqlPayload, colorize = true)
  echo "  Path Traversal:  ", highlightSuspiciousUri(lfiPayload, colorize = true)
  echo "  Command Exec:    ", highlightSuspiciousUri(rcePayload, colorize = true)
  echo ""

  echo "  --- Query Parameter Diffing (Tampering Detection) ---"
  let baseline = "/api/v1/user?id=42&role=viewer"
  let tampered = "/api/v1/user?id=1&role=admin&debug=true"
  echo "  Baseline URI: ", baseline
  echo "  Tampered URI: ", highlightUriDiff(baseline, tampered, colorize = true)
  echo ""

  # --------------------------------------------------------------------------
  # 4. Live Status Ticker & Traffic Summary Banner (Item 03)
  # --------------------------------------------------------------------------
  echo "[4] Live Status Ticker & Traffic Summary Banner (Item 03):"
  var ticker = initStatusTicker()
  for r in records:
    ticker.record(r)

  # Simulate additional background traffic for a realistic ticker
  for _ in 1 .. 80:
    ticker.record(records[0]) # real users
  for _ in 1 .. 15:
    ticker.record(records[1]) # good bot
  for _ in 1 .. 8:
    ticker.record(records[2]) # .env probe
  for _ in 1 .. 6:
    ticker.record(records[3]) # wp-login probe

  echo "  Colorized Ticker: ", renderTicker(ticker, colorize = true, maxWidth = 120)
  echo "  Monochrome Ticker: ", renderTicker(ticker, colorize = false, maxWidth = 120)
  echo ""

  echo "  --- Structured Session Summary Banner ---"
  echo renderSummaryBanner(ticker, colorize = true, width = 78)
  echo ""

  # --------------------------------------------------------------------------
  # 5. JSON Output Mode & NDJSON Streaming for SIEM Ingestion (Item 05)
  # --------------------------------------------------------------------------
  echo "[5] JSON Output Mode & NDJSON Streaming for SIEM Pipelines (Item 05):"
  echo "  --- Single Line NDJSON Stream Line ---"
  echo renderJsonStreamLine(records[4])
  echo ""
  echo "  --- Pretty JSON Record Representation ---"
  echo renderJsonRecord(records[4], pretty = true)
  echo ""

  echo "=== Demonstration Completed Successfully ==="

when isMainModule:
  main()

# Example: Behavioral Heuristics & Anomaly Scoring
# Demonstrates Phase 04 / Category C: Static asset ratios, 404 error velocity,
# HTTP method anomaly scoring, composite risk score calculation (0-100),
# and canonical ActorCategory classification.
#
# Compile and run with:
#   nim r --path:src examples/behavioral_heuristics.nim

import std/[strutils, times, options]
import http_logviewer/core/types
import http_logviewer/analyzer/classifier

proc main() =
  echo "=== http_logviewer: Behavioral Heuristics & Anomaly Scoring (Phase 04 / Category C) ==="
  echo ""

  # 1. Static Asset Ratio Heuristic (Item 01)
  echo "[1] Static Asset Ratio Heuristic (Item 01):"
  let tracker = newVisitorBehaviorTracker()
  let t0 = now().utc

  # Human visitor: 1 page + 4 secondary static resources
  let humanIp = "192.0.2.10"
  discard tracker.recordEntry(initHttpLogEntry(clientIp = humanIp, timestamp = t0, path = "/index.html", statusCode = 200))
  discard tracker.recordEntry(initHttpLogEntry(clientIp = humanIp, timestamp = t0 + initDuration(seconds = 1), path = "/style.css", statusCode = 200))
  discard tracker.recordEntry(initHttpLogEntry(clientIp = humanIp, timestamp = t0 + initDuration(seconds = 1), path = "/bundle.js", statusCode = 200))
  discard tracker.recordEntry(initHttpLogEntry(clientIp = humanIp, timestamp = t0 + initDuration(seconds = 2), path = "/logo.png", statusCode = 200))
  discard tracker.recordEntry(initHttpLogEntry(clientIp = humanIp, timestamp = t0 + initDuration(seconds = 2), path = "/inter.woff2", statusCode = 200))

  let humanStats = tracker.getStats(humanIp).get()
  echo "  [HUMAN]   Static Ratio: ", formatFloat(humanStats.staticAssetRatio() * 100, ffDecimal, 1), "% (", humanStats.staticAssetRequests, "/", humanStats.totalRequests, " requests) -> Mitigating bonus (-10 pts)"

  # Scraper: 8 endpoint requests without downloading static assets
  let scraperIp = "198.51.100.42"
  for i in 1..8:
    discard tracker.recordEntry(initHttpLogEntry(clientIp = scraperIp, timestamp = t0 + initDuration(seconds = i), path = "/catalog/item/" & $i, statusCode = 200))
  let scraperStats = tracker.getStats(scraperIp).get()
  let (scrapScore, scrapFlags, _) = evaluateStaticAssetRatio(some(scraperStats))
  echo "  [SCRAPER] Static Ratio: ", formatFloat(scraperStats.staticAssetRatio() * 100, ffDecimal, 1), "% (", scraperStats.endpointRequests, " endpoints, 0 assets) -> Flags: ", scrapFlags, " (+", scrapScore, " pts)"
  echo ""

  # 2. 404 Error Velocity Heuristic (Item 02)
  echo "[2] 404 Error Velocity & Rapid Fuzzing Heuristic (Item 02):"
  let benign404 = initHttpLogEntry(clientIp = "192.0.2.10", path = "/favicon.ico", statusCode = 404)
  let (bScore, _, _) = evaluate404Heuristics(benign404)
  echo "  [BENIGN]  404 on static asset (/favicon.ico)       -> Score penalty: +", bScore, " pts (Tolerated)"

  let accidental404 = initHttpLogEntry(clientIp = "192.0.2.10", path = "/blog/old-post", statusCode = 404)
  let (aScore, _, _) = evaluate404Heuristics(accidental404)
  echo "  [USER]    Single broken link (/blog/old-post)       -> Score penalty: +", aScore, " pts (Remains RealUser)"

  let fuzzerIp = "203.0.113.99"
  for i in 1..6:
    discard tracker.recordEntry(initHttpLogEntry(clientIp = fuzzerIp, timestamp = t0 + initDuration(seconds = i), path = "/fuzz_" & $i, statusCode = 404))
  let fuzzerStats = tracker.getStats(fuzzerIp).get()
  let (fuzScore, fuzFlags, _) = evaluate404Heuristics(initHttpLogEntry(clientIp = fuzzerIp, path = "/fuzz_6", statusCode = 404), some(fuzzerStats))
  echo "  [FUZZER]  6 consecutive 404s within seconds         -> Score penalty: +", fuzScore, " pts, Flags: ", fuzFlags
  echo ""

  # 3. HTTP Method Anomaly Scoring (Item 03)
  echo "[3] HTTP Method Anomaly Scoring (Item 03):"
  let connectReq = initHttpLogEntry(clientIp = "198.51.100.5", `method` = HttpConnect, path = "evil-proxy.com:443", statusCode = 405)
  let (cScore, cFlags, _) = evaluateMethodAnomaly(connectReq)
  echo "  [METHOD]  CONNECT proxy attempt                     -> Score: +", cScore, " pts, Flags: ", cFlags

  let postAdminReq = initHttpLogEntry(clientIp = "198.51.100.5", `method` = HttpPost, path = "/wp-login.php", statusCode = 200, referer = "http://target.com/wp-login.php")
  let (pScore, pFlags, _) = evaluateMethodAnomaly(postAdminReq)
  echo "  [METHOD]  POST probe on /wp-login.php               -> Score: +", pScore, " pts, Flags: ", pFlags

  let writeProbe = initHttpLogEntry(clientIp = "198.51.100.5", `method` = HttpPost, path = "/api/upload", statusCode = 404, referer = "")
  let (wScore, wFlags, _) = evaluateMethodAnomaly(writeProbe)
  echo "  [METHOD]  POST 404 with missing Referer header      -> Score: +", wScore, " pts, Flags: ", wFlags
  echo ""

  # 4. Composite Risk Score & Intent Classification (Items 04 & 05)
  echo "[4] Composite Risk Scoring & Intent Categorization (Items 04 & 05):"
  let trafficSamples = [
    initHttpLogEntry(
      clientIp = "192.0.2.1",
      `method` = HttpGet,
      path = "/index.html",
      statusCode = 200,
      referer = "https://google.com/",
      userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
    ),
    initHttpLogEntry(
      clientIp = "66.249.66.1",
      `method` = HttpGet,
      path = "/products",
      statusCode = 200,
      userAgent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    ),
    initHttpLogEntry(
      clientIp = "198.51.100.15",
      `method` = HttpGet,
      path = "/api/v1/metrics",
      statusCode = 200,
      userAgent = "curl/8.4.0"
    ),
    initHttpLogEntry(
      clientIp = "185.220.101.5",
      `method` = HttpGet,
      path = "/login?user=admin' UNION SELECT 1,2,3--",
      statusCode = 404,
      userAgent = "sqlmap/1.7.2#stable (https://sqlmap.org)"
    ),
    initHttpLogEntry(
      clientIp = "185.220.101.9",
      `method` = HttpGet,
      path = "/.env",
      statusCode = 404,
      userAgent = "Mozilla/5.0"
    )
  ]

  for entry in trafficSamples:
    let profile = evaluateThreat(entry)
    let displayPath = if entry.path.len > 28: entry.path[0..25] & "..." else: entry.path
    echo "  [CLASSIFIED] ", displayPath.alignLeft(30), " -> Score: ", ($profile.score).alignLeft(3), " [", ($profile.category).alignLeft(18), "] Flags: ", profile.flags
  echo ""

  echo "=== Behavioral Heuristics & Anomaly Scoring Completed Successfully ==="

when isMainModule:
  main()

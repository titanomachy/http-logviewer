## Unit tests for Threat Classification, Behavioral Heuristics, and Anomaly Scoring.
## Tests Phase 04 / Category C (Items 01 through 06).

import std/[unittest, strutils, times, options]
import http_logviewer/core/types
import http_logviewer/analyzer/classifier

suite "Behavioral Heuristics - Static Asset Ratio (Phase 04 / Category C / Item 01)":
  test "Item 01: isStaticAssetPath recognizes standard web assets regardless of query parameters":
    let staticPaths = [
      "/style.css",
      "/bundle.min.js",
      "/app.mjs",
      "/images/logo.PNG",
      "/photos/banner.jpeg",
      "/icons/favicon.ico",
      "/vector/icon.svg?v=3.2.1",
      "/fonts/inter.woff2?hash=a4f1",
      "/fonts/roboto.ttf",
      "/assets/app.wasm",
      "/video/intro.mp4",
      "/audio/chime.mp3",
      "/docs/manual.pdf",
      "/robots.txt",
      "/sitemap.xml"
    ]
    for p in staticPaths:
      check isStaticAssetPath(p)
      check not isEndpointPath(p)

  test "Item 01: isEndpointPath identifies HTML pages, PHP scripts, and API routes":
    let endpointPaths = [
      "/",
      "/index.html",
      "/about-us",
      "/products/search?q=shoes",
      "/api/v1/users",
      "/wp-login.php",
      "/info.php",
      "/articles/latest/"
    ]
    for p in endpointPaths:
      check isEndpointPath(p)
      check not isStaticAssetPath(p)

  test "Item 01: VisitorBehaviorTracker tracks static asset ratio accurately":
    let tracker = newVisitorBehaviorTracker()
    let ip = "198.51.100.10"
    let t0 = now().utc

    # Simulate human visitor: 1 page request followed by 4 static assets
    discard tracker.recordEntry(initHttpLogEntry(clientIp = ip, timestamp = t0, path = "/index.html", statusCode = 200))
    discard tracker.recordEntry(initHttpLogEntry(clientIp = ip, timestamp = t0 + initDuration(seconds = 1), path = "/styles/main.css", statusCode = 200))
    discard tracker.recordEntry(initHttpLogEntry(clientIp = ip, timestamp = t0 + initDuration(seconds = 1), path = "/scripts/app.js", statusCode = 200))
    discard tracker.recordEntry(initHttpLogEntry(clientIp = ip, timestamp = t0 + initDuration(seconds = 2), path = "/images/logo.png", statusCode = 200))
    discard tracker.recordEntry(initHttpLogEntry(clientIp = ip, timestamp = t0 + initDuration(seconds = 2), path = "/fonts/inter.woff2", statusCode = 200))

    let statsOpt = tracker.getStats(ip)
    check statsOpt.isSome
    let stats = statsOpt.get()
    check stats.totalRequests == 5
    check stats.endpointRequests == 1
    check stats.staticAssetRequests == 4
    check stats.staticAssetRatio() == 0.80

    let (scoreMod, flags, rules) = evaluateStaticAssetRatio(statsOpt)
    check scoreMod == -10 # Human browsing bonus
    check flags == {}
    check rules.len > 0
    check "Behavior:HumanAssetPattern" in rules[0]

  test "Item 01: Automated scraper requesting only endpoints triggers ThreatNoAssetFetch":
    let tracker = newVisitorBehaviorTracker()
    let scraperIp = "203.0.113.88"
    let t0 = now().utc

    # Scraper requests 8 different HTML/API endpoints with zero static assets
    for i in 1..8:
      discard tracker.recordEntry(initHttpLogEntry(
        clientIp = scraperIp,
        timestamp = t0 + initDuration(seconds = i),
        path = "/catalog/item/" & $i,
        statusCode = 200
      ))

    let statsOpt = tracker.getStats(scraperIp)
    check statsOpt.isSome
    let stats = statsOpt.get()
    check stats.totalRequests == 8
    check stats.endpointRequests == 8
    check stats.staticAssetRequests == 0
    check stats.staticAssetRatio() == 0.0

    let (scoreMod, flags, rules) = evaluateStaticAssetRatio(statsOpt)
    check scoreMod == 20
    check ThreatNoAssetFetch in flags
    check rules.len > 0
    check "Behavior:NoStaticAssets" in rules[0]

suite "Behavioral Heuristics - 404 Error Velocity (Phase 04 / Category C / Item 02)":
  test "Item 02: Benign static asset 404 does not penalize score or trigger threat flags":
    let static404 = initHttpLogEntry(
      clientIp = "192.168.1.50",
      timestamp = now().utc,
      `method` = HttpGet,
      path = "/favicon.ico",
      statusCode = 404,
      userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )
    let (score, flags, rules) = evaluate404Heuristics(static404)
    check score == 0
    check flags == {}
    check rules.len == 0

  test "Item 02: Single accidental 404 on normal page adds minimal score without hacker flag":
    let accidental404 = initHttpLogEntry(
      clientIp = "192.168.1.50",
      timestamp = now().utc,
      `method` = HttpGet,
      path = "/blog/non-existent-article-1234",
      statusCode = 404,
      userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )
    let (score, flags, rules) = evaluate404Heuristics(accidental404)
    check score == 5
    check flags == {}
    check "404:SinglePageNotFound" in rules

  test "Item 02: 404 on administrative or sensitive path triggers ThreatHighRate404":
    let admin404 = initHttpLogEntry(
      clientIp = "198.51.100.22",
      timestamp = now().utc,
      `method` = HttpGet,
      path = "/admin/cpanel/backup.tar.gz",
      statusCode = 404,
      userAgent = "Mozilla/5.0"
    )
    let (score, flags, rules) = evaluate404Heuristics(admin404)
    check score >= 25
    check ThreatHighRate404 in flags
    check "404:OnAdminPath" in rules

  test "Item 02: Consecutive 404 runs trigger progressive velocity penalties":
    let tracker = newVisitorBehaviorTracker()
    let fuzzerIp = "198.51.100.77"
    let t0 = now().utc

    # 4 consecutive 404s
    for i in 1..4:
      discard tracker.recordEntry(initHttpLogEntry(
        clientIp = fuzzerIp,
        timestamp = t0 + initDuration(seconds = i),
        path = "/test_" & $i,
        statusCode = 404
      ))
    var stats = tracker.getStats(fuzzerIp)
    check stats.get().consecutive404s == 4
    var (score4, flags4, rules4) = evaluate404Heuristics(
      initHttpLogEntry(clientIp = fuzzerIp, path = "/test_4", statusCode = 404),
      stats
    )
    check score4 >= 15 # elevated streak
    check flags4 == {}
    check rules4.len > 0

    # Push to 6 consecutive 404s
    for i in 5..6:
      discard tracker.recordEntry(initHttpLogEntry(
        clientIp = fuzzerIp,
        timestamp = t0 + initDuration(seconds = i),
        path = "/test_" & $i,
        statusCode = 404
      ))
    stats = tracker.getStats(fuzzerIp)
    check stats.get().consecutive404s == 6
    var (score6, flags6, rules6) = evaluate404Heuristics(
      initHttpLogEntry(clientIp = fuzzerIp, path = "/test_6", statusCode = 404),
      stats
    )
    check score6 >= 35 # 5 base + 30 high rate
    check ThreatHighRate404 in flags6
    check rules6.len > 0

    # Successful request resets consecutive 404 count
    discard tracker.recordEntry(initHttpLogEntry(
      clientIp = fuzzerIp,
      timestamp = t0 + initDuration(seconds = 7),
      path = "/index.html",
      statusCode = 200
    ))
    stats = tracker.getStats(fuzzerIp)
    check stats.get().consecutive404s == 0

suite "Behavioral Heuristics - HTTP Method Anomaly Scoring (Phase 04 / Category C / Item 03)":
  test "Item 03: CONNECT and TRACE methods trigger ThreatMalformedRequest":
    let connectReq = initHttpLogEntry(
      clientIp = "198.51.100.99",
      `method` = HttpConnect,
      path = "proxy.evil.com:443",
      statusCode = 405
    )
    let (score1, flags1, rules1) = evaluateMethodAnomaly(connectReq)
    check score1 == 35
    check ThreatMalformedRequest in flags1
    check rules1.len > 0

    let traceReq = initHttpLogEntry(
      clientIp = "198.51.100.99",
      `method` = HttpTrace,
      path = "/",
      statusCode = 405
    )
    let (score2, flags2, rules2) = evaluateMethodAnomaly(traceReq)
    check score2 == 35
    check ThreatMalformedRequest in flags2
    check rules2.len > 0

  test "Item 03: Non-standard custom HTTP verb triggers ThreatMalformedRequest":
    let otherReq = initHttpLogEntry(
      clientIp = "198.51.100.99",
      `method` = HttpOther,
      path = "/dav/test",
      statusCode = 405
    )
    let (score, flags, rules) = evaluateMethodAnomaly(otherReq)
    check score == 20
    check ThreatMalformedRequest in flags
    check rules.len > 0

  test "Item 03: POST or PUT to administrative endpoint triggers ThreatCmsExploit":
    let postAdmin = initHttpLogEntry(
      clientIp = "203.0.113.44",
      `method` = HttpPost,
      path = "/wp-login.php",
      statusCode = 200,
      referer = "http://target.com/wp-login.php"
    )
    let (score, flags, rules) = evaluateMethodAnomaly(postAdmin)
    check score == 35
    check ThreatCmsExploit in flags
    check rules.len > 0

  test "Item 03: Write method returning 404 without Referer triggers multiple anomalies":
    let postProbe = initHttpLogEntry(
      clientIp = "203.0.113.44",
      `method` = HttpPost,
      path = "/api/internal/upload",
      statusCode = 404,
      referer = "" # Missing Referer
    )
    let (score, flags, rules) = evaluateMethodAnomaly(postProbe)
    check score == 35 # 25 (failed write probe 404) + 10 (missing referer)
    check ThreatNoAssetFetch in flags
    check rules.len > 0

suite "Behavioral Heuristics - Composite Risk Score Calculator (Phase 04 / Category C / Item 04)":
  test "Item 04: Authentic human visitor yields score 0 and no threat flags":
    let human = initHttpLogEntry(
      clientIp = "82.165.197.1",
      timestamp = now().utc,
      `method` = HttpGet,
      path = "/products/view?id=45",
      statusCode = 200,
      bytesSent = 14200,
      referer = "https://example.com/products",
      userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    )
    let profile = evaluateThreat(human)
    check profile.score == 0
    check profile.category == CategoryRealUser
    check profile.flags == {}

  test "Item 04: Malicious request combining offensive UA, SQLi, and 404":
    let hostile = initHttpLogEntry(
      clientIp = "185.220.101.5",
      timestamp = now().utc,
      `method` = HttpGet,
      path = "/login?user=admin' UNION SELECT 1,2,3--",
      statusCode = 404,
      userAgent = "sqlmap/1.7.2#stable (https://sqlmap.org)"
    )
    let profile = evaluateThreat(hostile)
    check profile.score >= 80
    check profile.score <= 100
    check profile.category == CategoryBadActorHacker
    check ThreatKnownScannerUa in profile.flags
    check ThreatSqlInjection in profile.flags

  test "Item 04: Score is strictly clamped to maximum 100":
    # Request stacking numerous severe exploits
    let extremeHostile = initHttpLogEntry(
      clientIp = "185.220.101.5",
      `method` = HttpPost,
      path = "/wp-login.php?cmd=$(whoami)&q=union+select&file=../../etc/passwd",
      statusCode = 404,
      referer = "",
      userAgent = "nikto/2.1.6"
    )
    let profile = evaluateThreat(extremeHostile)
    check profile.score == 100
    check profile.category == CategoryBadActorHacker

suite "Behavioral Heuristics - Score to ActorCategory Mapping (Phase 04 / Category C / Item 05)":
  test "Item 05: Score bracket boundary verification":
    check scoreToActorCategory(0) == CategoryRealUser
    check scoreToActorCategory(10) == CategoryRealUser
    check scoreToActorCategory(20) == CategoryRealUser
    check scoreToActorCategory(21) == CategorySuspicious
    check scoreToActorCategory(35) == CategorySuspicious
    check scoreToActorCategory(49) == CategorySuspicious
    check scoreToActorCategory(50) == CategoryBadActorHacker
    check scoreToActorCategory(85) == CategoryBadActorHacker
    check scoreToActorCategory(100) == CategoryBadActorHacker

  test "Item 05: Verified search engine bot retains VerifiedBot status at score 0":
    let googleEntry = initHttpLogEntry(
      clientIp = "66.249.66.1",
      `method` = HttpGet,
      path = "/blog/article-1",
      statusCode = 200,
      userAgent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    )
    let profile = evaluateThreat(googleEntry)
    check profile.score == 0
    check profile.category == CategoryVerifiedBot

  test "Item 05: Hostile payload using spoofed Googlebot UA is overridden to BadActorHacker":
    let fakeGoogle = initHttpLogEntry(
      clientIp = "185.220.101.5",
      `method` = HttpGet,
      path = "/.env",
      statusCode = 404,
      userAgent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    )
    let profile = evaluateThreat(fakeGoogle)
    check profile.score >= 50
    check profile.category == CategoryBadActorHacker
    check ThreatSensitiveFile in profile.flags
    check ThreatBotImpersonation in profile.flags

  test "Item 05: Script kiddie impersonating Googlebot targeting FCKeditor is classified as Hacker":
    let fckGoogle = initHttpLogEntry(
      clientIp = "185.220.101.5",
      `method` = HttpGet,
      path = "/fckeditor/editor/filemanager/browser/default/browser.html",
      statusCode = 301,
      userAgent = "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.201 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    )
    let profile = evaluateThreat(fckGoogle)
    check profile.score >= 80
    check profile.category == CategoryBadActorHacker
    check ThreatCmsExploit in profile.flags
    check ThreatBotImpersonation in profile.flags

  test "Item 05: Spoofed Googlebot from public non-crawler IP browsing normal paths flagged as suspicious":
    let fakeCrawler = initHttpLogEntry(
      clientIp = "185.220.101.5",
      `method` = HttpGet,
      path = "/blog/article-1",
      statusCode = 200,
      userAgent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    )
    let profile = evaluateThreat(fakeCrawler)
    check profile.category == CategorySuspicious
    check ThreatBotImpersonation in profile.flags

  test "Item 05: Generic scripting client (curl) maps to CategorySuspicious":
    let curlEntry = initHttpLogEntry(
      clientIp = "198.51.100.12",
      `method` = HttpGet,
      path = "/api/data.json",
      statusCode = 200,
      userAgent = "curl/8.4.0"
    )
    let profile = evaluateThreat(curlEntry)
    check profile.category == CategorySuspicious
    check profile.score in 20..49

suite "Behavioral Heuristics - Scoring Precision & False Positive Mitigation (Phase 04 / Category C / Item 06)":
  test "Item 06: Real human users across different OS and browsers stay at score 0":
    let realUserLogs = [
      ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36", "/home"),
      ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 Version/17.3 Safari/605.1.15", "/products"),
      ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1", "/contact"),
      ("Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0", "/pricing"),
      ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/122.0.0.0", "/docs")
    ]
    for (ua, p) in realUserLogs:
      let entry = initHttpLogEntry(
        clientIp = "192.0.2.1",
        `method` = HttpGet,
        path = p,
        statusCode = 200,
        referer = "https://example.com/",
        userAgent = ua
      )
      let profile = evaluateThreat(entry)
      check profile.score == 0
      check profile.category == CategoryRealUser
      check profile.flags == {}

  test "Item 06: Accidental user 404 does not classify visitor as hacker":
    let accidentalEntry = initHttpLogEntry(
      clientIp = "192.0.2.15",
      `method` = HttpGet,
      path = "/broken-user-link",
      statusCode = 404,
      referer = "https://example.com/page",
      userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
    )
    let profile = evaluateThreat(accidentalEntry)
    check profile.score <= 10
    check profile.category == CategoryRealUser

  test "Item 06: State-tracked human journey maintains RealUser status":
    let tracker = newVisitorBehaviorTracker()
    let ip = "192.0.2.77"
    let t0 = now().utc
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"

    # Step 1: User visits home page
    let p1 = evaluateThreat(initHttpLogEntry(clientIp = ip, timestamp = t0, path = "/", statusCode = 200, userAgent = ua), tracker)
    check p1.category == CategoryRealUser

    # Step 2: Browser loads CSS, JS, image, font
    discard evaluateThreat(initHttpLogEntry(clientIp = ip, timestamp = t0 + initDuration(seconds = 1), path = "/app.css", statusCode = 200, userAgent = ua), tracker)
    discard evaluateThreat(initHttpLogEntry(clientIp = ip, timestamp = t0 + initDuration(seconds = 1), path = "/app.js", statusCode = 200, userAgent = ua), tracker)
    discard evaluateThreat(initHttpLogEntry(clientIp = ip, timestamp = t0 + initDuration(seconds = 1), path = "/logo.svg", statusCode = 200, userAgent = ua), tracker)
    discard evaluateThreat(initHttpLogEntry(clientIp = ip, timestamp = t0 + initDuration(seconds = 1), path = "/font.woff2", statusCode = 200, userAgent = ua), tracker)

    # Step 3: User encounters one 404 on missing subpage
    let p3 = evaluateThreat(initHttpLogEntry(clientIp = ip, timestamp = t0 + initDuration(seconds = 5), path = "/missing-doc", statusCode = 404, userAgent = ua), tracker)
    check p3.category == CategoryRealUser
    check p3.score <= 10


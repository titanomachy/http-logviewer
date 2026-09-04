## User-Agent taxonomy, bot identification, offensive scanner recognition,
## generic HTTP library classification, and anomaly detection engine.
## Implements Phase 04 / Category B (Items 01 through 06).

import std/[strutils, parseutils, options]
import ../core/types

# ==============================================================================
# Types & Enums
# ==============================================================================

type
  ## Metadata record for a known bot or crawler signature
  BotSignature* = object
    pattern*: string           ## Substring identifier (case-insensitive)
    name*: string              ## Canonical display name (e.g. "Googlebot")
    category*: ActorCategory   ## Assigned category (VerifiedBot, FriendlyCrawler, CommercialBot)

  ## Detected User-Agent anomalies and evasion tactics
  UserAgentAnomaly* = enum
    AnomalyEmpty,                         ## Empty string, whitespace-only, or "-"
    AnomalySingleWord,                    ## Single token lacking Product/Version or OS structure
    AnomalyFakeChromeOnAncientWindows,    ## Modern Chrome (>= 50) on Windows NT 5.x / 4.0 / 98
    AnomalyMissingBrowserTokens,          ## Claims browser identity but missing mandatory tokens
    AnomalyExploitPayloadInUa,            ## Embedded SQLi, shell command, traversal, or Log4j syntax
    AnomalyNonAsciiOrControlChars         ## Raw control characters or non-printable bytes

  ## Detailed classification result for a User-Agent string
  UserAgentClassification* = object
    rawUserAgent*: string
    category*: ActorCategory
    matchedRule*: string
    flags*: set[ThreatFlag]
    anomalies*: set[UserAgentAnomaly]
    suggestedThreatScore*: int

# ==============================================================================
# Item 01: Verified Search Engine Bots & Friendly Crawlers
# ==============================================================================

const
  ## Verified search engine bots that index web content legitimately
  VerifiedSearchEngineBots*: array[16, BotSignature] = [
    BotSignature(pattern: "googlebot", name: "Googlebot", category: CategoryVerifiedBot),
    BotSignature(pattern: "google-inspectiontool", name: "Google Inspection Tool", category: CategoryVerifiedBot),
    BotSignature(pattern: "adsbot-google", name: "Google AdsBot", category: CategoryVerifiedBot),
    BotSignature(pattern: "bingbot", name: "Bingbot", category: CategoryVerifiedBot),
    BotSignature(pattern: "bingpreview", name: "BingPreview", category: CategoryVerifiedBot),
    BotSignature(pattern: "msnbot", name: "MSNBot", category: CategoryVerifiedBot),
    BotSignature(pattern: "duckduckbot", name: "DuckDuckBot", category: CategoryVerifiedBot),
    BotSignature(pattern: "duckduckgo-favicons-bot", name: "DuckDuckGo Favicons", category: CategoryVerifiedBot),
    BotSignature(pattern: "yandexbot", name: "YandexBot", category: CategoryVerifiedBot),
    BotSignature(pattern: "yandeximages", name: "YandexImages", category: CategoryVerifiedBot),
    BotSignature(pattern: "baiduspider", name: "Baiduspider", category: CategoryVerifiedBot),
    BotSignature(pattern: "applebot", name: "Applebot", category: CategoryVerifiedBot),
    BotSignature(pattern: "sogou web spider", name: "Sogou Spider", category: CategoryVerifiedBot),
    BotSignature(pattern: "sogou spider", name: "Sogou Spider", category: CategoryVerifiedBot),
    BotSignature(pattern: "qwantify", name: "Qwantify", category: CategoryVerifiedBot),
    BotSignature(pattern: "seznambot", name: "SeznamBot", category: CategoryVerifiedBot)
  ]

  ## Friendly social, preview, and archivist indexing bots
  FriendlyCrawlerBots*: array[8, BotSignature] = [
    BotSignature(pattern: "ia_archiver", name: "Internet Archive", category: CategoryFriendlyCrawler),
    BotSignature(pattern: "archive.org_bot", name: "Internet Archive Bot", category: CategoryFriendlyCrawler),
    BotSignature(pattern: "facebookexternalhit", name: "Facebook External Hit", category: CategoryFriendlyCrawler),
    BotSignature(pattern: "meta-externalagent", name: "Meta External Agent", category: CategoryFriendlyCrawler),
    BotSignature(pattern: "telegrambot", name: "TelegramBot", category: CategoryFriendlyCrawler),
    BotSignature(pattern: "twitterbot", name: "Twitterbot", category: CategoryFriendlyCrawler),
    BotSignature(pattern: "linkedinbot", name: "LinkedInBot", category: CategoryFriendlyCrawler),
    BotSignature(pattern: "slackbot", name: "Slackbot", category: CategoryFriendlyCrawler)
  ]

# ==============================================================================
# Item 02: Commercial & SEO Crawlers
# ==============================================================================

const
  ## Commercial, SEO, competitive intelligence, and marketing crawlers
  CommercialCrawlerBots*: array[20, BotSignature] = [
    BotSignature(pattern: "ahrefsbot", name: "AhrefsBot", category: CategoryCommercialBot),
    BotSignature(pattern: "semrushbot", name: "SemrushBot", category: CategoryCommercialBot),
    BotSignature(pattern: "mj12bot", name: "MJ12bot", category: CategoryCommercialBot),
    BotSignature(pattern: "dotbot", name: "DotBot", category: CategoryCommercialBot),
    BotSignature(pattern: "screaming frog seo spider", name: "Screaming Frog SEO Spider", category: CategoryCommercialBot),
    BotSignature(pattern: "screaming frog", name: "Screaming Frog", category: CategoryCommercialBot),
    BotSignature(pattern: "bytespider", name: "ByteSpider", category: CategoryCommercialBot),
    BotSignature(pattern: "petalbot", name: "PetalBot", category: CategoryCommercialBot),
    BotSignature(pattern: "criteobot", name: "CriteoBot", category: CategoryCommercialBot),
    BotSignature(pattern: "blexbot", name: "BLEXBot", category: CategoryCommercialBot),
    BotSignature(pattern: "seokicks", name: "SEOkicks", category: CategoryCommercialBot),
    BotSignature(pattern: "zoominfobot", name: "ZoominfoBot", category: CategoryCommercialBot),
    BotSignature(pattern: "dataforseobot", name: "DataForSeoBot", category: CategoryCommercialBot),
    BotSignature(pattern: "seekport bot", name: "Seekport Bot", category: CategoryCommercialBot),
    BotSignature(pattern: "siteauditbot", name: "SiteAuditBot", category: CategoryCommercialBot),
    BotSignature(pattern: "megaindex", name: "MegaIndex", category: CategoryCommercialBot),
    BotSignature(pattern: "serpstatbot", name: "SerpstatBot", category: CategoryCommercialBot),
    BotSignature(pattern: "ccbot", name: "Common Crawl Bot", category: CategoryCommercialBot),
    BotSignature(pattern: "mojeekbot", name: "MojeekBot", category: CategoryCommercialBot),
    BotSignature(pattern: "turnitinbot", name: "TurnitinBot", category: CategoryCommercialBot)
  ]

# ==============================================================================
# Item 03: Offensive Scanners & Exploit Tools
# ==============================================================================

const
  ## Known security scanners, vulnerability assessment tools, fuzzers, and exploit suites
  OffensiveScannerUas*: array[30, string] = [
    "sqlmap",
    "nikto",
    "masscan",
    "zgrab",
    "nuclei",
    "gobuster",
    "dirbuster",
    "nmap",
    "wpscan",
    "havij",
    "acunetix",
    "nessus",
    "qualys",
    "openvas",
    "arachni",
    "hydra",
    "medusa",
    "ffuf",
    "dirb",
    "whatweb",
    "metasploit",
    "commix",
    "jaeles",
    "wfuzz",
    "sublist3r",
    "amass",
    "censysinspect",
    "censys",
    "shodan",
    "projectdiscovery"
  ]

# ==============================================================================
# Item 04: Generic HTTP Libraries & Scripting Clients
# ==============================================================================

const
  ## Automated scripting libraries and generic HTTP programmatic clients
  GenericHttpLibraries*: array[24, string] = [
    "curl/",
    "curl",
    "python-requests",
    "python-urllib",
    "urllib/",
    "go-http-client",
    "wget/",
    "wget",
    "aiohttp",
    "httpx/",
    "httpx",
    "libwww-perl",
    "php/",
    "postmanruntime",
    "apache-httpclient",
    "okhttp",
    "java/",
    "axios/",
    "axios",
    "node-fetch",
    "got",
    "guzzlehttp",
    "faraday",
    "ruby"
  ]

# ==============================================================================
# Item 01 Procs: Verified Search Engine & Friendly Crawler Detection
# ==============================================================================

func detectSearchEngineBot*(ua: string): Option[BotSignature] =
  ## Checks if the User-Agent belongs to a verified search engine bot (Googlebot, Bingbot, etc.).
  ## Matching is case-insensitive. Returns some(BotSignature) or none(BotSignature).
  if ua.len == 0:
    return none(BotSignature)

  let uaLower = ua.toLowerAscii()
  for bot in VerifiedSearchEngineBots:
    if bot.pattern in uaLower:
      return some(bot)

  return none(BotSignature)

func isSearchEngineBot*(ua: string): bool {.inline.} =
  ## Returns true if `ua` matches a verified search engine bot.
  detectSearchEngineBot(ua).isSome

func detectFriendlyCrawler*(ua: string): Option[BotSignature] =
  ## Checks if the User-Agent belongs to a friendly social/archivist crawler.
  if ua.len == 0:
    return none(BotSignature)

  let uaLower = ua.toLowerAscii()
  for bot in FriendlyCrawlerBots:
    if bot.pattern in uaLower:
      return some(bot)

  return none(BotSignature)

func isFriendlyCrawler*(ua: string): bool {.inline.} =
  ## Returns true if `ua` matches a friendly crawler.
  detectFriendlyCrawler(ua).isSome

# ==============================================================================
# Item 02 Procs: Commercial & SEO Crawler Detection
# ==============================================================================

func detectCommercialCrawler*(ua: string): Option[BotSignature] =
  ## Checks if the User-Agent belongs to a known commercial, SEO, or data mining crawler.
  ## Matching is case-insensitive. Returns some(BotSignature) or none(BotSignature).
  if ua.len == 0:
    return none(BotSignature)

  let uaLower = ua.toLowerAscii()
  for bot in CommercialCrawlerBots:
    if bot.pattern in uaLower:
      return some(bot)

  return none(BotSignature)

func isCommercialCrawler*(ua: string): bool {.inline.} =
  ## Returns true if `ua` matches a known commercial crawler (Ahrefs, Semrush, etc.).
  detectCommercialCrawler(ua).isSome

# ==============================================================================
# Item 03 Procs: Offensive Scanner & Exploit Tool Detection
# ==============================================================================

func detectOffensiveScanner*(ua: string): Option[string] =
  ## Checks if the User-Agent contains signatures of offensive security tools,
  ## vulnerability scanners, fuzzers, or attack suites.
  ## Returns some(scannerName) or none(string).
  if ua.len == 0:
    return none(string)

  let uaLower = ua.toLowerAscii()
  for scanner in OffensiveScannerUas:
    if scanner in uaLower:
      return some(scanner)

  return none(string)

func isOffensiveScanner*(ua: string): bool {.inline.} =
  ## Returns true if `ua` identifies an offensive exploit or scanning tool.
  detectOffensiveScanner(ua).isSome

# ==============================================================================
# Item 04 Procs: Generic HTTP Library Detection
# ==============================================================================

func detectGenericHttpLibrary*(ua: string): Option[string] =
  ## Checks if the User-Agent identifies a generic programming HTTP client library
  ## (curl, python-requests, Go-http-client, Wget, aiohttp, etc.).
  ## Returns some(libraryIdentifier) or none(string).
  if ua.len == 0:
    return none(string)

  let uaLower = ua.toLowerAscii()
  for lib in GenericHttpLibraries:
    if lib.endsWith("/"):
      if lib in uaLower:
        return some(lib)
    else:
      # Boundary check: exact match, or followed by '/', ' ', ';', '(', ')', etc.
      let idx = uaLower.find(lib)
      if idx >= 0:
        let endPos = idx + lib.len
        if endPos == uaLower.len or uaLower[endPos] in {'/', ' ', ';', '-', '_', '(', ')'}:
          return some(lib)

  return none(string)

func isGenericHttpLibrary*(ua: string): bool {.inline.} =
  ## Returns true if `ua` identifies an automated programming library.
  detectGenericHttpLibrary(ua).isSome

# ==============================================================================
# Item 05 Procs: User-Agent Anomaly Detection
# ==============================================================================

func extractChromeMajorVersion(uaLower: string): int =
  ## Extracts the integer major version from a "chrome/XX.X.X.X" token in uaLower.
  ## Returns -1 if not found or unparseable.
  let idx = uaLower.find("chrome/")
  if idx < 0:
    return -1
  var pos = idx + 7
  var ver = 0
  let numDigits = uaLower.parseSaturatedNatural(ver, pos)
  if numDigits > 0:
    return ver
  return -1

func detectUserAgentAnomalies*(ua: string): set[UserAgentAnomaly] =
  ## Evaluates the User-Agent for evasion indicators, forging patterns, and anomalies:
  ## 1. AnomalyEmpty: Empty, whitespace-only, or "-"
  ## 2. AnomalySingleWord: Single bare word lacking Product/Version or structure
  ## 3. AnomalyFakeChromeOnAncientWindows: Modern Chrome (>= 50) on Windows NT 5.x / 4.0 / 98
  ## 4. AnomalyMissingBrowserTokens: Purports to be a browser but lacks standard components
  ## 5. AnomalyExploitPayloadInUa: Exploit vectors (SQLi, commands, Log4j, Shellshock) inside User-Agent
  ## 6. AnomalyNonAsciiOrControlChars: Raw non-printable control characters
  result = {}

  let stripped = ua.strip()
  if stripped.len == 0 or stripped == "-":
    result.incl(AnomalyEmpty)
    return result

  # Check for raw non-printable or control characters
  for c in ua:
    if c < ' ' and c notin {'\t'}:
      result.incl(AnomalyNonAsciiOrControlChars)
      break

  let uaLower = ua.toLowerAscii()

  # Check for exploit payloads inside User-Agent (Log4j, SQLi, command injection, Shellshock, traversal)
  if "${jndi:" in uaLower or "union select" in uaLower or "union+select" in uaLower or
     "../" in uaLower or "..\\" in uaLower or ";id" in uaLower or "$(whoami)" in uaLower or
     "`id`" in uaLower or "() {" in uaLower or "/bin/bash" in uaLower or "/bin/sh" in uaLower or
     "whoami" in uaLower or "base64_decode" in uaLower:
    result.incl(AnomalyExploitPayloadInUa)

  # Check for Fake Chrome on Ancient Windows
  # Chrome version >= 50 dropped support for Windows XP / Server 2003 (NT 5.1 / 5.2) and earlier
  let isAncientWindows = ("windows nt 5.0" in uaLower) or   # Windows 2000
                         ("windows nt 5.1" in uaLower) or   # Windows XP
                         ("windows nt 5.2" in uaLower) or   # Windows Server 2003 / XP 64-bit
                         ("windows nt 4.0" in uaLower) or   # Windows NT 4.0
                         ("windows 98" in uaLower) or
                         ("windows 95" in uaLower)

  if isAncientWindows:
    let chromeMajor = extractChromeMajorVersion(uaLower)
    if chromeMajor >= 50:
      result.incl(AnomalyFakeChromeOnAncientWindows)

  # Check for single-word UA (no spaces, no slashes, no parentheses, no semicolons)
  # Examples: "Mozilla", "scanner", "test", "bot", "admin", "custom"
  # Genuine UAs almost universally contain either spaces, slashes, or parentheses
  if ' ' notin stripped and '/' notin stripped and '(' notin stripped and ':' notin stripped:
    result.incl(AnomalySingleWord)

  # Check for missing browser tokens if claiming to be Mozilla/5.0 browser
  if stripped.startsWith("Mozilla/5.0") and stripped.len < 20:
    # Bare "Mozilla/5.0" with no platform or browser token
    result.incl(AnomalyMissingBrowserTokens)

func isUserAgentAnomalous*(ua: string): bool {.inline.} =
  ## Returns true if `ua` triggers one or more anomaly flags.
  detectUserAgentAnomalies(ua).len > 0

# ==============================================================================
# Comprehensive User-Agent Classifier
# ==============================================================================

func classifyUserAgent*(ua: string): UserAgentClassification =
  ## Performs end-to-end classification of a User-Agent string, synthesizing:
  ## - Intent category (`ActorCategory`)
  ## - Triggered `ThreatFlag` set
  ## - Specific rule identification
  ## - Anomaly indicators
  ## - Suggested risk score weighting
  let anomalies = detectUserAgentAnomalies(ua)

  # 1. Empty or missing User-Agent
  if AnomalyEmpty in anomalies:
    return UserAgentClassification(
      rawUserAgent: ua,
      category: CategorySuspicious,
      matchedRule: "EmptyUserAgent",
      flags: {ThreatMalformedRequest},
      anomalies: anomalies,
      suggestedThreatScore: 15
    )

  # 2. Exploit payload inside User-Agent (Immediate Hacker classification)
  if AnomalyExploitPayloadInUa in anomalies:
    var flags: set[ThreatFlag] = {ThreatKnownScannerUa}
    let uaLower = ua.toLowerAscii()
    if "${jndi:" in uaLower or ";id" in uaLower or "$(whoami)" in uaLower:
      flags.incl(ThreatCommandInjection)
    if "union select" in uaLower or "union+select" in uaLower:
      flags.incl(ThreatSqlInjection)
    if "../" in uaLower or "..\\" in uaLower:
      flags.incl(ThreatDirectoryTraversal)
    return UserAgentClassification(
      rawUserAgent: ua,
      category: CategoryBadActorHacker,
      matchedRule: "ExploitPayloadInUserAgent",
      flags: flags,
      anomalies: anomalies,
      suggestedThreatScore: 85
    )

  # 3. Known Offensive Scanner & Exploit Suite
  let offensive = detectOffensiveScanner(ua)
  if offensive.isSome:
    return UserAgentClassification(
      rawUserAgent: ua,
      category: CategoryBadActorHacker,
      matchedRule: "Scanner:" & offensive.get(),
      flags: {ThreatKnownScannerUa},
      anomalies: anomalies,
      suggestedThreatScore: 80
    )

  # 4. Verified Search Engine Bots (Legitimate)
  let searchBot = detectSearchEngineBot(ua)
  if searchBot.isSome:
    return UserAgentClassification(
      rawUserAgent: ua,
      category: CategoryVerifiedBot,
      matchedRule: "SearchBot:" & searchBot.get().name,
      flags: {},
      anomalies: anomalies,
      suggestedThreatScore: 0
    )

  # 5. Friendly Crawlers & Archival Bots
  let friendlyBot = detectFriendlyCrawler(ua)
  if friendlyBot.isSome:
    return UserAgentClassification(
      rawUserAgent: ua,
      category: CategoryFriendlyCrawler,
      matchedRule: "FriendlyBot:" & friendlyBot.get().name,
      flags: {},
      anomalies: anomalies,
      suggestedThreatScore: 0
    )

  # 6. Known Commercial & SEO Crawlers
  let commCrawler = detectCommercialCrawler(ua)
  if commCrawler.isSome:
    return UserAgentClassification(
      rawUserAgent: ua,
      category: CategoryCommercialBot,
      matchedRule: "CommercialBot:" & commCrawler.get().name,
      flags: {},
      anomalies: anomalies,
      suggestedThreatScore: 5
    )

  # 7. Generic HTTP Programming Libraries (curl, python-requests, etc.)
  let genericLib = detectGenericHttpLibrary(ua)
  if genericLib.isSome:
    return UserAgentClassification(
      rawUserAgent: ua,
      category: CategorySuspicious,
      matchedRule: "HttpLibrary:" & genericLib.get(),
      flags: {ThreatNoAssetFetch},
      anomalies: anomalies,
      suggestedThreatScore: 20
    )

  # 8. Forged / Anomalous User-Agent Patterns
  if AnomalyFakeChromeOnAncientWindows in anomalies:
    return UserAgentClassification(
      rawUserAgent: ua,
      category: CategoryBadActorHacker,
      matchedRule: "Anomaly:FakeChromeOnAncientWindows",
      flags: {ThreatKnownScannerUa},
      anomalies: anomalies,
      suggestedThreatScore: 70
    )

  if AnomalySingleWord in anomalies or AnomalyMissingBrowserTokens in anomalies or AnomalyNonAsciiOrControlChars in anomalies:
    return UserAgentClassification(
      rawUserAgent: ua,
      category: CategorySuspicious,
      matchedRule: "Anomaly:MalformedUserAgent",
      flags: {ThreatMalformedRequest},
      anomalies: anomalies,
      suggestedThreatScore: 30
    )

  # 9. Default: Legitimate Real User browser
  return UserAgentClassification(
    rawUserAgent: ua,
    category: CategoryRealUser,
    matchedRule: "StandardBrowser",
    flags: {},
    anomalies: anomalies,
    suggestedThreatScore: 0
  )

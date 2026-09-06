## Threat classification, behavioral heuristics, and anomaly scoring engine for http_logviewer.
## Implements Phase 04 / Category C (Items 01 through 06):
## - Item 01: Static asset ratio heuristic (human users request HTML + CSS/JS/images; scanners request endpoints only)
## - Item 02: 404 error velocity heuristic (rapid consecutive 404s indicate dictionary fuzzing or directory scanning)
## - Item 03: HTTP method anomaly scoring (POST/PUT/HEAD/CONNECT/TRACE to administrative or non-existent endpoints)
## - Item 04: Composite risk score calculator (0 to 100) aggregating signatures, taxonomy, and behavior
## - Item 05: Map composite risk score to ActorCategory (0-20: RealUser, 21-49: SuspiciousScanner, 50-100: BadActorHacker)
## - Item 06: Scoring precision, benign asset handling, and false positive mitigation

import std/[strutils, times, options, tables, math]
import ../core/types
import signatures, useragents, bot_verification

# ==============================================================================
# Pipeline Hello Placeholder (Maintained for backward compatibility)
# ==============================================================================

func analyzeHello*(msg: PipelineMessage): PipelineMessage =
  ## Simulates behavioral analysis on a pipeline message.
  initPipelineMessage(msg.message & " + analyzed", "analyzer")

# ==============================================================================
# Item 01: Static Asset Extensions & Path Classifiers
# ==============================================================================

const
  ## Known static asset file extensions.
  ## Browsers automatically request these secondary resources when rendering HTML.
  ## Automated scanners, fuzzers, and scrapers typically request only HTML/PHP endpoints.
  StaticAssetExtensions*: array[28, string] = [
    ".css", ".js", ".mjs", ".cjs",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp", ".tiff",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".map", ".wasm",
    ".mp4", ".webm", ".ogv", ".mp3", ".wav", ".ogg",
    ".pdf"
  ]

  ## Common administrative and sensitive endpoint path segments
  AdministrativeKeywords*: array[10, string] = [
    "/admin", "/administrator", "/wp-admin", "/cpanel", "/webadmin",
    "/login", "/actuator", "/telescope", "/pma", "/phpmyadmin"
  ]

func extractPathOnly*(rawUri: string): string =
  ## Extracts the clean path portion of a URI, stripping query strings and converting to lowercase.
  if rawUri.len == 0:
    return ""
  let qIdx = rawUri.find('?')
  let p = if qIdx >= 0: rawUri[0 ..< qIdx] else: rawUri
  p.toLowerAscii()

func isStaticAssetPath*(rawUri: string): bool =
  ## Checks whether `rawUri` targets a static web asset (CSS, JavaScript, images, fonts, media, icons).
  ## Query strings are ignored.
  if rawUri.len == 0:
    return false
  let path = extractPathOnly(rawUri)
  if path == "/robots.txt" or path == "/favicon.ico" or path == "/sitemap.xml":
    return true
  for ext in StaticAssetExtensions:
    if path.endsWith(ext):
      return true
  return false

func isEndpointPath*(rawUri: string): bool {.inline.} =
  ## Returns true if `rawUri` targets an HTML document, API endpoint, or script rather than a static asset.
  not isStaticAssetPath(rawUri)

func isAdministrativePath*(rawUri: string): bool =
  ## Checks if `rawUri` targets an administrative portal, dashboard, CMS backend, or framework debugger.
  if rawUri.len == 0:
    return false
  let path = extractPathOnly(rawUri)
  if isCmsExploit(rawUri) or isSensitiveFileProbe(rawUri):
    return true
  for kw in AdministrativeKeywords:
    if kw in path:
      return true
  return false

# ==============================================================================
# Behavioral Visitor State Tracking
# ==============================================================================

type
  ## Historical statistics and behavioral telemetry for a single client IP address
  VisitorStats* = object
    clientIp*: string
    totalRequests*: int
    staticAssetRequests*: int
    endpointRequests*: int
    status404Count*: int
    consecutive404s*: int
    recent404Timestamps*: seq[DateTime]
    recentTimestamps*: seq[DateTime]
    firstSeen*: DateTime
    lastSeen*: DateTime

  ## In-memory session tracking table managing per-IP behavioral metrics
  VisitorBehaviorTracker* = ref object
    stats*: Table[string, VisitorStats]
    maxEntries*: int
    timeWindowSeconds*: int

proc newVisitorBehaviorTracker*(maxEntries: int = 10000, timeWindowSeconds: int = 60): VisitorBehaviorTracker =
  ## Allocates and returns a new VisitorBehaviorTracker.
  VisitorBehaviorTracker(
    stats: initTable[string, VisitorStats](),
    maxEntries: maxEntries,
    timeWindowSeconds: timeWindowSeconds
  )

func staticAssetRatio*(stats: VisitorStats): float =
  ## Computes the ratio of static asset requests to total requests (0.0 to 1.0).
  ## Human browsing typically yields 0.35 to 0.95. Automated scrapers yield ~0.0.
  if stats.totalRequests <= 0:
    return 0.0
  float(stats.staticAssetRequests) / float(stats.totalRequests)

proc staticAssetRatio*(tracker: VisitorBehaviorTracker, ip: string): float =
  ## Returns the static asset ratio for `ip`, or 0.0 if not tracked.
  if tracker == nil or ip notin tracker.stats:
    return 0.0
  tracker.stats[ip].staticAssetRatio()

func calculate404Velocity*(stats: VisitorStats, currentTime: DateTime, windowSeconds: int = 60): int =
  ## Returns the count of 404 responses observed within the last `windowSeconds`.
  if not currentTime.isInitialized:
    return stats.recent404Timestamps.len
  var count = 0
  for ts in stats.recent404Timestamps:
    if ts.isInitialized:
      let diff = (currentTime - ts).inSeconds
      if diff >= 0 and diff <= int64(windowSeconds):
        inc count
  return count

proc calculate404Velocity*(tracker: VisitorBehaviorTracker, ip: string, currentTime: DateTime, windowSeconds: int = 60): int =
  ## Returns the 404 velocity for `ip` over the specified window.
  if tracker == nil or ip notin tracker.stats:
    return 0
  tracker.stats[ip].calculate404Velocity(currentTime, windowSeconds)

proc recordEntry*(tracker: VisitorBehaviorTracker, entry: HttpLogEntry): VisitorStats =
  ## Ingests an HttpLogEntry into the tracker, updating static asset counters,
  ## consecutive 404s, error velocities, and sliding time windows.
  if tracker == nil or entry.clientIp.len == 0:
    return default(VisitorStats)

  let ip = entry.clientIp
  if ip notin tracker.stats:
    tracker.stats[ip] = VisitorStats(
      clientIp: ip,
      totalRequests: 0,
      staticAssetRequests: 0,
      endpointRequests: 0,
      status404Count: 0,
      consecutive404s: 0,
      recent404Timestamps: @[],
      recentTimestamps: @[],
      firstSeen: entry.timestamp,
      lastSeen: entry.timestamp
    )

  var s = tracker.stats[ip]
  inc s.totalRequests

  if isStaticAssetPath(entry.path):
    inc s.staticAssetRequests
  else:
    inc s.endpointRequests

  if entry.statusCode == 404:
    inc s.status404Count
    inc s.consecutive404s
    if entry.timestamp.isInitialized:
      s.recent404Timestamps.add(entry.timestamp)
  else:
    # A successful non-404 request resets consecutive 404 counter
    s.consecutive404s = 0

  if entry.timestamp.isInitialized:
    s.recentTimestamps.add(entry.timestamp)
    if not s.firstSeen.isInitialized or entry.timestamp < s.firstSeen:
      s.firstSeen = entry.timestamp
    if not s.lastSeen.isInitialized or entry.timestamp > s.lastSeen:
      s.lastSeen = entry.timestamp

  # Bound in-memory list sizes
  if s.recent404Timestamps.len > 100:
    s.recent404Timestamps = s.recent404Timestamps[^50 .. ^1]
  if s.recentTimestamps.len > 100:
    s.recentTimestamps = s.recentTimestamps[^50 .. ^1]

  tracker.stats[ip] = s
  return s

proc getStats*(tracker: VisitorBehaviorTracker, ip: string): Option[VisitorStats] =
  ## Retrieves historical telemetry for `ip` if present.
  if tracker != nil and ip in tracker.stats:
    some(tracker.stats[ip])
  else:
    none(VisitorStats)

proc clear*(tracker: VisitorBehaviorTracker) =
  ## Clears all tracked visitor telemetry.
  if tracker != nil:
    tracker.stats.clear()

# ==============================================================================
# Item 01 Procs: Static Asset Ratio Heuristic Evaluation
# ==============================================================================

func evaluateStaticAssetRatio*(stats: Option[VisitorStats]): tuple[score: int, flags: set[ThreatFlag], rules: seq[string]] =
  ## Evaluates visitor request history for static asset ratio anomalies.
  ## - If a client makes >= 5 requests with 0 static assets, flags ThreatNoAssetFetch (+20 pts).
  ## - If a client demonstrates healthy browsing (> 35% static assets), provides a -10 pt mitigating bonus.
  result.score = 0
  result.flags = {}
  result.rules = @[]

  if stats.isNone:
    return

  let s = stats.get()
  # Only evaluate ratio after sufficient sample size to avoid penalizing first page visits
  if s.totalRequests >= 5:
    let ratio = s.staticAssetRatio()
    if ratio < 0.05 and s.endpointRequests >= 5:
      result.score = 20
      result.flags.incl(ThreatNoAssetFetch)
      result.rules.add("Behavior:NoStaticAssets(ratio=" & formatFloat(ratio, ffDecimal, 2) & ")")
    elif ratio >= 0.35:
      result.score = -10
      result.rules.add("Behavior:HumanAssetPattern(ratio=" & formatFloat(ratio, ffDecimal, 2) & ")")

# ==============================================================================
# Item 02 Procs: 404 Error Velocity Heuristic Evaluation
# ==============================================================================

func evaluate404Heuristics*(
  entry: HttpLogEntry,
  stats: Option[VisitorStats] = none(VisitorStats)
): tuple[score: int, flags: set[ThreatFlag], rules: seq[string]] =
  ## Evaluates 404 response codes, consecutive error runs, and velocity bursts.
  ## Mitigates false positives for benign static assets (e.g. missing favicon or image).
  result.score = 0
  result.flags = {}
  result.rules = @[]

  if entry.statusCode == 404:
    # 1. Benign static asset 404: 0 points, not suspicious
    if isStaticAssetPath(entry.path):
      return result

    # 2. 404 on administrative, sensitive, or CMS exploit endpoint
    if isAdministrativePath(entry.path):
      result.score += 25
      result.flags.incl(ThreatHighRate404)
      result.rules.add("404:OnAdminPath")
    else:
      # Accidental 404 on regular user URL (e.g. broken link): small score, stays within RealUser
      result.score += 5
      result.rules.add("404:SinglePageNotFound")

  # 3. Behavioral velocity checks across session history
  if stats.isSome:
    let s = stats.get()

    # Consecutive 404 streak
    if s.consecutive404s >= 10:
      result.score += 45
      result.flags.incl(ThreatHighRate404)
      result.rules.add("404Velocity:AggressiveFuzzing(" & $s.consecutive404s & ")")
    elif s.consecutive404s >= 5:
      result.score += 30
      result.flags.incl(ThreatHighRate404)
      result.rules.add("404Velocity:HighRate(" & $s.consecutive404s & ")")
    elif s.consecutive404s >= 3:
      result.score += 15
      result.rules.add("404Velocity:Elevated(" & $s.consecutive404s & ")")

    # Time-window velocity burst (e.g. within 60s)
    if entry.timestamp.isInitialized:
      let vel = s.calculate404Velocity(entry.timestamp, 60)
      if vel >= 10:
        result.score += 30
        result.flags.incl(ThreatHighRate404)
        result.rules.add("404Velocity:WindowBurst10(" & $vel & "/60s)")
      elif vel >= 5:
        result.score += 20
        result.flags.incl(ThreatHighRate404)
        result.rules.add("404Velocity:WindowBurst5(" & $vel & "/60s)")

# ==============================================================================
# Item 03 Procs: HTTP Method Anomaly Scoring
# ==============================================================================

func evaluateMethodAnomaly*(entry: HttpLogEntry): tuple[score: int, flags: set[ThreatFlag], rules: seq[string]] =
  ## Evaluates HTTP request method verbs for protocol anomalies and suspicious targeting:
  ## - CONNECT / TRACE proxy or debugging attempts (+35 pts, ThreatMalformedRequest)
  ## - Non-standard HTTP verbs (+20 pts, ThreatMalformedRequest)
  ## - POST/PUT/DELETE probes on administrative or exploit paths (+35 pts, ThreatCmsExploit)
  ## - POST/PUT returning 404, 401, 403, 405 on scripts (+25 pts)
  ## - Missing Referer header on non-GET endpoints (+10 pts, ThreatNoAssetFetch)
  ## - HEAD probes on administrative paths (+15 pts)
  result.score = 0
  result.flags = {}
  result.rules = @[]

  let m = entry.httpMethod

  # 1. CONNECT and TRACE proxy abuse / Cross-Site Tracing (XST)
  if m in {HttpConnect, HttpTrace}:
    result.score += 35
    result.flags.incl(ThreatMalformedRequest)
    result.rules.add("Method:ConnectOrTraceAttempt:" & $m)
    return result

  # 2. Unrecognized or arbitrary HTTP verbs
  if m == HttpOther:
    result.score += 20
    result.flags.incl(ThreatMalformedRequest)
    result.rules.add("Method:NonStandardVerb")

  # 3. Write methods (POST, PUT, DELETE, PATCH) targeting administrative or sensitive endpoints
  if m in {HttpPost, HttpPut, HttpDelete, HttpPatch}:
    if isAdministrativePath(entry.path) or isSensitiveFileProbe(entry.path):
      result.score += 35
      result.flags.incl(ThreatCmsExploit)
      result.rules.add("Method:WriteOnExploitPath:" & $m)
    elif entry.statusCode in [401, 403, 404, 405]:
      result.score += 25
      result.rules.add("Method:FailedWriteProbe:" & $m & ":" & $entry.statusCode)

    # Missing Referer on write methods
    if entry.referer.len == 0 and not isStaticAssetPath(entry.path):
      result.score += 10
      result.flags.incl(ThreatNoAssetFetch)
      result.rules.add("Method:MissingRefererOnWrite")

  # 4. HEAD requests probing administrative or non-existent endpoints
  elif m == HttpHead:
    if isAdministrativePath(entry.path) or entry.statusCode in [401, 403, 404]:
      result.score += 15
      result.rules.add("Method:HeadProbeOnAdmin")

# ==============================================================================
# Item 05: Score to ActorCategory Mapping
# ==============================================================================

func scoreToActorCategory*(score: int, uaCategory: ActorCategory = CategoryUnknown): ActorCategory =
  ## Maps composite risk score (0-100) and User-Agent category into canonical ActorCategory:
  ## - 50..100: CategoryBadActorHacker
  ## - 21..49:  CategorySuspicious (SuspiciousScanner)
  ## - 0..20:   CategoryRealUser (or VerifiedBot / FriendlyCrawler / CommercialBot if UA matches)
  if score >= 50:
    CategoryBadActorHacker
  elif score >= 21 or uaCategory == CategorySuspicious:
    CategorySuspicious
  else:
    case uaCategory
    of CategoryVerifiedBot: CategoryVerifiedBot
    of CategoryFriendlyCrawler: CategoryFriendlyCrawler
    of CategoryCommercialBot: CategoryCommercialBot
    else: CategoryRealUser

# ==============================================================================
# Item 04: Composite Risk Score Calculator
# ==============================================================================

func evaluateThreat*(
  entry: HttpLogEntry,
  stats: Option[VisitorStats]
): ThreatProfile =
  ## Comprehensive threat scoring engine combining:
  ## 1. User-Agent taxonomy & bot classification
  ## 2. OWASP Top 10 attack signatures (sensitive files, CMS, traversal, SQLi, RCE, Log4j)
  ## 3. Status code & 404 error heuristics
  ## 4. HTTP method anomalies
  ## 5. Behavioral metrics (static asset ratio, 404 velocity)
  ##
  ## Computes integer score (0-100) and assigns canonical ActorCategory.

  # 1. User-Agent Classification
  let uaClass = classifyUserAgent(entry.userAgent)

  # 2. Path & Query Attack Signatures
  let (sigFlags, sigRules) = analyzeAttackPayload(entry.path)
  let hasExploitPayload = sigFlags.len > 0 or isCmsExploit(entry.path)
  let isTargetingAdmin = isAdministrativePath(entry.path)

  # 3. Crawler IP verification
  var botStatus = BotIpVerified
  var isClaimingCrawler = false
  if uaClass.category in {CategoryVerifiedBot, CategoryFriendlyCrawler}:
    isClaimingCrawler = true
    botStatus = verifyCrawlerIp(uaClass.matchedRule, entry.clientIp)

  # 4. Verified search engine / friendly crawler fast path
  # Verified bots browsing legitimately from verified or local/test IPs are not flagged even on accidental 404s,
  # but ANY attempt to access exploit payloads or administrative paths revokes verified status.
  if isClaimingCrawler and not hasExploitPayload and not isTargetingAdmin and botStatus != BotIpSpoofed:
    return initThreatProfile(
      score = 0,
      category = uaClass.category,
      flags = {},
      matchedSignatures = @[uaClass.matchedRule]
    )

  var score = 0
  var flags: set[ThreatFlag] = {}
  var matchedRules: seq[string] = @[]

  # Add User-Agent component
  score += uaClass.suggestedThreatScore
  flags = flags + uaClass.flags
  if uaClass.matchedRule.len > 0:
    matchedRules.add("UA:" & uaClass.matchedRule)

  # Bot Impersonation detection
  if isClaimingCrawler:
    if botStatus == BotIpSpoofed:
      flags.incl(ThreatBotImpersonation)
      if hasExploitPayload or isTargetingAdmin:
        score += 85
        matchedRules.add("FakeBot:ExploitWhileSpoofingCrawler(" & entry.clientIp & ")")
      else:
        score += 40
        matchedRules.add("FakeBot:SpoofedCrawlerIp(" & entry.clientIp & ")")
    elif hasExploitPayload or isTargetingAdmin:
      flags.incl(ThreatBotImpersonation)
      score += 70
      matchedRules.add("FakeBot:ExploitUnderCrawlerMask")

  # Add Attack Signature component
  if ThreatSensitiveFile in sigFlags: score += 60
  if ThreatCommandInjection in sigFlags: score += 75
  if ThreatSqlInjection in sigFlags: score += 70
  if ThreatDirectoryTraversal in sigFlags: score += 65
  if ThreatCmsExploit in sigFlags: score += 55
  flags = flags + sigFlags
  for r in sigRules:
    matchedRules.add(r)

  # Add 404 & Velocity Heuristics
  let (h404Score, h404Flags, h404Rules) = evaluate404Heuristics(entry, stats)
  score += h404Score
  flags = flags + h404Flags
  for r in h404Rules:
    matchedRules.add(r)

  # Add Method Anomaly Heuristics
  let (mScore, mFlags, mRules) = evaluateMethodAnomaly(entry)
  score += mScore
  flags = flags + mFlags
  for r in mRules:
    matchedRules.add(r)

  # Add Static Asset Ratio Heuristics
  let (aScore, aFlags, aRules) = evaluateStaticAssetRatio(stats)
  score += aScore
  flags = flags + aFlags
  for r in aRules:
    matchedRules.add(r)

  # Clamp score to strictly [0..100]
  let finalScore = clamp(score, 0, 100)

  # Map score to ActorCategory
  # If bot impersonation was detected, do not grant VerifiedBot/FriendlyCrawler
  let effectiveUaCategory = if ThreatBotImpersonation in flags: CategorySuspicious else: uaClass.category
  let category = scoreToActorCategory(finalScore, effectiveUaCategory)

  return initThreatProfile(
    score = finalScore,
    category = category,
    flags = flags,
    matchedSignatures = matchedRules
  )

func evaluateThreat*(entry: HttpLogEntry): ThreatProfile =
  ## Evaluates threat posture for a standalone log entry without session history.
  evaluateThreat(entry, none(VisitorStats))

proc evaluateThreat*(entry: HttpLogEntry, tracker: VisitorBehaviorTracker): ThreatProfile =
  ## Evaluates threat posture for an entry while updating and referencing session history in `tracker`.
  if tracker == nil:
    return evaluateThreat(entry)
  let stats = tracker.recordEntry(entry)
  evaluateThreat(entry, some(stats))

proc evaluateThreat*(entry: HttpLogEntry, history: openArray[HttpLogEntry]): ThreatProfile =
  ## Evaluates an entry within the context of a sequence of preceding entries from the same visitor.
  let tracker = newVisitorBehaviorTracker()
  for h in history:
    discard tracker.recordEntry(h)
  evaluateThreat(entry, tracker)


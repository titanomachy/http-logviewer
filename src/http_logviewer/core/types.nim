## Foundational domain types for the http_logviewer pipeline.

import std/[strutils, times, json, hashes, sets, options]
import errors

type
  ## Classification of the visitor identity and intent
  ActorCategory* = enum
    CategoryUnknown,         ## Unclassified
    CategoryRealUser,        ## Real human visitor browsing legitimately
    CategoryVerifiedBot,     ## Verified search engine (Google, Bing, DuckDuckGo)
    CategoryFriendlyCrawler, ## Friendly indexing or archivist bot
    CategoryCommercialBot,   ## Commercial SEO / Data scraping service
    CategorySuspicious,      ## Elevated anomaly score / non-standard behavior
    CategoryBadActorHacker   ## Malicious intent: scanning exploits, .env, SQLi, etc.

const
  UnknownActor* = CategoryUnknown
  RealUser* = CategoryRealUser
  VerifiedBot* = CategoryVerifiedBot
  FriendlyCrawler* = CategoryFriendlyCrawler
  CommercialBot* = CategoryCommercialBot
  SuspiciousScanner* = CategorySuspicious
  CategorySuspiciousScanner* = CategorySuspicious
  BadActorHacker* = CategoryBadActorHacker

type
  ## Standard HTTP Request Methods
  HttpMethod* = enum
    HttpUnknown,
    HttpGet,
    HttpPost,
    HttpPut,
    HttpDelete,
    HttpHead,
    HttpOptions,
    HttpPatch,
    HttpConnect,
    HttpTrace,
    HttpOther

  ## Normalized representation of a single HTTP log line
  HttpLogEntry* = object
    clientIp*: string
    timestamp*: DateTime
    `method`*: HttpMethod
    path*: string
    statusCode*: int        ## HTTP Status Code (200, 301, 404, 500, etc.)
    bytesSent*: int64
    referer*: string
    userAgent*: string
    rawLine*: string        ## Preserved raw line for debug or verbatim display

  ## Atomic threat indicators detected during analysis
  ThreatFlag* = enum
    ThreatSensitiveFile,      ## Accessing .env, .git, id_rsa, backups, etc.
    ThreatCmsExploit,         ## Probing wp-login.php, xmlrpc.php, setup.php
    ThreatDirectoryTraversal, ## Path contains ../ or url-encoded variations
    ThreatSqlInjection,       ## Path/query contains SQL injection syntax
    ThreatCommandInjection,   ## Path/query contains shell commands (;id, $(whoami))
    ThreatKnownScannerUa,     ## User-Agent identifies offensive tools (sqlmap, nikto)
    ThreatMalformedRequest,   ## Corrupt protocol or impossible HTTP verbs
    ThreatHighRate404,        ## Rapid burst of 404 responses (fuzzing/scanning)
    ThreatNoAssetFetch        ## Scraping HTML only with zero static assets

const
  SensitiveFileProbe* = ThreatSensitiveFile
  PathExploit* = ThreatCmsExploit
  TraversalAttempt* = ThreatDirectoryTraversal
  SqlInjection* = ThreatSqlInjection
  CommandInjection* = ThreatCommandInjection
  KnownScannerUa* = ThreatKnownScannerUa
  MalformedRequest* = ThreatMalformedRequest
  AggressiveRate* = ThreatHighRate404
  NoAssetsRequested* = ThreatNoAssetFetch

type
  ## Geolocation enrichment data for an IP address
  GeoLocation* = object
    ip*: string
    countryCode*: string    ## 2-letter ISO 3166-1 alpha-2 code (e.g. "US", "DE")
    countryName*: string    ## Full name (e.g. "United States", "Germany")
    flagEmoji*: string      ## Unicode regional indicator emoji (e.g. "🇺🇸", "🇩🇪")
    isPrivate*: bool        ## RFC 1918 / Loopback / Bogon IP flag
    city*: Option[string]   ## Optional city if available from database

  ## Threat evaluation results for a single request
  ThreatProfile* = object
    score*: int                     ## Risk score from 0 (benign) to 100 (hostile)
    category*: ActorCategory
    flags*: set[ThreatFlag]
    matchedSignatures*: seq[string] ## Specific rule names triggered

  ## Grouped profile for an entity operating across one or more IP addresses
  ActorCluster* = ref object
    clusterId*: string              ## Unique identifier (e.g. "ACTOR-A4F1")
    primaryUa*: string              ## Dominant User-Agent signature
    ips*: HashSet[string]           ## Set of distinct client IPs observed
    entries*: seq[HttpLogEntry]     ## Observed log entries
    totalRequests*: int
    status404Count*: int
    firstSeen*: DateTime
    lastSeen*: DateTime
    highestThreatScore*: int
    aggregateRisk*: int             ## Aggregated risk metric
    category*: ActorCategory
    flags*: set[ThreatFlag]
    probedPaths*: seq[string]       ## Chronological sample of paths accessed
    proxyRotationDetected*: bool    ## Detected rapid rotation of distinct IPs (< threshold)
    proxyRotationCount*: int        ## Number of distinct IP rotations observed in rapid succession
    subnets*: HashSet[string]       ## Distinct /24 (IPv4) or /64 (IPv6) subnets observed
    hostingProviders*: HashSet[string] ## Known hosting providers / datacenters observed (e.g. Hetzner, AWS)
    hasDatacenterIps*: bool         ## Whether any client IP resides in a known hosting provider range
    synchronizedBurstDetected*: bool ## Whether synchronized burst requests (< 1000ms) across distinct IPs were detected
    synchronizedBurstCount*: int    ## Number of synchronized burst events observed
    clusterTag*: string             ## Human-readable tag (e.g. "[Actor #12: 18 IPs - WP-Scan Botnet]")

  ## Enriched event passed to the presentation layer
  EnrichedLogRecord* = object
    entry*: HttpLogEntry
    geo*: GeoLocation
    threat*: ThreatProfile
    clusterId*: Option[string]      ## Set when multi-IP correlation is enabled

  PipelineMessage* = object
    ## Minimal pipeline message envelope verifying cross-module flow.
    message*: string
    stage*: string

func initPipelineMessage*(msg: string, stage: string = "core"): PipelineMessage =
  ## Initializes a new pipeline message.
  PipelineMessage(message: msg, stage: stage)

func httpMethod*(entry: HttpLogEntry): HttpMethod {.inline.} =
  ## Ergonomic getter for `method` avoiding backticks.
  entry.`method`

proc `httpMethod=`*(entry: var HttpLogEntry, m: HttpMethod) {.inline.} =
  ## Ergonomic setter for `method` avoiding backticks.
  entry.`method` = m

func parseHttpMethod*(s: string): HttpMethod =
  ## Parses a standard or custom HTTP method verb string into an HttpMethod enum.
  ## Matching is case-insensitive. Empty string maps to HttpUnknown; unrecognized non-empty strings map to HttpOther.
  case s.toUpperAscii()
  of "GET": HttpGet
  of "POST": HttpPost
  of "PUT": HttpPut
  of "DELETE": HttpDelete
  of "HEAD": HttpHead
  of "OPTIONS": HttpOptions
  of "PATCH": HttpPatch
  of "CONNECT": HttpConnect
  of "TRACE": HttpTrace
  of "": HttpUnknown
  else: HttpOther

func `$`*(m: HttpMethod): string =
  ## Returns canonical uppercase HTTP verb string.
  case m
  of HttpUnknown: "UNKNOWN"
  of HttpGet: "GET"
  of HttpPost: "POST"
  of HttpPut: "PUT"
  of HttpDelete: "DELETE"
  of HttpHead: "HEAD"
  of HttpOptions: "OPTIONS"
  of HttpPatch: "PATCH"
  of HttpConnect: "CONNECT"
  of HttpTrace: "TRACE"
  of HttpOther: "OTHER"

func initHttpLogEntry*(
  clientIp: string = "",
  timestamp: DateTime = default(DateTime),
  `method`: HttpMethod = HttpUnknown,
  path: string = "",
  statusCode: int = 0,
  bytesSent: int64 = 0,
  referer: string = "",
  userAgent: string = "",
  rawLine: string = ""
): HttpLogEntry =
  ## Initializes a new HttpLogEntry with default or specified fields.
  HttpLogEntry(
    clientIp: clientIp,
    timestamp: timestamp,
    `method`: `method`,
    path: path,
    statusCode: statusCode,
    bytesSent: bytesSent,
    referer: referer,
    userAgent: userAgent,
    rawLine: rawLine
  )

func `$`*(entry: HttpLogEntry): string =
  ## Returns a standardized single-line string representation of the HTTP log entry.
  let tsStr = if not entry.timestamp.isInitialized: "-" else: entry.timestamp.format("yyyy-MM-dd'T'HH:mm:sszzz")
  let refStr = if entry.referer.len > 0: entry.referer else: "-"
  let uaStr = if entry.userAgent.len > 0: entry.userAgent else: "-"
  result = "[" & tsStr & "] " & entry.clientIp & " " & $entry.`method` & " " & entry.path & " " & $entry.statusCode & " " & $entry.bytesSent & " \"" & refStr & "\" \"" & uaStr & "\""

func pretty*(entry: HttpLogEntry): string =
  ## Formats the HttpLogEntry as a readable multi-line structured block.
  let tsStr = if not entry.timestamp.isInitialized: "-" else: entry.timestamp.format("yyyy-MM-dd'T'HH:mm:sszzz")
  result = "HttpLogEntry:\n" &
    "  Client IP:   " & (if entry.clientIp.len > 0: entry.clientIp else: "-") & "\n" &
    "  Timestamp:   " & tsStr & "\n" &
    "  Method:      " & $entry.`method` & "\n" &
    "  Path:        " & (if entry.path.len > 0: entry.path else: "-") & "\n" &
    "  Status Code: " & $entry.statusCode & "\n" &
    "  Bytes Sent:  " & $entry.bytesSent & "\n" &
    "  Referer:     " & (if entry.referer.len > 0: entry.referer else: "-") & "\n" &
    "  User-Agent:  " & (if entry.userAgent.len > 0: entry.userAgent else: "-")

proc `%`*(entry: HttpLogEntry): JsonNode =
  ## Converts an HttpLogEntry into a JSON object node.
  let tsStr = if not entry.timestamp.isInitialized: "" else: entry.timestamp.format("yyyy-MM-dd'T'HH:mm:sszzz")
  %*{
    "clientIp": entry.clientIp,
    "timestamp": tsStr,
    "method": $entry.`method`,
    "path": entry.path,
    "statusCode": entry.statusCode,
    "bytesSent": entry.bytesSent,
    "referer": entry.referer,
    "userAgent": entry.userAgent,
    "rawLine": entry.rawLine
  }

proc parseHttpLogEntryJson*(n: JsonNode): HttpLogEntry =
  ## Parses an HttpLogEntry from a JSON object node.
  let ip = if n.hasKey("clientIp") and n["clientIp"].kind == JString: n["clientIp"].getStr() else: ""
  let tsStr = if n.hasKey("timestamp") and n["timestamp"].kind == JString: n["timestamp"].getStr() else: ""
  let ts = if tsStr.len > 0:
    try: parse(tsStr, "yyyy-MM-dd'T'HH:mm:sszzz") except CatchableError: default(DateTime)
  else: default(DateTime)
  let methStr = if n.hasKey("method") and n["method"].kind == JString: n["method"].getStr() else: ""
  let meth = parseHttpMethod(methStr)
  let p = if n.hasKey("path") and n["path"].kind == JString: n["path"].getStr() else: ""
  let sc = if n.hasKey("statusCode") and n["statusCode"].kind == JInt: n["statusCode"].getInt() else: 0
  let bs = if n.hasKey("bytesSent") and n["bytesSent"].kind == JInt: n["bytesSent"].getBiggestInt() else: 0'i64
  let refStr = if n.hasKey("referer") and n["referer"].kind == JString: n["referer"].getStr() else: ""
  let ua = if n.hasKey("userAgent") and n["userAgent"].kind == JString: n["userAgent"].getStr() else: ""
  let raw = if n.hasKey("rawLine") and n["rawLine"].kind == JString: n["rawLine"].getStr() else: ""

  initHttpLogEntry(
    clientIp = ip,
    timestamp = ts,
    `method` = meth,
    path = p,
    statusCode = sc,
    bytesSent = bs,
    referer = refStr,
    userAgent = ua,
    rawLine = raw
  )

func `==`*(a, b: HttpLogEntry): bool =
  ## Value equality operator for HttpLogEntry.
  a.clientIp == b.clientIp and
    a.timestamp == b.timestamp and
    a.`method` == b.`method` and
    a.path == b.path and
    a.statusCode == b.statusCode and
    a.bytesSent == b.bytesSent and
    a.referer == b.referer and
    a.userAgent == b.userAgent and
    a.rawLine == b.rawLine

func hash*(entry: HttpLogEntry): Hash =
  ## Hash computation enabling HttpLogEntry to be stored in HashSets and Tables.
  var h: Hash = 0
  h = h !& hash(entry.clientIp)
  if entry.timestamp.isInitialized:
    h = h !& hash(entry.timestamp.toTime.toUnix)
    h = h !& hash(entry.timestamp.nanosecond)
  h = h !& hash(ord(entry.`method`))
  h = h !& hash(entry.path)
  h = h !& hash(entry.statusCode)
  h = h !& hash(entry.bytesSent)
  h = h !& hash(entry.referer)
  h = h !& hash(entry.userAgent)
  h = h !& hash(entry.rawLine)
  result = !$h

func isValid*(entry: HttpLogEntry): bool =
  ## Checks if the HttpLogEntry satisfies minimum valid constraints:
  ## non-empty client IP and status code within the standard HTTP range (100..599).
  entry.clientIp.len > 0 and entry.statusCode in 100..599

proc validate*(entry: HttpLogEntry) =
  ## Validates that the entry contains necessary core fields, raising ParseError if invalid.
  if entry.clientIp.len == 0:
    raise newException(ParseError, "HttpLogEntry validation failed: clientIp must not be empty")
  if entry.statusCode notin 100..599:
    raise newException(ParseError, "HttpLogEntry validation failed: statusCode must be between 100 and 599 (got " & $entry.statusCode & ")")

# ==============================================================================
# ActorCategory Procedures & Serialization
# ==============================================================================

func `$`*(c: ActorCategory): string =
  ## Returns canonical string representation of an ActorCategory.
  case c
  of CategoryUnknown: "UNKNOWN"
  of CategoryRealUser: "REAL_USER"
  of CategoryVerifiedBot: "VERIFIED_BOT"
  of CategoryFriendlyCrawler: "FRIENDLY_CRAWLER"
  of CategoryCommercialBot: "COMMERCIAL_BOT"
  of CategorySuspicious: "SUSPICIOUS"
  of CategoryBadActorHacker: "BAD_ACTOR_HACKER"

func parseActorCategory*(s: string): ActorCategory =
  ## Parses a string token into an ActorCategory enum.
  case s.toUpperAscii()
  of "REALUSER", "REAL_USER", "USER": CategoryRealUser
  of "VERIFIEDBOT", "VERIFIED_BOT": CategoryVerifiedBot
  of "FRIENDLYCRAWLER", "FRIENDLY_CRAWLER": CategoryFriendlyCrawler
  of "COMMERCIALBOT", "COMMERCIAL_BOT": CategoryCommercialBot
  of "SUSPICIOUS", "SUSPICIOUSSCANNER", "SUSPICIOUS_SCANNER": CategorySuspicious
  of "BADACTORHACKER", "BAD_ACTOR_HACKER", "HACKER", "BADACTOR": CategoryBadActorHacker
  of "UNKNOWN", "": CategoryUnknown
  else: CategoryUnknown

func isBot*(c: ActorCategory): bool {.inline.} =
  ## Returns true if the category represents a recognized bot or crawler.
  c in {CategoryVerifiedBot, CategoryFriendlyCrawler, CategoryCommercialBot}

func isHacker*(c: ActorCategory): bool {.inline.} =
  ## Returns true if the category represents a malicious bad actor.
  c == CategoryBadActorHacker

func isRealUser*(c: ActorCategory): bool {.inline.} =
  ## Returns true if the category represents a genuine human visitor.
  c == CategoryRealUser

proc `%`*(c: ActorCategory): JsonNode {.inline.} =
  ## Converts an ActorCategory to JSON string node.
  %($c)

# ==============================================================================
# ThreatFlag Procedures & Serialization
# ==============================================================================

func `$`*(flag: ThreatFlag): string =
  ## Returns canonical string representation of a ThreatFlag.
  case flag
  of ThreatSensitiveFile: "SensitiveFileProbe"
  of ThreatCmsExploit: "PathExploit"
  of ThreatDirectoryTraversal: "TraversalAttempt"
  of ThreatSqlInjection: "SqlInjection"
  of ThreatCommandInjection: "CommandInjection"
  of ThreatKnownScannerUa: "KnownScannerUa"
  of ThreatMalformedRequest: "MalformedRequest"
  of ThreatHighRate404: "AggressiveRate"
  of ThreatNoAssetFetch: "NoAssetsRequested"

func parseThreatFlag*(s: string): ThreatFlag =
  ## Parses a string representation into a ThreatFlag enum.
  case s.toUpperAscii()
  of "THREATSENSITIVEFILE", "SENSITIVEFILEPROBE", "SENSITIVEFILE": ThreatSensitiveFile
  of "THREATCMSEXPLOIT", "PATHEXPLOIT", "CMSEXPLOIT": ThreatCmsExploit
  of "THREATDIRECTORYTRAVERSAL", "TRAVERSALATTEMPT", "DIRECTORYTRAVERSAL", "TRAVERSAL": ThreatDirectoryTraversal
  of "THREATSQLINJECTION", "SQLINJECTION", "SQLI": ThreatSqlInjection
  of "THREATCOMMANDINJECTION", "COMMANDINJECTION", "RCE": ThreatCommandInjection
  of "THREATKNOWNSCANNERUA", "KNOWNSCANNERUA", "SCANNERUA": ThreatKnownScannerUa
  of "THREATMALFORMEDREQUEST", "MALFORMEDREQUEST": ThreatMalformedRequest
  of "THREATHIGHRATE404", "AGGRESSIVERATE", "HIGHRATE404": ThreatHighRate404
  of "THREATNOASSETFETCH", "NOASSETSREQUESTED", "NOASSETFETCH": ThreatNoAssetFetch
  else:
    raise newException(ParseError, "Unknown ThreatFlag token: " & s)

proc `%`*(flags: set[ThreatFlag]): JsonNode =
  ## Converts a set of ThreatFlags into a JSON array of strings.
  result = newJArray()
  for f in flags:
    result.add(%($f))

# ==============================================================================
# ThreatProfile Procedures & Serialization
# ==============================================================================

func initThreatProfile*(
  score: int = 0,
  category: ActorCategory = CategoryUnknown,
  flags: set[ThreatFlag] = {},
  matchedSignatures: seq[string] = @[]
): ThreatProfile =
  ## Initializes a new ThreatProfile.
  ThreatProfile(
    score: score,
    category: category,
    flags: flags,
    matchedSignatures: matchedSignatures
  )

func matchedRules*(p: ThreatProfile): seq[string] {.inline.} =
  ## Ergonomic alias for matchedSignatures.
  p.matchedSignatures

proc `matchedRules=`*(p: var ThreatProfile, rules: seq[string]) {.inline.} =
  ## Ergonomic setter for matchedSignatures.
  p.matchedSignatures = rules

func isHacker*(p: ThreatProfile): bool {.inline.} =
  ## Returns true if p.category == CategoryBadActorHacker or p.score >= 50.
  p.category == CategoryBadActorHacker or p.score >= 50

func isBot*(p: ThreatProfile): bool {.inline.} =
  ## Returns true if category is in {CategoryVerifiedBot, CategoryFriendlyCrawler, CategoryCommercialBot}.
  p.category in {CategoryVerifiedBot, CategoryFriendlyCrawler, CategoryCommercialBot}

func isSuspicious*(p: ThreatProfile): bool {.inline.} =
  ## Returns true if category is CategorySuspicious or score in 21..49.
  p.category == CategorySuspicious or p.score in 21..49

func isRealUser*(p: ThreatProfile): bool {.inline.} =
  ## Returns true if category is CategoryRealUser and score <= 20.
  p.category == CategoryRealUser and p.score <= 20

proc validate*(p: ThreatProfile) =
  ## Validates that threat score is within standard bounds (0..100).
  if p.score notin 0..100:
    raise newException(ThreatAnalysisError, "Threat score out of bounds [0..100]: " & $p.score)

func `==`*(a, b: ThreatProfile): bool =
  ## Equality check for ThreatProfile.
  a.score == b.score and
    a.category == b.category and
    a.flags == b.flags and
    a.matchedSignatures == b.matchedSignatures

func `$`*(p: ThreatProfile): string =
  ## Formatted string representation of ThreatProfile.
  result = "ThreatProfile(score: " & $p.score & ", category: " & $p.category & ", flags: {"
  var first = true
  for f in p.flags:
    if not first: result.add(", ")
    result.add($f)
    first = false
  result.add("}, rules: " & $p.matchedSignatures & ")")

proc `%`*(p: ThreatProfile): JsonNode =
  ## Serializes a ThreatProfile to a JSON object.
  %*{
    "score": p.score,
    "category": $p.category,
    "flags": %p.flags,
    "matchedSignatures": %p.matchedSignatures
  }

proc parseThreatProfileJson*(n: JsonNode): ThreatProfile =
  ## Deserializes a ThreatProfile from a JSON object.
  let score = if n.hasKey("score") and n["score"].kind == JInt: n["score"].getInt() else: 0
  let catStr = if n.hasKey("category") and n["category"].kind == JString: n["category"].getStr() else: ""
  let cat = parseActorCategory(catStr)
  var flags: set[ThreatFlag] = {}
  if n.hasKey("flags") and n["flags"].kind == JArray:
    for item in n["flags"]:
      if item.kind == JString:
        try: flags.incl(parseThreatFlag(item.getStr())) except CatchableError: discard
  var rules: seq[string] = @[]
  if n.hasKey("matchedSignatures") and n["matchedSignatures"].kind == JArray:
    for item in n["matchedSignatures"]:
      if item.kind == JString: rules.add(item.getStr())
  initThreatProfile(score = score, category = cat, flags = flags, matchedSignatures = rules)

# ==============================================================================
# GeoLocation Procedures & Serialization
# ==============================================================================

func initGeoLocation*(
  ip: string = "",
  countryCode: string = "",
  countryName: string = "",
  flagEmoji: string = "",
  isPrivate: bool = false,
  city: Option[string] = none(string)
): GeoLocation =
  ## Initializes a new GeoLocation.
  GeoLocation(
    ip: ip,
    countryCode: countryCode,
    countryName: countryName,
    flagEmoji: flagEmoji,
    isPrivate: isPrivate,
    city: city
  )

func `$`*(geo: GeoLocation): string =
  ## String representation of GeoLocation (e.g. "🇺🇸 US (United States)").
  let flag = if geo.flagEmoji.len > 0: geo.flagEmoji & " " else: ""
  let cc = if geo.countryCode.len > 0: geo.countryCode else: "??"
  let name = if geo.countryName.len > 0: " (" & geo.countryName & ")" else: ""
  let priv = if geo.isPrivate: " [Private/LAN]" else: ""
  flag & cc & name & priv

func `==`*(a, b: GeoLocation): bool =
  ## Value equality for GeoLocation.
  a.ip == b.ip and
    a.countryCode == b.countryCode and
    a.countryName == b.countryName and
    a.flagEmoji == b.flagEmoji and
    a.isPrivate == b.isPrivate and
    a.city == b.city

func hash*(geo: GeoLocation): Hash =
  ## Hash for GeoLocation.
  var h: Hash = 0
  h = h !& hash(geo.ip)
  h = h !& hash(geo.countryCode)
  h = h !& hash(geo.countryName)
  h = h !& hash(geo.flagEmoji)
  h = h !& hash(geo.isPrivate)
  if geo.city.isSome:
    h = h !& hash(geo.city.get())
  result = !$h

proc `%`*(geo: GeoLocation): JsonNode =
  ## Serializes GeoLocation to JSON object.
  result = %*{
    "ip": geo.ip,
    "countryCode": geo.countryCode,
    "countryName": geo.countryName,
    "flagEmoji": geo.flagEmoji,
    "isPrivate": geo.isPrivate
  }
  if geo.city.isSome:
    result["city"] = %geo.city.get()
  else:
    result["city"] = newJNull()

proc parseGeoLocationJson*(n: JsonNode): GeoLocation =
  ## Deserializes GeoLocation from JSON object.
  let ip = if n.hasKey("ip") and n["ip"].kind == JString: n["ip"].getStr() else: ""
  let cc = if n.hasKey("countryCode") and n["countryCode"].kind == JString: n["countryCode"].getStr() else: ""
  let cn = if n.hasKey("countryName") and n["countryName"].kind == JString: n["countryName"].getStr() else: ""
  let fe = if n.hasKey("flagEmoji") and n["flagEmoji"].kind == JString: n["flagEmoji"].getStr() else: ""
  let priv = if n.hasKey("isPrivate") and n["isPrivate"].kind == JBool: n["isPrivate"].getBool() else: false
  let city = if n.hasKey("city") and n["city"].kind == JString: some(n["city"].getStr()) else: none(string)
  initGeoLocation(ip, cc, cn, fe, priv, city)

# ==============================================================================
# ActorCluster Procedures & Serialization
# ==============================================================================

proc newActorCluster*(
  clusterId: string = "",
  primaryUa: string = "",
  ips: HashSet[string] = initHashSet[string](),
  entries: seq[HttpLogEntry] = @[],
  totalRequests: int = 0,
  status404Count: int = 0,
  firstSeen: DateTime = default(DateTime),
  lastSeen: DateTime = default(DateTime),
  highestThreatScore: int = 0,
  aggregateRisk: int = 0,
  category: ActorCategory = CategoryUnknown,
  flags: set[ThreatFlag] = {},
  probedPaths: seq[string] = @[],
  proxyRotationDetected: bool = false,
  proxyRotationCount: int = 0,
  subnets: HashSet[string] = initHashSet[string](),
  hostingProviders: HashSet[string] = initHashSet[string](),
  hasDatacenterIps: bool = false,
  synchronizedBurstDetected: bool = false,
  synchronizedBurstCount: int = 0,
  clusterTag: string = ""
): ActorCluster =
  ## Allocates and returns a new ActorCluster reference object.
  ActorCluster(
    clusterId: clusterId,
    primaryUa: primaryUa,
    ips: ips,
    entries: entries,
    totalRequests: totalRequests,
    status404Count: status404Count,
    firstSeen: firstSeen,
    lastSeen: lastSeen,
    highestThreatScore: highestThreatScore,
    aggregateRisk: aggregateRisk,
    category: category,
    flags: flags,
    probedPaths: probedPaths,
    proxyRotationDetected: proxyRotationDetected,
    proxyRotationCount: proxyRotationCount,
    subnets: subnets,
    hostingProviders: hostingProviders,
    hasDatacenterIps: hasDatacenterIps,
    synchronizedBurstDetected: synchronizedBurstDetected,
    synchronizedBurstCount: synchronizedBurstCount,
    clusterTag: clusterTag
  )

proc addEntry*(
  cluster: ActorCluster,
  entry: HttpLogEntry,
  score: int = 0,
  category: ActorCategory = CategoryUnknown,
  flags: set[ThreatFlag] = {}
) =
  ## Ingests an HTTP log entry into the cluster, dynamically updating unique IPs,
  ## request counts, error metrics, time windows, and aggregated threat posture.
  if entry.clientIp.len > 0:
    cluster.ips.incl(entry.clientIp)
  cluster.entries.add(entry)
  inc cluster.totalRequests
  if entry.statusCode == 404:
    inc cluster.status404Count
  if entry.timestamp.isInitialized:
    if not cluster.firstSeen.isInitialized or entry.timestamp < cluster.firstSeen:
      cluster.firstSeen = entry.timestamp
    if not cluster.lastSeen.isInitialized or entry.timestamp > cluster.lastSeen:
      cluster.lastSeen = entry.timestamp
  if score > cluster.highestThreatScore:
    cluster.highestThreatScore = score
  if score > cluster.aggregateRisk:
    cluster.aggregateRisk = score
  if category > cluster.category:
    cluster.category = category
  cluster.flags = cluster.flags + flags
  if entry.path.len > 0 and entry.path notin cluster.probedPaths:
    cluster.probedPaths.add(entry.path)
  if cluster.primaryUa.len == 0 and entry.userAgent.len > 0:
    cluster.primaryUa = entry.userAgent

proc `$`*(cluster: ActorCluster): string =
  ## Compact summary string for ActorCluster.
  let ipCount = cluster.ips.len
  let firstStr = if not cluster.firstSeen.isInitialized: "-" else: cluster.firstSeen.format("yyyy-MM-dd'T'HH:mm:sszzz")
  let lastStr = if not cluster.lastSeen.isInitialized: "-" else: cluster.lastSeen.format("yyyy-MM-dd'T'HH:mm:sszzz")
  let proxyStr = if cluster.proxyRotationDetected: ", ProxyRotation: true" else: ""
  let burstStr = if cluster.synchronizedBurstDetected: ", Burst: true" else: ""
  let tagStr = if cluster.clusterTag.len > 0: " " & cluster.clusterTag else: ""
  "ActorCluster(" & cluster.clusterId & tagStr & ", IPs: " & $ipCount & ", Req: " & $cluster.totalRequests &
    ", 404s: " & $cluster.status404Count & ", Category: " & $cluster.category &
    ", Risk: " & $cluster.aggregateRisk & proxyStr & burstStr & ", Window: [" & firstStr & " .. " & lastStr & "])"

proc `%`*(cluster: ActorCluster): JsonNode =
  ## Serializes ActorCluster to a JSON object node.
  var ipArr = newJArray()
  for ip in cluster.ips:
    ipArr.add(%ip)
  var pathsArr = newJArray()
  for p in cluster.probedPaths:
    pathsArr.add(%p)
  var subnetsArr = newJArray()
  for s in cluster.subnets:
    subnetsArr.add(%s)
  var provArr = newJArray()
  for p in cluster.hostingProviders:
    provArr.add(%p)
  let firstStr = if not cluster.firstSeen.isInitialized: "" else: cluster.firstSeen.format("yyyy-MM-dd'T'HH:mm:sszzz")
  let lastStr = if not cluster.lastSeen.isInitialized: "" else: cluster.lastSeen.format("yyyy-MM-dd'T'HH:mm:sszzz")
  %*{
    "clusterId": cluster.clusterId,
    "clusterTag": cluster.clusterTag,
    "primaryUa": cluster.primaryUa,
    "ips": ipArr,
    "subnets": subnetsArr,
    "hostingProviders": provArr,
    "hasDatacenterIps": cluster.hasDatacenterIps,
    "totalRequests": cluster.totalRequests,
    "status404Count": cluster.status404Count,
    "firstSeen": firstStr,
    "lastSeen": lastStr,
    "highestThreatScore": cluster.highestThreatScore,
    "aggregateRisk": cluster.aggregateRisk,
    "category": $cluster.category,
    "flags": %cluster.flags,
    "probedPaths": pathsArr,
    "proxyRotationDetected": cluster.proxyRotationDetected,
    "proxyRotationCount": cluster.proxyRotationCount,
    "synchronizedBurstDetected": cluster.synchronizedBurstDetected,
    "synchronizedBurstCount": cluster.synchronizedBurstCount
  }

# ==============================================================================
# EnrichedLogRecord Procedures & Serialization
# ==============================================================================

func initEnrichedLogRecord*(
  entry: HttpLogEntry,
  geo: GeoLocation = initGeoLocation(),
  threat: ThreatProfile = initThreatProfile(),
  clusterId: Option[string] = none(string)
): EnrichedLogRecord =
  ## Constructs an EnrichedLogRecord packaging log entry, geolocation, threat intel, and optional cluster ID.
  EnrichedLogRecord(
    entry: entry,
    geo: geo,
    threat: threat,
    clusterId: clusterId
  )

func `$`*(rec: EnrichedLogRecord): string =
  ## Formats EnrichedLogRecord into an enriched single-line representation.
  let geoStr = if rec.geo.countryCode.len > 0: "[" & $rec.geo & "] " else: ""
  let threatStr = "[" & $rec.threat.category & " (score:" & $rec.threat.score & ")] "
  let clusterStr = if rec.clusterId.isSome: "[Cluster:" & rec.clusterId.get() & "] " else: ""
  clusterStr & geoStr & threatStr & $rec.entry

func `==`*(a, b: EnrichedLogRecord): bool =
  ## Value equality operator for EnrichedLogRecord.
  a.entry == b.entry and
    a.geo == b.geo and
    a.threat == b.threat and
    a.clusterId == b.clusterId

proc `%`*(record: EnrichedLogRecord): JsonNode =
  ## Serializes EnrichedLogRecord to JSON object for structured NDJSON export.
  result = %*{
    "entry": %record.entry,
    "geo": %record.geo,
    "threat": %record.threat
  }
  if record.clusterId.isSome:
    result["clusterId"] = %record.clusterId.get()
  else:
    result["clusterId"] = newJNull()

proc parseEnrichedLogRecordJson*(n: JsonNode): EnrichedLogRecord =
  ## Deserializes EnrichedLogRecord from JSON object.
  let entry = if n.hasKey("entry") and n["entry"].kind == JObject: parseHttpLogEntryJson(n["entry"]) else: initHttpLogEntry()
  let geo = if n.hasKey("geo") and n["geo"].kind == JObject: parseGeoLocationJson(n["geo"]) else: initGeoLocation()
  let threat = if n.hasKey("threat") and n["threat"].kind == JObject: parseThreatProfileJson(n["threat"]) else: initThreatProfile()
  let clusterId = if n.hasKey("clusterId") and n["clusterId"].kind == JString: some(n["clusterId"].getStr()) else: none(string)
  initEnrichedLogRecord(entry, geo, threat, clusterId)

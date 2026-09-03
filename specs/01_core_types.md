# Specification 01: Core Architecture & Data Models

## 1. Overview & Scope
This specification defines the central domain models, enums, record types, and configuration schemas used throughout `http_logviewer`. All subsequent modules (parser, geoip, classifier, correlator, renderer) depend on these definitions.
Implementation target: `src/http_logviewer/core/types.nim` and `src/http_logviewer/core/config.nim`.

---

## 2. Type Definitions (`src/http_logviewer/core/types.nim`)

```nim
import std/[times, sets, options, json]

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
    HttpTrace

  ## Classification of the visitor identity and intent
  ActorCategory* = enum
    CategoryUnknown,        ## Unclassified
    CategoryRealUser,       ## Real human visitor browsing legitimately
    CategoryVerifiedBot,    ## Verified search engine (Google, Bing, DuckDuckGo)
    CategoryFriendlyCrawler,## Friendly indexing or archivist bot
    CategoryCommercialBot,  ## Commercial SEO / Data scraping service
    CategorySuspicious,     ## Elevated anomaly score / non-standard behavior
    CategoryBadActorHacker  ## Malicious intent: scanning exploits, .env, SQLi, etc.

  ## Atomic threat indicators detected during analysis
  ThreatFlag* = enum
    ThreatSensitiveFile,    ## Accessing .env, .git, id_rsa, backups, etc.
    ThreatCmsExploit,       ## Probing wp-login.php, xmlrpc.php, setup.php
    ThreatDirectoryTraversal,## Path contains ../ or url-encoded variations
    ThreatSqlInjection,     ## Path/query contains SQL injection syntax
    ThreatCommandInjection, ## Path/query contains shell commands (;id, $(whoami))
    ThreatKnownScannerUa,   ## User-Agent identifies offensive tools (sqlmap, nikto)
    ThreatMalformedRequest, ## Corrupt protocol or impossible HTTP verbs
    ThreatHighRate404,      ## Rapid burst of 404 responses (fuzzing/scanning)
    ThreatNoAssetFetch      ## Scraping HTML only with zero static assets

  ## Geolocation enrichment data for an IP address
  GeoLocation* = object
    ip*: string
    countryCode*: string    ## 2-letter ISO 3166-1 alpha-2 code (e.g. "US", "DE")
    countryName*: string    ## Full name (e.g. "United States", "Germany")
    flagEmoji*: string      ## Unicode regional indicator emoji (e.g. "🇺🇸", "🇩🇪")
    isPrivate*: bool        ## RFC 1918 / Loopback / Bogon IP flag
    city*: Option[string]   ## Optional city if available from database

  ## Normalized representation of a single HTTP log line
  HttpLogEntry* = object
    clientIp*: string
    timestamp*: DateTime
    method*: HttpMethod
    path*: string
    statusCode*: int        ## HTTP Status Code (200, 301, 404, 500, etc.)
    bytesSent*: int64
    referer*: string
    userAgent*: string
    rawLine*: string        ## Preserved raw line for debug or verbatim display

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
    totalRequests*: int
    status404Count*: int
    firstSeen*: DateTime
    lastSeen*: DateTime
    highestThreatScore*: int
    category*: ActorCategory
    flags*: set[ThreatFlag]
    probedPaths*: seq[string]       ## Chronological sample of paths accessed

  ## Enriched event passed to the presentation layer
  EnrichedLogRecord* = object
    entry*: HttpLogEntry
    geo*: GeoLocation
    threat*: ThreatProfile
    clusterId*: Option[string]      ## Set when multi-IP correlation is enabled
```

---

## 3. Configuration Models (`src/http_logviewer/core/config.nim`)

```nim
type
  OutputFormat* = enum
    FormatStreamTable,      ## Live tabular streaming output
    FormatJson,             ## JSON lines (NDJSON) output for pipelines
    FormatGroupedSummary    ## Aggregate view grouped by actor cluster

  ViewerConfig* = object
    logFilePath*: string            ## File path or "-" for STDIN
    follow*: bool                   ## Continuous live stream (-f)
    colorOutput*: bool              ## Emit ANSI colors
    outputFormat*: OutputFormat
    filterCategory*: Option[ActorCategory]
    minThreatScore*: int            ## 0-100 threshold filter
    statusCodeFilter*: seq[int]     ## Specific status codes to show (e.g. @[404, 500])
    geoDbPath*: Option[string]      ## Path to custom MMDB file
    enableGrouping*: bool           ## Group multi-IP actor requests
    correlationWindowSeconds*: int  ## Sliding window for actor correlation (default 1800)

proc defaultViewerConfig*(): ViewerConfig =
  ViewerConfig(
    logFilePath: "-",
    follow: false,
    colorOutput: true,
    outputFormat: FormatStreamTable,
    filterCategory: none(ActorCategory),
    minThreatScore: 0,
    statusCodeFilter: @[],
    geoDbPath: none(string),
    enableGrouping: false,
    correlationWindowSeconds: 1800
  )
```

---

## 4. Helper Methods & Serialization
Implement in `types.nim`:
1. `proc parseHttpMethod*(s: string): HttpMethod`
   - Maps strings `"GET"`, `"POST"`, `"PUT"`, `"DELETE"`, etc. Case-insensitive.
2. `proc isHacker*(p: ThreatProfile): bool`
   - Returns true if `p.category == CategoryBadActorHacker` or `p.score >= 50`.
3. `proc isBot*(p: ThreatProfile): bool`
   - Returns true if category in `{CategoryVerifiedBot, CategoryFriendlyCrawler, CategoryCommercialBot}`.
4. `proc `%*(entry: HttpLogEntry): JsonNode`
   - Converts an `HttpLogEntry` cleanly to structured JSON.
5. `proc `%*(record: EnrichedLogRecord): JsonNode`
   - Converts the complete enriched record to JSON for NDJSON export.

---

## 5. Acceptance Criteria
- Full test coverage in `tests/t_core_types.nim`.
- Zero compiler warnings under `--warning[ProveField]:on`.
- Serialization round-trip tests confirm data fidelity.

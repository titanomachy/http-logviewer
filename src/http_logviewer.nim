## Main entry point and library interface for http_logviewer.
## High-performance HTTP log analyzer CLI tool and library.

import std/[options, tables]
import http_logviewer/core/[prelude, types, config, errors]
import http_logviewer/parser/[engine, formats]
import http_logviewer/enrichment/[geoip, flags]
import http_logviewer/analyzer/[classifier, signatures, useragents, correlator]
import http_logviewer/renderer/[terminal, styles]
import http_logviewer/cli/args
import http_logviewer/submodule

export prelude, types, config, errors, engine, formats, geoip, flags, classifier, signatures, useragents, correlator, terminal, styles, args, submodule

# Thread-local control flag used strictly for POSIX signal handling during CLI streaming
var keepRunning* {.threadvar.}: bool

# Initialize threadvar for main execution thread
keepRunning = true

proc handleSigInt*() {.noconv.} =
  ## Signal handler for SIGINT (Ctrl+C). Initiates graceful shutdown of log streaming.
  ## Safe to call from signal handling contexts.
  keepRunning = false

# ==============================================================================
# Public Library API (Phase 07 / Category B)
# ==============================================================================

# Note: parseLine*(line: string, format: LogFormat = LogFormatAuto): Option[HttpLogEntry]
# and parseLine*(line: string, entry: var HttpLogEntry, format: LogFormat = LogFormatAuto): bool
# are fully implemented and exported from formats.nim.

proc enrichGeo*(ip: string, dbPath: Option[string] = none(string)): GeoLocation =
  ## High-level library procedure to resolve an IP address string to a `GeoLocation` record.
  ##
  ## Automatically resolves private, loopback, carrier-grade NAT, and bogon IP addresses
  ## with zero overhead (`isPrivate = true`). For public IPs, queries MaxMind GeoLite2 MMDB
  ## if `dbPath` is specified or found in standard system locations (`/usr/share/GeoIP/`, etc.),
  ## cleanly falling back to the embedded CIDR database. Returns ISO 3166-1 alpha-2 code,
  ## full English country name, and Unicode regional indicator flag emoji (e.g. 🇺🇸 US, 🇩🇪 DE).
  ##
  ## Thread-safety: Instantiates a thread-isolated engine instance; zero global mutable state.
  let engine = newGeoIpEngine(dbPath)
  engine.lookup(ip)

proc enrichGeo*(engine: GeoIpEngine, ip: string): GeoLocation =
  ## Resolves the given IP address string using an existing `GeoIpEngine` instance.
  ## Leverages the engine's internal LRU cache for ultra-high throughput batch operations.
  ##
  ## Thread-safety: Reentrant and safe for concurrent calls on distinct or thread-local engine instances.
  if engine != nil:
    engine.lookup(ip)
  else:
    enrichGeo(ip)

proc enrichWithGeo*(ip: string, dbPath: Option[string] = none(string)): GeoLocation {.inline.} =
  ## Specification 07 conformant alias for `enrichGeo(ip, dbPath)`.
  enrichGeo(ip, dbPath)

proc enrichWithGeo*(engine: GeoIpEngine, ip: string): GeoLocation {.inline.} =
  ## Specification 07 conformant alias for `enrichGeo(engine, ip)`.
  enrichGeo(engine, ip)

proc analyzeEntry*(entry: HttpLogEntry): ThreatProfile =
  ## High-level library procedure evaluating visitor intent and anomaly risk score (0 to 100)
  ## for a single `HttpLogEntry`.
  ##
  ## Scans request URI and query parameters against OWASP Top 10 attack signatures
  ## (SQL injection, directory traversal, sensitive environment/configuration probes,
  ## remote code execution, Log4j JNDI), matches User-Agents against known bot and scanner
  ## taxonomies, and evaluates HTTP method anomalies.
  ## Categorizes visitors into `CategoryRealUser`, `CategoryVerifiedBot`, `CategoryFriendlyCrawler`,
  ## `CategoryCommercialBot`, `CategorySuspicious`, or `CategoryBadActorHacker`.
  ##
  ## Thread-safety: Pure function, zero global mutable state, completely reentrant and thread-safe.
  classifier.evaluateThreat(entry)

proc analyzeRequest*(entry: HttpLogEntry): ThreatProfile {.inline.} =
  ## Specification 07 conformant alias for `analyzeEntry(entry)`.
  analyzeEntry(entry)

proc analyzeEntry*(entry: HttpLogEntry, tracker: VisitorBehaviorTracker): ThreatProfile =
  ## High-level library procedure evaluating visitor intent and threat score incorporating
  ## client behavioral tracking (404 velocity and static asset request ratio).
  ##
  ## Thread-safety: Mutates only the caller-provided `tracker` instance; zero global state.
  classifier.evaluateThreat(entry, tracker)

proc analyzeRequest*(entry: HttpLogEntry, tracker: VisitorBehaviorTracker): ThreatProfile {.inline.} =
  ## Specification 07 conformant alias for `analyzeEntry(entry, tracker)`.
  analyzeEntry(entry, tracker)

proc correlateStream*(
  correlator: ActorCorrelator,
  entry: HttpLogEntry,
  threat: ThreatProfile,
  acceptHeader: string = ""
): Option[string] =
  ## High-level library procedure correlating a single log entry into a multi-IP actor cluster.
  ##
  ## Synthesizes behavioral fingerprints, probe sequences, sliding-window temporal recency,
  ## residential proxy rotation, synchronized burst patterns, and subnet/ASN proximity.
  ## Returns `some(clusterId)` if the entry belongs to a suspicious or malicious multi-IP
  ## cluster, or `none(string)` if benign, non-threatening, or unmatched.
  ##
  ## Thread-safety: Mutates only the caller-provided `correlator` instance; zero global state.
  if correlator == nil:
    return none(string)
  correlator.correlateRecord(entry, threat, acceptHeader)

proc correlateEvent*(
  correlator: ActorCorrelator,
  entry: HttpLogEntry,
  threat: ThreatProfile,
  acceptHeader: string = ""
): Option[string] {.inline.} =
  ## Specification 07 conformant alias for `correlateStream(correlator, entry, threat, acceptHeader)`.
  correlateStream(correlator, entry, threat, acceptHeader)

proc correlateStream*(
  entries: openArray[HttpLogEntry],
  windowSeconds: int = 1800
): Table[string, ActorCluster] =
  ## High-level batch correlation procedure: processes a sequence or stream of `HttpLogEntry` records
  ## across a sliding time window (default: 1800s / 30m) and returns all discovered `ActorCluster` objects.
  ##
  ## Thread-safety: Creates a thread-isolated correlator instance; zero global mutable state.
  let correlator = newActorCorrelator(windowSeconds)
  for entry in entries:
    let threat = analyzeEntry(entry)
    discard correlator.correlateRecord(entry, threat)
  correlator.clusters

proc enrichAndAnalyze*(
  line: string,
  geoEngine: GeoIpEngine = nil,
  correlator: ActorCorrelator = nil,
  format: LogFormat = LogFormatAuto
): Option[EnrichedLogRecord] =
  ## High-level all-in-one pipeline helper for third-party embedding.
  ## Parses raw log line, enriches geolocation and Unicode flag emoji, evaluates threat intent,
  ## and optionally correlates with active multi-IP clusters.
  ## Returns `some(EnrichedLogRecord)` or `none(EnrichedLogRecord)` if unparseable.
  ##
  ## Thread-safety: Uses passed engines or creates thread-isolated instances; zero global state.
  let optEntry = parseLine(line, format)
  if optEntry.isNone:
    return none(EnrichedLogRecord)

  let entry = optEntry.get()
  let geo = if geoEngine != nil: geoEngine.lookup(entry.clientIp) else: enrichGeo(entry.clientIp)
  let threat = analyzeEntry(entry)

  var clusterId: Option[string] = none(string)
  if correlator != nil:
    clusterId = correlateStream(correlator, entry, threat)

  some(initEnrichedLogRecord(entry, geo, threat, clusterId))

proc runPipeline*(
  cfg: ViewerConfig,
  shouldStopHook: proc(): bool = nil,
  outputWriter: proc(line: string) = nil
): tuple[stats: StreamStats, ticker: StatusTicker] =
  ## Runs the complete log analysis and enrichment pipeline according to cfg.
  ## Continuously streams log lines, enriches with GeoIP and threat classification,
  ## applies CLI filters, and displays output in stream table or NDJSON format.
  ## Gracefully handles Ctrl+C or shouldStopHook, rendering a session summary before exiting.
  keepRunning = true
  try:
    setControlCHook(handleSigInt)
  except CatchableError:
    discard

  let geoEngine = newGeoIpEngine(cfg.geoDbPath)
  let correlator = newActorCorrelator(cfg.correlationWindowSeconds)
  var ticker = initStatusTicker()
  let defaultWriter = proc(s: string) = echo s
  let writeOut = if outputWriter != nil: outputWriter else: defaultWriter

  let shouldStop = proc(): bool =
    if not keepRunning: return true
    if shouldStopHook != nil and shouldStopHook(): return true
    return false

  let stats = streamLogLines(
    sourcePath = cfg.logFilePath,
    follow = cfg.follow,
    format = cfg.logFormat,
    shouldStop = shouldStop,
    onEntry = proc(entry: HttpLogEntry) =
      if not keepRunning: return

      let geo = geoEngine.lookup(entry.clientIp)
      let threat = evaluateThreat(entry)

      var clusterId: Option[string] = none(string)
      if cfg.enableGrouping:
        clusterId = correlator.correlateRecord(entry, threat)

      let record = initEnrichedLogRecord(entry, geo, threat, clusterId)
      ticker.record(record)

      if not cfg.filters.matches(record):
        return

      if cfg.outputFormat == FormatJson:
        writeOut(renderJsonStreamLine(record))
      else:
        writeOut(renderStreamLine(record, cfg.colorOutput))
  )

  # Display session summary banner unless in JSON mode
  if cfg.outputFormat != FormatJson:
    writeOut("")
    writeOut(renderSummaryBanner(ticker, cfg.colorOutput))
    if cfg.enableGrouping and correlator.clusters.len > 0:
      writeOut("")
      writeOut(renderGroupedSummaryTable(correlator.clusters, cfg.colorOutput))

  result = (stats: stats, ticker: ticker)

proc runHelloPipeline*(input: string = "pipeline_init"): string =
  ## Runs a minimal end-to-end hello pipeline through all core modules.
  let parsed = parseHello(input)
  let enriched = enrichHello(parsed)
  let analyzed = analyzeHello(enriched)
  result = renderHello(analyzed)

proc main() =
  try:
    let cfg = parseCommandLineArgs()
    let check = validateInputPath(cfg.logFilePath)
    if not check.valid:
      stderr.writeLine("http_logviewer: " & check.errorMsg)
      quit(check.errorCode)
    
    if cfg.geoDbPath.isSome:
      let geoCheck = validateInputPath(cfg.geoDbPath.get())
      if not geoCheck.valid:
        stderr.writeLine("http_logviewer: " & geoCheck.errorMsg)
        quit(geoCheck.errorCode)

    discard runPipeline(cfg)
    quit(0)
  except ConfigError as e:
    stderr.writeLine("http_logviewer error: " & e.msg)
    quit(1)
  except CatchableError as e:
    stderr.writeLine("http_logviewer fatal error: " & e.msg)
    quit(2)

when isMainModule:
  main()

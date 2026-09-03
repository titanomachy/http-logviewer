# Specification 07: CLI Tool, Library API & Pipeline Integration

## 1. Overview & Scope
This specification defines the CLI argument parser, the signal-safe streaming execution loop, and the public library API for `http_logviewer`.
Implementation targets: `src/http_logviewer/cli/args.nim` and `src/http_logviewer.nim`.

---

## 2. CLI Options & Syntax (`args.nim`)

### 2.1 Command-Line Interface Syntax
```
Usage:
  http_logviewer [options] [LOGFILE]
  tail -f /var/log/nginx/access.log | http_logviewer [options]

Arguments:
  LOGFILE                  Path to HTTP access log (or '-' for standard input)

Options:
  -f, --follow             Continuously follow the log file as it grows
  --filter=<category>      Filter events: 'real', 'bot', 'scraper', 'hacker', 'all' (default: 'all')
  --min-score=<0-100>      Only display requests with risk score >= threshold
  --group-actors           Correlate and group multi-IP requests by actor
  --status=<codes>         Filter by HTTP status codes (comma-separated, e.g. '404,500')
  --geoip-db=<path>        Path to custom MaxMind GeoIP MMDB database file
  --no-color               Disable ANSI color codes and background highlights
  --json                   Output enriched records as NDJSON lines
  -h, --help               Show this help message and exit
  -v, --version            Display version information
```

### 2.2 Option Parser Implementation
Implement using Nim standard library `std/parseopt`:
```nim
import std/[parseopt, strutils, options]
import ../core/[types, config]

proc parseCommandLineArgs*(): ViewerConfig =
  result = defaultViewerConfig()
  var p = initOptParser()
  
  for kind, key, val in p.next():
    case kind
    of cmdArgument:
      result.logFilePath = key
    of cmdLongOption, cmdShortOption:
      case key.toLowerAscii()
      of "f", "follow":
        result.follow = true
      of "filter":
        case val.toLowerAscii()
        of "real": result.filterCategory = some(CategoryRealUser)
        of "bot": result.filterCategory = some(CategoryVerifiedBot)
        of "hacker": result.filterCategory = some(CategoryBadActorHacker)
        of "all": result.filterCategory = none(ActorCategory)
      of "min-score":
        result.minThreatScore = parseInt(val)
      of "group-actors":
        result.enableGrouping = true
      of "status":
        for part in val.split(','):
          result.statusCodeFilter.add(parseInt(part.strip()))
      of "geoip-db":
        result.geoDbPath = some(val)
      of "no-color":
        result.colorOutput = false
      of "json":
        result.outputFormat = FormatJson
      of "h", "help":
        printHelpAndExit()
      of "v", "version":
        printVersionAndExit()
    of cmdEnd:
      discard
```

---

## 3. Streaming Loop & Graceful Signal Handling (`http_logviewer.nim`)

```nim
import std/[posix, strformat, terminal]
import http_logviewer/core/[types, config]
import http_logviewer/parser/[engine, formats]
import http_logviewer/enrichment/[geoip, flags]
import http_logviewer/analyzer/[classifier, correlator]
import http_logviewer/renderer/[styles, terminal]
import http_logviewer/cli/args

var keepRunning = true

proc handleSigInt(sig: cint) {.noconv.} =
  keepRunning = false

proc runPipeline*(cfg: ViewerConfig) =
  onSignal(SIGINT, handleSigInt)
  
  let geoEngine = newGeoIpEngine(cfg.geoDbPath)
  let correlator = newActorCorrelator(cfg.correlationWindowSeconds)
  
  var totalLines = 0
  var realUsers = 0
  var bots = 0
  var hackers = 0

  streamLogLines(cfg.logFilePath, cfg.follow, proc(entry: HttpLogEntry) =
    if not keepRunning: return
    inc(totalLines)
    
    # 1. Enrich with Geolocation & Flag
    let geo = geoEngine.lookup(entry.clientIp)
    
    # 2. Analyze Threat & Intent
    let threat = evaluateThreat(entry)
    
    # 3. Correlate with Multi-IP Actor Clusters
    var clusterId: Option[string] = none(string)
    if cfg.enableGrouping:
      clusterId = correlator.correlateRecord(entry, threat)

    # 4. Update Statistics
    case threat.category
    of CategoryRealUser: inc(realUsers)
    of CategoryVerifiedBot, CategoryFriendlyCrawler, CategoryCommercialBot: inc(bots)
    of CategoryBadActorHacker, CategorySuspicious: inc(hackers)
    else: discard

    # 5. Apply CLI Filters
    if cfg.minThreatScore > 0 and threat.score < cfg.minThreatScore: return
    if cfg.filterCategory.isSome and threat.category != cfg.filterCategory.get(): return
    if cfg.statusCodeFilter.len > 0 and entry.statusCode notin cfg.statusCodeFilter: return

    # 6. Render Output
    let record = EnrichedLogRecord(
      entry: entry,
      geo: geo,
      threat: threat,
      clusterId: clusterId
    )
    
    if cfg.outputFormat == FormatJson:
      echo $(%record)
    else:
      echo renderStreamLine(record, cfg.colorOutput)
  )
  
  # If grouping was enabled, print aggregate clusters upon completion or Ctrl+C
  if cfg.enableGrouping:
    echo renderGroupedClusters(correlator.clusters, cfg.colorOutput)
```

---

## 4. Public Library API
The package must export clean, reusable procedures for third-party Nim applications in `src/http_logviewer.nim`:
```nim
# Public Library API
proc parseLine*(line: string): Option[HttpLogEntry]
proc enrichWithGeo*(ip: string, dbPath: Option[string] = none(string)): GeoLocation
proc analyzeRequest*(entry: HttpLogEntry): ThreatProfile
proc correlateEvent*(correlator: ActorCorrelator, entry: HttpLogEntry, threat: ThreatProfile): Option[string]
```

---

## 5. Acceptance Criteria
- Running `./build/http_logviewer --help` prints usage instructions and exits with code 0.
- Piping logs via `cat tests/fixtures/attacks.log | ./build/http_logviewer` streams enriched events with colored badges.
- Ctrl+C terminates the stream gracefully without unhandled exceptions.

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

var keepRunning* = true

proc handleSigInt*() {.noconv.} =
  ## Signal handler for SIGINT (Ctrl+C). Initiates graceful shutdown of log streaming.
  keepRunning = false

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

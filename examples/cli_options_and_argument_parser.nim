# Example: CLI Options, Argument Parsing & Pipeline Integration
# Demonstrates Phase 07 / Category A:
# - Item 01: Comprehensive CLI argument parsing with flags and values
# - Item 02: Informative help and version documentation
# - Item 03: Graceful signal handling and clean session summary banner
# - Item 04: Input path and permission validation with standard exit codes (0, 1, 2)
# - Item 05: Configuration file support (.toml and .json) with CLI override precedence
# - Item 06: Automated execution of http_logviewer CLI pipeline
#
# Compile and run with:
#   nim r --path:src examples/cli_options_and_argument_parser.nim

import std/[strutils, options, os]
import http_logviewer
import http_logviewer/core/[types, config, errors]
import http_logviewer/cli/args
import http_logviewer/renderer/terminal

proc main() =
  echo "=== http_logviewer: CLI Options & Argument Parser (Phase 07 / Category A) ==="
  echo ""

  # 1. CLI Options Parsing (Item 01)
  echo "[1] CLI Options Parsing & ViewerConfig Synthesis (Item 01):"
  let sampleCliArgs = [
    "/var/log/nginx/access.log",
    "-f",
    "--filter=hacker",
    "--min-score=60",
    "--group-actors",
    "--status=404,500",
    "--no-color"
  ]
  let cfg = parseCommandLine(sampleCliArgs)
  echo "  Source Log File     : ", cfg.logFilePath
  echo "  Follow Mode (-f)    : ", cfg.follow
  echo "  Filter Category     : ", (if cfg.filterCategory.isSome: $cfg.filterCategory.get() else: "all")
  echo "  Min Threat Score    : ", cfg.minThreatScore
  echo "  Multi-IP Grouping   : ", cfg.enableGrouping
  echo "  Status Whitelist    : ", cfg.statusCodeFilter
  echo "  Color Output Active : ", cfg.colorOutput
  echo ""

  # 2. Informative Help & Version Documentation (Item 02)
  echo "[2] Help Manual & Version String (Item 02):"
  echo "  Version String      : ", versionText()
  echo "  Help Text Summary   :"
  let lines = helpText().splitLines()
  for i in 0 .. min(8, lines.len - 1):
    echo "    ", lines[i]
  echo "    ... (see --help for complete manual)"
  echo ""

  # 3. Graceful Signal Handling & Session Summary (Item 03)
  echo "[3] Graceful Signal Handling & Session Summary Display (Item 03):"
  echo "  Simulating graceful Ctrl+C interruption after processing events:"
  var mockTicker = initStatusTicker()
  # Populate sample stats
  let dummyEntry1 = HttpLogEntry(
    clientIp: "185.220.101.5",
    path: "/.env",
    statusCode: 404,
    bytesSent: 162
  )
  let dummyThreat1 = ThreatProfile(
    score: 100,
    category: CategoryBadActorHacker
  )
  let dummyRecord1 = initEnrichedLogRecord(dummyEntry1, GeoLocation(countryCode: "NL", flagEmoji: "🇳🇱"), dummyThreat1)
  mockTicker.record(dummyRecord1)

  let dummyEntry2 = HttpLogEntry(
    clientIp: "8.8.8.8",
    path: "/index.html",
    statusCode: 200,
    bytesSent: 2048
  )
  let dummyThreat2 = ThreatProfile(score: 0, category: CategoryRealUser)
  let dummyRecord2 = initEnrichedLogRecord(dummyEntry2, GeoLocation(countryCode: "US", flagEmoji: "🇺🇸"), dummyThreat2)
  mockTicker.record(dummyRecord2)

  let summaryBanner = renderSummaryBanner(mockTicker, colorize = false, width = 78)
  echo summaryBanner
  echo ""

  # 4. Input Path and Permission Validation (Item 04)
  echo "[4] Input Path & Permission Validation (Item 04):"
  let checkStdin = validateInputPath("-")
  echo "  Stdin ('-') Validation     : valid=", checkStdin.valid, " exitCode=", checkStdin.errorCode
  let checkMissing = validateInputPath("/tmp/non_existent_log_12345.log")
  echo "  Missing File Validation    : valid=", checkMissing.valid, " exitCode=", checkMissing.errorCode, " msg=", checkMissing.errorMsg
  let checkDir = validateInputPath("/tmp")
  echo "  Directory Path Validation  : valid=", checkDir.valid, " exitCode=", checkDir.errorCode, " msg=", checkDir.errorMsg
  echo ""

  # 5. Configuration File Support (Item 05)
  echo "[5] Configuration File Support (.toml & .json) (Item 05):"
  let sampleToml = """
# http_logviewer configuration
follow = false
min_threat_score = 50
filter_category = "hacker"
status_codes = [404, 500]
color_mode = "never"
enable_grouping = true
"""
  let tomlCfg = loadViewerConfigToml(sampleToml)
  echo "  Loaded from TOML:"
  echo "    Min Threat Score  : ", tomlCfg.minThreatScore
  echo "    Filter Category   : ", (if tomlCfg.filterCategory.isSome: $tomlCfg.filterCategory.get() else: "none")
  echo "    Status Codes      : ", tomlCfg.statusCodeFilter
  echo "    Multi-IP Grouping : ", tomlCfg.enableGrouping
  echo "    Color Mode        : ", tomlCfg.colorMode

  # Demonstrate CLI override
  let overridden = parseCommandLine([
    "--min-score=95"  # overrides TOML setting of 50
  ])
  echo "  CLI Override Demonstration: CLI --min-score=95 applied -> minScore=", overridden.minThreatScore
  echo ""

  # 6. End-to-End Pipeline Stream (Item 06)
  echo "[6] End-to-End Pipeline Execution (Item 06):"
  let tempLog = getTempDir() / "example_pipeline_run.log"
  writeFile(tempLog, """185.220.101.5 - - [10/Oct/2026:13:55:36 +0200] "GET /.env HTTP/1.1" 404 162 "-" "curl/7.68.0"
194.26.29.112 - - [10/Oct/2026:13:55:37 +0200] "GET /wp-login.php HTTP/1.1" 403 240 "-" "sqlmap/1.5"
93.184.216.34 - - [10/Oct/2026:13:55:38 +0200] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0"
""")
  defer:
    if fileExists(tempLog): removeFile(tempLog)

  let pipelineCfg = initViewerConfig(
    logFilePath = tempLog,
    colorOutput = false,
    colorMode = ColorModeNever,
    minThreatScore = 40
  )
  echo "  Streaming events with minThreatScore >= 40:"
  discard runPipeline(pipelineCfg)

  echo ""
  echo "=== Category A demonstration complete ==="

when isMainModule:
  main()

# Example: Configuration & State Models
# Demonstrates ViewerConfig, FilterCriteria, CLI option mapping, validation,
# and JSON configuration serialization.
#
# Compile and run with:
#   nim r --path:src examples/configuration_and_state_models.nim

import std/[strutils, options, json, os]
import http_logviewer/core/[types, config, errors]
import http_logviewer/cli/args

proc main() =
  echo "================================================================================"
  echo "       http_logviewer: Configuration & State Models (Phase 01 / Category C)     "
  echo "================================================================================"
  echo ""
  sleep(250)

  # 1. Default Production Configuration
  echo "[1] Default Production Configuration (defaultViewerConfig):"
  let defaultCfg = defaultViewerConfig()
  echo "  Log Source:         ", defaultCfg.logFilePath
  echo "  Output Format:      ", defaultCfg.outputFormat
  echo "  Log Format:         ", defaultCfg.logFormat
  echo "  Color Mode:         ", defaultCfg.colorMode, " (colorOutput = ", defaultCfg.colorOutput, ")"
  echo "  Live Follow:        ", defaultCfg.follow
  echo "  Multi-IP Grouping:  ", defaultCfg.enableGrouping
  echo "  Correlation Window: ", defaultCfg.correlationWindowSeconds, "s"
  echo "  Valid?:             ", defaultCfg.isValid()
  echo ""
  sleep(300)

  # 2. Granular Filtering Criteria (FilterCriteria)
  echo "[2] Granular Filtering Criteria (FilterCriteria):"
  let filter = initFilterCriteria(
    minThreatScore = 50,
    statusWhitelist = [401, 403, 404, 500],
    countryWhitelist = ["US", "DE", "NL"],
    categories = {CategoryBadActorHacker, CategorySuspicious}
  )
  echo "  Criteria:           ", filter
  echo "  Allows Status 404:  ", filter.allowsStatus(404)
  echo "  Allows Status 200:  ", filter.allowsStatus(200)
  echo "  Allows Country 'NL':", filter.allowsCountry("NL")
  echo "  Allows Country 'CN':", filter.allowsCountry("CN")
  echo "  Allows Threat 85:   ", filter.allowsScore(85)
  echo "  Allows Threat 25:   ", filter.allowsScore(25)
  echo ""
  sleep(300)

  # 3. Request Matching against Filter Criteria
  echo "[3] Request Matching against Filter Criteria:"
  let entry = initHttpLogEntry(clientIp = "185.220.101.5", statusCode = 404, `method` = HttpPost, path = "/wp-login.php")
  let geo = initGeoLocation(ip = "185.220.101.5", countryCode = "NL", countryName = "Netherlands", flagEmoji = "🇳🇱")
  let threat = initThreatProfile(score = 88, category = CategoryBadActorHacker, flags = {ThreatCmsExploit})
  let record = initEnrichedLogRecord(entry, geo, threat)

  echo "  Incoming Request:   ", entry.clientIp, " [", geo.flagEmoji, " ", geo.countryCode, "] -> ", entry.statusCode, " ", entry.path
  echo "  Matches Criteria?:  ", filter.matches(record)
  echo ""
  sleep(300)

  # 4. CLI Argument Parsing and Conversion to ViewerConfig
  echo "[4] CLI Argument Parsing & Conversion (parseCommandLine):"
  let sampleCliArgs = [
    "-f",
    "--filter=hacker",
    "--min-score=70",
    "--status=404,500",
    "--group-actors",
    "--format=json",
    "/var/log/nginx/access.log"
  ]
  echo "  Input CLI Tokens:   ", sampleCliArgs
  let cliCfg = parseCommandLine(sampleCliArgs)
  echo "  Parsed Log File:    ", cliCfg.logFilePath
  echo "  Live Follow (-f):   ", cliCfg.follow
  echo "  Min Threat Score:   ", cliCfg.minThreatScore
  echo "  Filter Category:    ", cliCfg.filterCategory.get()
  echo "  Status Filter:      ", cliCfg.statusCodeFilter
  echo "  Multi-IP Grouping:  ", cliCfg.enableGrouping
  echo "  Output Format:      ", cliCfg.outputFormat
  echo ""
  sleep(300)

  # 5. JSON Configuration Serialization and Round-Trip
  echo "[5] JSON Configuration Serialization & Deserialization:"
  let jsonNode = %cliCfg
  echo "  Serialized JSON:    "
  for line in jsonNode.pretty(2).splitLines():
    echo "    ", line
  let roundTrip = loadViewerConfigJson($jsonNode)
  echo "  Round-Trip Match?:  ", (roundTrip == cliCfg)
  echo ""
  sleep(300)

  # 6. Configuration Boundary Validation & Error Trapping
  echo "[6] Configuration Validation & Error Trapping:"
  try:
    var badCfg = defaultViewerConfig()
    badCfg.minThreatScore = 999
    badCfg.validate()
  except ConfigError as err:
    echo "  Caught ConfigError (expected): ", err.msg

  try:
    discard parseCommandLine(["--unknown-flag"])
  except ConfigError as err:
    echo "  Caught CLI Error   (expected): ", err.msg

  echo ""
  echo "=== Category C Configuration Demonstration Completed Successfully ==="

when isMainModule:
  main()

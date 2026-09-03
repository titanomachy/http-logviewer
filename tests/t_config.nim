## Unit test suite for Configuration and State Models (Phase 01 / Category C).

import unittest
import std/[strutils, options, json]
import http_logviewer/core/[types, errors, config]
import http_logviewer/cli/args

suite "Configuration & State Models - ViewerConfig (Phase 01 / Category C / Item 01)":
  test "Item 01: ViewerConfig definition, fields, and initialization":
    let cfg = initViewerConfig(
      logFilePath = "/var/log/nginx/access.log",
      follow = true,
      colorOutput = false,
      colorMode = ColorModeNever,
      outputFormat = FormatJson,
      logFormat = LogFormatCombined,
      filterCategory = some(CategoryBadActorHacker),
      minThreatScore = 42,
      statusCodeFilter = [404, 500],
      geoDbPath = some("/opt/GeoLite2-Country.mmdb"),
      enableGrouping = true,
      correlationWindowSeconds = 3600
    )
    check cfg.logFilePath == "/var/log/nginx/access.log"
    check cfg.follow == true
    check cfg.colorOutput == false
    check cfg.colorMode == ColorModeNever
    check cfg.outputFormat == FormatJson
    check cfg.logFormat == LogFormatCombined
    check cfg.filterCategory == some(CategoryBadActorHacker)
    check cfg.minThreatScore == 42
    check cfg.statusCodeFilter == @[404, 500]
    check cfg.geoDbPath == some("/opt/GeoLite2-Country.mmdb")
    check cfg.enableGrouping == true
    check cfg.correlationWindowSeconds == 3600

  test "Item 01: OutputFormat, LogFormat, and ColorMode enums and parsing":
    check $FormatStreamTable == "stream_table"
    check $FormatJson == "json"
    check $FormatGroupedSummary == "grouped_summary"
    check parseOutputFormat("stream") == FormatStreamTable
    check parseOutputFormat("table") == FormatStreamTable
    check parseOutputFormat("json") == FormatJson
    check parseOutputFormat("ndjson") == FormatJson
    check parseOutputFormat("grouped") == FormatGroupedSummary

    expect ConfigError:
      discard parseOutputFormat("invalid_format")

    check $LogFormatAuto == "auto"
    check $LogFormatClf == "clf"
    check $LogFormatCombined == "combined"
    check $LogFormatNginx == "nginx"
    check $LogFormatJson == "json"
    check parseLogFormat("auto") == LogFormatAuto
    check parseLogFormat("clf") == LogFormatClf
    check parseLogFormat("combined") == LogFormatCombined
    check parseLogFormat("nginx") == LogFormatNginx
    check parseLogFormat("json") == LogFormatJson

    expect ConfigError:
      discard parseLogFormat("unknown_log")

    check $ColorModeAuto == "auto"
    check $ColorModeAlways == "always"
    check $ColorModeNever == "never"
    check parseColorMode("auto") == ColorModeAuto
    check parseColorMode("always") == ColorModeAlways
    check parseColorMode("never") == ColorModeNever
    check parseColorMode("off") == ColorModeNever

    expect ConfigError:
      discard parseColorMode("invalid_color")

  test "Item 01: ViewerConfig stringifier and pretty printer":
    let cfg = defaultViewerConfig()
    let compact = $cfg
    check "ViewerConfig(" in compact
    check "log: \"-\"" in compact
    check "format: stream_table" in compact

    let formatted = cfg.pretty()
    check "ViewerConfig:" in formatted
    check "Log File Path:" in formatted
    check "Correlation Window Seconds: 1800" in formatted

suite "Configuration & State Models - FilterCriteria (Phase 01 / Category C / Item 02)":
  test "Item 02: FilterCriteria default construction and helpers":
    let fc = defaultFilterCriteria()
    check fc.minThreatScore == 0
    check fc.statusWhitelist.len == 0
    check fc.statusBlacklist.len == 0
    check fc.countryWhitelist.len == 0
    check fc.countryBlacklist.len == 0
    check fc.categories.len == 0
    check fc.categoryFilter.isNone

    check fc.allowsScore(0)
    check fc.allowsScore(100)
    check fc.allowsStatus(200)
    check fc.allowsStatus(404)
    check fc.allowsCountry("US")
    check fc.allowsCategory(CategoryRealUser)
    check fc.allowsCategory(CategoryBadActorHacker)

  test "Item 02: FilterCriteria status code whitelist and blacklist":
    var fc = initFilterCriteria(statusWhitelist = [200, 301, 404])
    check fc.allowsStatus(200)
    check fc.allowsStatus(301)
    check fc.allowsStatus(404)
    check not fc.allowsStatus(500)

    fc = initFilterCriteria(statusBlacklist = [200, 304])
    check not fc.allowsStatus(200)
    check not fc.allowsStatus(304)
    check fc.allowsStatus(404)
    check fc.allowsStatus(500)

  test "Item 02: FilterCriteria country whitelist and blacklist":
    let fcWl = initFilterCriteria(countryWhitelist = ["US", "NL", "DE"])
    check fcWl.allowsCountry("US")
    check fcWl.allowsCountry("us") # case-insensitivity
    check fcWl.allowsCountry("NL")
    check not fcWl.allowsCountry("CN")
    check not fcWl.allowsCountry("RU")

    let fcBl = initFilterCriteria(countryBlacklist = ["CN", "RU"])
    check not fcBl.allowsCountry("CN")
    check not fcBl.allowsCountry("cn")
    check not fcBl.allowsCountry("RU")
    check fcBl.allowsCountry("US")
    check fcBl.allowsCountry("NL")

  test "Item 02: FilterCriteria category filtering and composite matching":
    let fc = initFilterCriteria(
      minThreatScore = 50,
      statusWhitelist = [404, 500],
      countryWhitelist = ["NL", "DE"],
      categories = {CategoryBadActorHacker, CategorySuspicious}
    )

    check fc.matches(404, 60, CategoryBadActorHacker, "NL")
    check fc.matches(500, 50, CategorySuspicious, "DE")
    # Fails on score
    check not fc.matches(404, 49, CategoryBadActorHacker, "NL")
    # Fails on status
    check not fc.matches(200, 80, CategoryBadActorHacker, "NL")
    # Fails on category
    check not fc.matches(404, 80, CategoryRealUser, "NL")
    # Fails on country
    check not fc.matches(404, 80, CategoryBadActorHacker, "US")

  test "Item 02: FilterCriteria matching against EnrichedLogRecord":
    let fc = initFilterCriteria(minThreatScore = 60, statusWhitelist = [404])
    let entry = initHttpLogEntry(clientIp = "185.220.101.5", statusCode = 404)
    let threat = initThreatProfile(score = 85, category = CategoryBadActorHacker)
    let geo = initGeoLocation(ip = "185.220.101.5", countryCode = "NL")
    let record = initEnrichedLogRecord(entry, geo, threat)

    check fc.matches(record)
    check fc.matches(entry, threat, geo)

    let lowThreat = initThreatProfile(score = 20, category = CategoryRealUser)
    let lowRecord = initEnrichedLogRecord(entry, geo, lowThreat)
    check not fc.matches(lowRecord)

  test "Item 02: FilterCriteria validation constraints":
    var invalid = initFilterCriteria(minThreatScore = 150)
    expect ConfigError:
      invalid.validate()

    invalid = initFilterCriteria(minThreatScore = -1)
    expect ConfigError:
      invalid.validate()

    invalid = initFilterCriteria(statusWhitelist = [999])
    expect ConfigError:
      invalid.validate()

    invalid = initFilterCriteria(statusWhitelist = [404], statusBlacklist = [404])
    expect ConfigError:
      invalid.validate()

    invalid = initFilterCriteria(countryWhitelist = ["INVALID_TOO_LONG"])
    expect ConfigError:
      invalid.validate()

  test "Item 02: FilterCriteria JSON serialization and equality":
    let fc1 = initFilterCriteria(
      minThreatScore = 40,
      statusWhitelist = [404],
      countryWhitelist = ["NL"],
      categories = {CategorySuspicious}
    )
    let fc2 = initFilterCriteria(
      minThreatScore = 40,
      statusWhitelist = [404],
      countryWhitelist = ["NL"],
      categories = {CategorySuspicious}
    )
    let fc3 = initFilterCriteria(minThreatScore = 41)
    check fc1 == fc2
    check fc1 != fc3

    let j = %fc1
    check j["minThreatScore"].getInt() == 40
    check j["statusWhitelist"][0].getInt() == 404
    check j["countryWhitelist"][0].getStr() == "NL"

suite "Configuration & State Models - Default Config Loader & Validation (Phase 01 / Category C / Item 03)":
  test "Item 03: defaultViewerConfig production defaults":
    let cfg = defaultViewerConfig()
    check cfg.logFilePath == "-"
    check cfg.follow == false
    check cfg.colorOutput == true
    check cfg.colorMode == ColorModeAuto
    check cfg.outputFormat == FormatStreamTable
    check cfg.logFormat == LogFormatAuto
    check cfg.filterCategory.isNone
    check cfg.minThreatScore == 0
    check cfg.statusCodeFilter.len == 0
    check cfg.geoDbPath.isNone
    check cfg.enableGrouping == false
    check cfg.correlationWindowSeconds == 1800
    check cfg.isValid()

  test "Item 03: ViewerConfig validation boundaries":
    var invalid = defaultViewerConfig()
    invalid.logFilePath = ""
    expect ConfigError:
      invalid.validate()
    check not invalid.isValid()

    invalid = defaultViewerConfig()
    invalid.minThreatScore = 101
    expect ConfigError:
      invalid.validate()

    invalid = defaultViewerConfig()
    invalid.correlationWindowSeconds = 0
    expect ConfigError:
      invalid.validate()

    invalid = defaultViewerConfig()
    invalid.statusCodeFilter = @[80]
    expect ConfigError:
      invalid.validate()

  test "Item 03: ViewerConfig JSON serialization and round-trip":
    let original = initViewerConfig(
      logFilePath = "access.log",
      follow = true,
      colorOutput = true,
      colorMode = ColorModeAlways,
      outputFormat = FormatJson,
      logFormat = LogFormatClf,
      filterCategory = some(CategoryVerifiedBot),
      minThreatScore = 30,
      statusCodeFilter = [200, 301],
      geoDbPath = some("/etc/geoip/GeoLite2-Country.mmdb"),
      enableGrouping = true,
      correlationWindowSeconds = 900
    )
    let jsonNode = %original
    let parsed = parseViewerConfigJson(jsonNode)
    check parsed.logFilePath == original.logFilePath
    check parsed.follow == original.follow
    check parsed.colorOutput == original.colorOutput
    check parsed.colorMode == original.colorMode
    check parsed.outputFormat == original.outputFormat
    check parsed.logFormat == original.logFormat
    check parsed.filterCategory == original.filterCategory
    check parsed.minThreatScore == original.minThreatScore
    check parsed.statusCodeFilter == original.statusCodeFilter
    check parsed.geoDbPath == original.geoDbPath
    check parsed.enableGrouping == original.enableGrouping
    check parsed.correlationWindowSeconds == original.correlationWindowSeconds
    check parsed == original

    let roundTrip = loadViewerConfigJson($jsonNode)
    check roundTrip == original

  test "Item 03: loadViewerConfigJson invalid input raises ConfigError":
    expect ConfigError:
      discard loadViewerConfigJson("not valid json {")

suite "Configuration & State Models - CLI Option Mapping Structs (Phase 01 / Category C / Item 04)":
  test "Item 04: CliOptions struct initialization":
    let opts = initCliOptions()
    check opts.logFilePath.isNone
    check opts.follow == false
    check opts.colorOutput == true
    check opts.colorMode.isNone
    check opts.outputFormat.isNone
    check opts.logFormat.isNone
    check opts.filterCategory.isNone
    check opts.minThreatScore.isNone
    check opts.statusCodes.len == 0
    check opts.countryCodes.len == 0
    check opts.geoDbPath.isNone
    check opts.enableGrouping == false
    check opts.correlationWindowSeconds.isNone
    check opts.helpRequested == false
    check opts.versionRequested == false

  test "Item 04: Category string mapping":
    check parseCategoryString("real") == some(CategoryRealUser)
    check parseCategoryString("bot") == some(CategoryVerifiedBot)
    check parseCategoryString("friendly") == some(CategoryFriendlyCrawler)
    check parseCategoryString("scraper") == some(CategoryCommercialBot)
    check parseCategoryString("suspicious") == some(CategorySuspicious)
    check parseCategoryString("hacker") == some(CategoryBadActorHacker)
    check parseCategoryString("all").isNone
    check parseCategoryString("").isNone

    expect ConfigError:
      discard parseCategoryString("unknown_bad_cat")

  test "Item 04: parseCliArgs parsing flags and values":
    let args = [
      "-f",
      "--filter=hacker",
      "-m", "75",
      "-g",
      "--status=404,500,502",
      "--country=US,DE",
      "--geoip-db=/var/geo.mmdb",
      "--format=json",
      "--log-format=nginx",
      "--window=600",
      "/var/log/nginx/access.log"
    ]
    let opts = parseCliArgs(args)
    check opts.follow == true
    check opts.filterCategory == some("hacker")
    check opts.minThreatScore == some(75)
    check opts.enableGrouping == true
    check opts.statusCodes == @[404, 500, 502]
    check opts.countryCodes == @["US", "DE"]
    check opts.geoDbPath == some("/var/geo.mmdb")
    check opts.outputFormat == some(FormatJson)
    check opts.logFormat == some(LogFormatNginx)
    check opts.correlationWindowSeconds == some(600)
    check opts.logFilePath == some("/var/log/nginx/access.log")

  test "Item 04: toViewerConfig conversion from CliOptions":
    var opts = initCliOptions()
    opts.logFilePath = some("my_access.log")
    opts.follow = true
    opts.filterCategory = some("bot")
    opts.minThreatScore = some(15)
    opts.statusCodes = @[200, 304]
    opts.countryCodes = @["NL"]
    opts.enableGrouping = true
    opts.correlationWindowSeconds = some(1200)

    let cfg = toViewerConfig(opts)
    check cfg.logFilePath == "my_access.log"
    check cfg.follow == true
    check cfg.filterCategory == some(CategoryVerifiedBot)
    check cfg.minThreatScore == 15
    check cfg.statusCodeFilter == @[200, 304]
    check cfg.enableGrouping == true
    check cfg.correlationWindowSeconds == 1200
    check cfg.filters.allowsStatus(200)
    check not cfg.filters.allowsStatus(404)
    check cfg.filters.allowsCountry("NL")
    check not cfg.filters.allowsCountry("US")

  test "Item 04: parseCommandLine end-to-end":
    let cfg = parseCommandLine(["--no-color", "--json", "--min-score=80", "attacks.log"])
    check cfg.logFilePath == "attacks.log"
    check cfg.colorOutput == false
    check cfg.colorMode == ColorModeNever
    check cfg.outputFormat == FormatJson
    check cfg.minThreatScore == 80
    check cfg.isValid()

  test "Item 04: CLI error handling and validation":
    expect ConfigError:
      discard parseCommandLine(["--unknown-option"])

    expect ConfigError:
      discard parseCommandLine(["--min-score=notanint"])

    expect ConfigError:
      discard parseCommandLine(["--min-score=150"])

    expect ConfigError:
      discard parseCommandLine(["--status=invalid_code"])

    expect ConfigError:
      discard parseCommandLine(["--window=-5"])

    expect ConfigError:
      discard parseCommandLine(["arg1.log", "arg2.log"]) # extra positional arg

  test "Item 04: Help and version strings":
    check helpText().len > 0
    check "Usage:" in helpText()
    check "--follow" in helpText()
    check versionText().len > 0
    check "http_logviewer" in versionText()

suite "Configuration & State Models - Unit Tests & Edge Cases (Phase 01 / Category C / Item 05)":
  test "Item 05: Default ViewerConfig roundtrip with equality":
    let defCfg = defaultViewerConfig()
    let j = %defCfg
    let reconstructed = parseViewerConfigJson(j)
    check reconstructed == defCfg

  test "Item 05: FilterCriteria allowsCountry with lowercase and spaces":
    let fc = initFilterCriteria(countryWhitelist = ["us", " de "])
    check fc.allowsCountry("US")
    check fc.allowsCountry("de")
    check not fc.allowsCountry("FR")

  test "Item 05: ViewerConfig syncFilters handles programmatic field updates":
    var cfg = defaultViewerConfig()
    cfg.minThreatScore = 65
    cfg.statusCodeFilter = @[403, 404]
    cfg.filterCategory = some(CategoryBadActorHacker)
    cfg.syncFilters()
    check cfg.filters.minThreatScore == 65
    check cfg.filters.statusWhitelist == @[403, 404]
    check cfg.filters.categoryFilter == some(CategoryBadActorHacker)
    check CategoryBadActorHacker in cfg.filters.categories

## CLI argument parsing and flags processing module for http_logviewer.
## Provides CLI option mapping structs, validation, and conversion to ViewerConfig.

import std/[parseopt, strutils, options, os]
import ../core/[types, config, errors]

type
  ## Categorization of CLI options
  CliOptionKind* = enum
    OptFlag,       ## Boolean flag, e.g. -f, --follow, --no-color, --group-actors
    OptValue       ## Option requiring a value, e.g. --min-score=50, --filter=bot

  ## Descriptive definition of a supported CLI flag or parameter
  CliOptionDef* = object
    shortName*: string
    longName*: string
    kind*: CliOptionKind
    description*: string
    defaultValue*: string

  ## Intermediate structured representation of parsed CLI options
  CliOptions* = object
    logFilePath*: Option[string]
    follow*: bool
    colorOutput*: bool
    colorMode*: Option[ColorMode]
    outputFormat*: Option[OutputFormat]
    logFormat*: Option[LogFormat]
    filterCategory*: Option[string]
    minThreatScore*: Option[int]
    statusCodes*: seq[int]
    countryCodes*: seq[string]
    geoDbPath*: Option[string]
    enableGrouping*: bool
    correlationWindowSeconds*: Option[int]
    helpRequested*: bool
    versionRequested*: bool

const
  AppVersion* = "0.1.0"
  AppName* = "http_logviewer"

func cliHello*(greeting: string): string =
  ## Formats a CLI greeting message.
  "CLI: " & greeting

proc versionText*(): string =
  ## Returns canonical version string.
  AppName & " v" & AppVersion & " (Nim HTTP LogViewer & Rogue Bot Detector)"

proc helpText*(): string =
  ## Returns the complete CLI usage and help manual.
  result = """
Usage:
  http_logviewer [options] [LOGFILE]
  tail -f /var/log/nginx/access.log | http_logviewer [options]

Arguments:
  LOGFILE                         Path to HTTP access log file (use '-' for standard input)

Options:
  -f, --follow                    Continuously follow the log file as new lines are appended
  --filter=<category>             Filter by visitor category: 'real', 'bot', 'scraper', 'hacker', 'suspicious', 'all'
  -m, --min-score=<0-100>         Only display requests with risk score >= threshold
  -g, --group-actors              Correlate and group multi-IP requests by actor / botnet
  --status=<codes>                Filter by HTTP status codes (comma-separated, e.g. '404,500')
  --country=<codes>               Filter by ISO country codes (comma-separated, e.g. 'US,DE,NL')
  --geoip-db=<path>               Path to custom MaxMind GeoIP MMDB database file
  --format=<format>               Presentation format: 'stream' (table), 'json' (ndjson), 'grouped' (summary)
  --log-format=<format>           Input log format: 'auto', 'clf', 'combined', 'nginx', 'json'
  --color=<mode>                  Color mode: 'auto', 'always', 'never'
  --no-color                      Shortcut for --color=never
  --json                          Shortcut for --format=json
  --window=<seconds>              Sliding correlation window for multi-IP grouping (default: 1800)
  -h, --help                      Show this help manual and exit
  -v, --version                   Display version information and exit
"""

proc initCliOptions*(): CliOptions =
  ## Initializes an empty CliOptions structure with default values.
  CliOptions(
    logFilePath: none(string),
    follow: false,
    colorOutput: true,
    colorMode: none(ColorMode),
    outputFormat: none(OutputFormat),
    logFormat: none(LogFormat),
    filterCategory: none(string),
    minThreatScore: none(int),
    statusCodes: @[],
    countryCodes: @[],
    geoDbPath: none(string),
    enableGrouping: false,
    correlationWindowSeconds: none(int),
    helpRequested: false,
    versionRequested: false
  )

proc parseCategoryString*(val: string): Option[ActorCategory] =
  ## Maps CLI category string to ActorCategory enum.
  case val.toLowerAscii().strip()
  of "all", "": none(ActorCategory)
  of "real", "realuser", "user": some(CategoryRealUser)
  of "bot", "verifiedbot": some(CategoryVerifiedBot)
  of "friendly", "crawler", "friendlycrawler": some(CategoryFriendlyCrawler)
  of "scraper", "commercial", "commercialbot": some(CategoryCommercialBot)
  of "suspicious", "scanner": some(CategorySuspicious)
  of "hacker", "badactor", "exploit": some(CategoryBadActorHacker)
  else:
    raise newException(ConfigError, "Unknown filter category: '" & val & "'. Supported: real, bot, friendly, scraper, suspicious, hacker, all")

proc parseCliArgs*(args: openArray[string]): CliOptions =
  ## Parses raw command-line tokens into structured CliOptions.
  ## Raises ConfigError on unknown or malformed arguments.
  result = initCliOptions()
  var p = initOptParser(
    @args,
    shortNoVal = {'f', 'g', 'h', 'v'},
    longNoVal = @["follow", "group-actors", "group", "no-color", "nocolor", "json", "help", "version"]
  )

  proc fetchValue(p: var OptParser, optName: string): string =
    if p.val.len > 0:
      return p.val
    p.next()
    if p.kind == cmdArgument:
      return p.key
    raise newException(ConfigError, optName & " requires a value")
  
  while true:
    p.next()
    case p.kind
    of cmdEnd:
      break
    of cmdArgument:
      if result.logFilePath.isNone:
        result.logFilePath = some(p.key)
      else:
        raise newException(ConfigError, "Unexpected extra positional argument: '" & p.key & "'")
    of cmdLongOption, cmdShortOption:
      case p.key.toLowerAscii()
      of "f", "follow":
        result.follow = true
      of "filter":
        let val = p.fetchValue("--filter")
        result.filterCategory = some(val)
      of "m", "min-score", "minscore":
        let val = p.fetchValue("--min-score")
        try:
          let score = parseInt(val)
          ensureConfig(score in 0..100, "--min-score must be between 0 and 100, got: " & val)
          result.minThreatScore = some(score)
        except ValueError:
          raise newException(ConfigError, "Invalid integer for --min-score: '" & val & "'")
      of "g", "group-actors", "group":
        result.enableGrouping = true
      of "status":
        let val = p.fetchValue("--status")
        for part in val.split(','):
          let trimmed = part.strip()
          if trimmed.len > 0:
            try:
              let code = parseInt(trimmed)
              ensureConfig(code in 100..599, "Status code must be between 100 and 599, got: " & trimmed)
              result.statusCodes.add(code)
            except ValueError:
              raise newException(ConfigError, "Invalid integer in --status: '" & trimmed & "'")
      of "country":
        let val = p.fetchValue("--country")
        for part in val.split(','):
          let trimmed = part.strip().toUpperAscii()
          if trimmed.len > 0:
            ensureConfig(trimmed.len in 2..3, "Invalid ISO country code: '" & trimmed & "'")
            result.countryCodes.add(trimmed)
      of "geoip-db", "geoip", "mmdb":
        let val = p.fetchValue("--geoip-db")
        result.geoDbPath = some(val)
      of "format":
        let val = p.fetchValue("--format")
        result.outputFormat = some(parseOutputFormat(val))
      of "log-format", "logformat":
        let val = p.fetchValue("--log-format")
        result.logFormat = some(parseLogFormat(val))
      of "color":
        let val = p.fetchValue("--color")
        let mode = parseColorMode(val)
        result.colorMode = some(mode)
        result.colorOutput = (mode != ColorModeNever)
      of "no-color", "nocolor":
        result.colorMode = some(ColorModeNever)
        result.colorOutput = false
      of "json":
        result.outputFormat = some(FormatJson)
      of "window", "correlation-window":
        let val = p.fetchValue("--window")
        try:
          let secs = parseInt(val)
          ensureConfig(secs > 0, "--window must be positive (> 0), got: " & val)
          result.correlationWindowSeconds = some(secs)
        except ValueError:
          raise newException(ConfigError, "Invalid integer for --window: '" & val & "'")
      of "h", "help":
        result.helpRequested = true
      of "v", "version":
        result.versionRequested = true
      else:
        raise newException(ConfigError, "Unknown option: '--" & p.key & "'. Run with --help for usage instructions.")

proc toViewerConfig*(opts: CliOptions): ViewerConfig =
  ## Converts structured CliOptions into a validated ViewerConfig.
  result = defaultViewerConfig()
  
  if opts.logFilePath.isSome:
    result.logFilePath = opts.logFilePath.get()
  
  result.follow = opts.follow
  result.colorOutput = opts.colorOutput
  if opts.colorMode.isSome:
    result.colorMode = opts.colorMode.get()
  
  if opts.outputFormat.isSome:
    result.outputFormat = opts.outputFormat.get()
  
  if opts.logFormat.isSome:
    result.logFormat = opts.logFormat.get()
  
  if opts.minThreatScore.isSome:
    result.minThreatScore = opts.minThreatScore.get()
  
  if opts.filterCategory.isSome:
    result.filterCategory = parseCategoryString(opts.filterCategory.get())
  
  if opts.statusCodes.len > 0:
    result.statusCodeFilter = opts.statusCodes
  
  if opts.geoDbPath.isSome:
    result.geoDbPath = opts.geoDbPath
  
  result.enableGrouping = opts.enableGrouping
  
  if opts.correlationWindowSeconds.isSome:
    result.correlationWindowSeconds = opts.correlationWindowSeconds.get()
  
  result.filters = initFilterCriteria(
    minThreatScore = result.minThreatScore,
    statusWhitelist = result.statusCodeFilter,
    countryWhitelist = opts.countryCodes,
    categoryFilter = result.filterCategory
  )
  result.validate()

proc parseCommandLine*(args: openArray[string]): ViewerConfig =
  ## Parses and validates command-line arguments into ViewerConfig.
  let opts = parseCliArgs(args)
  result = toViewerConfig(opts)

proc parseCommandLineArgs*(): ViewerConfig =
  ## Convenience wrapper reading process commandLineParams().
  let params = commandLineParams()
  let opts = parseCliArgs(params)
  if opts.helpRequested:
    echo helpText()
    quit(0)
  if opts.versionRequested:
    echo versionText()
    quit(0)
  result = toViewerConfig(opts)

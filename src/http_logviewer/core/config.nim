## Configuration and runtime state models for http_logviewer.
## Provides ViewerConfig, FilterCriteria, format enums, validation routines,
## and serialization hooks.

import std/[strutils, options, json, os]
import errors, types

type
  ## Output presentation format for the log viewer
  OutputFormat* = enum
    FormatStreamTable,      ## Live tabular streaming output with ANSI formatting
    FormatJson,             ## JSON lines (NDJSON) output for pipelines and SIEM ingestion
    FormatGroupedSummary    ## Aggregate view grouped by actor cluster

  ## Input log format specifications
  LogFormat* = enum
    LogFormatAuto,          ## Automatic format detection from input stream
    LogFormatClf,           ## W3C Common Log Format (CLF)
    LogFormatCombined,      ## Nginx / Apache Combined Log Format
    LogFormatNginx,         ## Extended Nginx log format
    LogFormatJson           ## Structured JSON lines log format

  ## Terminal color mode options
  ColorMode* = enum
    ColorModeAuto,          ## Automatically detect TTY and NO_COLOR environment variable
    ColorModeAlways,        ## Always output ANSI escape sequences
    ColorModeNever          ## Monochromatic output without ANSI escape codes

  ## Granular filtering criteria applied to incoming HTTP requests
  FilterCriteria* = object
    minThreatScore*: int                    ## 0-100 threshold filter (requests below this score are discarded)
    statusWhitelist*: seq[int]              ## If non-empty, only these status codes are accepted
    statusBlacklist*: seq[int]              ## Status codes explicitly excluded
    countryWhitelist*: seq[string]          ## If non-empty, only these ISO country codes are accepted (case-insensitive)
    countryBlacklist*: seq[string]          ## ISO country codes explicitly excluded
    categories*: set[ActorCategory]         ## If non-empty, only these categories are accepted
    categoryFilter*: Option[ActorCategory]  ## Single category filter shortcut for CLI compatibility

  ## Primary configuration for http_logviewer session
  ViewerConfig* = object
    logFilePath*: string                    ## File path or "-" for STDIN
    follow*: bool                           ## Continuous live stream (-f / --follow)
    colorOutput*: bool                      ## Emit ANSI colors (derived from colorMode)
    colorMode*: ColorMode                   ## Color mode policy
    outputFormat*: OutputFormat             ## Presentation format
    logFormat*: LogFormat                   ## Input log parsing format
    filterCategory*: Option[ActorCategory]  ## Optional category filter shortcut
    minThreatScore*: int                    ## 0-100 threshold filter
    statusCodeFilter*: seq[int]             ## Specific status codes to display (e.g. @[404, 500])
    geoDbPath*: Option[string]              ## Path to custom MaxMind MMDB file
    enableGrouping*: bool                   ## Correlate and group multi-IP actor requests
    correlationWindowSeconds*: int          ## Sliding window for actor correlation (default 1800)
    filters*: FilterCriteria                ## Detailed filter criteria object

# --- Stringifiers and Parsers for Enums ---

func `$`*(f: OutputFormat): string =
  ## Returns canonical string representation of OutputFormat.
  case f
  of FormatStreamTable: "stream_table"
  of FormatJson: "json"
  of FormatGroupedSummary: "grouped_summary"

func parseOutputFormat*(s: string): OutputFormat =
  ## Parses OutputFormat from string. Raises ConfigError on unrecognized format.
  case s.toLowerAscii().strip()
  of "stream", "table", "stream_table", "streamtable": FormatStreamTable
  of "json", "ndjson": FormatJson
  of "grouped", "summary", "grouped_summary", "groupedsummary": FormatGroupedSummary
  else:
    raise newException(ConfigError, "Unknown output format: '" & s & "'. Supported: stream_table, json, grouped_summary")

func `$`*(f: LogFormat): string =
  ## Returns canonical string representation of LogFormat.
  case f
  of LogFormatAuto: "auto"
  of LogFormatClf: "clf"
  of LogFormatCombined: "combined"
  of LogFormatNginx: "nginx"
  of LogFormatJson: "json"

func parseLogFormat*(s: string): LogFormat =
  ## Parses LogFormat from string. Raises ConfigError on unrecognized format.
  case s.toLowerAscii().strip()
  of "auto", "": LogFormatAuto
  of "clf", "common": LogFormatClf
  of "combined", "apache": LogFormatCombined
  of "nginx": LogFormatNginx
  of "json", "ndjson": LogFormatJson
  else:
    raise newException(ConfigError, "Unknown log format: '" & s & "'. Supported: auto, clf, combined, nginx, json")

func `$`*(m: ColorMode): string =
  ## Returns canonical string representation of ColorMode.
  case m
  of ColorModeAuto: "auto"
  of ColorModeAlways: "always"
  of ColorModeNever: "never"

func parseColorMode*(s: string): ColorMode =
  ## Parses ColorMode from string. Raises ConfigError on unrecognized mode.
  case s.toLowerAscii().strip()
  of "auto", "": ColorModeAuto
  of "always", "true", "on", "yes": ColorModeAlways
  of "never", "false", "off", "no": ColorModeNever
  else:
    raise newException(ConfigError, "Unknown color mode: '" & s & "'. Supported: auto, always, never")

# --- FilterCriteria Procedures ---

func defaultFilterCriteria*(): FilterCriteria =
  ## Returns default FilterCriteria accepting all traffic without filtering.
  FilterCriteria(
    minThreatScore: 0,
    statusWhitelist: @[],
    statusBlacklist: @[],
    countryWhitelist: @[],
    countryBlacklist: @[],
    categories: {},
    categoryFilter: none(ActorCategory)
  )

func initFilterCriteria*(
    minThreatScore: int = 0,
    statusWhitelist: openArray[int] = [],
    statusBlacklist: openArray[int] = [],
    countryWhitelist: openArray[string] = [],
    countryBlacklist: openArray[string] = [],
    categories: set[ActorCategory] = {},
    categoryFilter: Option[ActorCategory] = none(ActorCategory)
): FilterCriteria =
  ## Constructs a customized FilterCriteria instance.
  result = FilterCriteria(
    minThreatScore: minThreatScore,
    statusWhitelist: @statusWhitelist,
    statusBlacklist: @statusBlacklist,
    countryWhitelist: @countryWhitelist,
    countryBlacklist: @countryBlacklist,
    categories: categories,
    categoryFilter: categoryFilter
  )
  if categoryFilter.isSome:
    result.categories.incl(categoryFilter.get())

func allowsScore*(fc: FilterCriteria, score: int): bool {.inline.} =
  ## Returns true if the threat score satisfies the minimum threshold.
  score >= fc.minThreatScore

func allowsStatus*(fc: FilterCriteria, code: int): bool =
  ## Checks if an HTTP status code is permitted by whitelist and blacklist.
  if fc.statusBlacklist.len > 0 and code in fc.statusBlacklist:
    return false
  if fc.statusWhitelist.len > 0:
    return code in fc.statusWhitelist
  return true

func allowsCountry*(fc: FilterCriteria, countryCode: string): bool =
  ## Checks if an ISO country code is permitted by whitelist and blacklist.
  let norm = countryCode.toUpperAscii().strip()
  if fc.countryBlacklist.len > 0:
    for bl in fc.countryBlacklist:
      if bl.toUpperAscii().strip() == norm:
        return false
  if fc.countryWhitelist.len > 0:
    for wl in fc.countryWhitelist:
      if wl.toUpperAscii().strip() == norm:
        return true
    return false
  return true

func allowsCategory*(fc: FilterCriteria, category: ActorCategory): bool =
  ## Checks if an ActorCategory is permitted.
  if fc.categoryFilter.isSome and category != fc.categoryFilter.get():
    return false
  if fc.categories.len > 0 and category notin fc.categories:
    return false
  return true

func matches*(fc: FilterCriteria, statusCode: int, threatScore: int,
              category: ActorCategory, countryCode: string): bool =
  ## Evaluates all filter dimensions against raw attribute parameters.
  if not fc.allowsScore(threatScore): return false
  if not fc.allowsStatus(statusCode): return false
  if not fc.allowsCategory(category): return false
  if countryCode.len > 0 and not fc.allowsCountry(countryCode): return false
  return true

func matches*(fc: FilterCriteria, entry: HttpLogEntry, threat: ThreatProfile, geo: GeoLocation): bool =
  ## Evaluates filter criteria against an entry and its enrichment.
  fc.matches(entry.statusCode, threat.score, threat.category, geo.countryCode)

func matches*(fc: FilterCriteria, record: EnrichedLogRecord): bool =
  ## Evaluates filter criteria against an EnrichedLogRecord.
  fc.matches(record.entry.statusCode, record.threat.score, record.threat.category, record.geo.countryCode)

proc validate*(fc: FilterCriteria) =
  ## Validates FilterCriteria, raising ConfigError on invalid settings.
  ensureConfig(fc.minThreatScore >= 0 and fc.minThreatScore <= 100,
    "minThreatScore must be between 0 and 100, got: " & $fc.minThreatScore)
  for code in fc.statusWhitelist:
    ensureConfig(code in 100..599, "Invalid status code in statusWhitelist: " & $code & " (must be 100..599)")
  for code in fc.statusBlacklist:
    ensureConfig(code in 100..599, "Invalid status code in statusBlacklist: " & $code & " (must be 100..599)")
  for code in fc.statusWhitelist:
    if code in fc.statusBlacklist:
      raise newException(ConfigError, "Status code " & $code & " appears in both statusWhitelist and statusBlacklist")
  for cc in fc.countryWhitelist:
    ensureConfig(cc.len >= 2 and cc.len <= 3, "Invalid country code in countryWhitelist: '" & cc & "'")
  for cc in fc.countryBlacklist:
    ensureConfig(cc.len >= 2 and cc.len <= 3, "Invalid country code in countryBlacklist: '" & cc & "'")

func `==`*(a, b: FilterCriteria): bool =
  ## Value equality for FilterCriteria.
  if a.minThreatScore != b.minThreatScore: return false
  if a.statusWhitelist != b.statusWhitelist: return false
  if a.statusBlacklist != b.statusBlacklist: return false
  if a.countryWhitelist != b.countryWhitelist: return false
  if a.countryBlacklist != b.countryBlacklist: return false
  if a.categories != b.categories: return false
  if a.categoryFilter != b.categoryFilter: return false
  return true

func `$`*(fc: FilterCriteria): string =
  ## Returns compact string description of FilterCriteria.
  result = "FilterCriteria(minThreatScore: " & $fc.minThreatScore
  if fc.statusWhitelist.len > 0:
    result.add(", statusWhitelist: " & $fc.statusWhitelist)
  if fc.statusBlacklist.len > 0:
    result.add(", statusBlacklist: " & $fc.statusBlacklist)
  if fc.countryWhitelist.len > 0:
    result.add(", countryWhitelist: " & $fc.countryWhitelist)
  if fc.countryBlacklist.len > 0:
    result.add(", countryBlacklist: " & $fc.countryBlacklist)
  if fc.categories.len > 0:
    result.add(", categories: " & $fc.categories)
  if fc.categoryFilter.isSome:
    result.add(", categoryFilter: " & $fc.categoryFilter.get())
  result.add(")")

proc `%`*(fc: FilterCriteria): JsonNode =
  ## Serializes FilterCriteria to a JsonNode.
  result = %*{
    "minThreatScore": fc.minThreatScore,
    "statusWhitelist": fc.statusWhitelist,
    "statusBlacklist": fc.statusBlacklist,
    "countryWhitelist": fc.countryWhitelist,
    "countryBlacklist": fc.countryBlacklist,
    "categories": newJArray(),
    "categoryFilter": (if fc.categoryFilter.isSome: %($fc.categoryFilter.get()) else: newJNull())
  }
  for cat in fc.categories:
    result["categories"].add(%($cat))

# --- ViewerConfig Procedures ---

func defaultViewerConfig*(): ViewerConfig =
  ## Returns standard production default ViewerConfig.
  result = ViewerConfig(
    logFilePath: "-",
    follow: false,
    colorOutput: true,
    colorMode: ColorModeAuto,
    outputFormat: FormatStreamTable,
    logFormat: LogFormatAuto,
    filterCategory: none(ActorCategory),
    minThreatScore: 0,
    statusCodeFilter: @[],
    geoDbPath: none(string),
    enableGrouping: false,
    correlationWindowSeconds: 1800,
    filters: defaultFilterCriteria()
  )

func initViewerConfig*(
    logFilePath: string = "-",
    follow: bool = false,
    colorOutput: bool = true,
    colorMode: ColorMode = ColorModeAuto,
    outputFormat: OutputFormat = FormatStreamTable,
    logFormat: LogFormat = LogFormatAuto,
    filterCategory: Option[ActorCategory] = none(ActorCategory),
    minThreatScore: int = 0,
    statusCodeFilter: openArray[int] = [],
    geoDbPath: Option[string] = none(string),
    enableGrouping: bool = false,
    correlationWindowSeconds: int = 1800,
    filters: Option[FilterCriteria] = none(FilterCriteria)
): ViewerConfig =
  ## Constructs a customized ViewerConfig instance, keeping embedded filters synchronized.
  result = ViewerConfig(
    logFilePath: logFilePath,
    follow: follow,
    colorOutput: colorOutput,
    colorMode: colorMode,
    outputFormat: outputFormat,
    logFormat: logFormat,
    filterCategory: filterCategory,
    minThreatScore: minThreatScore,
    statusCodeFilter: @statusCodeFilter,
    geoDbPath: geoDbPath,
    enableGrouping: enableGrouping,
    correlationWindowSeconds: correlationWindowSeconds
  )
  if filters.isSome:
    result.filters = filters.get()
  else:
    result.filters = initFilterCriteria(
      minThreatScore = minThreatScore,
      statusWhitelist = statusCodeFilter,
      categoryFilter = filterCategory
    )

proc syncFilters*(cfg: var ViewerConfig) =
  ## Synchronizes top-level shortcut fields with the embedded FilterCriteria.
  if cfg.minThreatScore > 0 and cfg.filters.minThreatScore == 0:
    cfg.filters.minThreatScore = cfg.minThreatScore
  if cfg.statusCodeFilter.len > 0 and cfg.filters.statusWhitelist.len == 0:
    cfg.filters.statusWhitelist = cfg.statusCodeFilter
  if cfg.filterCategory.isSome and cfg.filters.categoryFilter.isNone:
    cfg.filters.categoryFilter = cfg.filterCategory
    cfg.filters.categories.incl(cfg.filterCategory.get())

proc validate*(cfg: ViewerConfig) =
  ## Validates ViewerConfig, raising ConfigError on any inconsistency or invalid boundary.
  ensureConfig(cfg.logFilePath.len > 0, "logFilePath must not be empty (use '-' for STDIN)")
  ensureConfig(cfg.minThreatScore in 0..100,
    "minThreatScore must be between 0 and 100, got: " & $cfg.minThreatScore)
  ensureConfig(cfg.correlationWindowSeconds > 0,
    "correlationWindowSeconds must be positive (> 0), got: " & $cfg.correlationWindowSeconds)
  for code in cfg.statusCodeFilter:
    ensureConfig(code in 100..599, "Invalid status code in statusCodeFilter: " & $code & " (must be 100..599)")
  cfg.filters.validate()

proc isValid*(cfg: ViewerConfig): bool =
  ## Returns true if configuration passes all validation checks without raising.
  try:
    cfg.validate()
    return true
  except ConfigError:
    return false

func `==`*(a, b: ViewerConfig): bool =
  ## Structural value equality for ViewerConfig.
  if a.logFilePath != b.logFilePath: return false
  if a.follow != b.follow: return false
  if a.colorOutput != b.colorOutput: return false
  if a.colorMode != b.colorMode: return false
  if a.outputFormat != b.outputFormat: return false
  if a.logFormat != b.logFormat: return false
  if a.filterCategory != b.filterCategory: return false
  if a.minThreatScore != b.minThreatScore: return false
  if a.statusCodeFilter != b.statusCodeFilter: return false
  if a.geoDbPath != b.geoDbPath: return false
  if a.enableGrouping != b.enableGrouping: return false
  if a.correlationWindowSeconds != b.correlationWindowSeconds: return false
  if a.filters != b.filters: return false
  return true

func `$`*(cfg: ViewerConfig): string =
  ## Returns compact single-line description of ViewerConfig.
  result = "ViewerConfig(log: \"" & cfg.logFilePath & "\"" &
    ", format: " & $cfg.outputFormat &
    ", logFormat: " & $cfg.logFormat &
    ", color: " & $cfg.colorOutput &
    ", follow: " & $cfg.follow &
    ", grouping: " & $cfg.enableGrouping &
    ", minScore: " & $cfg.minThreatScore &
    ")"

func pretty*(cfg: ViewerConfig): string =
  ## Formats a multi-line human-readable summary of the configuration.
  result = "ViewerConfig:\n"
  result.add("  Log File Path:              " & cfg.logFilePath & "\n")
  result.add("  Follow Live Growth:         " & $cfg.follow & "\n")
  result.add("  Color Output:               " & $cfg.colorOutput & " (" & $cfg.colorMode & ")\n")
  result.add("  Output Format:              " & $cfg.outputFormat & "\n")
  result.add("  Input Log Format:           " & $cfg.logFormat & "\n")
  result.add("  Min Threat Score:           " & $cfg.minThreatScore & "\n")
  result.add("  Category Filter:            " & (if cfg.filterCategory.isSome: $cfg.filterCategory.get() else: "none") & "\n")
  result.add("  Status Codes:               " & (if cfg.statusCodeFilter.len > 0: $cfg.statusCodeFilter else: "all") & "\n")
  result.add("  GeoIP Database:             " & (if cfg.geoDbPath.isSome: cfg.geoDbPath.get() else: "embedded / auto-discover") & "\n")
  result.add("  Multi-IP Grouping:          " & $cfg.enableGrouping & "\n")
  result.add("  Correlation Window Seconds: " & $cfg.correlationWindowSeconds & "\n")
  result.add("  Detailed Filters:           " & $cfg.filters)

proc `%`*(cfg: ViewerConfig): JsonNode =
  ## Serializes ViewerConfig to structured JSON.
  result = %*{
    "logFilePath": cfg.logFilePath,
    "follow": cfg.follow,
    "colorOutput": cfg.colorOutput,
    "colorMode": $cfg.colorMode,
    "outputFormat": $cfg.outputFormat,
    "logFormat": $cfg.logFormat,
    "filterCategory": (if cfg.filterCategory.isSome: %($cfg.filterCategory.get()) else: newJNull()),
    "minThreatScore": cfg.minThreatScore,
    "statusCodeFilter": cfg.statusCodeFilter,
    "geoDbPath": (if cfg.geoDbPath.isSome: %cfg.geoDbPath.get() else: newJNull()),
    "enableGrouping": cfg.enableGrouping,
    "correlationWindowSeconds": cfg.correlationWindowSeconds,
    "filters": %cfg.filters
  }

proc parseViewerConfigJson*(node: JsonNode): ViewerConfig =
  ## Deserializes a ViewerConfig from a JsonNode.
  result = defaultViewerConfig()
  if node.hasKey("logFilePath") and node["logFilePath"].kind == JString:
    result.logFilePath = node["logFilePath"].getStr()
  if node.hasKey("follow") and node["follow"].kind == JBool:
    result.follow = node["follow"].getBool()
  if node.hasKey("colorOutput") and node["colorOutput"].kind == JBool:
    result.colorOutput = node["colorOutput"].getBool()
  if node.hasKey("colorMode") and node["colorMode"].kind == JString:
    result.colorMode = parseColorMode(node["colorMode"].getStr())
  if node.hasKey("outputFormat") and node["outputFormat"].kind == JString:
    result.outputFormat = parseOutputFormat(node["outputFormat"].getStr())
  if node.hasKey("logFormat") and node["logFormat"].kind == JString:
    result.logFormat = parseLogFormat(node["logFormat"].getStr())
  if node.hasKey("filterCategory") and node["filterCategory"].kind == JString:
    result.filterCategory = some(parseActorCategory(node["filterCategory"].getStr()))
  if node.hasKey("minThreatScore") and node["minThreatScore"].kind in {JInt}:
    result.minThreatScore = node["minThreatScore"].getInt()
  if node.hasKey("statusCodeFilter") and node["statusCodeFilter"].kind == JArray:
    result.statusCodeFilter = @[]
    for item in node["statusCodeFilter"]:
      if item.kind == JInt:
        result.statusCodeFilter.add(item.getInt())
  if node.hasKey("geoDbPath") and node["geoDbPath"].kind == JString:
    result.geoDbPath = some(node["geoDbPath"].getStr())
  if node.hasKey("enableGrouping") and node["enableGrouping"].kind == JBool:
    result.enableGrouping = node["enableGrouping"].getBool()
  if node.hasKey("correlationWindowSeconds") and node["correlationWindowSeconds"].kind == JInt:
    result.correlationWindowSeconds = node["correlationWindowSeconds"].getInt()
  result.syncFilters()

proc loadViewerConfigJson*(jsonStr: string): ViewerConfig =
  ## Parses and validates ViewerConfig from a raw JSON string.
  try:
    let parsed = parseJson(jsonStr)
    result = parseViewerConfigJson(parsed)
    result.validate()
  except JsonParsingError as e:
    raise newException(ConfigError, "Invalid JSON configuration format: " & e.msg)

proc loadViewerConfigToml*(tomlStr: string): ViewerConfig =
  ## Parses and validates ViewerConfig from a TOML configuration string.
  result = defaultViewerConfig()
  for line in tomlStr.splitLines():
    let trimmed = line.strip()
    if trimmed.len == 0 or trimmed.startsWith("#") or trimmed.startsWith(";"):
      continue
    if trimmed.startsWith("[") and trimmed.endsWith("]"):
      continue
    let eqPos = trimmed.find('=')
    if eqPos < 0:
      continue
    let rawKey = trimmed[0 ..< eqPos].strip().toLowerAscii().replace("_", "").replace("-", "")
    var rawVal = trimmed[eqPos + 1 .. ^1].strip()

    if not (rawVal.startsWith("\"") or rawVal.startsWith("'")):
      let hashPos = rawVal.find('#')
      if hashPos >= 0:
        rawVal = rawVal[0 ..< hashPos].strip()

    proc unquote(s: string): string =
      if (s.startsWith("\"") and s.endsWith("\"")) or (s.startsWith("'") and s.endsWith("'")):
        if s.len >= 2: s[1 .. ^2] else: ""
      else:
        s

    case rawKey
    of "logfilepath", "logfile", "path":
      result.logFilePath = unquote(rawVal)
    of "follow":
      result.follow = (rawVal.toLowerAscii() in ["true", "1", "yes", "on"])
    of "colormode", "color":
      result.colorMode = parseColorMode(unquote(rawVal))
      result.colorOutput = (result.colorMode != ColorModeNever)
    of "coloroutput":
      result.colorOutput = (rawVal.toLowerAscii() in ["true", "1", "yes", "on"])
      if not result.colorOutput:
        result.colorMode = ColorModeNever
    of "outputformat", "format":
      result.outputFormat = parseOutputFormat(unquote(rawVal))
    of "logformat":
      result.logFormat = parseLogFormat(unquote(rawVal))
    of "filtercategory", "category":
      let catStr = unquote(rawVal)
      if catStr.len > 0 and catStr.toLowerAscii() != "all":
        result.filterCategory = some(parseActorCategory(catStr))
      else:
        result.filterCategory = none(ActorCategory)
    of "minthreatscore", "minscore", "threatscore":
      try:
        result.minThreatScore = parseInt(rawVal)
      except ValueError:
        raise newException(ConfigError, "Invalid integer for min_threat_score in TOML: '" & rawVal & "'")
    of "statuscodes", "statuscodefilter", "status":
      if rawVal.startsWith("[") and rawVal.endsWith("]"):
        let inner = rawVal[1 .. ^2].strip()
        result.statusCodeFilter = @[]
        if inner.len > 0:
          for part in inner.split(','):
            let pTrim = part.strip()
            if pTrim.len > 0:
              try:
                result.statusCodeFilter.add(parseInt(pTrim))
              except ValueError:
                raise newException(ConfigError, "Invalid status code integer in TOML: '" & pTrim & "'")
    of "countrycodes", "countrywhitelist", "countries":
      if rawVal.startsWith("[") and rawVal.endsWith("]"):
        let inner = rawVal[1 .. ^2].strip()
        result.filters.countryWhitelist = @[]
        if inner.len > 0:
          for part in inner.split(','):
            let pTrim = unquote(part.strip())
            if pTrim.len > 0:
              result.filters.countryWhitelist.add(pTrim.toUpperAscii())
    of "geodbpath", "geoipdb", "mmdb":
      let pathVal = unquote(rawVal)
      if pathVal.len > 0:
        result.geoDbPath = some(pathVal)
    of "enablegrouping", "groupactors", "grouping":
      result.enableGrouping = (rawVal.toLowerAscii() in ["true", "1", "yes", "on"])
    of "correlationwindowseconds", "correlationwindow", "window":
      try:
        result.correlationWindowSeconds = parseInt(rawVal)
      except ValueError:
        raise newException(ConfigError, "Invalid integer for correlation_window_seconds in TOML: '" & rawVal & "'")
    else:
      discard
  result.syncFilters()
  result.validate()

proc loadViewerConfigFile*(path: string): ViewerConfig =
  ## Loads and validates ViewerConfig from either a .json or .toml file path.
  ## Raises ConfigError if file is not found or malformed.
  if not fileExists(path):
    raise newException(ConfigError, "Configuration file not found: '" & path & "'")
  let content = readFile(path)
  let norm = path.toLowerAscii()
  if norm.endsWith(".json"):
    return loadViewerConfigJson(content)
  elif norm.endsWith(".toml"):
    return loadViewerConfigToml(content)
  else:
    try:
      return loadViewerConfigJson(content)
    except ConfigError:
      return loadViewerConfigToml(content)


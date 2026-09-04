## Terminal rendering and layout formatting module for http_logviewer.
## Implements Phase 06 terminal presentation, streaming line output,
## column alignment, and status badge integration.

import std/[strutils, times, terminal, unicode, tables, sets, algorithm, json]
import ../core/types
import styles

export styles

func renderHello*(msg: PipelineMessage): string =
  ## Formats the final pipeline output string for terminal presentation.
  "[" & msg.stage & "] " & msg.message

type
  StreamFormatOptions* = object
    ## Configurable options for formatting streaming log lines and tabular output.
    colorize*: bool             ## Whether to emit ANSI colors and styling
    useEmoji*: bool             ## Whether to render Unicode country flag emojis
    includeUserAgent*: bool     ## Whether to include User-Agent column
    maxWidth*: int              ## Max terminal width constraint (0 = unconstrained)
    maxPathLen*: int            ## Maximum path length before shortening (0 = auto)
    maxUaLen*: int              ## Maximum User-Agent length before truncation (0 = auto)
    highlightSuspicious*: bool  ## Whether to highlight exploit tokens in URI parameters

func defaultStreamFormatOptions*(): StreamFormatOptions =
  ## Returns production default options for stream formatting.
  StreamFormatOptions(
    colorize: true,
    useEmoji: true,
    includeUserAgent: true,
    maxWidth: 0,
    maxPathLen: 0,
    maxUaLen: 0,
    highlightSuspicious: false
  )

proc getEffectiveTerminalWidth*(overrideWidth: int = 0, fallback: int = 120): int =
  ## Returns effective terminal column width:
  ## - Uses `overrideWidth` if > 0
  ## - Otherwise queries `terminal.terminalWidth()`
  ## - Falls back to `fallback` (default 120) if stdout is redirected or query fails
  if overrideWidth > 0:
    return overrideWidth
  try:
    let w = terminal.terminalWidth()
    if w > 0:
      return w
  except CatchableError:
    discard
  fallback

proc shortenPath*(path: string, maxLen: int): string =
  ## Shortens a URI path using middle ellipsis truncation to fit within `maxLen`.
  ## Preserves leading slash/root structure and the ending filename/resource.
  if maxLen <= 0 or path.len <= maxLen:
    return path
  if maxLen <= 3:
    return "...".substr(0, maxLen - 1)

  let avail = maxLen - 3
  let headLen = (avail + 1) div 2
  let tailLen = avail - headLen
  if tailLen > 0:
    path[0 ..< headLen] & "..." & path[path.len - tailLen .. ^1]
  else:
    path[0 ..< headLen] & "..."

proc truncateText*(text: string, maxLen: int, ellipsis: string = "..."): string =
  ## Truncates arbitrary text to `maxLen` terminal characters with an ellipsis suffix.
  if maxLen <= 0 or text.len <= maxLen:
    return text
  let ellLen = terminalDisplayWidth(ellipsis)
  if maxLen <= ellLen:
    return ellipsis.substr(0, maxLen - 1)
  text[0 ..< (maxLen - ellLen)] & ellipsis

proc truncateAnsi*(s: string, maxVisibleWidth: int, ellipsis: string = "..."): string =
  ## Safely truncates a string containing ANSI escape sequences to `maxVisibleWidth` visual columns.
  ## Preserves internal escape codes without counting them and appends ANSI Reset (`\e[0m`) if truncated.
  let currentWidth = terminalDisplayWidth(s)
  if currentWidth <= maxVisibleWidth:
    return s
  if maxVisibleWidth <= 0:
    return ""

  let ellWidth = terminalDisplayWidth(ellipsis)
  let targetWidth = if maxVisibleWidth > ellWidth: maxVisibleWidth - ellWidth else: maxVisibleWidth

  result = newStringOfCap(s.len)
  var visibleCount = 0
  var regionalIndicatorCount = 0
  var hadEscape = false
  var i = 0

  while i < s.len:
    if s[i] == '\e' and i + 1 < s.len and s[i + 1] == '[':
      hadEscape = true
      let start = i
      i += 2
      while i < s.len and s[i] notin {'m', 'A'..'Z', 'a'..'z'}:
        inc i
      if i < s.len:
        inc i
      result.add(s[start ..< i])
    else:
      let r = runeAt(s, i)
      let rLen = r.toUTF8().len
      let cp = int(r)
      var runeWidth = 1
      if cp in [0xFE0E, 0xFE0F]:
        runeWidth = 0
      elif isRegionalIndicatorRune(r):
        inc regionalIndicatorCount
        if regionalIndicatorCount == 2:
          runeWidth = 2
          regionalIndicatorCount = 0
        else:
          runeWidth = 0
      elif isEmojiRune(r):
        runeWidth = 2
      elif cp in 0x00..0x1F or cp == 0x7F:
        runeWidth = 0

      if visibleCount + runeWidth > targetWidth:
        break

      visibleCount += runeWidth
      result.add(s[i ..< i + rLen])
      i += rLen

  if maxVisibleWidth > ellWidth:
    result.add(ellipsis)
  if hadEscape:
    result.add(Reset)

proc renderStreamHeader*(
  colorize: bool = true,
  useEmoji: bool = true,
  includeUserAgent: bool = true,
  maxWidth: int = 0
): string =
  ## Renders a standardized columnar table header for the stream view:
  ## `TIME      GEO    STATUS  INTENT       CLIENT IP        METHOD PATH                 USER-AGENT`
  let timeHdr = "TIME    "
  let geoHdr = "GEO    "
  let statusHdr = "STATUS"
  let intentHdr = "INTENT     "
  let ipHdr = "CLIENT IP      "

  let prefix = "$1  $2  $3  $4  $5" % [timeHdr, geoHdr, statusHdr, intentHdr, ipHdr]

  var line = ""
  if maxWidth <= 0:
    line = prefix & "  METHOD PATH" & (if includeUserAgent: "                 USER-AGENT" else: "")
  elif maxWidth < 85 or not includeUserAgent:
    line = prefix & "  METHOD PATH"
  else:
    line = prefix & "  METHOD PATH                 USER-AGENT"

  if maxWidth > 0 and terminalDisplayWidth(line) > maxWidth:
    line = truncateAnsi(line, maxWidth)

  if colorize:
    result = Bold & FgCyan & line & Reset
  else:
    result = line

proc renderStreamSeparator*(width: int = 80, sepChar: char = '-'): string =
  ## Renders a horizontal separator rule of specified width.
  let w = if width > 0: width else: 80
  repeat(sepChar, w)

proc renderStreamHeader*(opts: StreamFormatOptions): string =
  ## Renders a standardized columnar table header using StreamFormatOptions.
  renderStreamHeader(opts.colorize, opts.useEmoji, opts.includeUserAgent, opts.maxWidth)

proc renderStreamSeparator*(opts: StreamFormatOptions, sepChar: char = '-'): string =
  ## Renders a horizontal separator rule sized to opts.maxWidth or fallback.
  let w = if opts.maxWidth > 0: opts.maxWidth else: 80
  repeat(sepChar, w)

proc isSuspiciousParamValue*(val: string): bool =
  ## Returns true if a URI path or parameter value contains known attack signatures.
  let lower = val.toLowerAscii()
  # Directory traversal
  if ".." in lower or "%2e" in lower or "%252e" in lower: return true
  # SQL injection
  if "union" in lower and ("select" in lower or "%20" in lower or "+" in lower): return true
  if "' or " in lower or "\" or " in lower or "1=1" in lower or "sleep(" in lower or "waitfor" in lower or "information_schema" in lower: return true
  # Command injection & RCE
  if ";id" in lower or "|id" in lower or "whoami" in lower or "/bin/" in lower or "$( " in lower or "$(" in lower or "eval(" in lower or "base64" in lower: return true
  # Log4j / JNDI
  if "jndi:" in lower or "${" in lower: return true
  # Sensitive files & admin portals
  if ".env" in lower or "wp-config" in lower or "id_rsa" in lower or "/etc/passwd" in lower or "passwd" in lower: return true
  if "wp-login" in lower or "xmlrpc" in lower or "phpmyadmin" in lower or "/actuator/" in lower: return true
  false

proc highlightSuspiciousUri*(uri: string, colorize: bool = true): string =
  ## Highlights attack payloads and suspicious parameters within a URI using high-contrast ANSI styling.
  ## Monochromatic mode returns the original URI unmodified.
  if not colorize or uri.len == 0:
    return uri

  let qPos = uri.find('?')
  if qPos < 0:
    let lower = uri.toLowerAscii()
    if isSuspiciousParamValue(lower):
      return BgDarkRed & uri & Reset
    return uri

  let pathPart = uri[0 ..< qPos]
  let queryPart = uri[qPos + 1 .. ^1]

  var formattedPath = pathPart
  let lowerPath = pathPart.toLowerAscii()
  if isSuspiciousParamValue(lowerPath):
    formattedPath = BgDarkRed & pathPart & Reset

  let pairs = queryPart.split('&')
  var formattedPairs: seq[string] = @[]

  for pair in pairs:
    let eqPos = pair.find('=')
    if eqPos < 0:
      if isSuspiciousParamValue(pair):
        formattedPairs.add(BgRedBold & " " & pair & " " & Reset)
      else:
        formattedPairs.add(FgWhite & pair & Reset)
    else:
      let key = pair[0 ..< eqPos]
      let val = pair[eqPos + 1 .. ^1]
      if isSuspiciousParamValue(key) or isSuspiciousParamValue(val):
        formattedPairs.add(FgYellow & key & FgGray & "=" & BgRedBold & " " & val & " " & Reset)
      else:
        formattedPairs.add(FgCyan & key & FgGray & "=" & FgWhite & val & Reset)

  result = formattedPath & FgGray & "?" & Reset & formattedPairs.join(FgGray & "&" & Reset)

proc highlightUriDiff*(baseline: string, modified: string, colorize: bool = true): string =
  ## Compares a suspicious or modified URI against a benign baseline URI,
  ## highlighting added or altered parameters in high-contrast ANSI bold red/yellow.
  if not colorize or baseline == modified:
    return modified

  let baseQ = baseline.find('?')
  let modQ = modified.find('?')

  if modQ < 0 or baseQ < 0:
    return highlightSuspiciousUri(modified, colorize)

  let basePath = baseline[0 ..< baseQ]
  let modPath = modified[0 ..< modQ]

  var pathStr = modPath
  if basePath != modPath:
    pathStr = BgDarkRed & modPath & Reset

  let basePairs = baseline[baseQ + 1 .. ^1].split('&')
  var baseTable = initTable[string, string]()
  for p in basePairs:
    let eq = p.find('=')
    if eq >= 0:
      baseTable[p[0 ..< eq]] = p[eq + 1 .. ^1]
    else:
      baseTable[p] = ""

  let modPairs = modified[modQ + 1 .. ^1].split('&')
  var formattedPairs: seq[string] = @[]

  for p in modPairs:
    let eq = p.find('=')
    let (key, val) = if eq >= 0: (p[0 ..< eq], p[eq + 1 .. ^1]) else: (p, "")
    if key notin baseTable:
      formattedPairs.add(FgBrightRedBold & "+" & key & "=" & val & Reset)
    elif baseTable[key] != val:
      formattedPairs.add(FgYellow & key & FgGray & "=" & BgRedBold & " " & val & " " & Reset)
    else:
      formattedPairs.add(FgGray & key & "=" & val & Reset)

  result = pathStr & FgGray & "?" & Reset & formattedPairs.join(FgGray & "&" & Reset)

proc formatPathForStream(path: string, maxLen: int, highlight: bool, isSuspicious: bool): string =
  let p = if maxLen > 0: shortenPath(path, maxLen) else: path
  if highlight and isSuspicious:
    highlightSuspiciousUri(p, colorize = true)
  else:
    p

proc renderStreamLine*(
  record: EnrichedLogRecord,
  opts: StreamFormatOptions
): string =
  ## Formats a single EnrichedLogRecord into an aligned columnar stream line:
  ## `[TIMESTAMP] [FLAG+CC] [STATUS_BADGE] [INTENT] [CLIENT_IP] [METHOD PATH] [USER_AGENT]`
  let timeStr = if record.entry.timestamp.isInitialized:
                  record.entry.timestamp.format("HH:mm:ss")
                else:
                  "--:--:--"
  let geoStr = formatCountryColumn(record.geo, useEmoji = opts.useEmoji, width = 7)
  let statusStr = formatStatusCode(record.entry.statusCode, opts.colorize)
  let intentBadge = formatIntentBadge(record.threat.category, opts.colorize)
  let ipStr = alignLeft(if record.entry.clientIp.len > 0: record.entry.clientIp else: "-", 15)

  let prefix = "$1  $2  $3  $4  $5" % [
    timeStr, geoStr, statusStr, intentBadge, ipStr
  ]
  let prefixWidth = terminalDisplayWidth(prefix) # 54
  let isSuspicious = record.threat.category in {CategoryBadActorHacker, CategorySuspicious} or record.threat.score >= 50

  if opts.maxWidth <= 0:
    let formattedPath = formatPathForStream(record.entry.path, opts.maxPathLen, opts.highlightSuspicious and opts.colorize, isSuspicious)
    let reqStr = $record.entry.method & " " & formattedPath
    if opts.includeUserAgent:
      let rawUa = if record.entry.userAgent.len > 0: record.entry.userAgent else: "-"
      let uaStr = if opts.maxUaLen > 0: truncateText(rawUa, opts.maxUaLen) else: rawUa
      result = prefix & "  " & reqStr & "  " & uaStr
    else:
      result = prefix & "  " & reqStr
  else:
    if opts.maxWidth <= prefixWidth:
      let reqStr = $record.entry.method & " " & record.entry.path
      let line = prefix & "  " & reqStr
      return truncateAnsi(line, opts.maxWidth)

    let remaining = opts.maxWidth - prefixWidth - 2
    let rawPath = record.entry.path
    let methStr = $record.entry.method & " "
    let fullReqLen = methStr.len + rawPath.len
    let rawUa = if record.entry.userAgent.len > 0: record.entry.userAgent else: "-"

    if not opts.includeUserAgent or remaining < 30:
      let maxP = if opts.maxPathLen > 0: min(opts.maxPathLen, max(5, remaining - methStr.len))
                 else: max(5, remaining - methStr.len)
      let formattedPath = formatPathForStream(rawPath, maxP, opts.highlightSuspicious and opts.colorize, isSuspicious)
      result = prefix & "  " & methStr & formattedPath
    else:
      # Both request and User-Agent are eligible for display
      if fullReqLen + 2 + rawUa.len <= remaining and (opts.maxPathLen == 0 or rawPath.len <= opts.maxPathLen) and (opts.maxUaLen == 0 or rawUa.len <= opts.maxUaLen):
        # Entire request and entire User-Agent fit within remaining width
        let formattedPath = formatPathForStream(rawPath, 0, opts.highlightSuspicious and opts.colorize, isSuspicious)
        result = prefix & "  " & methStr & formattedPath & "  " & rawUa
      else:
        # Prioritize preserving the request path if it leaves at least 15 columns for UA
        var maxP: int
        if fullReqLen <= remaining - 15:
          maxP = if opts.maxPathLen > 0: min(opts.maxPathLen, rawPath.len) else: rawPath.len
        else:
          let targetReqWidth = min(max(25, (remaining * 60) div 100), remaining - 15)
          maxP = if opts.maxPathLen > 0: min(opts.maxPathLen, max(5, targetReqWidth - methStr.len))
                 else: max(5, targetReqWidth - methStr.len)

        let formattedPath = formatPathForStream(rawPath, maxP, opts.highlightSuspicious and opts.colorize, isSuspicious)
        let reqStr = methStr & formattedPath
        let reqWidth = terminalDisplayWidth(reqStr)
        let availUa = remaining - reqWidth - 2
        if availUa >= 8:
          let maxUa = if opts.maxUaLen > 0: min(opts.maxUaLen, availUa) else: availUa
          let uaStr = truncateText(rawUa, maxUa)
          result = prefix & "  " & reqStr & "  " & uaStr
        else:
          result = prefix & "  " & reqStr

    if terminalDisplayWidth(result) > opts.maxWidth:
      result = truncateAnsi(result, opts.maxWidth)

proc renderStreamLine*(
  record: EnrichedLogRecord,
  colorize: bool = true,
  useEmoji: bool = true,
  maxWidth: int = 0,
  includeUserAgent: bool = true
): string =
  ## Backwards-compatible convenience overload for renderStreamLine.
  var opts = defaultStreamFormatOptions()
  opts.colorize = colorize
  opts.useEmoji = useEmoji
  opts.maxWidth = maxWidth
  opts.includeUserAgent = includeUserAgent
  renderStreamLine(record, opts)

# ==============================================================================
# Live Status Ticker & Summary Banner (Phase 06 / Category B / Item 03)
# ==============================================================================

type
  StatusTicker* = object
    ## In-memory accumulator tracking live ingestion metrics, visitor intent distribution,
    ## status code frequencies, and top attack paths for status tickers and banners.
    totalLines*: int
    realUsers*: int
    verifiedBots*: int
    crawlers*: int
    commercialBots*: int
    suspicious*: int
    hackers*: int
    attackPaths*: CountTable[string]
    statusCounts*: CountTable[int]
    uniqueIps*: HashSet[string]
    bytesSentTotal*: int64

proc initStatusTicker*(): StatusTicker =
  ## Initializes an empty StatusTicker.
  StatusTicker(
    totalLines: 0,
    realUsers: 0,
    verifiedBots: 0,
    crawlers: 0,
    commercialBots: 0,
    suspicious: 0,
    hackers: 0,
    attackPaths: initCountTable[string](),
    statusCounts: initCountTable[int](),
    uniqueIps: initHashSet[string](),
    bytesSentTotal: 0
  )

proc totalBots*(ticker: StatusTicker): int {.inline.} =
  ## Returns total count of all bot traffic (verified + friendly crawlers + commercial bots).
  ticker.verifiedBots + ticker.crawlers + ticker.commercialBots

proc hackerRatio*(ticker: StatusTicker): float =
  ## Returns the proportion of requests flagged as malicious hackers (0.0 .. 1.0).
  if ticker.totalLines > 0:
    float(ticker.hackers) / float(ticker.totalLines)
  else:
    0.0

proc record*(ticker: var StatusTicker, record: EnrichedLogRecord) =
  ## Ingests an EnrichedLogRecord, incrementing classification counters and tracking top attack probes.
  inc ticker.totalLines
  if record.entry.clientIp.len > 0:
    ticker.uniqueIps.incl(record.entry.clientIp)
  if record.entry.statusCode > 0:
    ticker.statusCounts.inc(record.entry.statusCode)
  ticker.bytesSentTotal += record.entry.bytesSent

  case record.threat.category
  of CategoryRealUser: inc ticker.realUsers
  of CategoryVerifiedBot: inc ticker.verifiedBots
  of CategoryFriendlyCrawler: inc ticker.crawlers
  of CategoryCommercialBot: inc ticker.commercialBots
  of CategorySuspicious: inc ticker.suspicious
  of CategoryBadActorHacker: inc ticker.hackers
  of CategoryUnknown: discard

  # Track targeted endpoints if marked suspicious, hacker, or 404
  if record.threat.category in {CategoryBadActorHacker, CategorySuspicious} or
     record.threat.score >= 50 or
     record.entry.statusCode == 404:
    if record.entry.path.len > 0:
      ticker.attackPaths.inc(record.entry.path)

proc getTopAttackPaths*(ticker: StatusTicker, limit: int = 5): seq[tuple[path: string, count: int]] =
  ## Returns the top targeted attack endpoints sorted by frequency in descending order.
  var pairs: seq[tuple[path: string, count: int]] = @[]
  for path, count in ticker.attackPaths.pairs:
    pairs.add((path: path, count: count))
  pairs.sort(proc(a, b: tuple[path: string, count: int]): int = cmp(b.count, a.count))
  let count = min(limit, pairs.len)
  if count > 0:
    result = pairs[0 ..< count]

proc renderTicker*(ticker: StatusTicker, colorize: bool = true, maxWidth: int = 0): string =
  ## Renders a compact single-line status ticker:
  ## `[STATUS] Parsed: 1,450 | Real: 1,200 | Bots: 180 | Hackers: 70 (4.8%) | Top: /.env (32), /wp-login.php (18)`
  let total = ticker.totalLines
  let real = ticker.realUsers
  let bots = ticker.totalBots
  let hackers = ticker.hackers
  let pct = if total > 0: (float(hackers) * 100.0) / float(total) else: 0.0
  let pctStr = formatFloat(pct, ffDecimal, 1) & "%"

  var topProbes = ""
  let topList = ticker.getTopAttackPaths(3)
  if topList.len > 0:
    var items: seq[string] = @[]
    for item in topList:
      items.add(item.path & " (" & $item.count & ")")
    topProbes = items.join(", ")

  if not colorize:
    var line = "[STATUS] Parsed: " & $total & " | Real: " & $real & " | Bots: " & $bots &
               " | Hackers: " & $hackers & " (" & pctStr & ")"
    if topProbes.len > 0:
      line.add(" | Top: " & topProbes)
    if maxWidth > 0 and terminalDisplayWidth(line) > maxWidth:
      line = truncateText(line, maxWidth)
    return line
  else:
    let tag = Bold & FgCyan & "[STATUS]" & Reset
    let parsedStr = FgWhite & "Parsed: " & Reset & Bold & $total & Reset
    let realStr = FgWhite & "Real: " & Reset & FgGreen & Bold & $real & Reset
    let botsStr = FgWhite & "Bots: " & Reset & FgCyan & Bold & $bots & Reset
    let hackerColor = if hackers > 0: BgRedBold & " " & $hackers & " (" & pctStr & ") " & Reset
                      else: FgGreen & $hackers & " (" & pctStr & ")" & Reset
    let hackerStr = FgWhite & "Hackers: " & Reset & hackerColor

    var line = tag & " " & parsedStr & " | " & realStr & " | " & botsStr & " | " & hackerStr
    if topProbes.len > 0:
      line.add(" | " & FgYellow & "Top: " & topProbes & Reset)
    if maxWidth > 0 and terminalDisplayWidth(line) > maxWidth:
      line = truncateAnsi(line, maxWidth)
    return line

proc renderSummaryBanner*(ticker: StatusTicker, colorize: bool = true, width: int = 80): string =
  ## Renders a multi-line structured session summary banner suitable for display on stream completion or exit.
  let w = if width > 0: width else: 80
  let sepDouble = repeat('=', w)
  let sepSingle = repeat('-', w)

  let title = "HTTP LOGVIEWER - SESSION TRAFFIC SUMMARY"
  let total = ticker.totalLines
  let uniqueIpCount = ticker.uniqueIps.len
  let real = ticker.realUsers
  let bots = ticker.totalBots
  let suspicious = ticker.suspicious
  let hackers = ticker.hackers
  let err404 = ticker.statusCounts.getOrDefault(404)

  let realPct = if total > 0: formatFloat((float(real) * 100.0) / float(total), ffDecimal, 1) & "%" else: "0.0%"
  let botsPct = if total > 0: formatFloat((float(bots) * 100.0) / float(total), ffDecimal, 1) & "%" else: "0.0%"
  let suspPct = if total > 0: formatFloat((float(suspicious) * 100.0) / float(total), ffDecimal, 1) & "%" else: "0.0%"
  let hackPct = if total > 0: formatFloat((float(hackers) * 100.0) / float(total), ffDecimal, 1) & "%" else: "0.0%"

  var b = ""
  b.add(sepDouble & "\n")
  if colorize:
    b.add(Bold & FgCyan & title & Reset & "\n")
  else:
    b.add(title & "\n")
  b.add(sepSingle & "\n")
  b.add("Total Lines Ingested : " & $total & "\n")
  b.add("Unique Client IPs    : " & $uniqueIpCount & "\n")
  b.add("Real Human Visitors  : " & $real & " (" & realPct & ")\n")
  b.add("Verified / SEO Bots  : " & $bots & " (" & botsPct & ")\n")
  b.add("Suspicious Scanners  : " & $suspicious & " (" & suspPct & ")\n")
  if colorize and hackers > 0:
    b.add("Rogue Hackers        : " & BgRedBold & " " & $hackers & " (" & hackPct & ") " & Reset & "\n")
  else:
    b.add("Rogue Hackers        : " & $hackers & " (" & hackPct & ")\n")
  b.add("Total 404 Responses  : " & $err404 & "\n")

  let topList = ticker.getTopAttackPaths(5)
  if topList.len > 0:
    b.add("Top Probed Endpoints :\n")
    for i, item in topList:
      let line = "  " & $(i + 1) & ". " & item.path & " (" & $item.count & " requests)\n"
      if colorize:
        b.add(FgYellow & line & Reset)
      else:
        b.add(line)
  b.add(sepDouble)
  result = b

# ==============================================================================
# JSON Output Rendering Engine (Phase 06 / Category B / Item 05)
# ==============================================================================

proc renderJsonRecord*(record: EnrichedLogRecord, pretty: bool = false): string =
  ## Serializes an EnrichedLogRecord into JSON.
  ## When `pretty` is false (default), produces compact single-line JSON (NDJSON),
  ## ideal for piping directly into jq, Vector, or SIEM collectors.
  let j = %record
  if pretty:
    pretty(j, indent = 2)
  else:
    $j

proc renderJsonStreamLine*(record: EnrichedLogRecord): string {.inline.} =
  ## Emits a single newline-delimited JSON (NDJSON) event line for streaming pipelines.
  $(%record)

proc renderJsonEntry*(entry: HttpLogEntry, pretty: bool = false): string =
  ## Serializes an HttpLogEntry into JSON (compact or pretty-printed).
  let j = %entry
  if pretty:
    pretty(j, indent = 2)
  else:
    $j

proc renderJsonBatch*(records: openArray[EnrichedLogRecord], pretty: bool = false): string =
  ## Serializes a collection of enriched records.
  ## When `pretty` is true, returns a JSON array; when false, returns NDJSON (newline-delimited).
  if pretty:
    var arr = newJArray()
    for r in records:
      arr.add(%r)
    pretty(arr, indent = 2)
  else:
    var lines = newSeqOfCap[string](records.len)
    for r in records:
      lines.add($(%r))
    lines.join("\n")

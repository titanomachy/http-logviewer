## Terminal rendering and layout formatting module for http_logviewer.
## Implements Phase 06 terminal presentation, streaming line output,
## column alignment, and status badge integration.

import std/[strutils, times, terminal, unicode, tables, sets, algorithm, json, options]
import ../core/types
import ../enrichment/[geoip, flags]
import ../analyzer/correlator
import ../parser/formats
import styles

export styles
export formats.cleanVhost

func renderHello*(msg: PipelineMessage): string =
  ## Formats the final pipeline output string for terminal presentation.
  "[" & msg.stage & "] " & msg.message

type
  StreamFormatOptions* = object
    ## Configurable options for formatting streaming log lines and tabular output.
    colorize*: bool             ## Whether to emit ANSI colors and styling
    useEmoji*: bool             ## Whether to render Unicode country flag emojis
    includeUserAgent*: bool     ## Whether to include User-Agent column
    includeVhost*: bool         ## Whether to include Website / Virtual Host column
    maxWidth*: int              ## Max terminal width constraint (0 = unconstrained)
    maxPathLen*: int            ## Maximum path length before shortening (0 = auto)
    maxUaLen*: int              ## Maximum User-Agent length before truncation (0 = auto)
    maxHostLen*: int            ## Maximum Host/Website length before truncation (0 = auto)
    highlightSuspicious*: bool  ## Whether to highlight exploit tokens in URI parameters

func defaultStreamFormatOptions*(): StreamFormatOptions =
  ## Returns production default options for stream formatting.
  StreamFormatOptions(
    colorize: true,
    useEmoji: true,
    includeUserAgent: true,
    includeVhost: false,
    maxWidth: 0,
    maxPathLen: 0,
    maxUaLen: 0,
    maxHostLen: 0,
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

func shortenPath*(path: string, maxLen: int): string =
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

func truncateText*(text: string, maxLen: int, ellipsis: string = "..."): string =
  ## Truncates arbitrary text to `maxLen` terminal characters with an ellipsis suffix.
  if maxLen <= 0 or text.len <= maxLen:
    return text
  let ellLen = terminalDisplayWidth(ellipsis)
  if maxLen <= ellLen:
    return ellipsis.substr(0, maxLen - 1)
  text[0 ..< (maxLen - ellLen)] & ellipsis

func truncateAnsi*(s: string, maxVisibleWidth: int, ellipsis: string = "..."): string =
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
  maxWidth: int = 0,
  includeVhost: bool = false
): string =
  ## Renders a standardized columnar table header for the stream view:
  ## `TIME      GEO    STATUS  INTENT       CLIENT IP        (WEBSITE                 )  METHOD PATH                 USER-AGENT`
  let timeHdr = "TIME    "
  let geoHdr = "GEO    "
  let statusHdr = "STATUS"
  let intentHdr = "INTENT     "
  let ipHdr = "CLIENT IP      "
  let vhostHdr = "WEBSITE                 "

  let prefix = if includeVhost:
                 "$1  $2  $3  $4  $5  $6" % [timeHdr, geoHdr, statusHdr, intentHdr, ipHdr, vhostHdr]
               else:
                 "$1  $2  $3  $4  $5" % [timeHdr, geoHdr, statusHdr, intentHdr, ipHdr]

  var line = ""
  let minUaWidth = if includeVhost: 110 else: 85
  if maxWidth <= 0:
    line = prefix & "  METHOD PATH" & (if includeUserAgent: "                 USER-AGENT" else: "")
  elif maxWidth < minUaWidth or not includeUserAgent:
    line = prefix & "  METHOD PATH"
  else:
    line = prefix & "  METHOD PATH                 USER-AGENT"

  if maxWidth > 0 and terminalDisplayWidth(line) > maxWidth:
    line = truncateAnsi(line, maxWidth)

  if colorize:
    result = Bold & FgCyan & line & Reset
  else:
    result = line

func renderStreamSeparator*(width: int = 80, sepChar: char = '-'): string =
  ## Renders a horizontal separator rule of specified width.
  let w = if width > 0: width else: 80
  repeat(sepChar, w)

proc renderStreamHeader*(opts: StreamFormatOptions): string =
  ## Renders a standardized columnar table header using StreamFormatOptions.
  renderStreamHeader(opts.colorize, opts.useEmoji, opts.includeUserAgent, opts.maxWidth, opts.includeVhost)

func renderStreamSeparator*(opts: StreamFormatOptions, sepChar: char = '-'): string =
  ## Renders a horizontal separator rule sized to opts.maxWidth or fallback.
  let w = if opts.maxWidth > 0: opts.maxWidth else: 80
  repeat(sepChar, w)

func isSuspiciousParamValue*(val: string): bool =
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
  let cleanPath = sanitizeControlChars(path)
  let p = if maxLen > 0: shortenPath(cleanPath, maxLen) else: cleanPath
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
  let cleanIp = sanitizeControlChars(record.entry.clientIp)
  let ipStr = alignLeft(if cleanIp.len > 0: cleanIp else: "-", 15)

  let showVhost = opts.includeVhost or record.entry.vhost.len > 0
  let prefix = if showVhost:
                 let cv = cleanVhost(record.entry.vhost)
                 let rawHost = if cv.len > 0: cv else: "-"
                 let hostClean = sanitizeControlChars(rawHost)
                 let truncatedHost = if opts.maxHostLen > 0: truncateText(hostClean, opts.maxHostLen) else: hostClean
                 let vhostCol = alignLeft(truncatedHost, 24)
                 "$1  $2  $3  $4  $5  $6" % [
                   timeStr, geoStr, statusStr, intentBadge, ipStr, vhostCol
                 ]
               else:
                 "$1  $2  $3  $4  $5" % [
                   timeStr, geoStr, statusStr, intentBadge, ipStr
                 ]
  let prefixWidth = terminalDisplayWidth(prefix)
  let isSuspicious = record.threat.category in {CategoryBadActorHacker, CategorySuspicious} or record.threat.score >= 50

  if opts.maxWidth <= 0:
    let formattedPath = formatPathForStream(record.entry.path, opts.maxPathLen, opts.highlightSuspicious and opts.colorize, isSuspicious)
    let reqStr = $record.entry.method & " " & formattedPath
    if opts.includeUserAgent:
      let rawUa = if record.entry.userAgent.len > 0: sanitizeControlChars(record.entry.userAgent) else: "-"
      let uaStr = if opts.maxUaLen > 0: truncateText(rawUa, opts.maxUaLen) else: rawUa
      result = prefix & "  " & reqStr & "  " & uaStr
    else:
      result = prefix & "  " & reqStr
  else:
    if opts.maxWidth <= prefixWidth:
      let reqStr = $record.entry.method & " " & sanitizeControlChars(record.entry.path)
      let line = prefix & "  " & reqStr
      return truncateAnsi(line, opts.maxWidth)

    let remaining = opts.maxWidth - prefixWidth - 2
    let rawPath = sanitizeControlChars(record.entry.path)
    let methStr = $record.entry.method & " "
    let fullReqLen = methStr.len + rawPath.len
    let rawUa = if record.entry.userAgent.len > 0: sanitizeControlChars(record.entry.userAgent) else: "-"

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
  includeUserAgent: bool = true,
  includeVhost: bool = false
): string =
  ## Backwards-compatible convenience overload for renderStreamLine.
  var opts = defaultStreamFormatOptions()
  opts.colorize = colorize
  opts.useEmoji = useEmoji
  opts.maxWidth = maxWidth
  opts.includeUserAgent = includeUserAgent
  opts.includeVhost = includeVhost
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
  ## `[STATUS] Parsed: 1,450 | Real: 1,200 | Bots: 180 | Crackers: 70 (4.8%) | Top: /.env (32), /wp-login.php (18)`
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
               " | Crackers: " & $hackers & " (" & pctStr & ")"
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
    let hackerStr = FgWhite & "Crackers: " & Reset & hackerColor

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
    b.add("Rogue Crackers       : " & BgRedBold & " " & $hackers & " (" & hackPct & ") " & Reset & "\n")
  else:
    b.add("Rogue Crackers       : " & $hackers & " (" & hackPct & ")\n")
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

# ==============================================================================
# Grouped Summary Table (Phase 06 / Category C / Item 01)
# ==============================================================================

proc sortClustersByRisk*(clusters: openArray[ActorCluster]): seq[ActorCluster] =
  ## Sorts an openArray of ActorCluster references in descending order of risk score:
  ## primary key: aggregateRisk, secondary key: highestThreatScore,
  ## tertiary key: totalRequests, quaternary: unique IP count, tie-breaker: clusterId.
  result = newSeqOfCap[ActorCluster](clusters.len)
  for c in clusters:
    if c != nil:
      result.add(c)
  result.sort(proc(a, b: ActorCluster): int =
    let riskA = if a.aggregateRisk > 0: a.aggregateRisk else: a.highestThreatScore
    let riskB = if b.aggregateRisk > 0: b.aggregateRisk else: b.highestThreatScore
    if riskA != riskB:
      return cmp(riskB, riskA) # Descending
    if a.highestThreatScore != b.highestThreatScore:
      return cmp(b.highestThreatScore, a.highestThreatScore)
    if a.totalRequests != b.totalRequests:
      return cmp(b.totalRequests, a.totalRequests)
    if a.ips.len != b.ips.len:
      return cmp(b.ips.len, a.ips.len)
    return cmp(a.clusterId, b.clusterId)
  )

func formatThreatLevelBadge*(category: ActorCategory, score: int, colorize: bool = true): string =
  ## Formats intent badge along with numeric score for tabular views:
  ## e.g. `[ HACKER! ] 95` or `[REAL USER]  5`
  let badge = formatIntentBadge(category, colorize)
  let scoreStr = align($score, 2)
  if colorize:
    let scoreColor = if score >= 80: FgBrightRedBold
                     elif score >= 50: FgRed
                     elif score >= 25: FgYellow
                     else: FgGreen
    badge & " " & scoreColor & scoreStr & Reset
  else:
    badge & " " & scoreStr

proc renderGroupedSummaryTable*(
  clusters: openArray[ActorCluster],
  colorize: bool = true,
  maxWidth: int = 0
): string =
  ## Renders a grouped summary table displaying correlated multi-IP actors
  ## sorted by risk score in descending order (Phase 06 / Category C / Item 01).
  ## Adapts column formatting to terminal width (supports compact 80-col and wide layouts).
  let sorted = sortClustersByRisk(clusters)
  let effWidth = if maxWidth > 0: maxWidth else: 120
  let isWide = effWidth >= 105 or maxWidth == 0

  let tableWidth = if maxWidth > 0: min(effWidth, if isWide: 120 else: 80) else: (if isWide: 115 else: 80)
  let sepDouble = repeat('=', tableWidth)
  let sepSingle = repeat('-', tableWidth)

  var b = ""
  b.add(sepDouble & "\n")

  let title = "CORRELATED MULTI-IP ACTOR CLUSTERS (" & $sorted.len & " clusters detected, sorted by risk)"
  if colorize:
    b.add(Bold & FgCyan & title & Reset & "\n")
  else:
    b.add(title & "\n")
  b.add(sepSingle & "\n")

  if sorted.len == 0:
    b.add("No correlated multi-IP actor clusters detected.\n")
    b.add(sepDouble)
    return b

  if isWide:
    # Wide layout (>= 105 columns)
    # RANK  CLUSTER ID    TAG / CAMPAIGN                        THREAT LEVEL     REQS  404s  IPS  DURATION
    let hdr = "RANK  CLUSTER ID    TAG / CAMPAIGN                        THREAT LEVEL     REQS   404s   IPS  DURATION"
    if colorize:
      b.add(Bold & FgCyan & hdr & Reset & "\n")
    else:
      b.add(hdr & "\n")
    b.add(sepSingle & "\n")

    for i, c in sorted:
      let rankStr = alignLeft("#" & $(i + 1), 6)
      let idStr = alignLeft(c.clusterId, 14)
      let tagRaw = if c.clusterTag.len > 0: c.clusterTag else: formatClusterTag(c, i + 1)
      let tagStr = alignColumn(truncateText(tagRaw, 36), 38)
      let threatBadge = formatThreatLevelBadge(c.category, c.aggregateRisk, colorize)
      let threatWidth = terminalDisplayWidth(threatBadge)
      let threatPadded = threatBadge & (if threatWidth < 17: repeat(' ', 17 - threatWidth) else: " ")
      let reqsStr = align($c.totalRequests, 5) & "  "
      let s404Str = align($c.status404Count, 5) & "  "
      let ipsStr = align($c.ips.len, 4) & "  "
      let durStr = formatDuration(c.attackDuration)

      var row = rankStr & idStr & tagStr & threatPadded & reqsStr & s404Str & ipsStr & durStr
      if maxWidth > 0 and terminalDisplayWidth(row) > maxWidth:
        row = truncateAnsi(row, maxWidth)
      b.add(row & "\n")
  else:
    # Compact layout (80 columns)
    # #   CLUSTER ID    THREAT LEVEL     REQS  IPS  TAG / CAMPAIGN
    let hdr = "#   CLUSTER ID    THREAT LEVEL     REQS  IPS  TAG / CAMPAIGN"
    if colorize:
      b.add(Bold & FgCyan & hdr & Reset & "\n")
    else:
      b.add(hdr & "\n")
    b.add(sepSingle & "\n")

    for i, c in sorted:
      let rankStr = alignLeft("#" & $(i + 1), 4)
      let idStr = alignLeft(c.clusterId, 14)
      let threatBadge = formatThreatLevelBadge(c.category, c.aggregateRisk, colorize)
      let threatWidth = terminalDisplayWidth(threatBadge)
      let threatPadded = threatBadge & (if threatWidth < 17: repeat(' ', 17 - threatWidth) else: " ")
      let reqsStr = align($c.totalRequests, 4) & "  "
      let ipsStr = align($c.ips.len, 3) & "  "
      let availForTag = max(10, tableWidth - 4 - 14 - 17 - 6 - 5)
      let tagRaw = if c.clusterTag.len > 0: c.clusterTag else: formatClusterTag(c, i + 1)
      let tagStr = truncateText(tagRaw, availForTag)

      var row = rankStr & idStr & threatPadded & reqsStr & ipsStr & tagStr
      if maxWidth > 0 and terminalDisplayWidth(row) > maxWidth:
        row = truncateAnsi(row, maxWidth)
      b.add(row & "\n")

  b.add(sepDouble)
  result = b

proc renderGroupedSummaryTable*(
  clusters: Table[string, ActorCluster],
  colorize: bool = true,
  maxWidth: int = 0
): string =
  ## Overload accepting a Table of clusters.
  var clusterSeq: seq[ActorCluster] = @[]
  for _, c in clusters:
    clusterSeq.add(c)
  renderGroupedSummaryTable(clusterSeq, colorize, maxWidth)

proc renderGroupedSummaryTable*(
  correlator: ActorCorrelator,
  colorize: bool = true,
  maxWidth: int = 0
): string =
  ## Overload accepting an ActorCorrelator engine instance.
  if correlator == nil:
    return renderGroupedSummaryTable(@[], colorize, maxWidth)
  renderGroupedSummaryTable(correlator.clusters, colorize, maxWidth)

# ==============================================================================
# Actor Cluster Card Display (Phase 06 / Category C / Item 02)
# ==============================================================================

proc resolveGeoProvider(provider: GeoIpProvider): GeoIpProvider =
  if provider != nil:
    return provider
  newCidrGeoIpProvider()

proc renderActorClusterCard*(
  cluster: ActorCluster,
  colorize: bool = true,
  useEmoji: bool = true,
  geoProvider: GeoIpProvider = nil,
  width: int = 80
): string =
  ## Renders a detailed multi-line actor cluster card (Phase 06 / Category C / Item 02).
  ## Displays: Cluster ID, Threat Level, Total Requests, Unique IPs with Geolocation,
  ## Countries, Probed Endpoints, Primary User-Agent, and Observed Time Windows.
  ## Follows the visual format defined in Spec 06 Section 4.
  if cluster == nil:
    return ""

  let w = if width > 0: width else: 80
  let sepDouble = repeat('=', w)
  let sepSingle = repeat('-', w)
  let geo = resolveGeoProvider(geoProvider)

  # Determine severity level
  let severity =
    if cluster.aggregateRisk >= 80 or cluster.category == CategoryBadActorHacker:
      "CRITICAL ACTOR CLUSTER"
    elif cluster.aggregateRisk >= 50:
      "HIGH RISK ACTOR CLUSTER"
    elif cluster.aggregateRisk >= 25 or cluster.category == CategorySuspicious:
      "SUSPICIOUS ACTOR CLUSTER"
    else:
      "ACTOR CLUSTER"

  let tagTitle = if cluster.clusterTag.len > 0:
                   cluster.clusterTag
                 else:
                   "[" & cluster.clusterId & "] - Unknown Campaign"

  var b = ""
  b.add(sepDouble & "\n")

  # Header line
  let headerText = severity & ": " & tagTitle
  if colorize:
    let headerStyle =
      if cluster.aggregateRisk >= 80: Bold & FgBrightRed
      elif cluster.aggregateRisk >= 50: Bold & FgRed
      elif cluster.aggregateRisk >= 25: Bold & FgYellow
      else: Bold & FgCyan
    b.add(headerStyle & headerText & Reset & "\n")
  else:
    b.add(headerText & "\n")
  b.add(sepSingle & "\n")

  # 1. Risk Level
  let intentBadge = formatIntentBadge(cluster.category, colorize)
  let scoreStr = $cluster.aggregateRisk & "/100"
  let scoreDisplay = if colorize:
                       (if cluster.aggregateRisk >= 80: FgBrightRedBold & scoreStr & Reset
                        elif cluster.aggregateRisk >= 50: FgRed & scoreStr & Reset
                        elif cluster.aggregateRisk >= 25: FgYellow & scoreStr & Reset
                        else: FgGreen & scoreStr & Reset)
                     else:
                       scoreStr
  b.add("Risk Level      : " & intentBadge & " (Score: " & scoreDisplay & ")\n")

  # 2. Total Requests & 404 count
  let reqCount = $cluster.totalRequests & " requests"
  let errCount = if cluster.status404Count > 0:
                   if colorize:
                     " (" & $cluster.status404Count & " x [" & formatStatusCode(404, true) & "])"
                   else:
                     " (" & $cluster.status404Count & " x [ 404 ])"
                 else:
                   ""
  b.add("Total Requests  : " & reqCount & errCount & "\n")

  # 3. Distinct IPs & Countries
  var sortedIps: seq[string] = @[]
  for ip in cluster.ips:
    sortedIps.add(ip)
  sortedIps.sort()

  var countrySet = initHashSet[string]()
  type IpGeoSummary = object
    ip: string
    countryCode: string
    countryName: string
    flagEmoji: string
    isPrivate: bool

  var ipDetails: seq[IpGeoSummary] = @[]
  for ip in sortedIps:
    let loc = geo.lookup(ip)
    let cc = if loc.countryCode.len > 0: loc.countryCode else: "??"
    let cn = if loc.countryName.len > 0: loc.countryName else: "Unknown"
    let fl = if loc.flagEmoji.len > 0: loc.flagEmoji else: isoToFlagEmoji(cc)
    if loc.countryCode.len > 0 and not loc.isPrivate:
      countrySet.incl(loc.countryCode)
    ipDetails.add(IpGeoSummary(ip: ip, countryCode: cc, countryName: cn, flagEmoji: fl, isPrivate: loc.isPrivate))

  let countryCount = if countrySet.len > 0: countrySet.len else: (if ipDetails.len > 0: 1 else: 0)
  let countryLabel = if countryCount == 1: "1 country" else: $countryCount & " countries"
  let ipSummary = $sortedIps.len & " IPs across " & countryLabel & ":"
  b.add("Distinct IPs    : " & ipSummary & "\n")

  for item in ipDetails:
    let flagPart = if useEmoji and item.flagEmoji.len > 0: item.flagEmoji & " " else: ""
    let geoLabel = if item.isPrivate:
                     "🏠 LO - Local / Private LAN"
                   else:
                     flagPart & item.countryCode & " - " & item.countryName
    let ipPadded = alignLeft(item.ip, 16)
    if colorize:
      b.add("                  - " & FgWhite & ipPadded & Reset & "(" & geoLabel & ")\n")
    else:
      b.add("                  - " & ipPadded & "(" & geoLabel & ")\n")

  # 4. Subnets & Datacenter Telemetry
  if cluster.hostingProviders.len > 0:
    var provList: seq[string] = @[]
    for p in cluster.hostingProviders: provList.add(p)
    provList.sort()
    b.add("Hosting / DC    : " & provList.join(", ") & "\n")

  if cluster.subnets.len > 0:
    var subList: seq[string] = @[]
    for s in cluster.subnets: subList.add(s)
    subList.sort()
    b.add("Subnets         : " & subList.join(", ") & "\n")

  # 5. Indicators (Proxy rotation & Synchronized burst)
  var indicators: seq[string] = @[]
  if cluster.proxyRotationDetected:
    indicators.add(if colorize: FgOrange & "⚠️ Residential Proxy Rotation Detected" & Reset
                   else: "Residential Proxy Rotation Detected")
  if cluster.synchronizedBurstDetected:
    indicators.add(if colorize: FgYellow & "⚡ Synchronized Burst Fleet" & Reset
                   else: "Synchronized Burst Fleet")
  if indicators.len > 0:
    b.add("Indicators      : " & indicators.join(", ") & "\n")

  # 6. Primary User-Agent
  let uaStr = if cluster.primaryUa.len > 0: cluster.primaryUa else: "-"
  b.add("Primary UA      : " & uaStr & "\n")

  # 7. Probed Paths
  if cluster.probedPaths.len == 0:
    b.add("Probed Paths    : (none recorded)\n")
  else:
    b.add("Probed Paths    : " & cluster.probedPaths[0] & "\n")
    let maxShow = min(cluster.probedPaths.len, 15)
    for i in 1 ..< maxShow:
      b.add("                  " & cluster.probedPaths[i] & "\n")
    if cluster.probedPaths.len > maxShow:
      b.add("                  ... (" & $(cluster.probedPaths.len - maxShow) & " more paths)\n")

  # 8. First Seen / Last Seen / Duration
  let firstStr = if cluster.firstSeen.isInitialized:
                   cluster.firstSeen.format("yyyy-MM-dd HH:mm:ss")
                 else:
                   "-"
  let lastStr = if cluster.lastSeen.isInitialized:
                  cluster.lastSeen.format("yyyy-MM-dd HH:mm:ss")
                else:
                  "-"
  b.add("First Seen      : " & firstStr & "\n")
  b.add("Last Seen       : " & lastStr)
  if cluster.firstSeen.isInitialized and cluster.lastSeen.isInitialized:
    b.add(" (Duration: " & formatDuration(cluster.attackDuration) & ")")
  b.add("\n")

  b.add(sepDouble)
  result = b

proc renderGroupedClusters*(
  clusters: openArray[ActorCluster],
  colorize: bool = true,
  useEmoji: bool = true,
  geoProvider: GeoIpProvider = nil,
  width: int = 80
): string =
  ## Renders all correlated multi-IP actor clusters sorted by risk score,
  ## displaying each cluster as an individual detailed card (Phase 06 / Category C / Item 02).
  let sorted = sortClustersByRisk(clusters)
  if sorted.len == 0:
    let w = if width > 0: width else: 80
    let sepDouble = repeat('=', w)
    let sepSingle = repeat('-', w)
    return sepDouble & "\nCORRELATED ACTOR CLUSTERS\n" & sepSingle & "\nNo correlated actor clusters recorded.\n" & sepDouble

  var cards: seq[string] = @[]
  for c in sorted:
    cards.add(renderActorClusterCard(c, colorize, useEmoji, geoProvider, width))
  result = cards.join("\n\n")

proc renderGroupedClusters*(
  clusters: Table[string, ActorCluster],
  colorize: bool = true,
  useEmoji: bool = true,
  geoProvider: GeoIpProvider = nil,
  width: int = 80
): string =
  ## Overload accepting a Table of clusters.
  var clusterSeq: seq[ActorCluster] = @[]
  for _, c in clusters: clusterSeq.add(c)
  renderGroupedClusters(clusterSeq, colorize, useEmoji, geoProvider, width)

proc renderGroupedClusters*(
  correlator: ActorCorrelator,
  colorize: bool = true,
  useEmoji: bool = true,
  geoProvider: GeoIpProvider = nil,
  width: int = 80
): string =
  ## Overload accepting ActorCorrelator.
  if correlator == nil:
    return renderGroupedClusters(@[], colorize, useEmoji, geoProvider, width)
  renderGroupedClusters(correlator.clusters, colorize, useEmoji, geoProvider, width)

# ==============================================================================
# Chronological Attack Timeline & Drill-Down (Phase 06 / Category C / Item 03)
# ==============================================================================

proc renderActorTimeline*(
  cluster: ActorCluster,
  colorize: bool = true,
  useEmoji: bool = true,
  geoProvider: GeoIpProvider = nil,
  maxWidth: int = 0
): string =
  ## Renders the complete chronological attack timeline across all participating IPs
  ## for a specific actor cluster (Phase 06 / Category C / Item 03).
  ## Displays time deltas (+00:00s), absolute timestamps, country flags, status badges,
  ## client IPs, and requested paths.
  if cluster == nil:
    return ""

  let effWidth = if maxWidth > 0: maxWidth else: 120
  let tableWidth = min(effWidth, 120)
  let sepDouble = repeat('=', tableWidth)
  let sepSingle = repeat('-', tableWidth)
  let geo = resolveGeoProvider(geoProvider)

  var b = ""
  b.add(sepDouble & "\n")

  let title = "CHRONOLOGICAL ATTACK TIMELINE: [" & cluster.clusterId & "] (" &
              $cluster.entries.len & " events across " & $cluster.ips.len & " distinct IPs)"
  if colorize:
    b.add(Bold & FgCyan & title & Reset & "\n")
  else:
    b.add(title & "\n")
  b.add(sepSingle & "\n")

  if cluster.entries.len == 0:
    # If no raw entries stored, fallback to displaying probed paths
    if cluster.probedPaths.len > 0:
      b.add("Probed path sequence:\n")
      for i, p in cluster.probedPaths:
        b.add("  " & $(i + 1) & ". " & p & "\n")
    else:
      b.add("No chronological events recorded for this cluster.\n")
    b.add(sepDouble)
    return b

  # Sort entries chronologically
  var sortedEntries = cluster.entries
  sortedEntries.sort(proc(a, b: HttpLogEntry): int =
    if a.timestamp.isInitialized and b.timestamp.isInitialized:
      let secA = a.timestamp.toTime.toUnix
      let secB = b.timestamp.toTime.toUnix
      if secA != secB: return cmp(secA, secB)
      return cmp(a.timestamp.nanosecond, b.timestamp.nanosecond)
    elif a.timestamp.isInitialized:
      return -1
    elif b.timestamp.isInitialized:
      return 1
    return 0
  )

  let baseTime = if sortedEntries[0].timestamp.isInitialized:
                   sortedEntries[0].timestamp.toTime
                 else:
                   default(Time)

  # Timeline table header
  let hdr = "DELTA    TIME      GEO    STATUS  CLIENT IP        METHOD PATH"
  if colorize:
    b.add(Bold & FgCyan & hdr & Reset & "\n")
  else:
    b.add(hdr & "\n")
  b.add(sepSingle & "\n")

  for entry in sortedEntries:
    var deltaStr = "+00:00s "
    if baseTime != default(Time) and entry.timestamp.isInitialized:
      let dSec = max(0'i64, (entry.timestamp.toTime - baseTime).inSeconds)
      let dMin = dSec div 60
      let dRem = dSec mod 60
      deltaStr = "+" & align($dMin, 2, '0') & ":" & align($dRem, 2, '0') & "s "

    let timeStr = if entry.timestamp.isInitialized:
                    entry.timestamp.format("HH:mm:ss")
                  else:
                    "--:--:--"
    let loc = geo.lookup(entry.clientIp)
    let geoStr = formatCountryColumn(loc, useEmoji = useEmoji, width = 7)
    let statusStr = formatStatusCode(entry.statusCode, colorize)
    let ipStr = alignLeft(if entry.clientIp.len > 0: entry.clientIp else: "-", 15)
    let reqStr = $entry.method & " " & entry.path

    var line = deltaStr & " " & timeStr & "  " & geoStr & "  " & statusStr & "  " & ipStr & "  " & reqStr
    if maxWidth > 0 and terminalDisplayWidth(line) > maxWidth:
      line = truncateAnsi(line, maxWidth)
    b.add(line & "\n")

  b.add(sepDouble)
  result = b

proc renderActorDetail*(
  cluster: ActorCluster,
  colorize: bool = true,
  useEmoji: bool = true,
  geoProvider: GeoIpProvider = nil,
  maxWidth: int = 0
): string =
  ## Complete drill-down view (`--actor-detail=<ID>`) combining cluster profile card,
  ## chronological attack timeline across all IPs, and instant mitigation rules.
  if cluster == nil:
    return "Error: Actor cluster reference is nil."

  let card = renderActorClusterCard(cluster, colorize, useEmoji, geoProvider, width = if maxWidth > 0: maxWidth else: 80)
  let timeline = renderActorTimeline(cluster, colorize, useEmoji, geoProvider, maxWidth)

  var mitRules = ""
  mitRules.add("QUICK MITIGATION (UFW / FAIL2BAN / IPTABLES):\n")
  for ip in cluster.ips:
    mitRules.add("  ufw deny from " & ip & " to any comment 'http_logviewer " & cluster.clusterId & "'\n")
  for ip in cluster.ips:
    mitRules.add("  iptables -A INPUT -s " & ip & " -j DROP -m comment --comment 'http_logviewer " & cluster.clusterId & "'\n")

  result = card & "\n\n" & timeline & "\n\n" & mitRules.strip(trailing = true)

proc renderActorDetail*(
  correlator: ActorCorrelator,
  clusterId: string,
  colorize: bool = true,
  useEmoji: bool = true,
  geoProvider: GeoIpProvider = nil,
  maxWidth: int = 0
): string =
  ## Looks up the cluster by its clusterId from an ActorCorrelator and renders drill-down view.
  if correlator == nil:
    return "Error: Actor correlator is nil."
  let opt = correlator.getCluster(clusterId)
  if opt.isNone:
    return "Error: Actor cluster '" & clusterId & "' not found in active correlation table."
  renderActorDetail(opt.get(), colorize, useEmoji, geoProvider, maxWidth)

# ==============================================================================
# Exportable Incident Reports & Firewall Rule Generators (Phase 06 / Category C / Item 04)
# ==============================================================================

type
  IncidentReportFormat* = enum
    ReportMarkdown,   ## Full Markdown report with tables, telemetry, and firewall blocks
    ReportPlainText,  ## Monochromatic plain text report with ASCII formatting
    ReportFail2ban,   ## Executable bash script containing fail2ban-client banip commands
    ReportUfw,        ## Executable bash script containing ufw deny commands
    ReportIptables    ## Executable bash script containing iptables DROP commands

func generateFail2banRules*(
  clusters: openArray[ActorCluster],
  jail: string = "nginx-botsearch",
  minRiskScore: int = 50
): string =
  ## Generates ready-to-run fail2ban-client commands for rogue IPs.
  var ipSet = initHashSet[string]()
  for c in clusters:
    if c != nil and (c.aggregateRisk >= minRiskScore or c.category == CategoryBadActorHacker):
      for ip in c.ips:
        if ip.len > 0 and not isPrivateIp(ip):
          ipSet.incl(ip)

  var sortedIps: seq[string] = @[]
  for ip in ipSet: sortedIps.add(ip)
  sortedIps.sort()

  var lines: seq[string] = @[
    "#!/usr/bin/env bash",
    "# http_logviewer Fail2ban Blocking Script",
    "# Total Rogue IPs: " & $sortedIps.len,
    "set -euo pipefail",
    ""
  ]
  for ip in sortedIps:
    lines.add("fail2ban-client set " & jail & " banip " & ip)
  result = lines.join("\n")

func generateUfwRules*(
  clusters: openArray[ActorCluster],
  minRiskScore: int = 50
): string =
  ## Generates ready-to-run UFW firewall rules for rogue IPs.
  var ipToCluster = initTable[string, string]()
  for c in clusters:
    if c != nil and (c.aggregateRisk >= minRiskScore or c.category == CategoryBadActorHacker):
      for ip in c.ips:
        if ip.len > 0 and not isPrivateIp(ip):
          ipToCluster[ip] = c.clusterId

  var sortedIps: seq[string] = @[]
  for ip in ipToCluster.keys: sortedIps.add(ip)
  sortedIps.sort()

  var lines: seq[string] = @[
    "#!/usr/bin/env bash",
    "# http_logviewer UFW Firewall Rules",
    "# Total Rogue IPs: " & $sortedIps.len,
    "set -euo pipefail",
    ""
  ]
  for ip in sortedIps:
    let cid = ipToCluster[ip]
    lines.add("ufw deny from " & ip & " to any comment 'http_logviewer " & cid & "'")
  result = lines.join("\n")

func generateIptablesRules*(
  clusters: openArray[ActorCluster],
  chain: string = "INPUT",
  minRiskScore: int = 50
): string =
  ## Generates ready-to-run iptables rules for rogue IPs.
  var ipToCluster = initTable[string, string]()
  for c in clusters:
    if c != nil and (c.aggregateRisk >= minRiskScore or c.category == CategoryBadActorHacker):
      for ip in c.ips:
        if ip.len > 0 and not isPrivateIp(ip):
          ipToCluster[ip] = c.clusterId

  var sortedIps: seq[string] = @[]
  for ip in ipToCluster.keys: sortedIps.add(ip)
  sortedIps.sort()

  var lines: seq[string] = @[
    "#!/usr/bin/env bash",
    "# http_logviewer iptables Firewall Rules",
    "# Total Rogue IPs: " & $sortedIps.len,
    "set -euo pipefail",
    ""
  ]
  for ip in sortedIps:
    let cid = ipToCluster[ip]
    lines.add("iptables -A " & chain & " -s " & ip & " -j DROP -m comment --comment 'http_logviewer " & cid & "'")
  result = lines.join("\n")

func generateFirewallRules*(
  clusters: openArray[ActorCluster],
  ruleType: string = "fail2ban",
  minRiskScore: int = 50
): string =
  ## Generates automated firewall containment rules based on ruleType: "fail2ban", "ufw", or "iptables".
  case ruleType.toLowerAscii()
  of "fail2ban":
    generateFail2banRules(clusters, minRiskScore = minRiskScore)
  of "ufw":
    generateUfwRules(clusters, minRiskScore = minRiskScore)
  of "iptables":
    generateIptablesRules(clusters, minRiskScore = minRiskScore)
  else:
    generateFail2banRules(clusters, minRiskScore = minRiskScore)

proc generateMarkdownReport*(
  clusters: openArray[ActorCluster],
  title: string = "HTTP LogViewer Security Incident Report",
  minRiskScore: int = 50,
  geoProvider: GeoIpProvider = nil
): string =
  ## Generates an incident report formatted in GitHub Flavored Markdown (Phase 06 / Category C / Item 04).
  let sorted = sortClustersByRisk(clusters)
  let geo = resolveGeoProvider(geoProvider)

  var maliciousClusters: seq[ActorCluster] = @[]
  var totalIps = initHashSet[string]()
  var totalReqs = 0
  var total404s = 0

  for c in sorted:
    if c.aggregateRisk >= minRiskScore or c.category in {CategoryBadActorHacker, CategorySuspicious}:
      maliciousClusters.add(c)
      for ip in c.ips:
        if ip.len > 0 and not isPrivateIp(ip):
          totalIps.incl(ip)
      totalReqs += c.totalRequests
      total404s += c.status404Count

  var md = ""
  md.add("# " & title & "\n\n")
  md.add("> [!IMPORTANT]\n")
  md.add("> Correlated threat intelligence and rogue actor report generated by `http_logviewer`.\n\n")

  # Executive Summary
  md.add("## 1. Executive Summary\n\n")
  md.add("- **Correlated Actor Clusters**: " & $sorted.len & "\n")
  md.add("- **High-Risk Rogue Clusters** (Risk >= " & $minRiskScore & "): " & $maliciousClusters.len & "\n")
  md.add("- **Distinct Rogue IP Addresses**: " & $totalIps.len & "\n")
  md.add("- **Total Hostile Requests Analyzed**: " & $totalReqs & " (" & $total404s & " x 404 responses)\n\n")

  # Summary Table
  md.add("## 2. Correlated Actor Clusters\n\n")
  md.add("| Cluster ID | Campaign / Tag | Risk Score | Category | Unique IPs | Requests | 404s | Duration |\n")
  md.add("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")

  for c in sorted:
    let tag = if c.clusterTag.len > 0: c.clusterTag else: c.clusterId
    let dur = formatDuration(c.attackDuration)
    md.add("| `" & c.clusterId & "` | " & tag & " | **" & $c.aggregateRisk & "/100** | `" & $c.category & "` | " &
           $c.ips.len & " | " & $c.totalRequests & " | " & $c.status404Count & " | " & dur & " |\n")
  md.add("\n")

  # Deep Dive Per Rogue Actor
  md.add("## 3. Rogue Threat Actor Profiles\n\n")
  for c in maliciousClusters:
    md.add("### Cluster `" & c.clusterId & "`\n\n")
    if c.clusterTag.len > 0:
      md.add("**Campaign Tag**: `" & c.clusterTag & "`  \n")
    md.add("**Risk Score**: " & $c.aggregateRisk & "/100 (`" & $c.category & "`)  \n")
    md.add("**Requests**: " & $c.totalRequests & " (" & $c.status404Count & " x 404)  \n")
    if c.primaryUa.len > 0:
      md.add("**Primary User-Agent**: `" & c.primaryUa & "`  \n")

    var indicators: seq[string] = @[]
    if c.proxyRotationDetected: indicators.add("Residential Proxy Rotation Detected")
    if c.synchronizedBurstDetected: indicators.add("Synchronized Burst Fleet")
    if c.hasDatacenterIps: indicators.add("Datacenter / Hosting IPs")
    if indicators.len > 0:
      md.add("**Observed Indicators**: " & indicators.join(", ") & "  \n")

    md.add("\n**Participating IP Addresses**:\n\n")
    var sortedIps: seq[string] = @[]
    for ip in c.ips: sortedIps.add(ip)
    sortedIps.sort()

    for ip in sortedIps:
      let loc = geo.lookup(ip)
      let flag = if loc.flagEmoji.len > 0: loc.flagEmoji & " " else: ""
      let country = if loc.isPrivate: "Local LAN" else: flag & loc.countryCode & " (" & loc.countryName & ")"
      md.add("- `" & ip & "` — " & country & "\n")

    md.add("\n**Targeted Probed Endpoints**:\n\n")
    for p in c.probedPaths:
      md.add("- `" & p & "`\n")
    md.add("\n")

  # Firewall Containment Commands
  md.add("## 4. Automated Firewall & Containment Rules\n\n")
  md.add("### 4.1 Fail2ban Block Commands\n\n")
  md.add("```bash\n")
  md.add(generateFail2banRules(maliciousClusters, minRiskScore = minRiskScore) & "\n")
  md.add("```\n\n")

  md.add("### 4.2 UFW Firewall Rules\n\n")
  md.add("```bash\n")
  md.add(generateUfwRules(maliciousClusters, minRiskScore = minRiskScore) & "\n")
  md.add("```\n\n")

  md.add("### 4.3 iptables Rules\n\n")
  md.add("```bash\n")
  md.add(generateIptablesRules(maliciousClusters, minRiskScore = minRiskScore) & "\n")
  md.add("```\n")

  result = md

proc generatePlainTextReport*(
  clusters: openArray[ActorCluster],
  title: string = "HTTP LogViewer Security Incident Report",
  minRiskScore: int = 50,
  geoProvider: GeoIpProvider = nil
): string =
  ## Generates an incident report formatted in pure ASCII plain text (Phase 06 / Category C / Item 04).
  let summaryTable = renderGroupedSummaryTable(clusters, colorize = false, maxWidth = 80)
  let cards = renderGroupedClusters(clusters, colorize = false, useEmoji = false, geoProvider = geoProvider, width = 80)
  let ufw = generateUfwRules(clusters, minRiskScore = minRiskScore)
  let f2b = generateFail2banRules(clusters, minRiskScore = minRiskScore)

  var b = ""
  b.add("================================================================================\n")
  b.add(title.toUpperAscii() & "\n")
  b.add("================================================================================\n\n")
  b.add(summaryTable & "\n\n")
  b.add(cards & "\n\n")
  b.add("--------------------------------------------------------------------------------\n")
  b.add("AUTOMATED FIREWALL CONTAINMENT RULES\n")
  b.add("--------------------------------------------------------------------------------\n\n")
  b.add("--- UFW Rules ---\n" & ufw & "\n\n")
  b.add("--- Fail2ban Rules ---\n" & f2b & "\n")
  result = b

proc generateIncidentReport*(
  clusters: openArray[ActorCluster],
  format: IncidentReportFormat = ReportMarkdown,
  title: string = "HTTP LogViewer Security Incident Report",
  minRiskScore: int = 50,
  geoProvider: GeoIpProvider = nil
): string =
  ## Master dispatcher for incident reports across supported formats (Phase 06 / Category C / Item 04).
  case format
  of ReportMarkdown:
    generateMarkdownReport(clusters, title, minRiskScore, geoProvider)
  of ReportPlainText:
    generatePlainTextReport(clusters, title, minRiskScore, geoProvider)
  of ReportFail2ban:
    generateFail2banRules(clusters, minRiskScore = minRiskScore)
  of ReportUfw:
    generateUfwRules(clusters, minRiskScore = minRiskScore)
  of ReportIptables:
    generateIptablesRules(clusters, minRiskScore = minRiskScore)



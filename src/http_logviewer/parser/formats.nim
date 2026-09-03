## High-performance HTTP log parsing formats and tokenizers.
## Provides zero-allocation slicing parsers for CLF, Combined, Nginx, and JSON log lines.

import std/[parseutils, strutils, times, options, json]
import ../core/[types, config]
export config.LogFormat

proc cleanIpAddress*(rawIp: string): string =
  ## Strips port suffixes, bracket enclosures, and trims whitespace from IPv4 and IPv6 addresses.
  ## Examples:
  ##   ``"192.168.1.1:8080"`` -> ``"192.168.1.1"``
  ##   ``"[2001:db8::1]:443"`` -> ``"2001:db8::1"``
  ##   ``"[2001:db8::1]"``     -> ``"2001:db8::1"``
  ##   ``"10.0.0.1"``          -> ``"10.0.0.1"``
  ##   ``"2001:db8::1"``       -> ``"2001:db8::1"``
  let s = rawIp.strip()
  if s.len == 0:
    return ""

  # Bracketed IPv6 address with optional port: [2001:db8::1]:8080 or [2001:db8::1]
  if s[0] == '[':
    let closeBracket = s.find(']')
    if closeBracket > 0:
      return s[1 ..< closeBracket]

  # IPv4 with port: contains dots and a single colon: 192.168.1.1:8080
  let colonCount = s.count(':')
  if colonCount == 1 and s.find('.') > 0:
    let colonIdx = s.find(':')
    return s[0 ..< colonIdx]

  return s

proc parseLogDateTime*(timeStr: string): DateTime =
  ## Parses standard HTTP access log timestamps such as "10/Oct/2026:13:55:36 +0200".
  ## Handles optional enclosing brackets, UTC fallback, and ISO-8601 timestamps.
  ## Returns default(DateTime) if unparseable without raising exceptions.
  let clean = timeStr.strip(chars = {' ', '[', ']'})
  if clean.len == 0:
    return default(DateTime)

  # Try standard Apache/Nginx format with unseparated offset (+0200): "dd/MMM/yyyy:HH:mm:ss ZZZ"
  try:
    return parse(clean, "dd/MMM/yyyy:HH:mm:ss ZZZ")
  except CatchableError:
    discard

  # Try with single digit day (+0200): "d/MMM/yyyy:HH:mm:ss ZZZ"
  try:
    return parse(clean, "d/MMM/yyyy:HH:mm:ss ZZZ")
  except CatchableError:
    discard

  # Try standard Apache/Nginx format with colon offset (+02:00): "dd/MMM/yyyy:HH:mm:ss zzz"
  try:
    return parse(clean, "dd/MMM/yyyy:HH:mm:ss zzz")
  except CatchableError:
    discard

  # Try without timezone offset: "dd/MMM/yyyy:HH:mm:ss"
  try:
    return parse(clean, "dd/MMM/yyyy:HH:mm:ss", utc())
  except CatchableError:
    discard

  # Try ISO-8601 with offset: "yyyy-MM-dd'T'HH:mm:sszzz"
  try:
    return parse(clean, "yyyy-MM-dd'T'HH:mm:sszzz")
  except CatchableError:
    discard

  # Try ISO-8601 UTC: "yyyy-MM-dd'T'HH:mm:ss'Z'"
  try:
    return parse(clean, "yyyy-MM-dd'T'HH:mm:ss'Z'", utc())
  except CatchableError:
    discard

  # Try ISO-8601 date-space-time: "yyyy-MM-dd HH:mm:ss"
  try:
    return parse(clean, "yyyy-MM-dd HH:mm:ss", utc())
  except CatchableError:
    discard

  # Fallback gracefully to now() if timestamp is corrupted, without raising an unhandled exception
  return now().utc

proc parseRequestLine*(
  reqLine: string,
  methodOut: var HttpMethod,
  pathOut: var string,
  protocolOut: var string
) =
  ## Parses raw HTTP request line (e.g. "GET /index.html HTTP/1.1") into method, path, and protocol.
  ## Handles single-token or malformed requests gracefully.
  var idx = 0
  let lineLen = reqLine.len
  idx += skipWhitespace(reqLine, idx)

  # 1. Parse HTTP Method token
  var methToken: string
  idx += parseUntil(reqLine, methToken, {' ', '\t'}, idx)
  methodOut = parseHttpMethod(methToken)

  idx += skipWhitespace(reqLine, idx)
  if idx >= lineLen:
    pathOut = ""
    protocolOut = ""
    return

  # 2. Parse Path / URI token
  var p: string
  idx += parseUntil(reqLine, p, {' ', '\t'}, idx)
  pathOut = p

  idx += skipWhitespace(reqLine, idx)
  if idx >= lineLen:
    protocolOut = ""
    return

  # 3. Parse Protocol (rest of line)
  var proto: string
  idx += parseUntil(reqLine, proto, {'\r', '\n'}, idx)
  protocolOut = proto.strip()

proc parseRequestLine*(reqLine: string, methodOut: var HttpMethod, pathOut: var string) {.inline.} =
  ## Convenience overload when protocol is not needed.
  var proto: string
  parseRequestLine(reqLine, methodOut, pathOut, proto)

type
  HttpStatusClass* = enum
    StatusInformational, ## 1xx Informational (100-199)
    StatusSuccess,       ## 2xx Success (200-299)
    StatusRedirection,   ## 3xx Redirection (300-399)
    StatusClientError,   ## 4xx Client Error (400-499)
    StatusServerError,   ## 5xx Server Error (500-599)
    StatusInvalid        ## Non-standard or unparseable (<100 or >599)

func isValidStatusCode*(code: int): bool {.inline.} =
  ## Returns true if code is within standard HTTP status range 100..599.
  code >= 100 and code <= 599

func statusClass*(code: int): HttpStatusClass =
  ## Maps an integer HTTP status code to its corresponding RFC status class.
  case code
  of 100..199: StatusInformational
  of 200..299: StatusSuccess
  of 300..399: StatusRedirection
  of 400..499: StatusClientError
  of 500..599: StatusServerError
  else: StatusInvalid

func isSuccess*(code: int): bool {.inline.} = code >= 200 and code <= 299
func isRedirect*(code: int): bool {.inline.} = code >= 300 and code <= 399
func isClientError*(code: int): bool {.inline.} = code >= 400 and code <= 499
func isServerError*(code: int): bool {.inline.} = code >= 500 and code <= 599
func isNotFound*(code: int): bool {.inline.} = code == 404
func isForbidden*(code: int): bool {.inline.} = code == 401 or code == 403

func statusDescription*(code: int): string =
  ## Returns canonical HTTP status reason phrase for standard HTTP status codes.
  case code
  of 200: "OK"
  of 201: "Created"
  of 202: "Accepted"
  of 204: "No Content"
  of 301: "Moved Permanently"
  of 302: "Found"
  of 304: "Not Modified"
  of 307: "Temporary Redirect"
  of 308: "Permanent Redirect"
  of 400: "Bad Request"
  of 401: "Unauthorized"
  of 403: "Forbidden"
  of 404: "Not Found"
  of 405: "Method Not Allowed"
  of 408: "Request Timeout"
  of 409: "Conflict"
  of 410: "Gone"
  of 418: "I'm a teapot"
  of 429: "Too Many Requests"
  of 500: "Internal Server Error"
  of 501: "Not Implemented"
  of 502: "Bad Gateway"
  of 503: "Service Unavailable"
  of 504: "Gateway Timeout"
  else:
    case statusClass(code)
    of StatusInformational: "Informational"
    of StatusSuccess: "Success"
    of StatusRedirection: "Redirection"
    of StatusClientError: "Client Error"
    of StatusServerError: "Server Error"
    of StatusInvalid: "Unknown Status"

proc parseHttpMethodToken*(token: string): HttpMethod =
  ## Parses an HTTP method token from string or slice, stripping whitespace and quotes.
  let s = token.strip(chars = {' ', '\t', '"', '\''})
  parseHttpMethod(s)

proc parseStatusCode*(s: string, code: var int): bool =
  ## Parses a 3-digit HTTP status code from string, stripping surrounding quotes or spaces.
  ## Returns true if valid integer within 100..599.
  let clean = s.strip(chars = {' ', '\t', '"', '\''})
  if clean.len == 0:
    return false
  var val: int
  let parsed = parseInt(clean, val)
  if parsed > 0 and isValidStatusCode(val):
    code = val
    return true
  return false

proc parseStatusCode*(s: string): int =
  ## Convenience parser returning 0 if parsing fails.
  var code: int
  if parseStatusCode(s, code):
    return code
  return 0

proc parseQuotedString*(line: string, idx: var int, outStr: var string): bool =
  ## Parses a quoted string starting at or after idx, handling backslash-escapes.
  ## Advances idx past the closing quote. Returns true on success, false if opening/closing quote is missing.
  idx += skipUntil(line, '"', idx)
  if idx >= line.len:
    return false
  inc(idx) # Skip opening quote
  outStr.setLen(0)
  var inEscape = false
  while idx < line.len:
    let c = line[idx]
    if inEscape:
      outStr.add(c)
      inEscape = false
      inc(idx)
    elif c == '\\':
      inEscape = true
      inc(idx)
    elif c == '"':
      inc(idx) # Skip closing quote
      return true
    else:
      outStr.add(c)
      inc(idx)
  return false # Missing closing quote

proc parseClfLine*(line: string, entry: var HttpLogEntry): bool =
  ## Parses a single line in W3C Common Log Format (CLF) into `entry`.
  ## Format: ``$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent``
  ## Example: ``127.0.0.1 - frank [10/Oct/2026:13:55:36 -0700] "POST /api/login HTTP/1.0" 401 512``
  ## Returns true on success, false if the line was malformed.
  let lineLen = line.len
  if lineLen == 0:
    return false

  var idx = 0
  idx += skipWhitespace(line, idx)
  if idx >= lineLen:
    return false

  # 1. Parse Client IP (delimited by space)
  var ip: string
  idx += parseUntil(line, ip, {' ', '\t'}, idx)
  if ip.len == 0 or idx >= lineLen:
    return false
  entry.clientIp = cleanIpAddress(ip)

  # 2. Skip Ident & Auth User (e.g. "- - " or "- frank ") up to opening '['
  idx += skipUntil(line, '[', idx)
  if idx >= lineLen:
    return false
  inc(idx) # Skip '['

  # 3. Parse Timestamp (delimited by ']')
  var timeStr: string
  idx += parseUntil(line, timeStr, ']', idx)
  if idx >= lineLen:
    return false
  entry.timestamp = parseLogDateTime(timeStr)
  inc(idx) # Skip ']'

  # 4. Parse Request Line ("METHOD PATH PROTOCOL")
  var reqLine: string
  if not parseQuotedString(line, idx, reqLine):
    return false
  parseRequestLine(reqLine, entry.`method`, entry.path)

  # 5. Parse Status Code
  idx += skipWhitespace(line, idx)
  if idx >= lineLen:
    return false
  var statusStr: string
  idx += parseUntil(line, statusStr, {' ', '\t'}, idx)
  if not parseStatusCode(statusStr, entry.statusCode):
    var statusInt = 0
    if parseInt(statusStr, statusInt) > 0:
      entry.statusCode = statusInt
    else:
      return false

  # 6. Parse Body Bytes
  idx += skipWhitespace(line, idx)
  if idx >= lineLen:
    entry.bytesSent = 0
  elif line[idx] == '-':
    entry.bytesSent = 0
    inc(idx)
  else:
    var bytesVal: BiggestInt = 0
    let parsedBytes = parseBiggestInt(line, bytesVal, idx)
    if parsedBytes > 0:
      entry.bytesSent = bytesVal
      idx += parsedBytes
    else:
      entry.bytesSent = 0

  # CLF does not specify referer or user agent
  entry.referer = ""
  entry.userAgent = ""
  entry.rawLine = line
  return true

proc parseClfLine*(line: string): Option[HttpLogEntry] =
  ## Parses a CLF line returning ``Option[HttpLogEntry]``.
  var entry: HttpLogEntry
  if parseClfLine(line, entry):
    return some(entry)
  return none(HttpLogEntry)

proc parseCombinedLine*(line: string, entry: var HttpLogEntry): bool =
  ## Parses a single line in Nginx / Apache Combined Log Format into `entry`.
  ## Format: ``$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"``
  ## Example:
  ##   ``192.168.1.100 - - [10/Oct/2026:13:55:36 +0200] "GET /index.html HTTP/1.1" 200 2326 "https://example.com" "Mozilla/5.0"``
  ## Returns true on success, false if the line was malformed.
  let lineLen = line.len
  if lineLen == 0:
    return false

  var idx = 0
  idx += skipWhitespace(line, idx)
  if idx >= lineLen:
    return false

  # 1. Parse Client IP (delimited by space)
  var ip: string
  idx += parseUntil(line, ip, {' ', '\t'}, idx)
  if ip.len == 0 or idx >= lineLen:
    return false
  entry.clientIp = cleanIpAddress(ip)

  # 2. Skip Ident & Auth User up to opening '['
  idx += skipUntil(line, '[', idx)
  if idx >= lineLen:
    return false
  inc(idx) # Skip '['

  # 3. Parse Timestamp (delimited by ']')
  var timeStr: string
  idx += parseUntil(line, timeStr, ']', idx)
  if idx >= lineLen:
    return false
  entry.timestamp = parseLogDateTime(timeStr)
  inc(idx) # Skip ']'

  # 4. Parse Request Line ("METHOD PATH PROTOCOL")
  var reqLine: string
  if not parseQuotedString(line, idx, reqLine):
    return false
  parseRequestLine(reqLine, entry.`method`, entry.path)

  # 5. Parse Status Code
  idx += skipWhitespace(line, idx)
  if idx >= lineLen:
    return false
  var statusStr: string
  idx += parseUntil(line, statusStr, {' ', '\t'}, idx)
  if not parseStatusCode(statusStr, entry.statusCode):
    var statusInt = 0
    if parseInt(statusStr, statusInt) > 0:
      entry.statusCode = statusInt
    else:
      return false

  # 6. Parse Body Bytes
  idx += skipWhitespace(line, idx)
  if idx >= lineLen:
    entry.bytesSent = 0
  elif line[idx] == '-':
    entry.bytesSent = 0
    inc(idx)
  else:
    var bytesVal: BiggestInt = 0
    let parsedBytes = parseBiggestInt(line, bytesVal, idx)
    if parsedBytes > 0:
      entry.bytesSent = bytesVal
      idx += parsedBytes
    else:
      entry.bytesSent = 0

  # 7. Parse Referer (quoted string)
  var refStr: string
  if not parseQuotedString(line, idx, refStr):
    return false
  entry.referer = if refStr == "-": "" else: refStr

  # 8. Parse User-Agent (quoted string)
  var uaStr: string
  if not parseQuotedString(line, idx, uaStr):
    return false
  entry.userAgent = if uaStr == "-": "" else: uaStr

  entry.rawLine = line
  return true

proc parseCombinedLine*(line: string): Option[HttpLogEntry] =
  ## Parses a Combined log line returning ``Option[HttpLogEntry]``.
  var entry: HttpLogEntry
  if parseCombinedLine(line, entry):
    return some(entry)
  return none(HttpLogEntry)

proc parseNginxLine*(line: string, entry: var HttpLogEntry): bool {.inline.} =
  ## Parses an Nginx log line (standard or extended Combined format) into `entry`.
  parseCombinedLine(line, entry)

proc parseNginxLine*(line: string): Option[HttpLogEntry] {.inline.} =
  ## Parses an Nginx log line returning ``Option[HttpLogEntry]``.
  parseCombinedLine(line)

proc detectLogFormatLine*(line: string): LogFormat =
  ## Analyzes a single log line to heuristically identify its format.
  ## Detects JSON (leading/trailing braces), Combined format (>= 4 quote marks),
  ## or CLF (fewer quotes, standard structure).
  let s = line.strip()
  if s.len == 0:
    return LogFormatCombined

  if s.startsWith('{') and s.endsWith('}'):
    return LogFormatJson

  var quotes = 0
  for ch in s:
    if ch == '"':
      inc(quotes)

  if quotes >= 4:
    return LogFormatCombined
  else:
    return LogFormatClf

proc detectLogFormat*(sampleLines: openArray[string]): LogFormat =
  ## Analyzes up to 5 non-empty lines from the input to heuristically detect the log format.
  ## Implements Spec 02 heuristic:
  ## - If lines are JSON, selects LogFormatJson.
  ## - If lines have 2 or more quoted strings ("..."), selects LogFormatCombined.
  ## - Otherwise falls back to LogFormatClf.
  var jsonVotes = 0
  var combinedVotes = 0
  var clfVotes = 0
  var inspected = 0

  for line in sampleLines:
    let s = line.strip()
    if s.len == 0:
      continue
    let fmt = detectLogFormatLine(s)
    case fmt
    of LogFormatJson: inc(jsonVotes)
    of LogFormatCombined, LogFormatNginx: inc(combinedVotes)
    of LogFormatClf: inc(clfVotes)
    of LogFormatAuto: discard

    inc(inspected)
    if inspected >= 5:
      break

  if inspected == 0:
    return LogFormatCombined

  if jsonVotes > combinedVotes and jsonVotes > clfVotes:
    return LogFormatJson
  elif clfVotes > combinedVotes and clfVotes > jsonVotes:
    return LogFormatClf
  else:
    return LogFormatCombined

proc detectLogFormat*(sampleText: string): LogFormat =
  ## Overload of detectLogFormat accepting a multi-line string or single line.
  if sampleText.contains('\n'):
    var lines: seq[string] = @[]
    for line in sampleText.splitLines():
      if line.strip().len > 0:
        lines.add(line)
        if lines.len >= 5:
          break
    return detectLogFormat(lines)
  else:
    return detectLogFormatLine(sampleText)

proc getJsonString(node: JsonNode, keys: openArray[string]): string =
  for k in keys:
    if node.hasKey(k):
      let val = node[k]
      if val.kind == JString:
        return val.getStr()
      elif val.kind == JInt:
        return $val.getInt()
  return ""

proc parseJsonLine*(line: string, entry: var HttpLogEntry): bool =
  ## Parses a structured JSON log line (supporting Nginx and Caddy schemas) into `entry`.
  ## Returns true on success, false if JSON was malformed or unparseable.
  let s = line.strip()
  if s.len < 2 or s[0] != '{' or s[^1] != '}':
    return false

  var root: JsonNode
  try:
    root = parseJson(s)
  except CatchableError:
    return false

  if root.kind != JObject:
    return false

  # Caddy nests request attributes inside "request": { ... }
  let hasReq = root.hasKey("request") and root["request"].kind == JObject
  let reqNode = if hasReq: root["request"] else: root

  # 1. Client IP
  var ipStr = getJsonString(reqNode, ["client_ip", "remote_ip", "remote_addr", "ip", "client", "clientIp"])
  if ipStr.len == 0 and hasReq:
    ipStr = getJsonString(root, ["client_ip", "remote_ip", "remote_addr", "ip", "client", "clientIp"])
  entry.clientIp = cleanIpAddress(ipStr)

  # 2. Timestamp
  var tsParsed = false
  if root.hasKey("timestamp") or root.hasKey("time") or root.hasKey("time_local") or root.hasKey("time_iso8601"):
    let tsKey = if root.hasKey("timestamp"): "timestamp"
                elif root.hasKey("time"): "time"
                elif root.hasKey("time_local"): "time_local"
                else: "time_iso8601"
    let tsNode = root[tsKey]
    if tsNode.kind == JString:
      entry.timestamp = parseLogDateTime(tsNode.getStr())
      tsParsed = true
    elif tsNode.kind == JFloat:
      entry.timestamp = fromUnixFloat(tsNode.getFloat()).utc
      tsParsed = true
    elif tsNode.kind == JInt:
      entry.timestamp = fromUnix(tsNode.getBiggestInt()).utc
      tsParsed = true

  if not tsParsed and root.hasKey("ts"):
    let tsNode = root["ts"]
    if tsNode.kind == JFloat:
      entry.timestamp = fromUnixFloat(tsNode.getFloat()).utc
      tsParsed = true
    elif tsNode.kind == JInt:
      entry.timestamp = fromUnix(tsNode.getBiggestInt()).utc
      tsParsed = true
    elif tsNode.kind == JString:
      entry.timestamp = parseLogDateTime(tsNode.getStr())
      tsParsed = true

  if not tsParsed:
    entry.timestamp = now().utc

  # 3. HTTP Method
  var methStr = getJsonString(reqNode, ["method", "request_method", "http_method"])
  if methStr.len == 0 and hasReq:
    methStr = getJsonString(root, ["method", "request_method", "http_method"])
  entry.`method` = parseHttpMethod(methStr)

  # 4. Path / URI
  var pathStr = getJsonString(reqNode, ["uri", "path", "request_uri", "url"])
  if pathStr.len == 0 and hasReq:
    pathStr = getJsonString(root, ["uri", "path", "request_uri", "url"])

  # Fallback to parsing full "request" line if present
  if pathStr.len == 0:
    let reqLine = getJsonString(reqNode, ["request"])
    if reqLine.len > 0:
      var m: HttpMethod
      parseRequestLine(reqLine, m, pathStr)
      if entry.`method` == HttpUnknown or entry.`method` == HttpOther:
        entry.`method` = m

  entry.path = pathStr

  # 5. Status Code
  var sc = 0
  for nodeCandidate in [root, reqNode]:
    for k in ["status", "status_code", "response_status", "statusCode"]:
      if nodeCandidate.hasKey(k):
        let val = nodeCandidate[k]
        if val.kind == JInt:
          sc = val.getInt()
          break
        elif val.kind == JString:
          sc = parseStatusCode(val.getStr())
          break
    if sc != 0:
      break
  entry.statusCode = sc

  # 6. Bytes Sent
  var bs: int64 = 0
  for nodeCandidate in [root, reqNode]:
    for k in ["bytes", "size", "body_bytes_sent", "bytes_sent", "bytesSent"]:
      if nodeCandidate.hasKey(k):
        let val = nodeCandidate[k]
        if val.kind == JInt:
          bs = val.getBiggestInt()
          break
        elif val.kind == JString:
          var parsedBs: BiggestInt
          if parseBiggestInt(val.getStr(), parsedBs) > 0:
            bs = parsedBs
          break
    if bs != 0:
      break
  entry.bytesSent = bs

  # 7. Referer
  var refStr = getJsonString(reqNode, ["referer", "http_referer"])
  if refStr.len == 0 and hasReq:
    refStr = getJsonString(root, ["referer", "http_referer"])
  if refStr.len == 0 and reqNode.hasKey("headers") and reqNode["headers"].kind == JObject:
    let headers = reqNode["headers"]
    if headers.hasKey("Referer"):
      let rNode = headers["Referer"]
      if rNode.kind == JArray and rNode.len > 0 and rNode[0].kind == JString:
        refStr = rNode[0].getStr()
      elif rNode.kind == JString:
        refStr = rNode.getStr()
  entry.referer = if refStr == "-": "" else: refStr

  # 8. User-Agent
  var uaStr = getJsonString(reqNode, ["user_agent", "http_user_agent", "userAgent", "ua"])
  if uaStr.len == 0 and hasReq:
    uaStr = getJsonString(root, ["user_agent", "http_user_agent", "userAgent", "ua"])
  if uaStr.len == 0 and reqNode.hasKey("headers") and reqNode["headers"].kind == JObject:
    let headers = reqNode["headers"]
    if headers.hasKey("User-Agent"):
      let uNode = headers["User-Agent"]
      if uNode.kind == JArray and uNode.len > 0 and uNode[0].kind == JString:
        uaStr = uNode[0].getStr()
      elif uNode.kind == JString:
        uaStr = uNode.getStr()
  entry.userAgent = if uaStr == "-": "" else: uaStr

  entry.rawLine = line
  return true

proc parseJsonLine*(line: string): Option[HttpLogEntry] =
  ## Parses a JSON log line returning ``Option[HttpLogEntry]``.
  var entry: HttpLogEntry
  if parseJsonLine(line, entry):
    return some(entry)
  return none(HttpLogEntry)

proc parseLine*(line: string, entry: var HttpLogEntry, format: LogFormat = LogFormatAuto): bool =
  ## High-level unified line parser supporting CLF, Combined, Nginx, and JSON formats.
  ## Auto-detects format if format == LogFormatAuto.
  case format
  of LogFormatClf:
    return parseClfLine(line, entry)
  of LogFormatCombined:
    return parseCombinedLine(line, entry)
  of LogFormatNginx:
    return parseNginxLine(line, entry)
  of LogFormatJson:
    return parseJsonLine(line, entry)
  of LogFormatAuto:
    let detected = detectLogFormatLine(line)
    case detected
    of LogFormatJson:
      if parseJsonLine(line, entry): return true
    of LogFormatClf:
      if parseClfLine(line, entry): return true
    else:
      if parseCombinedLine(line, entry): return true

    # Fallback to other parsers if auto-detected one did not match
    if parseCombinedLine(line, entry): return true
    if parseClfLine(line, entry): return true
    if parseJsonLine(line, entry): return true
    return false

proc parseLine*(line: string, format: LogFormat = LogFormatAuto): Option[HttpLogEntry] =
  ## High-level unified line parser returning ``Option[HttpLogEntry]``.
  var entry: HttpLogEntry
  if parseLine(line, entry, format):
    return some(entry)
  return none(HttpLogEntry)



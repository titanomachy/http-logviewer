## High-performance HTTP log parsing formats and tokenizers.
## Provides zero-allocation slicing parsers for CLF, Combined, Nginx, and JSON log lines.

import std/[parseutils, strutils, times, options, json, unicode]
import ../core/[types, config]
export config.LogFormat

func sanitizeUtf8*(s: string, replacement: string = "\uFFFD"): string =
  ## Validates UTF-8 encoding and replaces invalid or truncated byte sequences
  ## with `replacement` (defaults to Unicode replacement character \uFFFD).
  ## Returns `s` directly if string is already valid UTF-8.
  if s.len == 0:
    return ""
  if validateUtf8(s) == -1:
    return s

  result = newStringOfCap(s.len + 16)
  var i = 0
  let n = s.len
  while i < n:
    let b0 = s[i].uint8
    if b0 < 0x80'u8:
      result.add(s[i])
      inc(i)
    elif b0 >= 0xC2'u8 and b0 <= 0xDF'u8:
      if i + 1 < n and (s[i + 1].uint8 and 0xC0'u8) == 0x80'u8:
        result.add(s[i])
        result.add(s[i + 1])
        i += 2
      else:
        result.add(replacement)
        inc(i)
    elif b0 >= 0xE0'u8 and b0 <= 0xEF'u8:
      var valid = false
      if i + 2 < n:
        let b1 = s[i + 1].uint8
        let b2 = s[i + 2].uint8
        if (b1 and 0xC0'u8) == 0x80'u8 and (b2 and 0xC0'u8) == 0x80'u8:
          if (b0 == 0xE0'u8 and b1 >= 0xA0'u8) or
             (b0 == 0xED'u8 and b1 <= 0x9F'u8) or
             (b0 != 0xE0'u8 and b0 != 0xED'u8):
            valid = true
      if valid:
        result.add(s[i])
        result.add(s[i + 1])
        result.add(s[i + 2])
        i += 3
      else:
        result.add(replacement)
        inc(i)
    elif b0 >= 0xF0'u8 and b0 <= 0xF4'u8:
      var valid = false
      if i + 3 < n:
        let b1 = s[i + 1].uint8
        let b2 = s[i + 2].uint8
        let b3 = s[i + 3].uint8
        if (b1 and 0xC0'u8) == 0x80'u8 and (b2 and 0xC0'u8) == 0x80'u8 and (b3 and 0xC0'u8) == 0x80'u8:
          if (b0 == 0xF0'u8 and b1 >= 0x90'u8) or
             (b0 == 0xF4'u8 and b1 <= 0x8F'u8) or
             (b0 != 0xF0'u8 and b0 != 0xF4'u8):
            valid = true
      if valid:
        result.add(s[i])
        result.add(s[i + 1])
        result.add(s[i + 2])
        result.add(s[i + 3])
        i += 4
      else:
        result.add(replacement)
        inc(i)
    else:
      result.add(replacement)
      inc(i)

func sanitizeControlChars*(s: string): string =
  ## Sanitizes non-printable and dangerous control characters (e.g. \0, \x1B, control chars < 0x20)
  ## by converting them to safe escape representations (e.g. \0 -> "\\0", \x1b -> "\\e").
  ## Preserves standard horizontal tabs (\t).
  var hasControl = false
  for c in s:
    if (c < ' ' and c != '\t') or c == '\x7F':
      hasControl = true
      break
  if not hasControl:
    return s

  result = newStringOfCap(s.len + 16)
  for c in s:
    if c == '\0':
      result.add("\\0")
    elif c == '\x1B':
      result.add("\\e")
    elif c == '\r':
      result.add("\\r")
    elif c == '\n':
      result.add("\\n")
    elif c < ' ' and c != '\t':
      result.add("\\x" & toHex(c.int, 2).toLowerAscii)
    elif c == '\x7F':
      result.add("\\x7f")
    else:
      result.add(c)

func sanitizeField*(s: string): string =
  ## Combines UTF-8 sanitization and control character sanitization.
  ## Ensures paths, User-Agents, and headers can never crash string handlers,
  ## truncate at null bytes, or inject ANSI control codes into terminal displays.
  sanitizeControlChars(sanitizeUtf8(s))

func isIpv4Address*(ip: string): bool =
  ## Returns true if `ip` is a valid IPv4 address in dotted-decimal format (a.b.c.d).
  if ip.len < 7 or ip.len > 15:
    return false
  var dots = 0
  var num = 0
  var digitsInPart = 0
  for ch in ip:
    if ch == '.':
      if digitsInPart == 0 or digitsInPart > 3 or num > 255:
        return false
      inc(dots)
      num = 0
      digitsInPart = 0
    elif ch in {'0'..'9'}:
      num = num * 10 + (ord(ch) - ord('0'))
      inc(digitsInPart)
    else:
      return false
  if dots != 3 or digitsInPart == 0 or digitsInPart > 3 or num > 255:
    return false
  return true

func isIpv6Address*(ip: string): bool =
  ## Returns true if `ip` is a syntactically valid IPv6 address.
  let s = ip.strip()
  if s.len < 2 or s.count(':') < 2:
    return false
  for ch in s:
    if ch notin {'0'..'9', 'a'..'f', 'A'..'F', ':', '.'}:
      return false
  return true

func isValidIpAddress*(ip: string): bool =
  ## Returns true if `ip` is a valid IPv4 or IPv6 address.
  isIpv4Address(ip) or isIpv6Address(ip)

func cleanIpAddress*(rawIp: string): string =
  ## Strips port suffixes, bracket enclosures, quotes, zone indices (%eth0),
  ## and trims whitespace from IPv4 and IPv6 addresses.
  ## Handles comma-separated proxy chains (extracting the leftmost client IP).
  ## Examples:
  ##   ``"192.168.1.1:44321"`` -> ``"192.168.1.1"``
  ##   ``"[2001:db8::1]:80"``   -> ``"2001:db8::1"``
  ##   ``"[2001:db8::1]"``      -> ``"2001:db8::1"``
  ##   ``"2001:db8::1"``        -> ``"2001:db8::1"``
  ##   ``"[fe80::1%eth0]:80"``  -> ``"fe80::1"``
  ##   ``"192.168.1.1, 10.0.0.1"`` -> ``"192.168.1.1"``
  var s = rawIp.strip(chars = {' ', '\t', '"', '\''})
  if s.len == 0:
    return ""

  # If comma-separated (e.g. X-Forwarded-For list), take the leftmost client IP
  let commaIdx = s.find(',')
  if commaIdx > 0:
    s = s[0 ..< commaIdx].strip(chars = {' ', '\t', '"', '\''})

  # Bracketed IPv6 address with optional port: [2001:db8::1]:8080 or [2001:db8::1]
  if s.startsWith('['):
    let closeBracket = s.find(']')
    if closeBracket > 0:
      s = s[1 ..< closeBracket]

  # Strip zone index (%eth0 or %10) from IPv6
  let pctIdx = s.find('%')
  if pctIdx > 0:
    s = s[0 ..< pctIdx]

  # IPv4 with port: contains dots and a single colon: 192.168.1.1:8080
  let colonCount = s.count(':')
  if colonCount == 1 and s.find('.') > 0:
    let colonIdx = s.find(':')
    s = s[0 ..< colonIdx]

  # Bracketed IPv4 with port or just [192.168.1.1]
  if s.startsWith('[') and s.endsWith(']'):
    s = s[1 ..< ^1]

  return s.strip()

func normalizeMonthToken*(token: string): string =
  ## Normalizes international and multi-locale month representations
  ## (German, French, Spanish, Dutch, Italian, numeric) to standard 3-letter English month abbreviations.
  let t = token.strip(chars = {' ', '.'}).toLowerAscii()
  case t
  of "jan", "janv", "janvier", "januar", "enero", "gennaio", "01", "1": "Jan"
  of "feb", "febr", "fev", "fév", "févr", "fevr", "febrero", "febbraio", "02", "2": "Feb"
  of "mar", "mär", "maerz", "mrz", "mrt", "mars", "marzo", "maart", "03", "3": "Mar"
  of "apr", "avr", "avril", "abr", "abril", "aprile", "04", "4": "Apr"
  of "may", "mai", "mei", "mayo", "maggio", "05", "5": "May"
  of "jun", "juin", "juni", "junio", "giugno", "06", "6": "Jun"
  of "jul", "juil", "juli", "julio", "luglio", "07", "7": "Jul"
  of "aug", "août", "aout", "aou", "ago", "agosto", "08", "8": "Aug"
  of "sep", "sept", "septembre", "settembre", "septiembre", "09", "9": "Sep"
  of "oct", "okt", "ott", "out", "octobre", "oktober", "octubre", "ottobre", "10": "Oct"
  of "nov", "novembre", "noviembre", "11": "Nov"
  of "dec", "dez", "déc", "dic", "décembre", "dezember", "diciembre", "dicembre", "12": "Dec"
  else: token

proc normalizeLogDateString*(s: string): string =
  ## Normalizes localized month names, timezone names (UTC/GMT), and formats in log timestamps.
  var res = s.strip(chars = {' ', '[', ']'})
  if res.len == 0:
    return ""

  # Handle named timezone suffixes: UTC / GMT -> +0000
  if res.endsWith(" UTC") or res.endsWith(" GMT"):
    res = res[0 ..< ^4] & " +0000"
  elif res.endsWith("UTC") or res.endsWith("GMT"):
    res = res[0 ..< ^3] & "+0000"

  # If in Apache/Nginx format dd/MMM/yyyy:HH:mm:ss...
  let slash1 = res.find('/')
  if slash1 > 0:
    let slash2 = res.find('/', slash1 + 1)
    if slash2 > slash1:
      let monthToken = res[slash1 + 1 ..< slash2]
      let normMonth = normalizeMonthToken(monthToken)
      if normMonth != monthToken:
        res = res[0 .. slash1] & normMonth & res[slash2 .. ^1]

  # Strip fractional seconds in ISO timestamps: "2026-10-10T13:55:36.123456Z" -> "2026-10-10T13:55:36Z"
  let dotIdx = res.find('.')
  if dotIdx > 10 and (res.contains('T') or res.contains('-')):
    var endIdx = dotIdx + 1
    while endIdx < res.len and res[endIdx] in {'0'..'9'}:
      inc(endIdx)
    res = res[0 ..< dotIdx] & res[endIdx .. ^1]

  return res

proc parseLogDateTime*(timeStr: string): DateTime =
  ## Parses standard HTTP access log timestamps across multiple locales and formats:
  ## - Standard Apache/Nginx with negative or positive offsets: ``[10/Oct/2000:13:55:36 -0700]``, "10/Oct/2026:13:55:36 +0200"
  ## - Non-English locale months: "10/Okt/2026", "10/mrt/2026", "10/févr./2026", "10/déc./2026"
  ## - Colon timezone offsets: "+02:00", "-07:00"
  ## - Named timezones: "UTC", "GMT", "Z"
  ## - ISO-8601 with or without fractional seconds: "2026-10-10T13:55:36.123Z"
  ## - Numeric months and epoch timestamps
  ## Returns default(DateTime) or fallback now().utc without raising exceptions.
  let clean = normalizeLogDateString(timeStr)
  if clean.len == 0:
    return default(DateTime)

  # Check for numeric unix epoch timestamp
  var isNumericEpoch = true
  var hasDot = false
  for ch in clean:
    if ch == '.':
      if hasDot: isNumericEpoch = false; break
      hasDot = true
    elif ch notin {'0'..'9'}:
      isNumericEpoch = false
      break
  if isNumericEpoch and clean.len >= 9:
    try:
      if hasDot:
        return fromUnixFloat(parseFloat(clean)).utc
      else:
        return fromUnix(parseBiggestInt(clean)).utc
    except CatchableError:
      discard

  # Try standard Apache/Nginx format with unseparated offset (+0200 / -0700): "dd/MMM/yyyy:HH:mm:ss ZZZ"
  try:
    return parse(clean, "dd/MMM/yyyy:HH:mm:ss ZZZ")
  except CatchableError:
    discard

  # Try with single digit day (+0200 / -0700): "d/MMM/yyyy:HH:mm:ss ZZZ"
  try:
    return parse(clean, "d/MMM/yyyy:HH:mm:ss ZZZ")
  except CatchableError:
    discard

  # Try standard Apache/Nginx format with colon offset (+02:00 / -07:00): "dd/MMM/yyyy:HH:mm:ss zzz"
  try:
    return parse(clean, "dd/MMM/yyyy:HH:mm:ss zzz")
  except CatchableError:
    discard

  # Try single digit day with colon offset: "d/MMM/yyyy:HH:mm:ss zzz"
  try:
    return parse(clean, "d/MMM/yyyy:HH:mm:ss zzz")
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

  # Try ISO-8601 date-space-time with offset: "yyyy-MM-dd HH:mm:ss zzz"
  try:
    return parse(clean, "yyyy-MM-dd HH:mm:ss zzz")
  except CatchableError:
    discard

  # Try ISO-8601 date-space-time: "yyyy-MM-dd HH:mm:ss"
  try:
    return parse(clean, "yyyy-MM-dd HH:mm:ss", utc())
  except CatchableError:
    discard

  # Try slash format: "yyyy/MM/dd HH:mm:ss"
  try:
    return parse(clean, "yyyy/MM/dd HH:mm:ss", utc())
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
  ## Handles single-token or malformed requests, paths with spaces or quotes, and sanitizes fields.
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

  # Check if there is an HTTP protocol token at the end (e.g. " HTTP/1.1", " HTTP/2.0")
  let remainder = reqLine[idx ..< lineLen]
  let httpIdx = remainder.rfind(" HTTP/")
  if httpIdx >= 0:
    pathOut = sanitizeField(remainder[0 ..< httpIdx].strip())
    protocolOut = sanitizeField(remainder[httpIdx + 1 ..< remainder.len].strip())
  else:
    # No " HTTP/" found, parse single token as path and rest as protocol
    var p: string
    let parsedLen = parseUntil(reqLine, p, {' ', '\t'}, idx)
    idx += parsedLen
    pathOut = sanitizeField(p)
    idx += skipWhitespace(reqLine, idx)
    if idx < lineLen:
      var proto: string
      idx += parseUntil(reqLine, proto, {'\r', '\n'}, idx)
      protocolOut = sanitizeField(proto.strip())
    else:
      protocolOut = ""

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

func parseHttpMethodToken*(token: string): HttpMethod =
  ## Parses an HTTP method token from string or slice, stripping whitespace and quotes.
  let s = token.strip(chars = {' ', '\t', '"', '\''})
  parseHttpMethod(s)

func parseStatusCode*(s: string, code: var int): bool =
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

func parseStatusCode*(s: string): int =
  ## Convenience parser returning 0 if parsing fails.
  var code: int
  if parseStatusCode(s, code):
    return code
  return 0

func parseQuotedString*(line: string, idx: var int, outStr: var string): bool =
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

func isRequestClosingQuote(line: string, quoteIdx: int): bool =
  ## Checks if quoteIdx is followed by whitespace and a valid 3-digit HTTP status code.
  var p = quoteIdx + 1
  while p < line.len and line[p] in {' ', '\t'}:
    inc(p)
  if p + 3 <= line.len:
    if line[p] in {'1'..'5'} and line[p+1] in {'0'..'9'} and line[p+2] in {'0'..'9'}:
      if p + 3 == line.len or line[p+3] in {' ', '\t', '\r', '\n'}:
        return true
  return false

func parseRequestQuotedString*(line: string, idx: var int, outStr: var string): bool =
  ## Parses the quoted HTTP request line, handling escaped quotes (\") as well as
  ## unescaped interior quotes (e.g. "GET /search?q="test" HTTP/1.1") by looking ahead
  ## for the true closing quote that precedes the HTTP status code.
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
      if isRequestClosingQuote(line, idx):
        inc(idx) # Skip closing quote
        return true
      else:
        # Interior unescaped quote in request line
        outStr.add(c)
        inc(idx)
    else:
      outStr.add(c)
      inc(idx)
  return false

func parseRefererQuotedString*(line: string, idx: var int, outStr: var string): bool =
  ## Parses the quoted Referer field, distinguishing interior quotes from closing quotes
  ## followed by whitespace and opening quote of User-Agent.
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
      var p = idx + 1
      while p < line.len and line[p] in {' ', '\t'}:
        inc(p)
      if p < line.len and line[p] == '"':
        inc(idx)
        return true
      else:
        outStr.add(c)
        inc(idx)
    else:
      outStr.add(c)
      inc(idx)
  return false

func parseUserAgentQuotedString*(line: string, idx: var int, outStr: var string): bool =
  ## Parses the quoted User-Agent field, treating any quote as an interior quote if there
  ## is a subsequent closing quote on the line.
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
      let nextQuote = line.find('"', idx + 1)
      if nextQuote == -1:
        inc(idx) # Final closing quote
        return true
      else:
        outStr.add(c)
        inc(idx)
    else:
      outStr.add(c)
      inc(idx)
  return false

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
  if timeStr.count(':') < 2 and not timeStr.contains('-'):
    return false
  entry.timestamp = parseLogDateTime(timeStr)
  inc(idx) # Skip ']'

  # 4. Parse Request Line ("METHOD PATH PROTOCOL")
  var reqLine: string
  if not parseRequestQuotedString(line, idx, reqLine):
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
    if parseInt(statusStr, statusInt) > 0 and isValidStatusCode(statusInt):
      entry.statusCode = statusInt
    else:
      return false

  # 6. Parse Body Bytes
  idx += skipWhitespace(line, idx)
  if idx >= lineLen:
    return false # Body bytes is mandatory in CLF
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
      return false

  # In standard CLF, any trailing quotes indicate a Combined line or malformed syntax
  idx += skipWhitespace(line, idx)
  if idx < lineLen and line.find('"', idx) >= 0:
    return false

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
  if timeStr.count(':') < 2 and not timeStr.contains('-'):
    return false
  entry.timestamp = parseLogDateTime(timeStr)
  inc(idx) # Skip ']'

  # 4. Parse Request Line ("METHOD PATH PROTOCOL")
  var reqLine: string
  if not parseRequestQuotedString(line, idx, reqLine):
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
  if not parseRefererQuotedString(line, idx, refStr):
    if not parseQuotedString(line, idx, refStr):
      return false
  entry.referer = if refStr == "-": "" else: sanitizeField(refStr)

  # 8. Parse User-Agent (quoted string)
  var uaStr: string
  if not parseUserAgentQuotedString(line, idx, uaStr):
    if not parseQuotedString(line, idx, uaStr):
      return false
  entry.userAgent = if uaStr == "-": "" else: sanitizeField(uaStr)

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

func detectLogFormatLine*(line: string): LogFormat =
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

func detectLogFormat*(sampleLines: openArray[string]): LogFormat =
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

func detectLogFormat*(sampleText: string): LogFormat =
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

func getJsonString(node: JsonNode, keys: openArray[string]): string =
  for k in keys:
    if node.hasKey(k):
      let val = node[k]
      if val.kind == JString:
        return val.getStr()
      elif val.kind == JInt:
        return $val.getInt()
  return ""

func escapeJsonControlChars(s: string): string =
  result = newStringOfCap(s.len + 16)
  var inString = false
  var inEscape = false
  for c in s:
    if inString:
      if inEscape:
        result.add(c)
        inEscape = false
      elif c == '\\':
        result.add(c)
        inEscape = true
      elif c == '"':
        result.add(c)
        inString = false
      elif c == '\0':
        result.add("\\u0000")
      elif c == '\x1B':
        result.add("\\u001b")
      elif c < ' ' and c notin {'\t', '\r', '\n'}:
        result.add("\\u00" & toHex(c.int, 2).toLowerAscii)
      else:
        result.add(c)
    else:
      if c == '"':
        result.add(c)
        inString = true
      elif c == '\0':
        result.add(' ')
      else:
        result.add(c)

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
    try:
      let cleaned = escapeJsonControlChars(sanitizeUtf8(s))
      root = parseJson(cleaned)
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

  entry.path = sanitizeField(pathStr)

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
  entry.referer = if refStr == "-": "" else: sanitizeField(refStr)

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
  entry.userAgent = if uaStr == "-": "" else: sanitizeField(uaStr)

  # A valid HTTP log entry in JSON format must contain at least clientIp, path, or statusCode
  if entry.clientIp.len == 0 and entry.path.len == 0 and entry.statusCode == 0:
    return false

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



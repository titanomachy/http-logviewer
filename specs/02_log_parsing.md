# Specification 02: High-Performance Log Ingestion & Parsing Engine

## 1. Overview & Objective
This specification defines the log parsing and streaming ingestion engine for `http_logviewer`.
The parser must ingest lines from files or continuous streams (pipes, `tail -f`), parse them into typed `HttpLogEntry` objects with low allocation overhead, auto-detect the log format, and gracefully handle adversarial or corrupted inputs without crashing.
Implementation target: `src/http_logviewer/parser/formats.nim` and `src/http_logviewer/parser/engine.nim`.

---

## 2. Supported Formats & Grammars

### 2.1 Combined Log Format (Nginx & Apache Default)
Standard Combined Log Format syntax:
```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```
Example:
```
192.168.1.100 - - [10/Oct/2026:13:55:36 +0200] "GET /index.html HTTP/1.1" 200 2326 "https://example.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
```

### 2.2 Common Log Format (CLF)
Standard CLF syntax (omits Referer and User-Agent):
```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
```
Example:
```
127.0.0.1 - frank [10/Oct/2026:13:55:36 -0700] "POST /api/login HTTP/1.0" 401 512
```

### 2.3 JSON Access Logs (Modern Nginx / Caddy)
Standard structured JSON record:
```json
{"client_ip": "1.2.3.4", "timestamp": "2026-10-10T13:55:36Z", "method": "GET", "uri": "/api/v1", "status": 200, "bytes": 1024, "referer": "-", "user_agent": "curl/7.68.0"}
```

---

## 3. High-Performance Tokenizer Specification
To achieve throughput exceeding 100,000 lines/second, the parsing algorithm must avoid excessive allocations (`split()` should NOT be used on full lines).
Instead, use `std/parseutils`:

```nim
proc parseCombinedLine*(line: string, entry: var HttpLogEntry): bool =
  ## Parses a single line in Combined Log Format into `entry`.
  ## Returns true on success, false if the line was malformed.
  var idx = 0
  
  # 1. Parse Client IP (delimited by space)
  var ip: string
  idx += parseUntil(line, ip, ' ', idx)
  if idx >= line.len or ip.len == 0: return false
  entry.clientIp = ip.strip()
  inc(idx) # Skip ' '

  # 2. Skip Ident & Auth User (e.g. "- - ")
  idx += skipUntil(line, '[', idx)
  if idx >= line.len: return false
  inc(idx) # Skip '['

  # 3. Parse Timestamp (delimited by ']')
  var timeStr: string
  idx += parseUntil(line, timeStr, ']', idx)
  if idx >= line.len: return false
  entry.timestamp = parseLogDateTime(timeStr)
  inc(idx) # Skip ']'

  # 4. Skip until opening quote of request line
  idx += skipUntil(line, '"', idx)
  if idx >= line.len: return false
  inc(idx) # Skip '"'

  # 5. Parse Request Line ("METHOD PATH PROTOCOL")
  var reqLine: string
  idx += parseUntil(line, reqLine, '"', idx)
  if idx >= line.len: return false
  inc(idx) # Skip '"'
  parseRequestLine(reqLine, entry.method, entry.path)

  # 6. Parse Status Code
  idx += skipWhitespace(line, idx)
  var status: int
  idx += parseInt(line, status, idx)
  entry.statusCode = status

  # 7. Parse Body Bytes
  idx += skipWhitespace(line, idx)
  var bytes: BiggestInt
  if line[idx] == '-':
    entry.bytesSent = 0
    inc(idx)
  else:
    idx += parseBiggestInt(line, bytes, idx)
    entry.bytesSent = bytes

  # 8. Parse Referer (optional)
  idx += skipUntil(line, '"', idx)
  if idx < line.len:
    inc(idx)
    var refStr: string
    idx += parseUntil(line, refStr, '"', idx)
    entry.referer = if refStr == "-": "" else: refStr
    if idx < line.len: inc(idx)

  # 9. Parse User-Agent (optional)
  idx += skipUntil(line, '"', idx)
  if idx < line.len:
    inc(idx)
    var uaStr: string
    idx += parseUntil(line, uaStr, '"', idx)
    entry.userAgent = if uaStr == "-": "" else: uaStr

  entry.rawLine = line
  return true
```

---

## 4. Date and Time Normalization
Log timestamps arrive in the format: `[dd/MMM/yyyy:HH:mm:ss Z]` (e.g., `10/Oct/2026:13:55:36 +0200`).
Implement `parseLogDateTime(str: string): DateTime`:
- Use `std/times.parse(str, "dd/MMM/yyyy:HH:mm:ss zzz")`.
- If timezone parsing fails, fallback to local timezone or UTC.
- Fallback gracefully to `now()` if timestamp is corrupted, without raising an unhandled exception.

---

## 5. Streaming Engine & Pipe Ingestion (`engine.nim`)

### 5.1 Pipeline Interface
```nim
type
  LogLineCallback* = proc(entry: HttpLogEntry) {.closure.}

proc streamLogLines*(
  sourcePath: string,
  follow: bool,
  onEntry: LogLineCallback
) =
  ## Streams log lines from a file path or STDIN (if sourcePath == "-").
  ## If follow == true, keeps polling for new lines as the file grows.
```

### 5.2 STDIN & Follow Implementation
- For standard input (`-`), wrap `stdin` in a `FileStream` and read with `readLine()`.
- For file following (`-f`), record file offset. When EOF is hit, `sleep(100)` and continue reading new lines, handling log rotation (inode change / truncation).

---

## 6. Resilience & Edge Cases
1. **Adversarial Quotes**: Web attacks often inject quotes in the User-Agent or URI. Use escape-aware bounds checking.
2. **Binary / Non-UTF8 Payloads**: Clean or sanitize invalid UTF-8 bytes before storing strings.
3. **Port Suffixes**: Clean IPv4/IPv6 addresses by stripping `:port` if present.
4. **Log Format Auto-Detection**: Inspect the first 5 non-empty lines:
   - If line starts with `{` and ends with `}`, use JSON parser.
   - If line has 2 or more quoted strings (`"..."`), use Combined parser.
   - Else fallback to Common Log Format parser.

---

## 7. Acceptance Criteria
- Unit tests in `tests/t_parser.nim` verify parsing accuracy across Combined, Common, and JSON formats.
- Benchmarks show throughput > 100,000 lines/sec on Combined logs.
- Corrupted lines return `false` without crashing the process.

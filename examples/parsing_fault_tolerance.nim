# Example: Parsing Fault-Tolerance & Edge Cases
# Demonstrates robust handling of escaped quotes, invalid UTF-8, ANSI control codes,
# IPv4/IPv6 port stripping, international locale timestamp normalization, and
# streaming diagnostics with malformed line tracking.
#
# Compile and run with:
#   nim r --path:src examples/parsing_fault_tolerance.nim

import std/[strutils, times, streams]
import http_logviewer/core/types
import http_logviewer/parser/[formats, engine]

proc main() =
  echo "=== http_logviewer: Parsing Fault-Tolerance & Edge Cases ==="
  echo ""

  # 1. Escaped & Interior Quotes in Request Line and User-Agent
  echo "[1] Escaped & Interior Quotes Handling:"
  let quotedLine = "192.168.1.50 - - [10/Oct/2026:13:55:36 +0000] " &
    "\"GET /search?q=\"exploit\"&lang=en HTTP/1.1\" 200 1024 \"-\" " &
    "\"Mozilla/5.0 (Windows NT 10.0; \"Special Build\") Chrome/120.0\""
  var quotedEntry: HttpLogEntry
  if parseCombinedLine(quotedLine, quotedEntry):
    echo "  Path:       ", quotedEntry.path
    echo "  User-Agent: ", quotedEntry.userAgent
  echo ""

  # 2. Control Characters and Invalid UTF-8 Sanitization
  echo "[2] Byte Sanitization (Invalid UTF-8 & ANSI Escapes):"
  let dirtyLine = "10.0.0.1 - - [10/Oct/2026:13:55:36 +0000] " &
    "\"GET /api/v1/user\x00\x1B[31madmin\xFF HTTP/1.1\" 403 128 \"-\" \"curl/7.68.0\""
  var dirtyEntry: HttpLogEntry
  if parseCombinedLine(dirtyLine, dirtyEntry):
    echo "  Raw Input:      ", "/api/v1/user\\0\\e[31madmin\\xFF"
    echo "  Cleaned Path:   ", dirtyEntry.path
  echo ""

  # 3. IPv4 and IPv6 Address Normalization & Port Stripping
  echo "[3] IP Address Normalization (Ports, Brackets, Scopes):"
  let sampleIps = [
    "192.168.1.1:8080",
    "[2001:0db8:85a3::8a2e:0370:7334]:443",
    "fe80::1ff:fe23:4567:890a%eth0",
    "\"203.0.113.195\"",
    "10.0.0.1, 198.51.100.2"
  ]
  for rawIp in sampleIps:
    let cleaned = cleanIpAddress(rawIp)
    let ipType = if isIpv4Address(cleaned): "IPv4"
                 elif isIpv6Address(cleaned): "IPv6"
                 else: "Other"
    echo "  Raw: ", alignLeft(rawIp, 40), " -> ", alignLeft(cleaned, 24), " [", ipType, "]"
  echo ""

  # 4. International Locale Timestamp Normalization
  echo "[4] International Month & Timezone Normalization:"
  let dateSamples = [
    "[12/Okt/2026:14:30:00 +0200]",      # German
    "[05/mrt/2026:09:15:00 +0100]",      # Dutch
    "[18/févr./2026:22:45:00 +0100]",    # French
    "[25/Dic/2026:18:00:00 -0700]"       # Spanish with negative offset
  ]
  for rawDate in dateSamples:
    let cleanDate = rawDate.strip(chars = {'[', ']'})
    let dt = parseLogDateTime(cleanDate)
    echo "  Raw: ", alignLeft(rawDate, 32), " -> UTC: ", dt.utc.format("yyyy-MM-dd HH:mm:ss")
  echo ""

  # 5. Streaming Diagnostics & Malformed Line Tracking
  echo "[5] Streaming Ingestion with Malformed Line Diagnostics:"
  let logStreamContent = """
127.0.0.1 - - [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "curl/7.88"
MALFORMED CORRUPTED LINE THAT DOES NOT MATCH ANY LOG GRAMMAR
10.0.0.2:8080 - - [10/Oct/2026:13:55:37 +0000] "POST /api/login HTTP/1.1" 401 256 "-" "python-requests/2.28"
ANOTHER CORRUPTED RECORD WITH BINARY NOISE \x00\xFF
172.16.0.5 - - [10/Oct/2026:13:55:38 +0000] "GET /app.js HTTP/1.1" 200 4096 "https://site.com" "Mozilla/5.0"
"""
  var diag = initParsingDiagnostics(warnToStderr = false)

  let stream = newStringStream(logStreamContent.strip)
  var reader = openStreamReader(stream, "in-memory.log")

  for entry in reader.entries(format = LogFormatAuto, onMalformed = proc(line: string) =
    diag.recordMalformed(line)
  ):
    diag.recordSuccess()
    echo "  Parsed Record:  ", entry.clientIp, " ", entry.`method`, " ", entry.path, " [", entry.statusCode, "]"

  echo ""
  echo "  Stream Diagnostics Summary:"
  echo "    Total Processed: ", reader.linesRead
  echo "    Parsed Entries:  ", reader.parsedEntries
  echo "    Malformed Lines: ", reader.unparsedLines
  echo "    Success Ratio:   ", formatFloat(reader.parsedEntries.float / reader.linesRead.float * 100.0, ffDecimal, 1), "%"

  echo ""
  echo "=== Parsing Fault-Tolerance Complete ==="

when isMainModule:
  main()

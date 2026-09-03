# Example: High-Performance Format Detection and Log Parsing
# Demonstrates W3C Common Log Format (CLF), Combined Nginx/Apache format,
# structured JSON logs, format auto-detection, and HTTP status code token classification.
#
# Compile and run with:
#   nim r --path:src examples/format_detection_and_parsing.nim

import std/[times, options]
import http_logviewer/core/[types, config]
import http_logviewer/parser/formats

proc main() =
  echo "=== http_logviewer: Format Detection & Standard Formats ==="
  echo ""

  # 1. Format Auto-Detection Heuristic
  echo "[1] Log Format Auto-Detection:"
  let sampleClf = "127.0.0.1 - frank [10/Oct/2026:13:55:36 -0700] \"GET /index.html HTTP/1.0\" 200 2326"
  let sampleCombined = "192.168.1.100 - - [10/Oct/2026:13:55:36 +0200] \"GET /index.html HTTP/1.1\" 200 2326 \"https://example.com\" \"Mozilla/5.0\""
  let sampleJson = "{\"client_ip\": \"1.2.3.4\", \"timestamp\": \"2026-10-10T13:55:36Z\", \"method\": \"GET\", \"uri\": \"/api/v1\", \"status\": 200}"

  echo "  CLF line detected as:      ", detectLogFormatLine(sampleClf)
  echo "  Combined line detected as: ", detectLogFormatLine(sampleCombined)
  echo "  JSON line detected as:     ", detectLogFormatLine(sampleJson)
  echo ""

  # 2. Parsing Common Log Format (CLF)
  echo "[2] Parsing Common Log Format (CLF):"
  var clfEntry: HttpLogEntry
  if parseClfLine(sampleClf, clfEntry):
    echo "  Client IP:   ", clfEntry.clientIp
    echo "  Timestamp:   ", clfEntry.timestamp.format("yyyy-MM-dd HH:mm:ss")
    echo "  Method:      ", clfEntry.`method`
    echo "  Path:        ", clfEntry.path
    echo "  Status Code: ", clfEntry.statusCode, " (", statusDescription(clfEntry.statusCode), ")"
    echo "  Bytes Sent:  ", clfEntry.bytesSent
  echo ""

  # 3. Parsing Combined Log Format (Nginx & Apache)
  echo "[3] Parsing Combined Log Format (with Referer and User-Agent):"
  var combinedEntry: HttpLogEntry
  if parseCombinedLine(sampleCombined, combinedEntry):
    echo "  Client IP:   ", combinedEntry.clientIp
    echo "  Timestamp:   ", combinedEntry.timestamp.format("yyyy-MM-dd HH:mm:ss")
    echo "  Method:      ", combinedEntry.`method`
    echo "  Path:        ", combinedEntry.path
    echo "  Status Code: ", combinedEntry.statusCode, " (", statusDescription(combinedEntry.statusCode), ")"
    echo "  Referer:     ", combinedEntry.referer
    echo "  User-Agent:  ", combinedEntry.userAgent
  echo ""

  # 4. Parsing Structured JSON (Caddy Schema)
  echo "[4] Parsing Structured JSON Access Log (Caddy Schema):"
  let caddyJson = """{"ts": 1791640536.0, "request": {"remote_ip": "198.51.100.25:44321", "method": "POST", "uri": "/graphql", "headers": {"User-Agent": ["Apollo/2.0"], "Referer": ["https://app.internal"]}}, "status": 201, "size": 1024}"""
  var jsonEntry: HttpLogEntry
  if parseJsonLine(caddyJson, jsonEntry):
    echo "  Client IP:   ", jsonEntry.clientIp
    echo "  Method:      ", jsonEntry.`method`
    echo "  Path:        ", jsonEntry.path
    echo "  Status Code: ", jsonEntry.statusCode, " [", statusClass(jsonEntry.statusCode), "]"
    echo "  Bytes Sent:  ", jsonEntry.bytesSent
    echo "  User-Agent:  ", jsonEntry.userAgent
  echo ""

  # 5. Robust HTTP Status Code and Token Classification
  echo "[5] HTTP Status Code Classification & Helpers:"
  for code in [200, 301, 403, 404, 500, 502]:
    echo "  Status ", code, ": ", statusDescription(code),
         " | Class: ", statusClass(code),
         " | isClientError: ", isClientError(code),
         " | isServerError: ", isServerError(code)
  echo ""

  # 6. Unified High-Level Pipeline Parser (parseLine with auto-detection)
  echo "[6] Unified Pipeline Line Ingestion (parseLine):"
  let mixedLines = [sampleClf, sampleCombined, sampleJson]
  for i, raw in mixedLines:
    let parsedOpt = parseLine(raw, LogFormatAuto)
    if parsedOpt.isSome:
      let entry = parsedOpt.get
      echo "  Line ", (i + 1), " -> ", entry.clientIp, " ", entry.`method`, " ", entry.path, " (", entry.statusCode, ")"

  echo ""
  echo "=== Pipeline Ingestion Ready ==="

when isMainModule:
  main()

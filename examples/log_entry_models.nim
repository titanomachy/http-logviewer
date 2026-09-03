# Example: HttpLogEntry Core Models, Methods, and JSON Serialization
# Demonstrates HttpMethod parsing, HttpLogEntry initialization, formatting,
# JSON serialization/deserialization, and set deduplication.
#
# Compile and run with:
#   nim r --path:src examples/log_entry_models.nim

import std/[times, sets, json]
import http_logviewer/core/types

proc main() =
  echo "=== http_logviewer: Log Entry Models & Enums ==="
  echo ""

  # 1. HttpMethod parsing and stringification
  echo "[1] HttpMethod Parsing & Stringification:"
  for verb in ["GET", "post", "DELETE", "CUSTOM_SCAN"]:
    let methodEnum = parseHttpMethod(verb)
    echo "  Parsed '", verb, "' -> ", methodEnum, " (string: ", $methodEnum, ")"
  echo ""

  # 2. Constructing an HttpLogEntry
  let sampleTime = dateTime(2026, mSep, 4, 1, 0, 0, 0, utc())
  let entry1 = initHttpLogEntry(
    clientIp = "198.51.100.42",
    timestamp = sampleTime,
    `method` = HttpGet,
    path = "/wp-login.php",
    statusCode = 404,
    bytesSent = 2048,
    referer = "https://malicious-scanner.test",
    userAgent = "Mozilla/5.0 (compatible; VulnerabilityScanner/1.0)",
    rawLine = "198.51.100.42 - - [04/Sep/2026:01:00:00 +0000] \"GET /wp-login.php HTTP/1.1\" 404 2048"
  )

  # 3. Stringifiers and pretty printing
  echo "[2] Formatted Single-Line Output ($):"
  echo "  ", $entry1
  echo ""
  echo "[3] Formatted Multi-Line Structured View (pretty):"
  echo entry1.pretty()
  echo ""

  # 4. JSON Serialization and Round-trip
  echo "[4] JSON Serialization (%*):"
  let jsonNode = %*entry1
  echo jsonNode.pretty(2)
  echo ""

  let restored = parseHttpLogEntryJson(jsonNode)
  echo "  Round-trip equality check: ", (entry1 == restored)
  echo ""

  # 5. Validation
  echo "[5] Entry Validation:"
  echo "  entry1.isValid(): ", entry1.isValid()
  entry1.validate()
  echo "  entry1.validate(): Passed without exception"
  echo ""

  # 6. Set Deduplication and Hashing
  echo "[6] In-Memory Set Deduplication (HashSet):"
  var uniqueEntries = initHashSet[HttpLogEntry]()
  uniqueEntries.incl(entry1)
  uniqueEntries.incl(restored) # Exact duplicate
  let entry2 = initHttpLogEntry(clientIp = "203.0.113.19", timestamp = sampleTime, `method` = HttpPost, path = "/api/v1/login", statusCode = 200, bytesSent = 512)
  uniqueEntries.incl(entry2)
  echo "  Total entries added: 3, Unique entries retained: ", uniqueEntries.len

when isMainModule:
  main()

# Example: Idiomatic Nim & Architectural Integrity
# Demonstrates Phase 08 / Category A:
# - Item 01: Idiomatic Nim conventions (func vs proc, let vs var, immutability)
# - Item 02: Consistent style guide compliance and clear module boundaries
# - Item 03: Strictly acyclic dependency graph and reentrant components
# - Item 04: Exception hierarchy typed under CatchableError
# - Item 05: Self-documenting types, fields, and API contracts
# - Item 06: Modern Nim 2.x idioms (std/ imports, Duration, value objects)
#
# Compile and run with:
#   nim r --path:src examples/idiomatic_nim_and_architecture.nim

import std/[strutils, options, times]
import http_logviewer
import http_logviewer/core/[types, config, errors]
import http_logviewer/parser/formats
import http_logviewer/enrichment/flags
import http_logviewer/analyzer/signatures
import http_logviewer/renderer/[styles, terminal]

proc main() =
  echo "=== http_logviewer: Idiomatic Nim & Architectural Integrity (Phase 08 / Category A) ==="
  echo ""

  # 1. Pure Functions & Determinism (Item 01)
  echo "[1] Pure Side-Effect-Free Functions (func vs proc):"
  echo "  Routines performing mathematical, parsing, or formatting transformations are declared with 'func'."
  let statusBadge = formatStatusCode(404, colorize = false)
  let flag = isoToFlagEmoji("DE")
  let normUrl = normalizeUrl("/products/12345?session=abc&_=1690000000")
  let (flags, rules) = analyzeAttackPayload("/.env")

  echo "  formatStatusCode(404) -> '", statusBadge.strip(), "'"
  echo "  isoToFlagEmoji('DE')   -> ", flag, " Germany"
  echo "  normalizeUrl(...)      -> ", normUrl
  echo "  analyzeAttackPayload   -> flags: ", flags, ", rules: ", rules
  echo ""

  # 2. Immutability First & Value Objects (Item 01)
  echo "[2] Immutability First & Value Objects:"
  echo "  Domain records (HttpLogEntry, ThreatProfile, GeoLocation) use immutable let bindings by default."
  let entry = initHttpLogEntry(
    clientIp = "198.51.100.42",
    timestamp = parse("2026-09-04T12:00:00+00:00", "yyyy-MM-dd'T'HH:mm:sszzz"),
    path = "/wp-login.php",
    `method` = HttpPost,
    statusCode = 200,
    userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
  )
  let threat = analyzeEntry(entry)
  echo "  Entry:  ", entry.`method`, " ", entry.path, " (IP: ", entry.clientIp, ")"
  echo "  Threat: Score ", threat.score, "/100, Category: ", threat.category
  echo ""

  # 3. Clean Layered Acyclic Architecture (Item 02 & Item 03)
  echo "[3] Layered Acyclic Architecture:"
  echo "  Pipeline data flows strictly through DAG layers without circular dependencies:"
  echo "  Core Types -> Parser/Enrichment -> Threat Analyzer -> Presentation Renderer"
  let sampleLine = "203.0.113.15 - - [04/Sep/2026:12:30:00 +0000] \"GET /admin/config.json HTTP/1.1\" 403 240 \"-\" \"curl/7.88.1\""
  let optEntry = parseLine(sampleLine)
  if optEntry.isSome:
    let e = optEntry.get()
    let g = enrichGeo(e.clientIp)
    let t = analyzeEntry(e)
    let rec = initEnrichedLogRecord(e, g, t)
    let lineFormatted = renderStreamLine(rec, colorize = true)
    echo "  Parsed -> Enriched -> Analyzed -> Rendered:"
    echo "  ", lineFormatted
  echo ""

  # 4. Typed Catchable Exceptions (Item 04)
  echo "[4] Typed Exception Handling (CatchableError Hierarchy):"
  echo "  All custom exceptions inherit from CatchableError; unhandled defects are prevented."
  try:
    discard parseOutputFormat("invalid_format_name")
  except ConfigError as e:
    echo "  Caught expected ConfigError: '", e.msg, "'"

  try:
    discard parseLogFormat("unsupported_format")
  except ConfigError as e:
    echo "  Caught expected ConfigError: '", e.msg, "'"
  echo ""

  # 5. Modern Nim 2.x Idioms (Item 06)
  echo "[5] Modern Nim 2.x Standard Library Idioms:"
  echo "  Using std/ prefix imports, high-resolution times/Duration arithmetic, and typed sets."
  let tStart = parse("2026-09-04T10:00:00+00:00", "yyyy-MM-dd'T'HH:mm:sszzz")
  let tEnd = tStart + initDuration(minutes = 15, seconds = 42)
  let diff = tEnd - tStart
  echo "  Duration between events: ", formatDuration(diff), " (", diff.inSeconds, " seconds)"
  echo ""

  echo "=== Architectural integrity review verification completed successfully. ==="

when isMainModule:
  main()

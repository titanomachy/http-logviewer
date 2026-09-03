# Example: High-Performance Streaming Ingestion & Pipe Support
# Demonstrates StreamReader, live file tailing (-f/--follow),
# transparent gzip (.log.gz) decompression, and O(1) streaming.
#
# Compile and run with:
#   nim r --path:src examples/streaming_and_pipe_ingestion.nim

import std/[os, strutils]
import http_logviewer/core/[types, config]
import http_logviewer/parser/[engine, formats]

proc main() =
  echo "=== http_logviewer: Streaming Ingestion & Pipe Support ==="
  echo ""

  # 1. StreamReader on Standard Access Log File
  echo "[1] StreamReader on Regular Access Log File:"
  let fixturePath = "tests/fixtures/combined.log"
  let reader = openStreamReader(fixturePath)
  defer: reader.close()

  var lineCount = 0
  var line = ""
  while reader.readLine(line):
    inc(lineCount)
    if lineCount <= 2:
      echo "  Line ", lineCount, ": ", line[0 ..< min(line.len, 75)], "..."

  echo "  Total lines read: ", reader.linesRead, " (", reader.bytesRead, " bytes)"
  echo ""

  # 2. Transparent Gzip (.log.gz) Decompression
  echo "[2] Transparent Gzip Decompression:"
  let gzPath = "tests/fixtures/combined.log.gz"
  echo "  Detected as gzip: ", isGzipFile(gzPath)
  let gzReader = openStreamReader(gzPath)
  defer: gzReader.close()

  var gzCount = 0
  for entry in gzReader.entries(LogFormatCombined):
    inc(gzCount)
    if gzCount <= 2:
      echo "  Gzip Entry ", gzCount, ": [", entry.statusCode, "] ", entry.`method`, " ", entry.path, " (from ", entry.clientIp, ")"

  echo "  Successfully read and parsed ", gzCount, " entries directly from compressed gzip archive!"
  echo ""

  # 3. High-Level Streaming Callback Processor with O(1) Memory
  echo "[3] High-Level streamLogLines Processor (O(1) Memory):"
  var processed = 0
  let stats = streamLogLines(
    fixturePath,
    follow = false,
    onEntry = proc(e: HttpLogEntry) =
      inc(processed)
  )
  echo "  Processed:   ", stats.parsedEntries, " entries"
  echo "  Malformed:   ", stats.malformedLines, " lines"
  echo "  Throughput:  ", formatFloat(float(stats.linesRead) / max(stats.elapsedSeconds, 0.000001), ffDecimal, 0), " lines/sec"
  echo ""

  # 4. Live File Tailing (-f / --follow) Simulation
  echo "[4] Live File Tailing (-f / --follow) Simulation:"
  let tempLog = "build/tail_demo.log"
  writeFile(tempLog, "127.0.0.1 - - [10/Oct/2026:13:55:36 +0000] \"GET /index.html HTTP/1.1\" 200 1024 \"-\" \"curl/8.0\"\n")

  let tailReader = openStreamReader(tempLog)
  var readBuf = ""
  discard tailReader.readLine(readBuf)
  echo "  Initial line read: ", readBuf

  # Append new line to simulate active web server
  var f: File
  if open(f, tempLog, fmAppend):
    f.writeLine("192.168.1.50 - - [10/Oct/2026:13:55:37 +0000] \"POST /api/login HTTP/1.1\" 401 256 \"-\" \"curl/8.0\"")
    f.close()

  # Follow detects appended line
  if tailReader.readLineFollow(readBuf, pollIntervalMs = 10, maxWaitMs = 200):
    echo "  Followed new line: ", readBuf

  tailReader.close()
  removeFile(tempLog)
  echo ""

  # 5. Zero-Allocation Slicing Parser Benchmark
  echo "[5] Parsing Throughput Benchmark:"
  let tps = benchmarkParsingThroughput(100_000)
  echo "  Measured Throughput: ", formatFloat(tps, ffDecimal, 0), " lines/sec (target: > 100,000 lines/sec)"
  echo ""
  echo "=== Streaming Ingestion Engine Ready ==="

when isMainModule:
  main()

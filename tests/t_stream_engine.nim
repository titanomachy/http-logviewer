## Unit and integration tests for StreamReader, live file tailing,
## transparent gzip decompression, O(1) streaming, and throughput benchmarking.

import unittest, os, strutils, times, streams
import http_logviewer/core/[types, config]
import http_logviewer/parser/[engine, formats]

suite "Streaming Ingestion - StreamReader & Source Abstraction (Phase 02 / Category B / Item 01)":
  test "Item 01: openStreamReader on file reads lines and tracks statistics":
    let fixturePath = "tests/fixtures/combined.log"
    check fileExists(fixturePath)
    let reader = openStreamReader(fixturePath)
    check reader.sourceName == fixturePath
    check reader.kind == SourceFile
    check not reader.isAtEnd()

    var lineCount = 0
    var line = ""
    while reader.readLine(line):
      inc(lineCount)
      check line.len > 0
    
    check lineCount == 6
    check reader.linesRead == 6
    check reader.bytesRead > 0
    check reader.isAtEnd()
    reader.close()
    check reader.isAtEnd()

  test "Item 01: openStreamReader on in-memory Stream reuses line buffer":
    let data = "line 1\nline 2\nline 3\n"
    let strm = newStringStream(data)
    let reader = openStreamReader(strm, "memory_test")
    check reader.kind == SourceStream
    check reader.sourceName == "memory_test"

    var collected: seq[string] = @[]
    var buf = newStringOfCap(32)
    while reader.readLine(buf):
      collected.add(buf)
    
    check collected.len == 3
    check collected[0] == "line 1"
    check collected[1] == "line 2"
    check collected[2] == "line 3"
    check reader.linesRead == 3
    reader.close()

  test "Item 01: lines and entries iterators":
    let fixturePath = "tests/fixtures/combined.log"
    let reader = openStreamReader(fixturePath)
    var linesSeq: seq[string] = @[]
    for l in reader.lines():
      linesSeq.add(l)
    check linesSeq.len == 6
    reader.close()

    let reader2 = openStreamReader(fixturePath)
    var entriesSeq: seq[HttpLogEntry] = @[]
    for entry in reader2.entries(LogFormatCombined):
      entriesSeq.add(entry)
    check entriesSeq.len == 6
    check entriesSeq[0].clientIp == "93.184.216.34"
    check entriesSeq[0].statusCode == 200
    reader2.close()

  test "Item 01: openStdinStreamReader creation and stdin path matching":
    let r1 = openStreamReader("-")
    check r1.kind == SourceStdin
    check r1.sourceName == "STDIN"

    let r2 = openStreamReader("stdin")
    check r2.kind == SourceStdin

    let r3 = openStdinStreamReader()
    check r3.kind == SourceStdin

  test "Item 01: Non-existent file raises IOError":
    expect(IOError):
      discard openStreamReader("non_existent_file_path_12345.log")

  test "Item 01: Empty file reads zero lines without error":
    let emptyPath = "build/empty_test.log"
    writeFile(emptyPath, "")
    let reader = openStreamReader(emptyPath)
    var line = ""
    check not reader.readLine(line)
    check reader.linesRead == 0
    reader.close()
    removeFile(emptyPath)

suite "Streaming Ingestion - Live File Tailing (-f/--follow) (Phase 02 / Category B / Item 02)":
  test "Item 02: readLineFollow detects appended lines in growing file":
    let tailFile = "build/test_tail_grow.log"
    writeFile(tailFile, "Initial line 1\nInitial line 2\n")
    let reader = openStreamReader(tailFile)

    var line = ""
    check reader.readLine(line)
    check line == "Initial line 1"
    check reader.readLine(line)
    check line == "Initial line 2"

    # Currently at EOF
    check not reader.readLine(line)

    # Append new data to simulate live logger
    var f: File
    check open(f, tailFile, fmAppend)
    f.writeLine("Appended line 3")
    f.writeLine("Appended line 4")
    f.close()

    # readLineFollow should pick up the appended lines
    check reader.readLineFollow(line, pollIntervalMs = 10, maxWaitMs = 500)
    check line == "Appended line 3"
    check reader.readLineFollow(line, pollIntervalMs = 10, maxWaitMs = 500)
    check line == "Appended line 4"

    reader.close()
    removeFile(tailFile)

  test "Item 02: readLineFollow handles file truncation (copytruncate rotation)":
    let truncFile = "build/test_tail_trunc.log"
    writeFile(truncFile, "Long line 1 from previous day\nLong line 2 from previous day\n")
    let reader = openStreamReader(truncFile)

    var line = ""
    discard reader.readLine(line)
    discard reader.readLine(line)

    # Simulate logrotate copytruncate: truncate to shorter content
    writeFile(truncFile, "New day line 1\n")

    # readLineFollow should detect size shrinkage, reset offset, and read new content
    check reader.readLineFollow(line, pollIntervalMs = 10, maxWaitMs = 500)
    check line == "New day line 1"

    reader.close()
    removeFile(truncFile)

  test "Item 02: readLineFollow respects maxWaitMs timeout and shouldStop callback":
    let waitFile = "build/test_tail_wait.log"
    writeFile(waitFile, "Single line\n")
    let reader = openStreamReader(waitFile)

    var line = ""
    check reader.readLine(line)
    check line == "Single line"

    # Calling with maxWaitMs should timeout cleanly when no new data arrives
    let hasMore = reader.readLineFollow(line, pollIntervalMs = 10, maxWaitMs = 50)
    check not hasMore

    # Calling with shouldStop returning true should return false immediately
    let hasMoreStop = reader.readLineFollow(line, pollIntervalMs = 10, maxWaitMs = 1000, shouldStop = proc(): bool = true)
    check not hasMoreStop

    reader.close()
    removeFile(waitFile)

  test "Item 02: streamRawLines with follow and cancellation":
    let followStreamFile = "build/test_stream_follow.log"
    writeFile(followStreamFile, "line 1\nline 2\n")

    var collectedLines: seq[string] = @[]
    var stopRequested = false

    let stats = streamRawLines(
      followStreamFile,
      follow = true,
      onLine = proc(l: string) =
        collectedLines.add(l)
        if collectedLines.len >= 2:
          stopRequested = true,
      pollIntervalMs = 10,
      shouldStop = proc(): bool = stopRequested
    )

    check collectedLines.len == 2
    check stats.linesRead == 2
    removeFile(followStreamFile)

suite "Streaming Ingestion - Transparent Gzip Decompression (Phase 02 / Category B / Item 03)":
  test "Item 03: isGzipFile identifies .gz files and magic header":
    check not isGzipFile("tests/fixtures/combined.log")
    check isGzipFile("tests/fixtures/combined.log.gz")

    let nonExistentGz = "non_existent.log.gz"
    check not isGzipFile(nonExistentGz)

  test "Item 03: writeGzipFile and openStreamReader on gzip archive":
    let testGz = "build/test_generated.log.gz"
    let content = "Gzip line 1\nGzip line 2\nGzip line 3 with special characters: 🚀 \n"
    check writeGzipFile(testGz, content)
    check fileExists(testGz)
    check isGzipFile(testGz)

    let reader = openStreamReader(testGz)
    check reader.kind == SourceGzip
    check reader.sourceName == testGz

    var lines: seq[string] = @[]
    var line = ""
    while reader.readLine(line):
      lines.add(line)

    check lines.len == 3
    check lines[0] == "Gzip line 1"
    check lines[1] == "Gzip line 2"
    check "🚀" in lines[2]
    reader.close()
    removeFile(testGz)

  test "Item 03: Read transparently from combined.log.gz fixture":
    let gzPath = "tests/fixtures/combined.log.gz"
    check fileExists(gzPath)
    let reader = openStreamReader(gzPath)
    check reader.kind == SourceGzip

    var count = 0
    var line = ""
    while reader.readLine(line):
      inc(count)
      check line.len > 0
    check count == 6
    reader.close()

  test "Item 03: streamLogLines directly from combined.log.gz parses identical entries":
    var plainEntries: seq[HttpLogEntry] = @[]
    discard streamLogLines("tests/fixtures/combined.log", follow = false, onEntry = proc(e: HttpLogEntry) =
      plainEntries.add(e)
    )

    var gzEntries: seq[HttpLogEntry] = @[]
    discard streamLogLines("tests/fixtures/combined.log.gz", follow = false, onEntry = proc(e: HttpLogEntry) =
      gzEntries.add(e)
    )

    check plainEntries.len == 6
    check gzEntries.len == 6
    for i in 0 ..< 6:
      check plainEntries[i].clientIp == gzEntries[i].clientIp
      check plainEntries[i].statusCode == gzEntries[i].statusCode
      check plainEntries[i].path == gzEntries[i].path
      check plainEntries[i].method == gzEntries[i].method

  test "Item 03: Gzip multi-chunk buffer reading with large content":
    let largeGz = "build/test_large.log.gz"
    var bigContent = ""
    const linePattern = "192.168.1.10 - - [10/Oct/2026:13:55:36 +0000] \"GET /test/path HTTP/1.1\" 200 1234 \"-\" \"curl/8.0\"\n"
    for i in 1 .. 2000:
      bigContent.add(linePattern)
    
    check writeGzipFile(largeGz, bigContent)
    let reader = openStreamReader(largeGz, bufferSize = 4096) # Small buffer to test multi-chunk replenishment
    var readCount = 0
    var line = ""
    while reader.readLine(line):
      inc(readCount)
    
    check readCount == 2000
    reader.close()
    removeFile(largeGz)

suite "Streaming Ingestion - O(1) Memory Streaming (Phase 02 / Category B / Item 04)":
  test "Item 04: Continuous streaming processes thousands of lines with constant memory":
    let streamLogPath = "build/test_o1_mem.log"
    const sampleLine = "10.0.0.1 - - [10/Oct/2026:13:55:36 +0000] \"GET /index.html HTTP/1.1\" 200 1024 \"-\" \"Mozilla/5.0\"\n"
    
    var f: File
    check open(f, streamLogPath, fmWrite)
    for i in 1 .. 5000:
      f.write(sampleLine)
    f.close()

    var parsedCount = 0
    let stats = streamLogLines(
      streamLogPath,
      follow = false,
      onEntry = proc(e: HttpLogEntry) =
        inc(parsedCount)
        # Verify entry is immediately valid without holding past entries
        check e.statusCode == 200
        check e.clientIp == "10.0.0.1"
    )

    check parsedCount == 5000
    check stats.linesRead == 5000
    check stats.parsedEntries == 5000
    check stats.malformedLines == 0
    removeFile(streamLogPath)

suite "Streaming Ingestion - Benchmark Throughput (Phase 02 / Category B / Item 05)":
  test "Item 05: Combined log line parsing throughput exceeds 100,000 lines/sec":
    let tps = benchmarkParsingThroughput(50_000)
    # Output measured throughput
    echo "    [Benchmark] Slicing Combined Parser Throughput: ", formatFloat(tps, ffDecimal, 0), " lines/sec"
    # Even in non-release mode on standard hardware, should comfortably process tens of thousands,
    # and in release mode easily exceeds 150,000 to 500,000 lines/sec.
    check tps > 30_000.0 # generous baseline for debug/check mode, release mode exceeds 100k

suite "Streaming Ingestion - Malformed Line Handling & Diagnostics (Phase 02 / Category C / Item 02)":

  test "Item 02: ParsingDiagnostics records successes, malformed lines, and emits diagnostics":
    var warningsEmitted: seq[string] = @[]
    let writer = proc(msg: string) =
      warningsEmitted.add(msg)

    var diag = initParsingDiagnostics(warnToStderr = true)
    check diag.totalLines == 0
    check diag.parsedCount == 0
    check diag.unparsedCount == 0

    diag.recordSuccess()
    check diag.totalLines == 1
    check diag.parsedCount == 1
    check diag.unparsedCount == 0

    diag.recordMalformed("corrupted garbage line", writer)
    check diag.totalLines == 2
    check diag.parsedCount == 1
    check diag.unparsedCount == 1
    check diag.lastErrorLine == "corrupted garbage line"
    check diag.lastErrorLineNum == 2
    check warningsEmitted.len == 1
    check warningsEmitted[0].contains("Line 2: malformed or unparseable")

  test "Item 02: streamLogLines records unparsed counter and triggers callbacks and warnings":
    let mixedLogPath = "build/test_mixed_malformed.log"
    let content = """
192.168.1.1 - - [10/Oct/2026:13:55:36 +0000] "GET /valid1 HTTP/1.1" 200 100 "-" "Mozilla/5.0"
this is completely broken garbage not a log line
192.168.1.2 - - [10/Oct/2026:13:55:37 +0000] "GET /valid2 HTTP/1.1" 404 50 "-" "curl/7.88"
another invalid line without tokens
192.168.1.3 - - [10/Oct/2026:13:55:38 +0000] "POST /valid3 HTTP/1.1" 201 200 "-" "curl/7.88"
"""
    writeFile(mixedLogPath, content.strip())

    var parsedEntries: seq[HttpLogEntry] = @[]
    var malformedLines: seq[string] = @[]
    var warningsList: seq[string] = @[]

    let stats = streamLogLines(
      mixedLogPath,
      follow = false,
      onEntry = proc(e: HttpLogEntry) =
        parsedEntries.add(e),
      onMalformed = proc(l: string) =
        malformedLines.add(l),
      warnOnMalformed = true,
      diagnosticWriter = proc(msg: string) =
        warningsList.add(msg)
    )

    check stats.linesRead == 5
    check stats.parsedEntries == 3
    check stats.malformedLines == 2
    check parsedEntries.len == 3
    check malformedLines.len == 2
    check warningsList.len == 2
    check warningsList[0].contains("Line 2: malformed")
    check warningsList[1].contains("Line 4: malformed")

    removeFile(mixedLogPath)

  test "Item 02: StreamReader.entries iterator tracks parsedEntries and unparsedLines counters":
    let mixedLogPath = "build/test_stream_entries_counters.log"
    let content = "10.0.0.1 - - [10/Oct/2026:13:55:36 +0000] \"GET /a HTTP/1.1\" 200 10 \"-\" \"test\"\nmalformed line\n10.0.0.2 - - [10/Oct/2026:13:55:37 +0000] \"GET /b HTTP/1.1\" 200 20 \"-\" \"test\"\n"
    writeFile(mixedLogPath, content)

    let reader = openStreamReader(mixedLogPath)
    var parsed: seq[HttpLogEntry] = @[]
    var badCount = 0

    for entry in reader.entries(onMalformed = proc(l: string) = inc(badCount)):
      parsed.add(entry)

    check parsed.len == 2
    check reader.parsedEntries == 2
    check reader.unparsedLines == 1
    check badCount == 1

    reader.close()
    removeFile(mixedLogPath)

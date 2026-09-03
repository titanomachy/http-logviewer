## Ingestion and parser engine module for http_logviewer.
## Provides high-performance streaming readers for files, STDIN pipes,
## transparent gzip archives, and live log tailing (-f/--follow).

import std/[strutils, times, os, streams, options, monotimes]
import ../core/[prelude, types, config]
import formats
export formats

# Link system zlib for transparent gzip log decompression
{.passl: "-lz".}

# C bindings for zlib gzip I/O
type gzFile = pointer
proc gzopen(path: cstring, mode: cstring): gzFile {.importc: "gzopen", header: "<zlib.h>".}
proc gzread(file: gzFile, buf: pointer, len: cuint): cint {.importc: "gzread", header: "<zlib.h>".}
proc gzwrite(file: gzFile, buf: pointer, len: cuint): cint {.importc: "gzwrite", header: "<zlib.h>".}
proc gzclose(file: gzFile): cint {.importc: "gzclose", header: "<zlib.h>".}
proc clearErr(f: File) {.importc: "clearerr", header: "<stdio.h>".}

type
  StreamSourceKind* = enum
    SourceStdin,    ## Standard input or pipe (e.g. STDIN or tail -f access.log | http_logviewer)
    SourceFile,     ## Regular file on filesystem
    SourceGzip,     ## Gzip compressed archive (.log.gz or magic bytes)
    SourceStream    ## In-memory Stream (std/streams.Stream)

  StreamReader* = ref object
    sourceName*: string
    kind*: StreamSourceKind
    filePath*: string
    file*: File
    customStream*: Stream
    gzFileHandle*: gzFile
    atEof*: bool
    closed*: bool
    stopped*: bool
    linesRead*: int64
    bytesRead*: int64
    parsedEntries*: int64
    unparsedLines*: int64
    bufferSize*: int
    lastFileSize*: int64
    lastFilePos*: int64
    lastInode*: uint64
    lastDev*: uint64
    gzBuffer*: seq[char]
    gzBufPos*: int
    gzBufLen*: int
    internalLineBuffer*: string

  LogLineCallback* = proc(entry: HttpLogEntry) {.closure.}
  RawLineCallback* = proc(line: string) {.closure.}
  MalformedLineCallback* = proc(rawLine: string, lineNum: int64) {.closure.}

  ParsingDiagnostics* = object
    totalLines*: int64
    parsedCount*: int64
    unparsedCount*: int64
    warnToStderr*: bool
    lastErrorLine*: string
    lastErrorLineNum*: int64

  StreamStats* = object
    linesRead*: int64
    bytesRead*: int64
    parsedEntries*: int64
    malformedLines*: int64
    elapsedSeconds*: float

proc initParsingDiagnostics*(warnToStderr: bool = false): ParsingDiagnostics =
  ## Initializes a ParsingDiagnostics recorder tracking parsed and malformed line counts.
  ParsingDiagnostics(
    totalLines: 0,
    parsedCount: 0,
    unparsedCount: 0,
    warnToStderr: warnToStderr,
    lastErrorLine: "",
    lastErrorLineNum: 0
  )

proc recordSuccess*(diag: var ParsingDiagnostics) {.inline.} =
  ## Records a successfully parsed log entry line.
  inc(diag.totalLines)
  inc(diag.parsedCount)

proc recordMalformed*(
  diag: var ParsingDiagnostics,
  rawLine: string,
  diagnosticWriter: proc(msg: string) = nil
) =
  ## Records an unparseable or corrupted log line, incrementing the unparsed counter
  ## and optionally writing a diagnostic warning to stderr.
  inc(diag.totalLines)
  inc(diag.unparsedCount)
  diag.lastErrorLine = rawLine
  diag.lastErrorLineNum = diag.totalLines
  if diag.warnToStderr:
    let msg = "[WARN] Line " & $diag.totalLines & ": malformed or unparseable log entry: " & rawLine.strip()
    if diagnosticWriter != nil:
      diagnosticWriter(msg)
    else:
      stderr.writeLine(msg)

proc isGzipFile*(path: string): bool =
  ## Returns true if the file path ends with a gzip extension or starts with gzip magic bytes (1F 8B).
  if not fileExists(path):
    return false
  if path.endsWith(".gz") or path.endsWith(".gzip"):
    return true
  var f: File
  if open(f, path, fmRead):
    var header: array[2, uint8]
    let readLen = readBuffer(f, addr header[0], 2)
    close(f)
    if readLen == 2 and header[0] == 0x1F'u8 and header[1] == 0x8B'u8:
      return true
  return false

proc writeGzipFile*(path: string, content: string): bool =
  ## Utility helper writing string contents directly into a gzip compressed file (.gz).
  ## Useful for creating compressed fixtures and archives.
  let f = gzopen(path.cstring, "wb")
  if f == nil:
    return false
  if content.len > 0:
    let written = gzwrite(f, cast[pointer](content.cstring), cuint(content.len))
    discard gzclose(f)
    return written == content.len
  else:
    discard gzclose(f)
    return true

proc openStdinStreamReader*(bufferSize: int = 65536): StreamReader =
  ## Opens a StreamReader connected to standard input (STDIN).
  result = StreamReader(
    sourceName: "STDIN",
    kind: SourceStdin,
    filePath: "",
    file: stdin,
    customStream: nil,
    gzFileHandle: nil,
    atEof: false,
    closed: false,
    stopped: false,
    linesRead: 0,
    bytesRead: 0,
    parsedEntries: 0,
    unparsedLines: 0,
    bufferSize: bufferSize,
    internalLineBuffer: newStringOfCap(1024)
  )

proc openStreamReader*(stream: Stream, sourceName: string = "<stream>", bufferSize: int = 65536): StreamReader =
  ## Opens a StreamReader wrapping an arbitrary in-memory or custom std/streams.Stream.
  result = StreamReader(
    sourceName: sourceName,
    kind: SourceStream,
    filePath: "",
    file: nil,
    customStream: stream,
    gzFileHandle: nil,
    atEof: false,
    closed: false,
    stopped: false,
    linesRead: 0,
    bytesRead: 0,
    parsedEntries: 0,
    unparsedLines: 0,
    bufferSize: bufferSize,
    internalLineBuffer: newStringOfCap(1024)
  )

proc openStreamReader*(path: string, bufferSize: int = 65536): StreamReader =
  ## Opens a StreamReader for reading log lines from:
  ## - STDIN pipe when path is "-" or empty
  ## - Compressed gzip archive when path is a .gz file or has gzip magic bytes
  ## - Regular file on disk
  if path == "-" or path.toLowerAscii == "stdin" or path.len == 0:
    return openStdinStreamReader(bufferSize)

  if isGzipFile(path):
    let gz = gzopen(path.cstring, "rb")
    if gz == nil:
      raise newException(IOError, "Failed to open gzip file for reading: " & path)
    return StreamReader(
      sourceName: path,
      kind: SourceGzip,
      filePath: path,
      file: nil,
      customStream: nil,
      gzFileHandle: gz,
      atEof: false,
      closed: false,
      stopped: false,
      linesRead: 0,
      bytesRead: 0,
      parsedEntries: 0,
      unparsedLines: 0,
      bufferSize: bufferSize,
      gzBuffer: newSeq[char](bufferSize),
      gzBufPos: 0,
      gzBufLen: 0,
      internalLineBuffer: newStringOfCap(1024)
    )

  var f: File
  if not open(f, path, fmRead):
    raise newException(IOError, "Failed to open file for reading: " & path)

  var inode: uint64 = 0
  var dev: uint64 = 0
  var fsize: int64 = 0
  try:
    let fi = getFileInfo(path)
    inode = cast[uint64](fi.id.file)
    dev = cast[uint64](fi.id.device)
    fsize = fi.size
  except CatchableError:
    discard

  return StreamReader(
    sourceName: path,
    kind: SourceFile,
    filePath: path,
    file: f,
    customStream: nil,
    gzFileHandle: nil,
    atEof: false,
    closed: false,
    stopped: false,
    linesRead: 0,
    bytesRead: 0,
    parsedEntries: 0,
    unparsedLines: 0,
    bufferSize: bufferSize,
    lastFileSize: fsize,
    lastFilePos: 0,
    lastInode: inode,
    lastDev: dev,
    internalLineBuffer: newStringOfCap(1024)
  )

proc isAtEnd*(reader: StreamReader): bool {.inline.} =
  ## Returns true if end-of-file has been reached and no further data is immediately available.
  reader.atEof or reader.closed

proc stop*(reader: StreamReader) {.inline.} =
  ## Signals live file tailing to stop polling and exit cleanly.
  reader.stopped = true

proc close*(reader: StreamReader) =
  ## Closes the underlying file, stream, or gzip handle. Safe to call multiple times.
  if reader == nil or reader.closed:
    return
  reader.closed = true
  case reader.kind
  of SourceFile:
    if reader.file != nil and reader.file != stdin:
      close(reader.file)
      reader.file = nil
  of SourceGzip:
    if reader.gzFileHandle != nil:
      discard gzclose(reader.gzFileHandle)
      reader.gzFileHandle = nil
  of SourceStream:
    if reader.customStream != nil:
      reader.customStream.close()
      reader.customStream = nil
  of SourceStdin:
    discard

proc readGzipLine(reader: StreamReader, line: var string): bool =
  line.setLen(0)
  if reader.gzFileHandle == nil:
    return false
  while true:
    if reader.gzBufPos >= reader.gzBufLen:
      if reader.gzBuffer.len != reader.bufferSize:
        reader.gzBuffer.setLen(reader.bufferSize)
      let readBytes = gzread(reader.gzFileHandle, addr reader.gzBuffer[0], cuint(reader.bufferSize))
      if readBytes <= 0:
        reader.atEof = true
        return line.len > 0
      reader.gzBufPos = 0
      reader.gzBufLen = readBytes

    var foundNewline = false
    while reader.gzBufPos < reader.gzBufLen:
      let c = reader.gzBuffer[reader.gzBufPos]
      inc(reader.gzBufPos)
      if c == '\n':
        foundNewline = true
        break
      elif c != '\r':
        line.add(c)

    if foundNewline:
      if line.len > 0 and line[^1] == '\r':
        line.setLen(line.len - 1)
      return true

proc readLine*(reader: StreamReader, line: var string): bool =
  ## Reads the next line from the stream into `line` without newline delimiters.
  ## Reuses `line` buffer for low allocation overhead.
  ## Returns true if a line was read, or false on EOF.
  if reader.closed or reader.stopped:
    return false

  case reader.kind
  of SourceFile:
    if reader.file == nil:
      return false
    if reader.file.readLine(line):
      inc(reader.linesRead)
      reader.bytesRead += line.len + 1
      return true
    else:
      reader.atEof = true
      return false

  of SourceStdin:
    if stdin.readLine(line):
      inc(reader.linesRead)
      reader.bytesRead += line.len + 1
      return true
    else:
      reader.atEof = true
      return false

  of SourceStream:
    if reader.customStream == nil:
      return false
    if reader.customStream.readLine(line):
      inc(reader.linesRead)
      reader.bytesRead += line.len + 1
      return true
    else:
      reader.atEof = true
      return false

  of SourceGzip:
    if readGzipLine(reader, line):
      inc(reader.linesRead)
      reader.bytesRead += line.len + 1
      return true
    else:
      reader.atEof = true
      return false

proc readLine*(reader: StreamReader): Option[string] =
  ## Convenience procedure reading next line as ``Option[string]``.
  var buf = newStringOfCap(512)
  if reader.readLine(buf):
    return some(buf)
  return none(string)

proc readLineFollow*(
  reader: StreamReader,
  line: var string,
  pollIntervalMs: int = 100,
  maxWaitMs: int = -1,
  shouldStop: proc(): bool = nil
): bool =
  ## Reads next line in follow mode (-f/--follow).
  ## When EOF is reached on regular files, continuously polls for file growth,
  ## resets on file truncation, and reopens on file rotation (inode change).
  ## Returns true if a new line was obtained, false if stream terminated or stopped.
  if reader.closed or reader.stopped:
    return false
  if shouldStop != nil and shouldStop():
    reader.stopped = true
    return false

  # First try reading available lines
  if reader.readLine(line):
    return true

  # If not a regular file on disk, EOF is definitive
  if reader.kind != SourceFile or reader.filePath.len == 0:
    return false

  # Regular file: enter polling loop for file growth / rotation
  var elapsedMs = 0
  while not reader.stopped and not reader.closed:
    if shouldStop != nil and shouldStop():
      reader.stopped = true
      return false

    if maxWaitMs >= 0 and elapsedMs >= maxWaitMs:
      return false

    if fileExists(reader.filePath):
      var fi: FileInfo
      var hasFi = false
      try:
        fi = getFileInfo(reader.filePath)
        hasFi = true
      except CatchableError:
        hasFi = false

      if hasFi:
        let curInode = cast[uint64](fi.id.file)
        let curDev = cast[uint64](fi.id.device)
        let curSize = fi.size

        # Check for file rotation (inode or device change)
        if curInode != reader.lastInode or curDev != reader.lastDev:
          if reader.file != nil and reader.file != stdin:
            close(reader.file)
          if open(reader.file, reader.filePath, fmRead):
            reader.lastInode = curInode
            reader.lastDev = curDev
            reader.lastFilePos = 0
            reader.lastFileSize = curSize
            reader.atEof = false
            if reader.readLine(line):
              return true

        # Check for file truncation (size decreased)
        var curPos: int64 = 0
        try:
          curPos = getFilePos(reader.file)
        except CatchableError:
          curPos = 0

        if curSize < curPos:
          try:
            setFilePos(reader.file, 0)
            if reader.file != nil:
              clearErr(reader.file)
            reader.lastFilePos = 0
            reader.lastFileSize = curSize
            reader.atEof = false
            if reader.readLine(line):
              return true
          except CatchableError:
            discard

        # Check for file growth (size increased past current position)
        if curSize > curPos:
          if reader.file != nil:
            clearErr(reader.file)
          reader.atEof = false
          if reader.readLine(line):
            return true

    sleep(pollIntervalMs)
    elapsedMs += pollIntervalMs

  return false

iterator lines*(reader: StreamReader): string =
  ## Iterates over lines in reader up to EOF. Reuses memory buffer internally.
  var line = newStringOfCap(512)
  while reader.readLine(line):
    yield line

iterator linesFollow*(
  reader: StreamReader,
  pollIntervalMs: int = 100,
  maxWaitMs: int = -1,
  shouldStop: proc(): bool = nil
): string =
  ## Iterates over lines continuously, polling as the file grows until stopped.
  var line = newStringOfCap(512)
  while reader.readLineFollow(line, pollIntervalMs, maxWaitMs, shouldStop):
    yield line

iterator entries*(
  reader: StreamReader,
  format: LogFormat = LogFormatAuto,
  onMalformed: proc(line: string) = nil
): HttpLogEntry =
  ## Iterates over parsed HttpLogEntry items from the stream.
  ## Increments reader.parsedEntries on success, or reader.unparsedLines on malformed lines.
  var line = newStringOfCap(512)
  var entry: HttpLogEntry
  while reader.readLine(line):
    if parseLine(line, entry, format):
      inc(reader.parsedEntries)
      yield entry
    else:
      inc(reader.unparsedLines)
      if onMalformed != nil:
        onMalformed(line)

proc streamRawLines*(
  sourcePath: string,
  follow: bool = false,
  onLine: RawLineCallback,
  pollIntervalMs: int = 100,
  shouldStop: proc(): bool = nil
): StreamStats =
  ## Streams raw log lines from a file path or STDIN to `onLine`.
  ## If follow == true, keeps polling for file growth.
  let startTime = getMonoTime()
  let reader = openStreamReader(sourcePath)
  defer: close(reader)

  var line = newStringOfCap(512)
  var count: int64 = 0
  var bytes: int64 = 0

  if follow:
    while reader.readLineFollow(line, pollIntervalMs, -1, shouldStop):
      inc(count)
      bytes += line.len + 1
      if onLine != nil:
        onLine(line)
  else:
    while reader.readLine(line):
      inc(count)
      bytes += line.len + 1
      if onLine != nil:
        onLine(line)

  let elapsed = (getMonoTime() - startTime).inMicroseconds.float / 1_000_000.0
  result = StreamStats(
    linesRead: count,
    bytesRead: bytes,
    parsedEntries: count,
    malformedLines: 0,
    elapsedSeconds: elapsed
  )

proc streamLogLines*(
  sourcePath: string,
  follow: bool = false,
  onEntry: LogLineCallback,
  format: LogFormat = LogFormatAuto,
  pollIntervalMs: int = 100,
  onMalformed: proc(line: string) = nil,
  shouldStop: proc(): bool = nil,
  warnOnMalformed: bool = false,
  diagnosticWriter: proc(msg: string) = nil
): StreamStats =
  ## High-level streaming log line processor ingesting from files, STDIN, or gzip.
  ## Parses each line into HttpLogEntry and invokes onEntry callback.
  ## Gracefully records malformed/unparsed line counts and optionally emits diagnostic warnings to stderr.
  let startTime = getMonoTime()
  let reader = openStreamReader(sourcePath)
  defer: close(reader)

  var line = newStringOfCap(512)
  var entry: HttpLogEntry
  var totalLines: int64 = 0
  var parsedCount: int64 = 0
  var malformedCount: int64 = 0
  var totalBytes: int64 = 0

  let readProc = proc(l: var string): bool =
    if follow:
      reader.readLineFollow(l, pollIntervalMs, -1, shouldStop)
    else:
      reader.readLine(l)

  while readProc(line):
    inc(totalLines)
    totalBytes += line.len + 1
    if parseLine(line, entry, format):
      inc(parsedCount)
      if onEntry != nil:
        onEntry(entry)
    else:
      inc(malformedCount)
      if onMalformed != nil:
        onMalformed(line)
      if warnOnMalformed:
        let msg = "[WARN] Line " & $totalLines & ": malformed or unparseable log entry: " & line.strip()
        if diagnosticWriter != nil:
          diagnosticWriter(msg)
        else:
          stderr.writeLine(msg)

  let elapsed = (getMonoTime() - startTime).inMicroseconds.float / 1_000_000.0
  result = StreamStats(
    linesRead: totalLines,
    bytesRead: totalBytes,
    parsedEntries: parsedCount,
    malformedLines: malformedCount,
    elapsedSeconds: elapsed
  )

proc benchmarkParsingThroughput*(linesCount: int = 100_000): float =
  ## Benchmarks parsing throughput on standard Combined log lines.
  ## Returns throughput in lines per second.
  const sample = "192.168.1.100 - - [10/Oct/2026:13:55:36 +0200] \"GET /index.html HTTP/1.1\" 200 2326 \"https://example.com\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\""
  var entry: HttpLogEntry
  let t0 = getMonoTime()
  for i in 0 ..< linesCount:
    discard parseCombinedLine(sample, entry)
  let elapsed = (getMonoTime() - t0).inMicroseconds.float / 1_000_000.0
  if elapsed > 0.0:
    return float(linesCount) / elapsed
  return 0.0

func parseHello*(input: string): PipelineMessage =
  ## Parses input into a pipeline message; raises ParseError if empty.
  ensureParse(input.len > 0, "Input cannot be empty")
  initPipelineMessage(input, "parser")


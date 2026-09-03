## Unit test suite for log formats and tokenizers (Phase 02 / Category A).

import std/[unittest, times, options, os, strutils]
import http_logviewer/core/types
import http_logviewer/parser/formats

suite "Log Parsing - W3C Common Log Format (CLF) (Phase 02 / Category A / Item 01)":

  test "Item 01: Clean IP address helper handles ports, brackets, and plain IPs":
    check cleanIpAddress("192.168.1.1:8080") == "192.168.1.1"
    check cleanIpAddress("10.0.0.1:443") == "10.0.0.1"
    check cleanIpAddress("[2001:db8::1]:8080") == "2001:db8::1"
    check cleanIpAddress("[2001:db8::1]") == "2001:db8::1"
    check cleanIpAddress("2001:db8::1") == "2001:db8::1"
    check cleanIpAddress("127.0.0.1") == "127.0.0.1"
    check cleanIpAddress("  192.168.0.5  ") == "192.168.0.5"
    check cleanIpAddress("") == ""

  test "Item 01: parseLogDateTime parses standard and fallback date formats":
    let dt1 = parseLogDateTime("10/Oct/2026:13:55:36 +0200")
    check dt1.year == 2026
    check dt1.month == mOct
    check dt1.monthday == 10
    check dt1.hour == 13
    check dt1.minute == 55
    check dt1.second == 36

    # With brackets
    let dt2 = parseLogDateTime("[10/Oct/2026:13:55:36 +0200]")
    check dt2.year == 2026
    check dt2.month == mOct

    # Without timezone
    let dt3 = parseLogDateTime("10/Oct/2026:13:55:36")
    check dt3.year == 2026
    check dt3.month == mOct

    # Invalid timestamp returns fallback now() without raising
    let dtInv = parseLogDateTime("not-a-timestamp")
    check dtInv.isInitialized

  test "Item 01: parseRequestLine extracts method, path, and protocol":
    var m: HttpMethod
    var p, proto: string
    parseRequestLine("GET /index.html HTTP/1.1", m, p, proto)
    check m == HttpGet
    check p == "/index.html"
    check proto == "HTTP/1.1"

    parseRequestLine("POST /api/v1/login HTTP/2.0", m, p, proto)
    check m == HttpPost
    check p == "/api/v1/login"
    check proto == "HTTP/2.0"

    # Malformed / short request lines
    parseRequestLine("GET /health", m, p, proto)
    check m == HttpGet
    check p == "/health"
    check proto == ""

    parseRequestLine("OPTIONS", m, p, proto)
    check m == HttpOptions
    check p == ""
    check proto == ""

  test "Item 01: parseStatusCode parses valid and invalid codes":
    var code: int
    check parseStatusCode("200", code) and code == 200
    check parseStatusCode("404", code) and code == 404
    check parseStatusCode("500", code) and code == 500
    check parseStatusCode(" 301 ", code) and code == 301
    check not parseStatusCode("99", code)
    check not parseStatusCode("600", code)
    check not parseStatusCode("abc", code)
    check parseStatusCode("200") == 200
    check parseStatusCode("invalid") == 0

  test "Item 01: parseClfLine parses standard CLF log line":
    let line = "127.0.0.1 - frank [10/Oct/2026:13:55:36 -0700] \"POST /api/login HTTP/1.0\" 401 512"
    var entry: HttpLogEntry
    check parseClfLine(line, entry)
    check entry.clientIp == "127.0.0.1"
    check entry.timestamp.year == 2026
    check entry.timestamp.month == mOct
    check entry.timestamp.monthday == 10
    check entry.`method` == HttpPost
    check entry.path == "/api/login"
    check entry.statusCode == 401
    check entry.bytesSent == 512
    check entry.referer == ""
    check entry.userAgent == ""
    check entry.rawLine == line

  test "Item 01: parseClfLine handles '-' bytes and IP with port":
    let line = "192.168.1.50:44321 - - [10/Oct/2026:14:00:00 +0000] \"GET /robots.txt HTTP/1.1\" 404 -"
    let opt = parseClfLine(line)
    check opt.isSome
    let entry = opt.get
    check entry.clientIp == "192.168.1.50"
    check entry.`method` == HttpGet
    check entry.path == "/robots.txt"
    check entry.statusCode == 404
    check entry.bytesSent == 0

  test "Item 01: parseClfLine returns false for malformed and empty lines":
    var entry: HttpLogEntry
    check not parseClfLine("", entry)
    check not parseClfLine("random garbage line without formatting", entry)
    check not parseClfLine("127.0.0.1 - - unbracketed-time \"GET /\" 200 123", entry)
    check not parseClfLine("127.0.0.1 - - [10/Oct/2026:13:55:36 +0000] unquoted 200 123", entry)

suite "Log Parsing - Nginx & Apache Combined Log Format (Phase 02 / Category A / Item 02)":

  test "Item 02: parseCombinedLine parses standard Nginx/Apache combined line":
    let line = "192.168.1.100 - - [10/Oct/2026:13:55:36 +0200] \"GET /index.html HTTP/1.1\" 200 2326 \"https://example.com\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\""
    var entry: HttpLogEntry
    check parseCombinedLine(line, entry)
    check entry.clientIp == "192.168.1.100"
    check entry.timestamp.year == 2026
    check entry.timestamp.month == mOct
    check entry.timestamp.monthday == 10
    check entry.timestamp.hour == 13
    check entry.timestamp.minute == 55
    check entry.timestamp.second == 36
    check entry.`method` == HttpGet
    check entry.path == "/index.html"
    check entry.statusCode == 200
    check entry.bytesSent == 2326
    check entry.referer == "https://example.com"
    check entry.userAgent == "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    check entry.rawLine == line

  test "Item 02: parseCombinedLine handles '-' for referer and user agent":
    let line = "10.0.0.5 - admin [15/Dec/2026:08:12:00 +0000] \"POST /api/v1/data HTTP/1.1\" 201 128 \"-\" \"-\""
    let opt = parseCombinedLine(line)
    check opt.isSome
    let entry = opt.get
    check entry.clientIp == "10.0.0.5"
    check entry.`method` == HttpPost
    check entry.path == "/api/v1/data"
    check entry.statusCode == 201
    check entry.bytesSent == 128
    check entry.referer == ""
    check entry.userAgent == ""

  test "Item 02: parseCombinedLine handles escaped quotes inside User-Agent or Request":
    let line = "198.51.100.2 - - [20/Jan/2026:22:15:30 +0100] \"GET /search?q=\\\"test\\\" HTTP/1.1\" 200 4096 \"-\" \"Mozilla/5.0 \\\"CustomBot\\\"/1.0\""
    var entry: HttpLogEntry
    check parseCombinedLine(line, entry)
    check entry.clientIp == "198.51.100.2"
    check entry.path == "/search?q=\"test\""
    check entry.userAgent == "Mozilla/5.0 \"CustomBot\"/1.0"

  test "Item 02: parseNginxLine parses extended Nginx line with trailing upstream fields":
    let line = "203.0.113.19 - - [10/Feb/2026:11:00:00 +0000] \"GET /api/status HTTP/1.1\" 200 64 \"https://dashboard.example.com\" \"curl/7.88.1\" 0.012 0.010"
    var entry: HttpLogEntry
    check parseNginxLine(line, entry)
    check entry.clientIp == "203.0.113.19"
    check entry.statusCode == 200
    check entry.bytesSent == 64
    check entry.referer == "https://dashboard.example.com"
    check entry.userAgent == "curl/7.88.1"

  test "Item 02: parseCombinedLine returns false on malformed lines":
    var entry: HttpLogEntry
    check not parseCombinedLine("", entry)
    check not parseCombinedLine("just text without structure", entry)
    check not parseCombinedLine("127.0.0.1 - - [bad-date] \"GET / HTTP/1.1\" 200 0", entry)
    check not parseCombinedLine("127.0.0.1 - - [10/Oct/2026:13:55:36 +0200] \"GET / HTTP/1.1\" notanumber 0 \"-\" \"-\"", entry)

suite "Log Parsing - Format Auto-Detection Heuristics (Phase 02 / Category A / Item 03)":

  test "Item 03: detectLogFormatLine detects JSON, Combined, and CLF lines":
    let jsonLine = "{\"client_ip\": \"1.2.3.4\", \"status\": 200}"
    check detectLogFormatLine(jsonLine) == LogFormatJson

    let combinedLine = "127.0.0.1 - - [10/Oct/2026:13:55:36 +0200] \"GET / HTTP/1.1\" 200 123 \"https://example.com\" \"curl/7.88.1\""
    check detectLogFormatLine(combinedLine) == LogFormatCombined

    let clfLine = "127.0.0.1 - - [10/Oct/2026:13:55:36 +0200] \"GET / HTTP/1.1\" 200 123"
    check detectLogFormatLine(clfLine) == LogFormatClf

  test "Item 03: detectLogFormat analyzes first 5 lines of sample input":
    let clfSamples = [
      "127.0.0.1 - - [10/Oct/2026:13:55:36 +0200] \"GET /a HTTP/1.1\" 200 10",
      "127.0.0.1 - - [10/Oct/2026:13:55:37 +0200] \"GET /b HTTP/1.1\" 200 10",
      "127.0.0.1 - - [10/Oct/2026:13:55:38 +0200] \"GET /c HTTP/1.1\" 200 10"
    ]
    check detectLogFormat(clfSamples) == LogFormatClf

    let combinedSamples = [
      "192.168.1.1 - - [10/Oct/2026:13:55:36 +0200] \"GET /a HTTP/1.1\" 200 10 \"-\" \"Mozilla/5.0\"",
      "192.168.1.2 - - [10/Oct/2026:13:55:37 +0200] \"GET /b HTTP/1.1\" 200 10 \"-\" \"curl/7.88\"",
      "192.168.1.3 - - [10/Oct/2026:13:55:38 +0200] \"GET /c HTTP/1.1\" 200 10 \"-\" \"Wget/1.2\""
    ]
    check detectLogFormat(combinedSamples) == LogFormatCombined

    let jsonSamples = [
      "{\"ip\": \"10.0.0.1\", \"uri\": \"/api\"}",
      "{\"ip\": \"10.0.0.2\", \"uri\": \"/login\"}"
    ]
    check detectLogFormat(jsonSamples) == LogFormatJson

  test "Item 03: detectLogFormat handles multi-line string input and ignores empty lines":
    let multiLineText = """

      192.168.1.1 - - [10/Oct/2026:13:55:36 +0200] "GET /a HTTP/1.1" 200 10 "-" "Mozilla/5.0"

      192.168.1.2 - - [10/Oct/2026:13:55:37 +0200] "GET /b HTTP/1.1" 200 10 "-" "curl/7.88"
    """
    check detectLogFormat(multiLineText) == LogFormatCombined

suite "Log Parsing - Structured JSON Log Formats (Phase 02 / Category A / Item 04)":

  test "Item 04: parseJsonLine parses standard Nginx flat JSON schema":
    let jsonLine = """{"client_ip": "1.2.3.4", "timestamp": "2026-10-10T13:55:36Z", "method": "GET", "uri": "/api/v1", "status": 200, "bytes": 1024, "referer": "-", "user_agent": "curl/7.68.0"}"""
    var entry: HttpLogEntry
    check parseJsonLine(jsonLine, entry)
    check entry.clientIp == "1.2.3.4"
    check entry.`method` == HttpGet
    check entry.path == "/api/v1"
    check entry.statusCode == 200
    check entry.bytesSent == 1024
    check entry.referer == ""
    check entry.userAgent == "curl/7.68.0"

  test "Item 04: parseJsonLine parses Caddy nested schema with unix timestamp and header arrays":
    let caddyLine = """{"ts": 1791640536.0, "request": {"remote_ip": "192.168.10.5:54321", "method": "POST", "uri": "/graphql", "headers": {"User-Agent": ["Apollo/2.0"], "Referer": ["https://frontend.internal"]}}, "status": 201, "size": 4096}"""
    var entry: HttpLogEntry
    check parseJsonLine(caddyLine, entry)
    check entry.clientIp == "192.168.10.5"
    check entry.`method` == HttpPost
    check entry.path == "/graphql"
    check entry.statusCode == 201
    check entry.bytesSent == 4096
    check entry.referer == "https://frontend.internal"
    check entry.userAgent == "Apollo/2.0"

  test "Item 04: parseJsonLine parses full request string fallback and string numbers":
    let jsonLine = """{"remote_addr": "203.0.113.88", "request": "DELETE /resource/42 HTTP/1.1", "status": "204", "bytes": "0"}"""
    var entry: HttpLogEntry
    check parseJsonLine(jsonLine, entry)
    check entry.clientIp == "203.0.113.88"
    check entry.`method` == HttpDelete
    check entry.path == "/resource/42"
    check entry.statusCode == 204
    check entry.bytesSent == 0

  test "Item 04: parseLine unifies parsing across CLF, Combined, and JSON":
    let jsonLine = """{"client_ip": "10.0.0.9", "uri": "/test", "status": 200}"""
    var entry: HttpLogEntry
    check parseLine(jsonLine, entry, LogFormatJson)
    check entry.clientIp == "10.0.0.9"

    var autoEntry: HttpLogEntry
    check parseLine(jsonLine, autoEntry, LogFormatAuto)
    check autoEntry.clientIp == "10.0.0.9"
    check autoEntry.path == "/test"

  test "Item 04: parseJsonLine returns false for invalid JSON":
    var entry: HttpLogEntry
    check not parseJsonLine("", entry)
    check not parseJsonLine("not json", entry)
    check not parseJsonLine("{unquoted_key: 123}", entry)
    check not parseJsonLine("[\"array\", \"not\", \"object\"]", entry)

suite "Log Parsing - HTTP Method and Status Code Token Parsers (Phase 02 / Category A / Item 05)":

  test "Item 05: parseHttpMethodToken parses standard, custom, and quoted verbs":
    check parseHttpMethodToken("GET") == HttpGet
    check parseHttpMethodToken("post") == HttpPost
    check parseHttpMethodToken("  PUT  ") == HttpPut
    check parseHttpMethodToken("\"DELETE\"") == HttpDelete
    check parseHttpMethodToken("HEAD") == HttpHead
    check parseHttpMethodToken("options") == HttpOptions
    check parseHttpMethodToken("Patch") == HttpPatch
    check parseHttpMethodToken("CONNECT") == HttpConnect
    check parseHttpMethodToken("TRACE") == HttpTrace
    check parseHttpMethodToken("PROPFIND") == HttpOther
    check parseHttpMethodToken("REPORT") == HttpOther
    check parseHttpMethodToken("") == HttpUnknown

  test "Item 05: parseStatusCode parses numbers, handles quotes and out of range values":
    var code: int
    check parseStatusCode("200", code) and code == 200
    check parseStatusCode("\"404\"", code) and code == 404
    check parseStatusCode(" '502' ", code) and code == 502
    check not parseStatusCode("99", code)
    check not parseStatusCode("600", code)
    check not parseStatusCode("0", code)
    check not parseStatusCode("", code)

  test "Item 05: statusClass and categorization predicates":
    check statusClass(101) == StatusInformational
    check statusClass(200) == StatusSuccess
    check statusClass(301) == StatusRedirection
    check statusClass(404) == StatusClientError
    check statusClass(500) == StatusServerError
    check statusClass(700) == StatusInvalid

    check isSuccess(200) and isSuccess(204)
    check not isSuccess(404)
    check isRedirect(301) and isRedirect(302)
    check isClientError(400) and isClientError(404)
    check isServerError(500) and isServerError(503)
    check isNotFound(404)
    check not isNotFound(403)
    check isForbidden(401) and isForbidden(403)

  test "Item 05: statusDescription returns canonical phrases":
    check statusDescription(200) == "OK"
    check statusDescription(404) == "Not Found"
    check statusDescription(403) == "Forbidden"
    check statusDescription(500) == "Internal Server Error"
    check statusDescription(502) == "Bad Gateway"
    check statusDescription(418) == "I'm a teapot"

suite "Log Parsing - Real-World Nginx and Apache Logs (Phase 02 / Category A / Item 06)":

  test "Item 06: Parse all entries from real-world Nginx Combined log fixture":
    let fixturePath = currentSourcePath.parentDir() / "fixtures" / "combined.log"
    check fileExists(fixturePath)
    let content = readFile(fixturePath)
    var count = 0
    for line in content.splitLines():
      if line.strip().len == 0: continue
      var entry: HttpLogEntry
      check parseCombinedLine(line, entry)
      check entry.clientIp.len > 0
      check entry.timestamp.year == 2026
      check entry.statusCode in [200, 301, 304, 404, 500]
      check entry.`method` in [HttpGet, HttpPost]
      inc(count)
    check count == 6

  test "Item 06: Verify specific record fields in combined.log fixture":
    let fixturePath = currentSourcePath.parentDir() / "fixtures" / "combined.log"
    let lines = readFile(fixturePath).strip().splitLines()

    # Line 0: Nginx HTTP/2 GET with Chrome UA
    var e0: HttpLogEntry
    check parseCombinedLine(lines[0], e0)
    check e0.clientIp == "93.184.216.34"
    check e0.path == "/assets/style.css"
    check e0.statusCode == 200
    check e0.bytesSent == 15420
    check e0.referer == "https://example.org/home"
    check e0.userAgent.contains("Chrome/120.0.0.0")

    # Line 4: 404 Not Found with Googlebot
    var e4: HttpLogEntry
    check parseCombinedLine(lines[4], e4)
    check e4.clientIp == "198.51.100.99"
    check e4.path == "/nonexistent-page"
    check e4.statusCode == 404
    check e4.userAgent.contains("Googlebot")

    # Line 5: IPv6 client address with 500 Internal Server Error
    var e5: HttpLogEntry
    check parseCombinedLine(lines[5], e5)
    check e5.clientIp == "2001:db8:85a3::8a2e:370:7334"
    check e5.statusCode == 500
    check e5.`method` == HttpPost
    check e5.path == "/api/checkout"

  test "Item 06: Parse all entries from real-world Apache CLF fixture":
    let fixturePath = currentSourcePath.parentDir() / "fixtures" / "clf.log"
    check fileExists(fixturePath)
    let content = readFile(fixturePath)
    var count = 0
    for line in content.splitLines():
      if line.strip().len == 0: continue
      var entry: HttpLogEntry
      check parseClfLine(line, entry)
      check entry.clientIp.len > 0
      check entry.referer == ""
      check entry.userAgent == ""
      inc(count)
    check count == 3

  test "Item 06: Compare parseLine with auto-detection against explicit parsers":
    let fixturePath = currentSourcePath.parentDir() / "fixtures" / "combined.log"
    let lines = readFile(fixturePath).strip().splitLines()
    for line in lines:
      var entryExplicit, entryAuto: HttpLogEntry
      check parseCombinedLine(line, entryExplicit)
      check parseLine(line, entryAuto, LogFormatAuto)
      check entryAuto.clientIp == entryExplicit.clientIp
      check entryAuto.`method` == entryExplicit.`method`
      check entryAuto.path == entryExplicit.path
      check entryAuto.statusCode == entryExplicit.statusCode
      check entryAuto.bytesSent == entryExplicit.bytesSent
      check entryAuto.referer == entryExplicit.referer
      check entryAuto.userAgent == entryExplicit.userAgent





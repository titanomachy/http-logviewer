import std/unittest
import std/times
import std/strutils
import std/json
import std/sets
import std/tables
import std/hashes
import http_logviewer/core/[types, errors]

suite "Core Types - HttpMethod (Phase 01 / Category A)":
  test "Item 01: HttpMethod enum definition and parsing":
    check parseHttpMethod("GET") == HttpGet
    check parseHttpMethod("get") == HttpGet
    check parseHttpMethod("POST") == HttpPost
    check parseHttpMethod("post") == HttpPost
    check parseHttpMethod("PUT") == HttpPut
    check parseHttpMethod("DELETE") == HttpDelete
    check parseHttpMethod("HEAD") == HttpHead
    check parseHttpMethod("OPTIONS") == HttpOptions
    check parseHttpMethod("PATCH") == HttpPatch
    check parseHttpMethod("CONNECT") == HttpConnect
    check parseHttpMethod("TRACE") == HttpTrace
    check parseHttpMethod("") == HttpUnknown
    check parseHttpMethod("PROPFIND") == HttpOther
    check parseHttpMethod("CUSTOM_VERB") == HttpOther

  test "Item 01: HttpMethod stringification":
    check $HttpGet == "GET"
    check $HttpPost == "POST"
    check $HttpPut == "PUT"
    check $HttpDelete == "DELETE"
    check $HttpHead == "HEAD"
    check $HttpOptions == "OPTIONS"
    check $HttpPatch == "PATCH"
    check $HttpConnect == "CONNECT"
    check $HttpTrace == "TRACE"
    check $HttpOther == "OTHER"
    check $HttpUnknown == "UNKNOWN"

suite "Core Types - HttpLogEntry (Phase 01 / Category A)":
  test "Item 02: HttpLogEntry definition and construction":
    let dt = dateTime(2026, mSep, 4, 1, 0, 0, 0, utc())
    let entry = initHttpLogEntry(
      clientIp = "192.168.1.100",
      timestamp = dt,
      `method` = HttpGet,
      path = "/index.html",
      statusCode = 200,
      bytesSent = 1024,
      referer = "https://google.com",
      userAgent = "Mozilla/5.0",
      rawLine = "192.168.1.100 - - [04/Sep/2026:01:00:00 +0000] \"GET /index.html HTTP/1.1\" 200 1024 \"https://google.com\" \"Mozilla/5.0\""
    )

    check entry.clientIp == "192.168.1.100"
    check entry.timestamp == dt
    check entry.`method` == HttpGet
    check entry.httpMethod == HttpGet
    check entry.path == "/index.html"
    check entry.statusCode == 200
    check entry.bytesSent == 1024
    check entry.referer == "https://google.com"
    check entry.userAgent == "Mozilla/5.0"
    check entry.rawLine.len > 0

  test "Item 02: HttpLogEntry default construction":
    let defaultEntry = initHttpLogEntry()
    check defaultEntry.clientIp == ""
    check defaultEntry.`method` == HttpUnknown
    check defaultEntry.httpMethod == HttpUnknown
    check defaultEntry.path == ""
    check defaultEntry.statusCode == 0
    check defaultEntry.bytesSent == 0
    check defaultEntry.referer == ""
    check defaultEntry.userAgent == ""
    check defaultEntry.rawLine == ""

  test "Item 03: HttpLogEntry stringifier and pretty-printer":
    let dt = dateTime(2026, mSep, 4, 1, 0, 0, 0, utc())
    let entry = initHttpLogEntry(
      clientIp = "192.168.1.100",
      timestamp = dt,
      `method` = HttpGet,
      path = "/index.html",
      statusCode = 200,
      bytesSent = 1024,
      referer = "https://google.com",
      userAgent = "Mozilla/5.0",
      rawLine = "raw_sample_line"
    )

    let strRep = $entry
    check "192.168.1.100" in strRep
    check "GET" in strRep
    check "/index.html" in strRep
    check "200" in strRep
    check "1024" in strRep
    check "https://google.com" in strRep
    check "Mozilla/5.0" in strRep

    let prettyRep = entry.pretty()
    check "HttpLogEntry:" in prettyRep
    check "Client IP:   192.168.1.100" in prettyRep
    check "Method:      GET" in prettyRep
    check "Path:        /index.html" in prettyRep
    check "Status Code: 200" in prettyRep
    check "Bytes Sent:  1024" in prettyRep

  test "Item 03: HttpLogEntry stringifier with empty fields":
    let defaultEntry = initHttpLogEntry()
    let strRep = $defaultEntry
    check "[-]" in strRep
    check "UNKNOWN" in strRep
    check "\"-\"" in strRep

    let prettyRep = defaultEntry.pretty()
    check "Client IP:   -" in prettyRep
    check "Referer:     -" in prettyRep

suite "Core Types - JSON Serialization (Phase 01 / Category A)":
  test "Item 04: HttpLogEntry to JSON and round-trip parsing":
    let dt = dateTime(2026, mSep, 4, 1, 0, 0, 0, utc())
    let entry = initHttpLogEntry(
      clientIp = "10.0.0.1",
      timestamp = dt,
      `method` = HttpPost,
      path = "/api/v1/data",
      statusCode = 201,
      bytesSent = 512,
      referer = "https://example.com/form",
      userAgent = "Curl/7.68.0",
      rawLine = "10.0.0.1 - - [04/Sep/2026:01:00:00 +0000] \"POST /api/v1/data HTTP/1.1\" 201 512"
    )

    let jsonNode = %*entry
    check jsonNode["clientIp"].getStr() == "10.0.0.1"
    check jsonNode["method"].getStr() == "POST"
    check jsonNode["path"].getStr() == "/api/v1/data"
    check jsonNode["statusCode"].getInt() == 201
    check jsonNode["bytesSent"].getBiggestInt() == 512
    check jsonNode["referer"].getStr() == "https://example.com/form"
    check jsonNode["userAgent"].getStr() == "Curl/7.68.0"
    check jsonNode["rawLine"].getStr().len > 0

    # Test round-trip
    let restored = parseHttpLogEntryJson(jsonNode)
    check restored.clientIp == entry.clientIp
    check restored.timestamp == entry.timestamp
    check restored.`method` == entry.`method`
    check restored.path == entry.path
    check restored.statusCode == entry.statusCode
    check restored.bytesSent == entry.bytesSent
    check restored.referer == entry.referer
    check restored.userAgent == entry.userAgent
    check restored.rawLine == entry.rawLine

  test "Item 04: JSON deserialization with missing/empty fields":
    let emptyObj = newJObject()
    let entry = parseHttpLogEntryJson(emptyObj)
    check entry.clientIp == ""
    check entry.`method` == HttpUnknown
    check entry.path == ""
    check entry.statusCode == 0
    check entry.bytesSent == 0
    check entry.referer == ""
    check entry.userAgent == ""

suite "Core Types - Equality & Hashing (Phase 01 / Category A)":
  test "Item 05: Equality reflexivity and equivalence":
    let dt = dateTime(2026, mSep, 4, 1, 0, 0, 0, utc())
    let e1 = initHttpLogEntry("1.2.3.4", dt, HttpGet, "/a", 200, 100, "ref", "ua", "raw")
    let e2 = initHttpLogEntry("1.2.3.4", dt, HttpGet, "/a", 200, 100, "ref", "ua", "raw")
    let eDiffIp = initHttpLogEntry("1.2.3.5", dt, HttpGet, "/a", 200, 100, "ref", "ua", "raw")
    let eDiffMethod = initHttpLogEntry("1.2.3.4", dt, HttpPost, "/a", 200, 100, "ref", "ua", "raw")
    let eDiffPath = initHttpLogEntry("1.2.3.4", dt, HttpGet, "/b", 200, 100, "ref", "ua", "raw")
    let eDiffStatus = initHttpLogEntry("1.2.3.4", dt, HttpGet, "/a", 404, 100, "ref", "ua", "raw")
    let eDiffBytes = initHttpLogEntry("1.2.3.4", dt, HttpGet, "/a", 200, 200, "ref", "ua", "raw")
    let eDiffRef = initHttpLogEntry("1.2.3.4", dt, HttpGet, "/a", 200, 100, "other-ref", "ua", "raw")
    let eDiffUa = initHttpLogEntry("1.2.3.4", dt, HttpGet, "/a", 200, 100, "ref", "other-ua", "raw")
    let eDiffRaw = initHttpLogEntry("1.2.3.4", dt, HttpGet, "/a", 200, 100, "ref", "ua", "other-raw")

    check e1 == e1
    check e1 == e2
    check hash(e1) == hash(e2)

    check e1 != eDiffIp
    check e1 != eDiffMethod
    check e1 != eDiffPath
    check e1 != eDiffStatus
    check e1 != eDiffBytes
    check e1 != eDiffRef
    check e1 != eDiffUa
    check e1 != eDiffRaw

  test "Item 05: HashSet and Table interoperability":
    let dt = dateTime(2026, mSep, 4, 1, 0, 0, 0, utc())
    let e1 = initHttpLogEntry("10.0.0.1", dt, HttpGet, "/test", 200, 100)
    let e2 = initHttpLogEntry("10.0.0.1", dt, HttpGet, "/test", 200, 100)
    let e3 = initHttpLogEntry("10.0.0.2", dt, HttpPost, "/login", 401, 50)

    var logSet = initHashSet[HttpLogEntry]()
    logSet.incl(e1)
    logSet.incl(e2)
    check logSet.len == 1
    logSet.incl(e3)
    check logSet.len == 2
    check e1 in logSet
    check e3 in logSet

    var logTable = initTable[HttpLogEntry, string]()
    logTable[e1] = "first"
    logTable[e2] = "updated"
    check logTable.len == 1
    check logTable[e1] == "updated"
    logTable[e3] = "third"
    check logTable.len == 2
    check logTable[e3] == "third"

suite "Core Types - Validations & Edge Cases (Phase 01 / Category A)":
  test "Item 06: Validation logic on valid and invalid entries":
    let validEntry = initHttpLogEntry(
      clientIp = "1.2.3.4",
      statusCode = 200,
      `method` = HttpGet
    )
    check validEntry.isValid()
    validEntry.validate() # Should not raise

    let emptyIpEntry = initHttpLogEntry(
      clientIp = "",
      statusCode = 200,
      `method` = HttpGet
    )
    check not emptyIpEntry.isValid()
    expect ParseError:
      emptyIpEntry.validate()

    let invalidStatusLow = initHttpLogEntry(
      clientIp = "1.2.3.4",
      statusCode = 99,
      `method` = HttpGet
    )
    check not invalidStatusLow.isValid()
    expect ParseError:
      invalidStatusLow.validate()

    let invalidStatusHigh = initHttpLogEntry(
      clientIp = "1.2.3.4",
      statusCode = 600,
      `method` = HttpGet
    )
    check not invalidStatusHigh.isValid()
    expect ParseError:
      invalidStatusHigh.validate()

  test "Item 06: Edge cases - IPv6 addresses":
    let ipv6List = @[
      "::1",
      "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
      "fe80::1ff:fe23:4567:890a",
      "::ffff:192.0.2.128"
    ]
    for ip in ipv6List:
      let entry = initHttpLogEntry(clientIp = ip, statusCode = 200)
      check entry.isValid()
      check entry.clientIp == ip
      check ip in $entry

  test "Item 06: Edge cases - Large byte transfer counts (64-bit)":
    let hugeBytes = 53_687_091_200'i64 # 50 GiB
    let entry = initHttpLogEntry(
      clientIp = "10.0.0.1",
      statusCode = 200,
      bytesSent = hugeBytes
    )
    check entry.bytesSent == hugeBytes
    check $hugeBytes in $entry
    let jsonNode = %*entry
    check jsonNode["bytesSent"].getBiggestInt() == hugeBytes
    let restored = parseHttpLogEntryJson(jsonNode)
    check restored.bytesSent == hugeBytes

  test "Item 06: Edge cases - Unusual paths and escaped characters":
    let paths = @[
      "/",
      "/path/to/resource?param=1&filter=true#anchor",
      "/api/v1/search?q=test%20query%26more",
      "/../../../etc/passwd",
      "/wp-admin/admin-ajax.php?action=exploit' OR '1'='1"
    ]
    for p in paths:
      let entry = initHttpLogEntry(
        clientIp = "127.0.0.1",
        statusCode = 404,
        path = p
      )
      check entry.path == p
      check p in entry.pretty()

  test "Item 06: Edge cases - Complex User-Agent and Referer":
    let complexUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 \"with quotes\" \\slashes"
    let complexRef = "https://example.com/search?q=\"quoted terms\"&lang=en"
    let entry = initHttpLogEntry(
      clientIp = "192.168.1.1",
      statusCode = 200,
      referer = complexRef,
      userAgent = complexUa
    )
    check entry.userAgent == complexUa
    check entry.referer == complexRef
    let j = %*entry
    let restored = parseHttpLogEntryJson(j)
    check restored.userAgent == complexUa
    check restored.referer == complexRef

## Test suite for Phase 07 / Category A: CLI Options & Argument Parser.

import unittest
import std/[strutils, options, os, osproc]
import http_logviewer
import http_logviewer/core/[types, errors, config]
import http_logviewer/cli/args

suite "CLI Options & Argument Parser - Options Parsing (Phase 07 / Category A / Item 01)":
  test "Item 01: All specified CLI options parse correctly into ViewerConfig":
    let args = [
      "/var/log/nginx/access.log",
      "-f",
      "--filter=hacker",
      "--min-score=50",
      "--group-actors",
      "--status=404,500",
      "--geoip-db=/var/data/GeoLite2-Country.mmdb",
      "--no-color",
      "--json"
    ]
    let cfg = parseCommandLine(args)
    check cfg.logFilePath == "/var/log/nginx/access.log"
    check cfg.follow == true
    check cfg.filterCategory == some(CategoryBadActorHacker)
    check cfg.minThreatScore == 50
    check cfg.enableGrouping == true
    check cfg.statusCodeFilter == @[404, 500]
    check cfg.geoDbPath == some("/var/data/GeoLite2-Country.mmdb")
    check cfg.colorOutput == false
    check cfg.colorMode == ColorModeNever
    check cfg.outputFormat == FormatJson
    check cfg.isValid()

  test "Item 01: Positional logfile argument defaults to stdin '-' when omitted":
    let cfg = parseCommandLine(["--no-color"])
    check cfg.logFilePath == "-"

  test "Item 01: Explicit '-' positional logfile represents stdin":
    let cfg = parseCommandLine(["-", "--filter=all"])
    check cfg.logFilePath == "-"
    check cfg.filterCategory.isNone

  test "Item 01: Follow flag works with both short (-f) and long (--follow) forms":
    let cfgShort = parseCommandLine(["access.log", "-f"])
    check cfgShort.follow == true

    let cfgLong = parseCommandLine(["access.log", "--follow"])
    check cfgLong.follow == true

  test "Item 01: Visitor category filtering maps all supported categories":
    check parseCommandLine(["--filter=real"]).filterCategory == some(CategoryRealUser)
    check parseCommandLine(["--filter=bot"]).filterCategory == some(CategoryVerifiedBot)
    check parseCommandLine(["--filter=scraper"]).filterCategory == some(CategoryCommercialBot)
    check parseCommandLine(["--filter=hacker"]).filterCategory == some(CategoryBadActorHacker)
    check parseCommandLine(["--filter=all"]).filterCategory.isNone

  test "Item 01: Min-score threshold parsing and bounds validation":
    check parseCommandLine(["--min-score=0"]).minThreatScore == 0
    check parseCommandLine(["--min-score=75"]).minThreatScore == 75
    check parseCommandLine(["--min-score=100"]).minThreatScore == 100

    expect ConfigError:
      discard parseCommandLine(["--min-score=-1"])

    expect ConfigError:
      discard parseCommandLine(["--min-score=101"])

    expect ConfigError:
      discard parseCommandLine(["--min-score=invalid"])

  test "Item 01: Group actors flag enables multi-IP correlation":
    let cfgDefault = parseCommandLine([])
    check cfgDefault.enableGrouping == false

    let cfgGroup = parseCommandLine(["--group-actors"])
    check cfgGroup.enableGrouping == true

    let cfgGroupShort = parseCommandLine(["-g"])
    check cfgGroupShort.enableGrouping == true

  test "Item 01: Status codes filtering with comma-separated and single values":
    let cfgMulti = parseCommandLine(["--status=404,500,502"])
    check cfgMulti.statusCodeFilter == @[404, 500, 502]

    let cfgSingle = parseCommandLine(["--status=403"])
    check cfgSingle.statusCodeFilter == @[403]

    expect ConfigError:
      discard parseCommandLine(["--status=99"])

    expect ConfigError:
      discard parseCommandLine(["--status=not_a_number"])

  test "Item 01: Custom GeoIP database path":
    let cfg = parseCommandLine(["--geoip-db=/custom/path/to/geo.mmdb"])
    check cfg.geoDbPath == some("/custom/path/to/geo.mmdb")

  test "Item 01: No-color flag disables ANSI styling":
    let cfg = parseCommandLine(["--no-color"])
    check cfg.colorOutput == false
    check cfg.colorMode == ColorModeNever

  test "Item 01: JSON flag switches output format to NDJSON":
    let cfg = parseCommandLine(["--json"])
    check cfg.outputFormat == FormatJson

suite "CLI Options & Argument Parser - Help & Version Documentation (Phase 07 / Category A / Item 02)":
  test "Item 02: helpText produces informative manual with usage, options, examples, and exit codes":
    let h = helpText()
    check "Usage:" in h
    check "LOGFILE" in h
    check "-f, --follow" in h
    check "--filter=<category>" in h
    check "-m, --min-score=<0-100>" in h
    check "-g, --group-actors" in h
    check "--status=<codes>" in h
    check "--country=<codes>" in h
    check "--geoip-db=<path>" in h
    check "--no-color" in h
    check "--json" in h
    check "-c, --config=<path>" in h
    check "-h, --help" in h
    check "-v, --version" in h
    check "Examples:" in h
    check "Exit Codes:" in h

  test "Item 02: versionText contains canonical application name and semantic version":
    let v = versionText()
    check AppName in v
    check AppVersion in v
    check "v" & AppVersion in v

  test "Item 02: CLI flags trigger helpRequested and versionRequested flags in CliOptions":
    check parseCliArgs(["--help"]).helpRequested == true
    check parseCliArgs(["-h"]).helpRequested == true
    check parseCliArgs(["--version"]).versionRequested == true
    check parseCliArgs(["-v"]).versionRequested == true
    check parseCliArgs(["access.log"]).helpRequested == false
    check parseCliArgs(["access.log"]).versionRequested == false

suite "CLI Options & Argument Parser - Signal Handling & Session Summary (Phase 07 / Category A / Item 03)":
  test "Item 03: handleSigInt sets keepRunning flag to false":
    keepRunning = true
    handleSigInt()
    check keepRunning == false
    keepRunning = true

  test "Item 03: runPipeline with shouldStop stops gracefully and emits session summary banner":
    let tempLog = getTempDir() / "test_signal_handling.log"
    writeFile(tempLog, """185.220.101.5 - - [10/Oct/2026:13:55:36 +0200] "GET /.env HTTP/1.1" 404 162 "-" "curl/7.68.0"
185.220.101.5 - - [10/Oct/2026:13:55:37 +0200] "GET /wp-config.php HTTP/1.1" 404 162 "-" "curl/7.68.0"
185.220.101.5 - - [10/Oct/2026:13:55:38 +0200] "GET /id_rsa HTTP/1.1" 404 162 "-" "curl/7.68.0"
""")
    defer:
      if fileExists(tempLog): removeFile(tempLog)

    var capturedLines: seq[string] = @[]
    var processedCount = 0
    let stopHook = proc(): bool =
      # Stop after processing 1 line
      processedCount >= 1

    let cfg = initViewerConfig(
      logFilePath = tempLog,
      colorOutput = false,
      colorMode = ColorModeNever
    )

    let (stats, ticker) = runPipeline(
      cfg,
      shouldStopHook = stopHook,
      outputWriter = proc(line: string) =
        if line.contains("GET /"):
          inc processedCount
        capturedLines.add(line)
    )

    check stats.parsedEntries >= 1
    check ticker.totalLines >= 1
    # Verify session summary banner was rendered and captured
    var foundSummary = false
    for l in capturedLines:
      if "HTTP LOGVIEWER - SESSION TRAFFIC SUMMARY" in l:
        foundSummary = true
        break
    check foundSummary

suite "CLI Options & Argument Parser - Path & Permission Validation (Phase 07 / Category A / Item 04)":
  test "Item 04: Standard input '-' and empty paths validate cleanly with exit code 0":
    let checkDash = validateInputPath("-")
    check checkDash.valid == true
    check checkDash.errorCode == 0

    let checkEmpty = validateInputPath("")
    check checkEmpty.valid == true
    check checkEmpty.errorCode == 0

  test "Item 04: Non-existent file returns user error with exit code 1":
    let checkMissing = validateInputPath("/non/existent/path/to/logfile.log")
    check checkMissing.valid == false
    check checkMissing.errorCode == 1
    check "Log file not found" in checkMissing.errorMsg

  test "Item 04: Directory path returns user error with exit code 1":
    let checkDir = validateInputPath(getCurrentDir())
    check checkDir.valid == false
    check checkDir.errorCode == 1
    check "directory" in checkDir.errorMsg

  test "Item 04: Existing readable file returns clean status with exit code 0":
    let tempValid = getTempDir() / "valid_readable_test.log"
    writeFile(tempValid, "127.0.0.1 - - [01/Jan/2026:00:00:00 +0000] \"GET / HTTP/1.1\" 200 123\n")
    defer:
      if fileExists(tempValid): removeFile(tempValid)

    let checkOk = validateInputPath(tempValid)
    check checkOk.valid == true
    check checkOk.errorCode == 0

  test "Item 04: Unreadable file (permission denied) returns fatal error with exit code 2":
    let unreadableFile = getTempDir() / "unreadable_permission_test.log"
    writeFile(unreadableFile, "test data\n")
    defer:
      discard execShellCmd("chmod 644 " & unreadableFile)
      if fileExists(unreadableFile): removeFile(unreadableFile)

    # Remove all read permissions
    let chmodRes = execShellCmd("chmod 000 " & unreadableFile)
    if chmodRes == 0:
      # Only verify if chmod succeeded (root users might still read 000)
      var f: File
      if not open(f, unreadableFile, fmRead):
        let checkDenied = validateInputPath(unreadableFile)
        check checkDenied.valid == false
        check checkDenied.errorCode == 2
        check "Permission denied" in checkDenied.errorMsg

suite "CLI Options & Argument Parser - Config File Support (Phase 07 / Category A / Item 05)":
  test "Item 05: loadViewerConfigToml parses TOML config strings into ViewerConfig":
    let tomlContent = """
# Display Settings
color_mode = "always"
output_format = "json"
log_format = "combined"
follow = true

# Threat & Filter Settings
min_threat_score = 45
filter_category = "hacker"
status_codes = [404, 500, 502]
country_codes = ["US", "NL"]

# Correlation & GeoIP
geo_db_path = "/var/data/GeoLite2.mmdb"
enable_grouping = true
correlation_window_seconds = 3600
"""
    let cfg = loadViewerConfigToml(tomlContent)
    check cfg.colorMode == ColorModeAlways
    check cfg.colorOutput == true
    check cfg.outputFormat == FormatJson
    check cfg.logFormat == LogFormatCombined
    check cfg.follow == true
    check cfg.minThreatScore == 45
    check cfg.filterCategory == some(CategoryBadActorHacker)
    check cfg.statusCodeFilter == @[404, 500, 502]
    check cfg.filters.countryWhitelist == @["US", "NL"]
    check cfg.geoDbPath == some("/var/data/GeoLite2.mmdb")
    check cfg.enableGrouping == true
    check cfg.correlationWindowSeconds == 3600

  test "Item 05: loadViewerConfigFile loads from .toml and .json files":
    let tempToml = getTempDir() / "test_cfg.toml"
    let tempJson = getTempDir() / "test_cfg.json"
    writeFile(tempToml, """min_threat_score = 60
enable_grouping = true
status_codes = [403, 404]
""")
    writeFile(tempJson, """{
  "minThreatScore": 70,
  "enableGrouping": false,
  "statusCodeFilter": [500]
}
""")
    defer:
      if fileExists(tempToml): removeFile(tempToml)
      if fileExists(tempJson): removeFile(tempJson)

    let cfgToml = loadViewerConfigFile(tempToml)
    check cfgToml.minThreatScore == 60
    check cfgToml.enableGrouping == true
    check cfgToml.statusCodeFilter == @[403, 404]

    let cfgJson = loadViewerConfigFile(tempJson)
    check cfgJson.minThreatScore == 70
    check cfgJson.enableGrouping == false
    check cfgJson.statusCodeFilter == @[500]

  test "Item 05: CLI arguments override settings specified in configuration file":
    let tempToml = getTempDir() / "test_override.toml"
    writeFile(tempToml, """min_threat_score = 25
color_mode = "always"
enable_grouping = false
""")
    defer:
      if fileExists(tempToml): removeFile(tempToml)

    # CLI passes --config AND --min-score=90 AND --no-color AND --group-actors
    let cfg = parseCommandLine([
      "--config=" & tempToml,
      "--min-score=90",
      "--no-color",
      "--group-actors"
    ])
    # Overridden by CLI:
    check cfg.minThreatScore == 90
    check cfg.colorOutput == false
    check cfg.colorMode == ColorModeNever
    check cfg.enableGrouping == true

  test "Item 05: Non-existent configuration file path raises ConfigError":
    expect ConfigError:
      discard loadViewerConfigFile("/path/does/not/exist/config.toml")

suite "CLI Options & Argument Parser - Automated CLI Binary Execution (Phase 07 / Category A / Item 06)":
  let binPath = getCurrentDir() / "build" / "http_logviewer"

  test "Item 06: Binary exists or compiles cleanly":
    if not fileExists(binPath):
      let buildRes = execShellCmd("nim c --outdir:build src/http_logviewer.nim")
      check buildRes == 0
    check fileExists(binPath)

  test "Item 06: Executing binary with --help and -h":
    let (outHelp, codeHelp) = execCmdEx(binPath & " --help")
    check codeHelp == 0
    check "Usage:" in outHelp
    check "--filter=<category>" in outHelp
    check "--min-score=<0-100>" in outHelp

    let (outH, codeH) = execCmdEx(binPath & " -h")
    check codeH == 0
    check "Usage:" in outH

  test "Item 06: Executing binary with --version and -v":
    let (outVer, codeVer) = execCmdEx(binPath & " --version")
    check codeVer == 0
    check "http_logviewer v0.1.0" in outVer

    let (outV, codeV) = execCmdEx(binPath & " -v")
    check codeV == 0
    check "http_logviewer v0.1.0" in outV

  test "Item 06: Executing binary with unknown options exits with code 1":
    let (outErr, codeErr) = execCmdEx(binPath & " --non-existent-flag")
    check codeErr == 1
    check "http_logviewer error:" in outErr or "Unknown option" in outErr

  test "Item 06: Executing binary with invalid numeric threshold exits with code 1":
    let (outErr, codeErr) = execCmdEx(binPath & " --min-score=999")
    check codeErr == 1

  test "Item 06: Executing binary with missing log file exits with code 1":
    let (outErr, codeErr) = execCmdEx(binPath & " /path/to/missing_log_file.log")
    check codeErr == 1
    check "Log file not found" in outErr

  test "Item 06: Executing binary with directory argument exits with code 1":
    let (outErr, codeErr) = execCmdEx(binPath & " " & getCurrentDir())
    check codeErr == 1
    check "directory" in outErr

  test "Item 06: Executing binary with file input and --no-color":
    let tempLog = getTempDir() / "test_exec_stream.log"
    writeFile(tempLog, """185.220.101.5 - - [10/Oct/2026:13:55:36 +0200] "GET /.env HTTP/1.1" 404 162 "-" "curl/7.68.0"
8.8.8.8 - - [10/Oct/2026:13:55:37 +0200] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
""")
    defer:
      if fileExists(tempLog): removeFile(tempLog)

    let (output, exitCode) = execCmdEx(binPath & " " & tempLog & " --no-color")
    check exitCode == 0
    check "/.env" in output
    check "HTTP LOGVIEWER - SESSION TRAFFIC SUMMARY" in output
    check "Total Lines Ingested : 2" in output

  test "Item 06: Executing binary with --json produces NDJSON lines":
    let tempLog = getTempDir() / "test_exec_json.log"
    writeFile(tempLog, """185.220.101.5 - - [10/Oct/2026:13:55:36 +0200] "GET /.env HTTP/1.1" 404 162 "-" "curl/7.68.0"
""")
    defer:
      if fileExists(tempLog): removeFile(tempLog)

    let (output, exitCode) = execCmdEx(binPath & " " & tempLog & " --json")
    check exitCode == 0
    check "\"clientIp\":\"185.220.101.5\"" in output
    check "\"path\":\"/.env\"" in output
    # In JSON mode, session summary banner is omitted
    check "SESSION TRAFFIC SUMMARY" notin output

  test "Item 06: Executing binary with --filter=hacker filters innocent traffic":
    let tempLog = getTempDir() / "test_exec_filter.log"
    writeFile(tempLog, """8.8.8.8 - - [10/Oct/2026:13:55:36 +0200] "GET /about.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
185.220.101.5 - - [10/Oct/2026:13:55:37 +0200] "GET /.env HTTP/1.1" 404 162 "-" "curl/7.68.0"
""")
    defer:
      if fileExists(tempLog): removeFile(tempLog)

    let (output, exitCode) = execCmdEx(binPath & " " & tempLog & " --filter=hacker --no-color")
    check exitCode == 0
    check "GET /.env" in output
    check "GET /about.html" notin output

  test "Item 06: Executing binary with --status=404 filters other status codes":
    let tempLog = getTempDir() / "test_exec_status.log"
    writeFile(tempLog, """8.8.8.8 - - [10/Oct/2026:13:55:36 +0200] "GET /about.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
185.220.101.5 - - [10/Oct/2026:13:55:37 +0200] "GET /notfound HTTP/1.1" 404 162 "-" "Mozilla/5.0"
""")
    defer:
      if fileExists(tempLog): removeFile(tempLog)

    let (output, exitCode) = execCmdEx(binPath & " " & tempLog & " --status=404 --no-color")
    check exitCode == 0
    check "GET /notfound" in output
    check "GET /about.html" notin output

  test "Item 06: Executing binary with --group-actors outputs actor clusters":
    let tempLog = getTempDir() / "test_exec_group.log"
    writeFile(tempLog, """185.220.101.5 - - [10/Oct/2026:13:55:36 +0200] "GET /.env HTTP/1.1" 404 162 "-" "curl/7.68.0"
185.220.101.6 - - [10/Oct/2026:13:55:37 +0200] "GET /.env HTTP/1.1" 404 162 "-" "curl/7.68.0"
""")
    defer:
      if fileExists(tempLog): removeFile(tempLog)

    let (output, exitCode) = execCmdEx(binPath & " " & tempLog & " --group-actors --no-color")
    check exitCode == 0
    check "CORRELATED ATTACK CAMPAIGNS" in output or "ACTOR" in output

  test "Item 06: Executing binary with --config loads custom TOML settings":
    let tempToml = getTempDir() / "test_cli_exec.toml"
    let tempLog = getTempDir() / "test_cli_exec.log"
    writeFile(tempToml, """min_threat_score = 90
output_format = "json"
""")
    writeFile(tempLog, """8.8.8.8 - - [10/Oct/2026:13:55:36 +0200] "GET /about.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"
185.220.101.5 - - [10/Oct/2026:13:55:37 +0200] "GET /.env HTTP/1.1" 404 162 "-" "curl/7.68.0"
""")
    defer:
      if fileExists(tempToml): removeFile(tempToml)
      if fileExists(tempLog): removeFile(tempLog)

    let (output, exitCode) = execCmdEx(binPath & " --config=" & tempToml & " " & tempLog)
    check exitCode == 0
    # Min score 90 + json output from config:
    check "\"clientIp\":\"185.220.101.5\"" in output
    check "8.8.8.8" notin output

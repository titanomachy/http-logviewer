## Persistent whitelist storage, display metadata, and CLI lifecycle regression tests.

import std/[unittest, os, osproc, strutils, tempfiles, options, json, strtabs]
import http_logviewer

suite "Persistent IP whitelist":
  test "Canonical addresses survive reopening; repeated adds and removals are idempotent":
    let testDir = createTempDir("http-logviewer-whitelist-", "")
    defer: removeDir(testDir)
    let path = testDir / "nested" / "state.sqlite3"
    check loadWhitelistedIps(path).len == 0
    check not fileExists(path)
    saveWhitelistedIps(path, ["192.0.2.10", "2001:0DB8:0:0:0:0:0:1"])
    saveWhitelistedIps(path, ["192.0.2.10", "2001:db8::1"])
    check loadWhitelistedIps(path) == @["192.0.2.10", "2001:db8::1"]
    removeWhitelistedIps(path, ["2001:0db8:0:0:0:0:0:1", "192.0.2.11"])
    check loadWhitelistedIps(path) == @["192.0.2.10"]
    removeWhitelistedIps(path, ["192.0.2.10"])
    check loadWhitelistedIps(path).len == 0

  test "Invalid add batches cannot partially update the database":
    let testDir = createTempDir("http-logviewer-whitelist-", "")
    defer: removeDir(testDir)
    let path = testDir / "state.sqlite3"
    saveWhitelistedIps(path, ["192.0.2.10"])
    expect ConfigError:
      saveWhitelistedIps(path, ["192.0.2.11", "invalid"])
    check loadWhitelistedIps(path) == @["192.0.2.10"]
    expect ConfigError:
      saveWhitelistedIps(":memory:", ["192.0.2.10"])
    expect ConfigError:
      discard loadWhitelistedIps(testDir)
    let missing = testDir / "missing.sqlite3"
    removeWhitelistedIps(missing, ["192.0.2.10"])
    check not fileExists(missing)

  test "Explicit trust has a visible badge and round-trips through JSON":
    let tracker = newVisitorBehaviorTracker(whitelistIps = ["192.0.2.10"])
    let profile = evaluateThreat(initHttpLogEntry(clientIp = "192.0.2.10", path = "/.env",
      statusCode = 404, userAgent = "sqlmap/1.7.2"), tracker)
    check profile.whitelisted
    check profile.category == CategoryRealUser
    check formatIntentBadge(profile, colorize = false) == "[WHITELISTED]"
    check "\e[92m" in formatIntentBadge(profile, colorize = true)
    check parseThreatProfileJson(%profile) == profile
    check not parseThreatProfileJson(parseJson("{\"category\":\"REAL_USER\",\"score\":0}")).whitelisted

  test "Viewer merges persistent and temporary trusted addresses":
    let testDir = createTempDir("http-logviewer-whitelist-", "")
    defer: removeDir(testDir)
    let path = testDir / "state.sqlite3"
    saveWhitelistedIps(path, ["141.145.159.132"])
    let cfg = initViewerConfig(logFilePath = "tests/fixtures/persistent_actor.log",
      outputFormat = FormatJson, stateDbPath = some(path), whitelistIps = ["192.0.2.77"])
    var output: seq[string] = @[]
    discard runPipeline(cfg, outputWriter = proc(line: string) = output.add(line))
    check output.len == 9
    for line in output:
      let record = parseJson(line)
      check record["threat"]["whitelisted"].getBool()
      check record["threat"]["score"].getInt() == 0

  test "Management CLI parses repeated addresses and rejects conflicting commands":
    let opts = parseCliArgs(["--state-db", "state.sqlite3", "--whitelist-add", "192.0.2.10",
      "--allowlist-add=2001:db8::1"])
    check opts.stateDbPath == some("state.sqlite3")
    check opts.whitelistAddIps == @["192.0.2.10", "2001:db8::1"]
    check parseCliArgs(["--allowlist-list"]).whitelistList
    check parseCliArgs(["--allowlist-remove", "192.0.2.10"]).whitelistRemoveIps == @["192.0.2.10"]
    expect ConfigError:
      discard parseCliArgs(["--whitelist-add=192.0.2.10", "--whitelist-list"])
    expect ConfigError:
      discard parseCliArgs(["--whitelist-list", "access.log"])
    expect ConfigError:
      discard parseCliArgs(["--whitelist-add", "invalid"])

  test "Separate CLI processes save, load, display, and remove trusted IPs":
    let testDir = createTempDir("http-logviewer-whitelist-", "")
    defer: removeDir(testDir)
    let path = testDir / "state.sqlite3"
    let command = quoteShell(getCurrentDir() / "build" / "http_logviewer") &
      " --state-db " & quoteShell(path)
    let (added, addCode) = execCmdEx(command & " --whitelist-add 141.145.159.132")
    check addCode == 0
    check "Saved whitelisted IP: 141.145.159.132" in added
    let (listed, listCode) = execCmdEx(command & " --whitelist-list")
    check listCode == 0
    check listed.strip() == "141.145.159.132"
    let (viewed, viewCode) = execCmdEx(command & " --no-color --group-actors tests/fixtures/persistent_actor.log")
    check viewCode == 0
    check viewed.count("[WHITELISTED]") == 8
    check viewed.count("[REAL USER]") == 1
    check "CORRELATED MULTI-IP ACTOR CLUSTERS" notin viewed
    let (_, removeCode) = execCmdEx(command & " --whitelist-remove 141.145.159.132")
    check removeCode == 0
    let (afterRemoval, afterCode) = execCmdEx(command & " --no-color tests/fixtures/persistent_actor.log")
    check afterCode == 0
    check "[WHITELISTED]" notin afterRemoval
    check afterRemoval.count("[ CRACKER!]") == 5

  test "State database configuration round-trips through JSON and TOML":
    let cfg = initViewerConfig(stateDbPath = some("state.sqlite3"))
    check loadViewerConfigJson($(%cfg)) == cfg
    check loadViewerConfigToml("state_db_path = \"state.sqlite3\"").stateDbPath == cfg.stateDbPath
    check parseCommandLine(["--state-db=other.sqlite3"]).stateDbPath == some("other.sqlite3")
    expect ConfigError:
      initViewerConfig(stateDbPath = some(":memory:")).validate()

  when defined(linux):
    test "CLI automatically uses the per-user SQLite whitelist on later runs":
      let testDir = createTempDir("http-logviewer-whitelist-", "")
      defer: removeDir(testDir)
      var childEnv = newStringTable(modeCaseSensitive)
      for key, value in envPairs():
        childEnv[key] = value
      childEnv["XDG_DATA_HOME"] = testDir
      let command = quoteShell(getCurrentDir() / "build" / "http_logviewer")
      let (_, addCode) = execCmdEx(command & " --whitelist-add 141.145.159.132", env = childEnv)
      check addCode == 0
      check fileExists(testDir / "http_logviewer" / "state.sqlite3")
      let (viewed, viewCode) = execCmdEx(command & " --no-color tests/fixtures/persistent_actor.log", env = childEnv)
      check viewCode == 0
      check viewed.count("[WHITELISTED]") == 8

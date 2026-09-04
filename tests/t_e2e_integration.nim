## Test suite for Phase 07 / Category C: End-to-End Testing & Sample Log Fixtures.
## Covers:
## - Item 01: tests/fixtures/combined.log (genuine Apache/Nginx web traffic)
## - Item 02: tests/fixtures/attacks.log (SQLi, directory traversal, .env probes, crawlers)
## - Item 03: tests/fixtures/distributed_botnet.log (rotating IPs, WordPress exploits, identical signatures)
## - Item 04: End-to-end integration test parsing sample fixtures & threat classification precision
## - Item 05: Validate 404 background red color styling emitted on error lines when ANSI is active
## - Item 06: Validate multi-IP actor grouping output on distributed_botnet.log

import unittest
import std/[strutils, options, os, osproc, tables, sets, sequtils]
import http_logviewer
import http_logviewer/core/types
import http_logviewer/parser/[engine, formats]
import http_logviewer/analyzer/[classifier, correlator]
import http_logviewer/renderer/[styles, terminal]

let projectRoot = getCurrentDir()
let binPath = projectRoot / "build" / "http_logviewer"

suite "End-to-End Fixtures & Threat Classification Precision (Phase 07 / Category C / Items 01, 02, 04)":

  test "Item 01: Ingestion and evaluation of genuine traffic from tests/fixtures/combined.log":
    let fixturePath = "tests/fixtures/combined.log"
    check fileExists(fixturePath)
    
    var entries: seq[HttpLogEntry] = @[]
    let stats = streamLogLines(fixturePath, follow = false, onEntry = proc(entry: HttpLogEntry) =
      entries.add(entry)
    )
    
    check stats.parsedEntries == 6
    check entries.len == 6
    
    # Verify genuine desktop/mobile browsers are classified as real users without false positives
    # Line 0: Chrome desktop requesting CSS -> RealUser
    let e0 = entries[0]
    check e0.clientIp == "93.184.216.34"
    check e0.path == "/assets/style.css"
    check e0.statusCode == 200
    let t0 = evaluateThreat(e0)
    check t0.category == CategoryRealUser
    check t0.score <= 20
    check ThreatSensitiveFile notin t0.flags
    check ThreatSqlInjection notin t0.flags
    
    # Line 4: Googlebot crawler requesting 404 page -> VerifiedBot
    let e4 = entries[4]
    check e4.clientIp == "198.51.100.99"
    check e4.path == "/nonexistent-page"
    check e4.statusCode == 404
    let t4 = evaluateThreat(e4)
    check t4.category == CategoryVerifiedBot
    check t4.score == 0
    
    # Line 5: iPhone checkout POST -> RealUser
    let e5 = entries[5]
    check e5.clientIp == "2001:db8:85a3::8a2e:370:7334"
    check e5.statusCode == 500
    let t5 = evaluateThreat(e5)
    check t5.category == CategoryRealUser
    check t5.score <= 20

  test "Item 02: Ingestion and evaluation of attack traffic from tests/fixtures/attacks.log":
    let fixturePath = "tests/fixtures/attacks.log"
    check fileExists(fixturePath)
    
    var entries: seq[HttpLogEntry] = @[]
    var threats: seq[ThreatProfile] = @[]
    
    let stats = streamLogLines(fixturePath, follow = false, onEntry = proc(entry: HttpLogEntry) =
      entries.add(entry)
      threats.add(evaluateThreat(entry))
    )
    
    check stats.parsedEntries == 16
    check entries.len == 16
    check threats.len == 16
    
    # Verify SQL Injection detection (lines 5 and 6)
    check entries[5].path.contains("UNION")
    check ThreatSqlInjection in threats[5].flags
    check threats[5].score >= 60
    check threats[5].category == CategoryBadActorHacker
    
    check entries[6].path.contains("%27%20OR%20%271%27%3D%271")
    check ThreatSqlInjection in threats[6].flags
    check threats[6].score >= 60
    check threats[6].category == CategoryBadActorHacker
    
    # Verify Directory Traversal detection (lines 7 and 8)
    check entries[7].path.contains("../../../../etc/passwd")
    check ThreatDirectoryTraversal in threats[7].flags
    check threats[7].score >= 60
    check threats[7].category == CategoryBadActorHacker
    
    check entries[8].path.contains("%2e%2e%2f%2e%2e%2fetc%2fshadow")
    check ThreatDirectoryTraversal in threats[8].flags
    check threats[8].score >= 60
    check threats[8].category == CategoryBadActorHacker
    
    # Verify Sensitive File Probes (.env, .git/config, /actuator/env, docker-compose.yml, .aws/credentials, id_rsa)
    check ThreatSensitiveFile in threats[0].flags # /.env
    check ThreatSensitiveFile in threats[1].flags # /.git/config
    check ThreatSensitiveFile in threats[12].flags # /actuator/env
    check ThreatSensitiveFile in threats[13].flags # /docker-compose.yml
    check ThreatSensitiveFile in threats[14].flags # /.aws/credentials
    check ThreatSensitiveFile in threats[15].flags # /id_rsa
    
    # Verify CMS Exploits (/wp-login.php, /xmlrpc.php, /phpmyadmin)
    check ThreatCmsExploit in threats[2].flags # /wp-login.php
    check ThreatCmsExploit in threats[3].flags # /xmlrpc.php
    check ThreatCmsExploit in threats[4].flags # /phpmyadmin/index.php
    
    # Verify Command Injection / RCE / Log4j (lines 9, 10, 11)
    check ThreatCommandInjection in threats[9].flags # cmd=$(whoami)
    check ThreatCommandInjection in threats[10].flags # shell.php?c=;id
    check ThreatCommandInjection in threats[11].flags # ${jndi:ldap://...}
    check threats[11].score >= 80
    
    # Verify Offensive Scanner and Tool User-Agents
    check ThreatKnownScannerUa in threats[4].flags # Nikto/2.1.6
    check ThreatKnownScannerUa in threats[5].flags # sqlmap/1.7.2#stable
    check ThreatKnownScannerUa in threats[7].flags # gobuster/3.5
    check ThreatKnownScannerUa in threats[9].flags # masscan/1.3.2
    check ThreatKnownScannerUa in threats[11].flags # nuclei/v3.1.0

  test "Item 04: End-to-end classification precision across sample fixtures":
    # 100% of attack lines in attacks.log must be classified as BadActorHacker or Suspicious (Threat score >= 40)
    let attackLines = readFile("tests/fixtures/attacks.log").strip().splitLines()
    for line in attackLines:
      var entry: HttpLogEntry
      check parseCombinedLine(line, entry)
      let threat = evaluateThreat(entry)
      check threat.score >= 40
      check threat.category in [CategoryBadActorHacker, CategorySuspicious]
      check threat.isHacker() or threat.isSuspicious()
    
    # 0% of clean lines in combined.log must be classified as BadActorHacker
    let cleanLines = readFile("tests/fixtures/combined.log").strip().splitLines()
    for line in cleanLines:
      var entry: HttpLogEntry
      check parseCombinedLine(line, entry)
      let threat = evaluateThreat(entry)
      check threat.category != CategoryBadActorHacker
      check threat.score <= 30

suite "HTTP 404 Status Code Background Red ANSI Styling (Phase 07 / Category C / Item 05)":

  test "Item 05: ANSI color badge formatter emits bold red background for 404 Not Found":
    let formatted404 = formatStatusCode(404, colorize = true)
    # Bright White on Red background: \e[41;97;1m 404 \e[0m
    check formatted404.contains("\e[41;")
    check formatted404.contains("404")
    check formatted404.contains("\e[0m")
    check formatted404 == "\e[41;97;1m 404 \e[0m"

  test "Item 05: Other HTTP status classes emit their specified ANSI badges":
    check formatStatusCode(500, colorize = true) == "\e[101;97;1m 500 \e[0m"
    check formatStatusCode(502, colorize = true) == "\e[101;97;1m 502 \e[0m"
    check formatStatusCode(403, colorize = true) == "\e[45;97m 403 \e[0m"
    check formatStatusCode(401, colorize = true) == "\e[45;97m 401 \e[0m"
    check formatStatusCode(200, colorize = true) == "\e[42;30m 200 \e[0m"
    check formatStatusCode(301, colorize = true) == "\e[43;30m 301 \e[0m"
    check formatStatusCode(304, colorize = true) == "\e[43;30m 304 \e[0m"

  test "Item 05: Monochromatic mode strips all ANSI styling from status badges":
    check formatStatusCode(404, colorize = false) == " 404 "
    check formatStatusCode(500, colorize = false) == " 500 "
    check formatStatusCode(200, colorize = false) == " 200 "
    check "\e[" notin formatStatusCode(404, colorize = false)

  test "Item 05: renderStreamLine emits red background 404 badge on error records":
    var entry: HttpLogEntry
    check parseCombinedLine("""185.220.101.5 - - [04/Sep/2026:03:00:01 +0200] "GET /.env HTTP/1.1" 404 162 "-" "curl/7.88.1"""", entry)
    let threat = evaluateThreat(entry)
    let geo = GeoLocation(ip: entry.clientIp, countryCode: "DE", countryName: "Germany", flagEmoji: "🇩🇪", isPrivate: false)
    let record = EnrichedLogRecord(entry: entry, geo: geo, threat: threat, clusterId: none(string))
    
    let renderedColored = renderStreamLine(record, colorize = true)
    check "\e[41;97;1m 404 \e[0m" in renderedColored
    check "🇩🇪 DE" in renderedColored
    check "/.env" in renderedColored
    
    let renderedPlain = renderStreamLine(record, colorize = false)
    check "\e[" notin renderedPlain
    check "404" in renderedPlain
    check "/.env" in renderedPlain

  test "Item 05: CLI execution on attacks.log emits ANSI red 404 badges when color is enabled":
    if not fileExists(binPath):
      let (_, bCode) = execCmdEx("nimble build")
      check bCode == 0
    
    let (output, exitCode) = execCmdEx(binPath & " tests/fixtures/attacks.log")
    check exitCode == 0
    # Must contain ANSI red 404 sequence in terminal output
    check "\e[41;97;1m 404 \e[0m" in output

suite "Multi-IP Actor Grouping Output on distributed_botnet.log (Phase 07 / Category C / Items 03, 06)":

  test "Item 03 & 06: ActorCorrelator links 5 rotating IPs from distributed_botnet.log into unified cluster":
    let fixturePath = "tests/fixtures/distributed_botnet.log"
    check fileExists(fixturePath)
    
    let correlator = newActorCorrelator(windowSeconds = 1800)
    var linesIngested = 0
    var assignedClusterId = ""
    
    for rawLine in lines(fixturePath):
      if rawLine.strip().len == 0: continue
      inc linesIngested
      var entry: HttpLogEntry
      check parseCombinedLine(rawLine, entry)
      let threat = evaluateThreat(entry)
      let cidOpt = correlator.correlateRecord(entry, threat)
      check cidOpt.isSome
      if assignedClusterId.len == 0:
        assignedClusterId = cidOpt.get()
      else:
        check cidOpt.get() == assignedClusterId
    
    check linesIngested == 5
    check correlator.clusters.len == 1
    
    let cluster = correlator.clusters[assignedClusterId]
    check cluster.ips.len == 5
    check "185.220.101.5" in cluster.ips
    check "45.154.255.12" in cluster.ips
    check "194.26.29.40" in cluster.ips
    check "91.240.118.82" in cluster.ips
    check "103.21.244.2" in cluster.ips
    check cluster.proxyRotationDetected
    check cluster.primaryUa == "WP-Scan-Distributed/3.1 (Botnet-Fleet)"

  test "Item 06: Grouped summary table, cluster card, and timeline render accurately":
    let correlator = newActorCorrelator(windowSeconds = 1800)
    for rawLine in lines("tests/fixtures/distributed_botnet.log"):
      if rawLine.strip().len == 0: continue
      var entry: HttpLogEntry
      check parseCombinedLine(rawLine, entry)
      discard correlator.correlateRecord(entry, evaluateThreat(entry))
    
    # 1. Grouped summary table formatting
    let summaryTable = renderGroupedSummaryTable(correlator, colorize = false, maxWidth = 120)
    check "CORRELATED MULTI-IP ACTOR CLUSTERS" in summaryTable
    check "WP-Scan Botnet" in summaryTable
    check "5" in summaryTable # 5 IPs
    
    # 2. Actor cluster card formatting
    let clusterCards = renderGroupedClusters(correlator.clusters, colorize = false)
    check "CRITICAL ACTOR CLUSTER:" in clusterCards
    check "Distinct IPs" in clusterCards
    check "185.220.101.5" in clusterCards
    check "45.154.255.12" in clusterCards
    check "WP-Scan-Distributed/3.1 (Botnet-Fleet)" in clusterCards
    check "Residential Proxy Rotation Detected" in clusterCards
    
    # 3. Forensic drill-down timeline
    let clusterId = toSeq(correlator.clusters.keys)[0]
    let timeline = renderActorDetail(correlator.clusters[clusterId], colorize = false)
    check "CHRONOLOGICAL ATTACK TIMELINE" in timeline
    check "/.env" in timeline
    check "/wp-login.php" in timeline
    check "/xmlrpc.php" in timeline
    check "/actuator/env" in timeline
    check "/setup.php" in timeline
    check "QUICK MITIGATION (UFW / FAIL2BAN / IPTABLES):" in timeline
    check "ufw deny" in timeline
    check "iptables -A INPUT" in timeline

  test "Item 06: CLI binary execution with --group-actors on distributed_botnet.log":
    if not fileExists(binPath):
      let (_, bCode) = execCmdEx("nimble build")
      check bCode == 0
    
    let cmd = binPath & " --group-actors --no-color tests/fixtures/distributed_botnet.log"
    let (output, exitCode) = execCmdEx(cmd)
    check exitCode == 0
    check "CORRELATED MULTI-IP ACTOR CLUSTERS" in output
    check "WP-Scan" in output
    check "ACTOR-" in output
    check "HTTP LOGVIEWER - SESSION TRAFFIC SUMMARY" in output
    check "Total Lines Ingested : 5" in output

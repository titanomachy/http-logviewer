# Example: Grouped Multi-IP Actor View, Cluster Cards, Anomaly Drill-Down & Incident Reports
# Demonstrates Phase 06 / Category C:
# - Grouped summary table displaying correlated multi-IP actors sorted by risk score (Item 01)
# - Detailed actor cluster cards with threat levels, unique IPs, countries, and probed paths (Item 02)
# - Chronological attack timeline drill-down displaying multi-IP progression and time deltas (Item 03)
# - Exportable security incident reports (Markdown, plain text, Fail2ban, UFW, iptables) (Item 04)
#
# Compile and run with:
#   nim r --path:src examples/grouped_actor_view.nim

import std/[times, sets, strutils]
import http_logviewer/core/types
import http_logviewer/renderer/terminal

proc createSampleClusters(): seq[ActorCluster] =
  # 1. Distributed WordPress & Secret Probe Botnet across 6 IPs in 3 countries
  let t0 = parse("2026-10-10 13:50:12", "yyyy-MM-dd HH:mm:ss")
  let t1 = parse("2026-10-10 13:50:14", "yyyy-MM-dd HH:mm:ss") # +02s
  let t2 = parse("2026-10-10 13:50:17", "yyyy-MM-dd HH:mm:ss") # +05s
  let t3 = parse("2026-10-10 13:50:22", "yyyy-MM-dd HH:mm:ss") # +10s
  let t4 = parse("2026-10-10 13:51:05", "yyyy-MM-dd HH:mm:ss") # +53s
  let t5 = parse("2026-10-10 13:58:45", "yyyy-MM-dd HH:mm:ss") # +08m 33s

  let e1 = initHttpLogEntry(clientIp = "45.154.255.8", timestamp = t0, `method` = HttpGet, path = "/.env", statusCode = 404, userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
  let e2 = initHttpLogEntry(clientIp = "194.26.29.112", timestamp = t1, `method` = HttpGet, path = "/wp-config.php", statusCode = 404, userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
  let e3 = initHttpLogEntry(clientIp = "185.220.101.5", timestamp = t2, `method` = HttpPost, path = "/wp-login.php", statusCode = 404, userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
  let e4 = initHttpLogEntry(clientIp = "193.32.161.20", timestamp = t3, `method` = HttpPost, path = "/xmlrpc.php", statusCode = 404, userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
  let e5 = initHttpLogEntry(clientIp = "193.32.161.21", timestamp = t4, `method` = HttpGet, path = "/actuator/env", statusCode = 404, userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
  let e6 = initHttpLogEntry(clientIp = "193.32.161.22", timestamp = t5, `method` = HttpGet, path = "/backup.sql", statusCode = 404, userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

  var ips1 = initHashSet[string]()
  ips1.incl("45.154.255.8")
  ips1.incl("194.26.29.112")
  ips1.incl("185.220.101.5")
  ips1.incl("193.32.161.20")
  ips1.incl("193.32.161.21")
  ips1.incl("193.32.161.22")

  var provs1 = initHashSet[string]()
  provs1.incl("Hetzner")
  provs1.incl("OVH")

  var subnets1 = initHashSet[string]()
  subnets1.incl("193.32.161.0/24")
  subnets1.incl("185.220.101.0/24")

  let cluster1 = newActorCluster(
    clusterId = "ACTOR-7F3A",
    clusterTag = "[Actor #1: 6 IPs - WP-Scan Botnet]",
    primaryUa = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ips = ips1,
    entries = @[e1, e2, e3, e4, e5, e6],
    totalRequests = 48,
    status404Count = 48,
    firstSeen = t0,
    lastSeen = t5,
    highestThreatScore = 95,
    aggregateRisk = 95,
    category = CategoryBadActorHacker,
    flags = {ThreatCmsExploit, ThreatSensitiveFile},
    probedPaths = @["/.env", "/wp-config.php", "/wp-login.php", "/xmlrpc.php", "/actuator/env", "/backup.sql"],
    proxyRotationDetected = true,
    proxyRotationCount = 3,
    subnets = subnets1,
    hostingProviders = provs1,
    hasDatacenterIps = true,
    synchronizedBurstDetected = true,
    synchronizedBurstCount = 2
  )

  # 2. SQL Injection Scanner Fleet (DigitalOcean)
  let s0 = parse("2026-10-10 13:52:00", "yyyy-MM-dd HH:mm:ss")
  let s1 = parse("2026-10-10 13:54:15", "yyyy-MM-dd HH:mm:ss")
  let se1 = initHttpLogEntry(clientIp = "159.65.10.20", timestamp = s0, `method` = HttpGet, path = "/search?q=1'+union+select+1,2,3--", statusCode = 500, userAgent = "sqlmap/1.7#stable")
  let se2 = initHttpLogEntry(clientIp = "159.65.10.21", timestamp = s1, `method` = HttpGet, path = "/search?q=1'+or+'1'='1", statusCode = 500, userAgent = "sqlmap/1.7#stable")

  var ips2 = initHashSet[string]()
  ips2.incl("159.65.10.20"); ips2.incl("159.65.10.21")
  var provs2 = initHashSet[string]()
  provs2.incl("DigitalOcean")
  var subnets2 = initHashSet[string]()
  subnets2.incl("159.65.0.0/16")

  let cluster2 = newActorCluster(
    clusterId = "ACTOR-B2A4",
    clusterTag = "[Actor #2: 2 IPs (DigitalOcean /16) - SQLi Exploit Cluster]",
    primaryUa = "sqlmap/1.7#stable (https://sqlmap.org)",
    ips = ips2,
    entries = @[se1, se2],
    totalRequests = 16,
    status404Count = 4,
    firstSeen = s0,
    lastSeen = s1,
    highestThreatScore = 85,
    aggregateRisk = 85,
    category = CategoryBadActorHacker,
    flags = {ThreatSqlInjection},
    probedPaths = @["/search?q=1'+union+select+1,2,3--", "/search?q=1'+or+'1'='1"],
    subnets = subnets2,
    hostingProviders = provs2,
    hasDatacenterIps = true
  )

  # 3. Commercial SEO / Crawler Scraper
  let c0 = parse("2026-10-10 13:40:00", "yyyy-MM-dd HH:mm:ss")
  let c1 = parse("2026-10-10 13:55:00", "yyyy-MM-dd HH:mm:ss")
  var ips3 = initHashSet[string]()
  ips3.incl("54.36.148.10"); ips3.incl("54.36.148.11")

  let cluster3 = newActorCluster(
    clusterId = "ACTOR-C18E",
    clusterTag = "[Actor #3: 2 IPs - Commercial Scraper Fleet]",
    primaryUa = "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    ips = ips3,
    totalRequests = 120,
    status404Count = 2,
    firstSeen = c0,
    lastSeen = c1,
    highestThreatScore = 35,
    aggregateRisk = 35,
    category = CategoryCommercialBot,
    probedPaths = @["/blog", "/pricing", "/features", "/about"]
  )

  result = @[cluster1, cluster2, cluster3]

when isMainModule:
  let clusters = createSampleClusters()

  echo "=== http_logviewer: Grouped Actor View & Anomaly Drill-Down (Phase 06 / Category C) ==="
  echo ""
  echo "================================================================================"
  echo "DEMO 1: GROUPED SUMMARY TABLE (Wide & Compact Terminal Views)"
  echo "================================================================================"
  echo ""
  # Wide table layout (120 columns)
  echo renderGroupedSummaryTable(clusters, colorize = true, maxWidth = 120)
  echo ""

  echo "================================================================================"
  echo "DEMO 2: ACTOR CLUSTER CARD (Spec 06 Section 4 Layout)"
  echo "================================================================================"
  echo ""
  # Render detailed card for critical cluster
  echo renderActorClusterCard(clusters[0], colorize = true, useEmoji = true, width = 80)
  echo ""

  echo "================================================================================"
  echo "DEMO 3: CHRONOLOGICAL ATTACK TIMELINE & ANOMALY DRILL-DOWN"
  echo "================================================================================"
  echo ""
  # Timeline showing multi-IP progression and time deltas
  echo renderActorTimeline(clusters[0], colorize = true, useEmoji = true, maxWidth = 100)
  echo ""

  echo "================================================================================"
  echo "DEMO 4: AUTOMATED FIREWALL & CONTAINMENT RULES"
  echo "================================================================================"
  echo ""
  echo "--- Fail2ban Ban Script ---"
  echo generateFail2banRules(clusters, jail = "nginx-botsearch")
  echo ""
  echo "--- UFW Firewall Rules ---"
  echo generateUfwRules(clusters)
  echo ""

  echo "================================================================================"
  echo "DEMO 5: EXPORTABLE MARKDOWN INCIDENT REPORT (Snippet)"
  echo "================================================================================"
  let mdReport = generateMarkdownReport(clusters, title = "Automated Rogue Botnet Incident Report")
  # Show executive summary and clusters table snippet of markdown report
  let mdLines = mdReport.split("\n")
  for i in 0 ..< min(18, mdLines.len):
    echo mdLines[i]
  echo "... [full incident report with mitigation rules ready for export] ..."

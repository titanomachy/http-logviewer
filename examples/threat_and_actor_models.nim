# Example: Threat & Actor Domain Models
# Demonstrates ActorCategory classification, ThreatFlag tracking, ThreatProfile scoring,
# multi-IP ActorCluster grouping, GeoLocation enrichment, and EnrichedLogRecord export.
#
# Compile and run with:
#   nim r --path:src examples/threat_and_actor_models.nim

import std/[times, sets, options, json, os]
import http_logviewer/core/types

proc main() =
  echo "================================================================================"
  echo "         http_logviewer: Threat & Actor Domain Models (Phase 01 / Category B)    "
  echo "================================================================================"
  echo ""
  sleep(250)

  # 1. Visitor Intent Classification (ActorCategory)
  echo "[1] Visitor Intent Classification (ActorCategory):"
  for cat in [CategoryRealUser, CategoryVerifiedBot, CategorySuspicious, CategoryBadActorHacker]:
    echo "  - Category: ", $cat, " | isBot: ", isBot(cat), " | isHacker: ", isHacker(cat), " | isRealUser: ", isRealUser(cat)
  echo ""
  sleep(300)

  # 2. Atomic Threat Indicators (ThreatFlag) & Bitsets
  echo "[2] Atomic Threat Indicators (ThreatFlag):"
  var activeFlags: set[ThreatFlag] = {ThreatCmsExploit, ThreatSensitiveFile, ThreatSqlInjection}
  echo "  Active flags:       ", activeFlags
  echo "  Flag count (card):  ", card(activeFlags)
  echo "  Has SQLi flag:      ", (ThreatSqlInjection in activeFlags)
  echo "  JSON Array:         ", (%activeFlags)
  echo ""
  sleep(300)

  # 3. Single-Request Threat Intelligence Profile (ThreatProfile):"
  echo "[3] Single-Request Threat Intelligence Profile (ThreatProfile):"
  let hackerProfile = initThreatProfile(
    score = 92,
    category = CategoryBadActorHacker,
    flags = {ThreatCmsExploit, ThreatSensitiveFile},
    matchedSignatures = @["wp_login_probe", "env_credential_harvest"]
  )
  echo "  Profile String:     ", hackerProfile
  echo "  isHacker:           ", hackerProfile.isHacker()
  echo "  Matched Rules:      ", hackerProfile.matchedRules
  echo "  JSON Structured:    ", (%hackerProfile).pretty(2)
  echo ""
  sleep(300)

  # 4. Geolocation & Flag Metadata (GeoLocation)
  echo "[4] Geolocation & Flag Metadata (GeoLocation):"
  let geoNl = initGeoLocation(
    ip = "185.220.101.5",
    countryCode = "NL",
    countryName = "Netherlands",
    flagEmoji = "🇳🇱",
    city = some("Amsterdam")
  )
  let geoLocal = initGeoLocation(
    ip = "192.168.1.10",
    countryCode = "LAN",
    countryName = "Private Network",
    flagEmoji = "🏠",
    isPrivate = true
  )
  echo "  Public IP Geo:      ", geoNl
  echo "  Internal LAN Geo:   ", geoLocal
  echo ""
  sleep(300)

  # 5. Distributed Multi-IP Correlation Cluster (ActorCluster)
  echo "[5] Multi-IP Distributed Actor Cluster (ActorCluster):"
  let cluster = newActorCluster(clusterId = "ACTOR-WP-BOTNET", primaryUa = "Masscan/1.3")
  let baseTime = dateTime(2026, mSep, 4, 1, 15, 0, 0, utc())

  # IP 1 probes wp-login.php
  let log1 = initHttpLogEntry(
    clientIp = "185.220.101.5",
    timestamp = baseTime,
    `method` = HttpPost,
    path = "/wp-login.php",
    statusCode = 404,
    userAgent = "Masscan/1.3"
  )
  cluster.addEntry(log1, score = 80, category = CategoryBadActorHacker, flags = {ThreatCmsExploit})

  # IP 2 probes xmlrpc.php 3 minutes later
  let log2 = initHttpLogEntry(
    clientIp = "194.26.29.11",
    timestamp = baseTime + initDuration(minutes = 3),
    `method` = HttpPost,
    path = "/xmlrpc.php",
    statusCode = 404,
    userAgent = "Masscan/1.3"
  )
  cluster.addEntry(log2, score = 95, category = CategoryBadActorHacker, flags = {ThreatCmsExploit})

  # IP 3 probes .env 7 minutes later
  let log3 = initHttpLogEntry(
    clientIp = "45.154.255.88",
    timestamp = baseTime + initDuration(minutes = 7),
    `method` = HttpGet,
    path = "/.env",
    statusCode = 404,
    userAgent = "Masscan/1.3"
  )
  cluster.addEntry(log3, score = 90, category = CategoryBadActorHacker, flags = {ThreatSensitiveFile})

  echo "  Cluster Summary:    ", cluster
  echo "  Distinct IPs:       ", cluster.ips
  echo "  Total Requests:     ", cluster.totalRequests
  echo "  404 Error Count:    ", cluster.status404Count
  echo "  Aggregate Risk:     ", cluster.aggregateRisk
  echo "  Probed Endpoints:   ", cluster.probedPaths
  echo ""
  sleep(300)

  # 6. Complete Enriched Event (EnrichedLogRecord)
  echo "[6] Complete Enriched Event Pipeline Envelope (EnrichedLogRecord):"
  let enriched = initEnrichedLogRecord(log1, geoNl, hackerProfile, some(cluster.clusterId))
  echo "  Enriched Line:      ", enriched
  echo "  Enriched JSON:      ", (%enriched).pretty(2)
  echo "================================================================================"

when isMainModule:
  main()

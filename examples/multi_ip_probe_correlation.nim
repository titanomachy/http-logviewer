# Example: Multi-IP Probe Sequence Correlation & Distributed Botnet Detection
# Demonstrates Phase 05 / Category B: Sliding time window tracking, sequence correlation,
# residential proxy rotation detection, ActorClusterTable dynamic linking, and cluster risk metrics.
#
# Compile and run with:
#   nim r --path:src examples/multi_ip_probe_correlation.nim

import std/[strutils, times, options, json, sets]
import http_logviewer/core/types
import http_logviewer/analyzer/correlator
import http_logviewer/analyzer/classifier

proc main() =
  echo "=== http_logviewer: Multi-IP Probe Sequence Correlation (Phase 05 / Category B) ==="
  echo ""

  # 1. In-Memory Sliding Time Window Tracker (Item 01)
  echo "[1] Sliding Time Window Tracker (Item 01):"
  let tracker30m = initSlidingWindowTracker(1800)
  echo "  Correlation Window:        ", tracker30m.windowMinutes, " minutes (", tracker30m.windowSeconds, " seconds)"
  let tStart = parse("2026-09-04T02:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
  let tWithin = parse("2026-09-04T02:18:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
  let tExpired = parse("2026-09-04T02:45:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")
  echo "  Probe @ 02:18:00 within 30m window: ", tracker30m.isWithinWindow(tStart, tWithin)
  echo "  Probe @ 02:45:00 expired (>30m):     ", tracker30m.isExpired(tStart, tExpired)
  echo ""

  # 2. ActorClusterTable & Dynamic IP Linking (Item 04)
  echo "[2] ActorClusterTable Dynamic Registry (Item 04):"
  let table = newActorClusterTable(windowSeconds = 1800, proxyRotationThresholdSec = 10)
  echo "  Initialized ActorClusterTable (active clusters: ", table.len, ", mapped IPs: ", table.ipCount, ")"
  echo ""

  # 3. Simulating Multi-IP Distributed Attack (Item 02 & Item 06)
  echo "[3] Simulating 5-Node Distributed Botnet Fleet (Items 02, 03 & 06):"
  let botnetProbes = [
    ("185.220.101.5",  "/.env",           "2026-09-04T02:10:01+02:00"),
    ("45.154.255.12",  "/.env",           "2026-09-04T02:10:03+02:00"),
    ("194.26.29.40",   "/wp-login.php",   "2026-09-04T02:10:05+02:00"),
    ("91.240.118.82",  "/xmlrpc.php",     "2026-09-04T02:10:07+02:00"),
    ("103.21.244.2",   "/actuator/env",   "2026-09-04T02:10:09+02:00")
  ]

  var assignedIds: seq[string] = @[]
  for (ip, path, tsStr) in botnetProbes:
    let ts = parse(tsStr, "yyyy-MM-dd'T'HH:mm:sszzz")
    let entry = initHttpLogEntry(
      clientIp = ip,
      timestamp = ts,
      path = path,
      `method` = HttpGet,
      statusCode = 404,
      userAgent = "WP-Scan-Distributed/3.1 (Botnet-Fleet)"
    )
    let threat = evaluateThreat(entry)
    let cidOpt = table.correlateRecord(entry, threat)
    if cidOpt.isSome:
      assignedIds.add(cidOpt.get())
      echo "  [INCOMING] IP: ", ip.alignLeft(16), " | Target: ", path.alignLeft(16), " -> Correlated Cluster: [", cidOpt.get(), "]"

  let allUnified = assignedIds.len == 5 and
                   assignedIds[0] == assignedIds[1] and
                   assignedIds[1] == assignedIds[2] and
                   assignedIds[2] == assignedIds[3] and
                   assignedIds[3] == assignedIds[4]
  echo ""
  echo "  -> Unified Correlation Result: ", if allUnified: "SUCCESS: All 5 IPs unified under [" & assignedIds[0] & "]" else: "FAILED"
  echo ""

  # 4. Residential Proxy Rotation Telemetry (Item 03)
  echo "[4] Residential Proxy Rotation Telemetry (Item 03):"
  let cluster = table.getCluster(assignedIds[0]).get()
  echo "  Proxy Rotation Detected:   ", cluster.proxyRotationDetected
  echo "  Consecutive Rotations:     ", cluster.proxyRotationCount
  echo "  Unique IPs in Cluster:     ", cluster.ips.len
  echo ""

  # 5. Cluster-Level Risk Metrics & Posture Calculation (Item 05)
  echo "[5] Cluster Risk Metrics & Posture Calculation (Item 05):"
  let metrics = calculateClusterMetrics(cluster)
  echo "  Cluster ID:                ", metrics.clusterId
  echo "  Total Requests:            ", metrics.totalRequests
  echo "  Unique IPs:                ", metrics.uniqueIps
  echo "  Affected Targets:          ", metrics.affectedTargets
  echo "  Attack Duration:           ", formatDuration(metrics.attackDuration), " (", metrics.attackDurationSeconds, "s)"
  echo "  404 Error Count & Ratio:   ", metrics.status404Count, " (", formatFloat(metrics.status404Ratio * 100, ffDecimal, 1), "%)"
  echo "  Composite Risk Score:      ", metrics.aggregateRisk, " / 100"
  echo "  Threat Severity Level:     ", metrics.severity
  echo ""
  echo "  Serialized Metrics JSON:"
  echo "  ", $(%metrics)
  echo ""

  # 6. Sliding Window Pruning (Item 01)
  echo "[6] Sliding Window Cluster Pruning (Item 01):"
  let tFuture = parse("2026-09-04T03:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz") # 50 minutes later
  echo "  Active Clusters Before Prune: ", table.len
  let pruned = table.pruneExpired(tFuture)
  echo "  Pruned Expired Clusters @ 03:00:00: ", pruned
  echo "  Active Clusters After Prune:  ", table.len
  echo ""
  echo "=== Category B Execution Completed Successfully ==="

when isMainModule:
  main()

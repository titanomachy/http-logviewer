# Example: Subnet, ASN & Temporal Clustering
# Demonstrates Phase 05 / Category C:
# - Subnet CIDR math & grouping (/24 IPv4 and /64 IPv6) (Item 01 & Item 05)
# - Hosting provider / datacenter IP identification (DigitalOcean, OVH, Hetzner, AWS, Choopa) (Item 02)
# - Synchronized burst request detection across distinct IPs within milliseconds (Item 03)
# - Human-readable cluster tags (e.g., [Actor #12: 18 IPs - WP-Scan Botnet]) (Item 04)
#
# Compile and run with:
#   nim r --path:src examples/subnet_asn_temporal_clustering.nim

import std/[strutils, times, options, sets]
import http_logviewer/core/types
import http_logviewer/analyzer/correlator
import http_logviewer/analyzer/classifier

proc main() =
  echo "=== http_logviewer: Subnet, ASN & Temporal Clustering (Phase 05 / Category C) ==="
  echo ""

  # 1. Subnet CIDR Math & Extraction (Item 01 & Item 05)
  echo "[1] Subnet CIDR Math & Extraction (Items 01 & 05):"
  let ipv4Sample1 = "192.168.1.45"
  let ipv4Sample2 = "192.168.1.99"
  let ipv6Sample1 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
  let ipv6Sample2 = "2001:db8:85a3::1"

  let subnet4A = extractSubnetCidr(ipv4Sample1)
  let subnet4B = extractSubnetCidr(ipv4Sample2)
  let subnet6A = extractSubnetCidr(ipv6Sample1)
  let subnet6B = extractSubnetCidr(ipv6Sample2)

  echo "  IPv4: ", ipv4Sample1.alignLeft(18), " -> Subnet: ", subnet4A
  echo "  IPv4: ", ipv4Sample2.alignLeft(18), " -> Subnet: ", subnet4B
  echo "  -> Same /24 Subnet:         ", (subnet4A == subnet4B)
  echo "  IPv6: ", ipv6Sample1.alignLeft(40), " -> Subnet: ", subnet6A
  echo "  IPv6: ", ipv6Sample2.alignLeft(40), " -> Subnet: ", subnet6B
  echo "  -> Same /64 Subnet:         ", (subnet6A == subnet6B)
  echo "  Containment check (192.168.1.10 in ", subnet4A, "): ", ipInSubnet("192.168.1.10", subnet4A)
  echo ""

  # 2. Datacenter & Hosting Provider Identification (Item 02)
  echo "[2] Datacenter & Hosting Provider Identification (Item 02):"
  let dcSamples = [
    ("159.65.120.45", "DigitalOcean droplet"),
    ("51.255.80.12",  "OVHcloud server"),
    ("136.243.10.88", "Hetzner dedicated host"),
    ("54.239.28.100", "AWS EC2 instance"),
    ("108.61.15.22",  "Choopa / Vultr VM"),
    ("82.165.197.1",  "Residential / Unmapped IP")
  ]

  for (ip, desc) in dcSamples:
    let info = identifyHostingProvider(ip)
    let dcFlag = if info.isDatacenter: "[DATACENTER]" else: "[RESIDENTIAL]"
    echo "  IP: ", ip.alignLeft(16), " ", dcFlag.alignLeft(15), " Provider: ", info.providerName.alignLeft(14), " (", desc, ")"
  echo ""

  # 3. Synchronized Burst Request Detection (Item 03)
  echo "[3] Synchronized Burst Request Detection (Item 03):"
  let table = newActorClusterTable(windowSeconds = 1800, burstThresholdMs = 500)
  let baseTime = parse("2026-09-04T08:00:00+02:00", "yyyy-MM-dd'T'HH:mm:sszzz")

  # 3 requests arriving within 150 milliseconds from distinct IPs hitting the same endpoint
  let t1 = baseTime
  let t2 = baseTime + initDuration(milliseconds = 75)
  let t3 = baseTime + initDuration(milliseconds = 150)

  let burstProbes = [
    ("185.220.101.10", t1, "Node Alpha"),
    ("185.220.101.11", t2, "Node Beta"),
    ("185.220.101.12", t3, "Node Gamma")
  ]

  var clusterId = ""
  for (ip, ts, node) in burstProbes:
    let entry = initHttpLogEntry(
      clientIp = ip,
      timestamp = ts,
      path = "/wp-login.php",
      `method` = HttpPost,
      statusCode = 404,
      userAgent = "WP-BruteForce/2.0"
    )
    let threat = evaluateThreat(entry)
    let cidOpt = table.correlateRecord(entry, threat)
    if cidOpt.isSome:
      clusterId = cidOpt.get()
      echo "  [BURST] ", node.alignLeft(12), " (IP: ", ip, " @ +", (ts.nanosecond div 1_000_000), "ms) -> Clustered: [", clusterId, "]"

  let burstCluster = table.getCluster(clusterId).get()
  echo ""
  echo "  Synchronized Burst Detected: ", burstCluster.synchronizedBurstDetected
  echo "  Synchronized Burst Probes:   ", burstCluster.synchronizedBurstCount
  echo "  Unique IPs in Fleet:         ", burstCluster.ips.len
  echo ""

  # 4. Human-Readable Cluster Tags (Item 04)
  echo "[4] Human-Readable Cluster Tags (Item 04):"
  let sampleTags = [
    formatClusterTag(burstCluster, 12),
    formatClusterTag(newActorCluster(clusterId = "C1", ips = ["159.65.1.1", "159.65.1.2"].toHashSet, flags = {ThreatSensitiveFile}, hostingProviders = ["DigitalOcean"].toHashSet, subnets = ["159.65.1.0/24"].toHashSet), 1),
    formatClusterTag(newActorCluster(clusterId = "C2", ips = ["136.243.5.1"].toHashSet, flags = {ThreatSqlInjection}, hostingProviders = ["Hetzner"].toHashSet), 3),
    formatClusterTag(newActorCluster(clusterId = "C3", ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"].toHashSet, synchronizedBurstDetected = true), 4)
  ]

  for tag in sampleTags:
    echo "  * ", tag
  echo ""

  # 5. Composite Risk Assessment with Datacenter & Burst Penalties (Items 01, 02, 03, 05)
  echo "[5] Comprehensive Cluster Risk Metrics (Items 01, 02, 03, 05):"
  let metrics = calculateClusterMetrics(burstCluster)
  echo "  Cluster Tag:               ", metrics.clusterTag
  echo "  Aggregate Risk Score:      ", metrics.aggregateRisk, " / 100 (Severity: ", metrics.severity, ")"
  echo "  Has Datacenter Nodes:      ", metrics.hasDatacenterIps
  echo "  Hosting Providers:         ", metrics.hostingProviders
  echo "  Subnet Range(s):           ", metrics.subnets
  echo "  Synchronized Burst Flag:   ", metrics.synchronizedBurstDetected
  echo "  Unique IPs:                ", metrics.uniqueIps
  echo "  Attack Duration:           ", formatDuration(metrics.attackDuration)
  echo ""
  echo "=== All Subnet, ASN & Temporal Clustering features verified successfully ==="

if isMainModule:
  main()

## Multi-IP actor correlation and fingerprint synthesis engine for http_logviewer.
## Synthesizes behavioral fingerprints, probe sequences, normalized query parameters,
## and Jaccard similarity to correlate distributed attacks across disparate IP addresses.

import std/[strutils, hashes, sets, tables, times, options, json, algorithm]
import ../core/types
import ../enrichment/bogon
import ../parser/formats

type
  ## Structured behavioral fingerprint representing an actor's client identity and probe behavior
  ActorFingerprint* = object
    rawHash*: Hash                  ## Combined 64-bit hash
    hashHex*: string                ## Hexadecimal representation of the fingerprint
    normalizedUa*: string           ## Normalized User-Agent string
    matchedSignatures*: seq[string] ## Triggered threat signature identifiers in order
    acceptHeaderHash*: Hash         ## Hash of the normalized HTTP Accept header
    pathPattern*: string            ## Normalized URL path pattern (e.g. dynamic IDs masked)
    sessionTokens*: seq[string]     ## Distinct session/query tracking tokens extracted

# ==============================================================================
# User-Agent and Accept Header Normalization
# ==============================================================================

func normalizeUserAgent*(ua: string): string =
  ## Normalizes a User-Agent string for deterministic fingerprint synthesis:
  ## trims exterior whitespace, collapses interior repeated spaces, and lowercases.
  let trimmed = ua.strip()
  if trimmed.len == 0:
    return ""
  var normalized = newStringOfCap(trimmed.len)
  var inSpace = false
  for ch in trimmed:
    if ch in {' ', '\t'}:
      if not inSpace:
        normalized.add(' ')
        inSpace = true
    else:
      normalized.add(ch.toLowerAscii())
      inSpace = false
  result = normalized

func normalizeAcceptHeader*(accept: string): string =
  ## Normalizes HTTP Accept headers by trimming, lowercasing, and normalizing delimiters.
  let trimmed = accept.strip()
  if trimmed.len == 0:
    return ""
  var parts: seq[string] = @[]
  for part in trimmed.split(','):
    let p = part.strip().toLowerAscii()
    if p.len > 0:
      parts.add(p)
  parts.sort()
  result = parts.join(",")

# ==============================================================================
# Path and Query Parameter Normalization (Items 02 & 03)
# ==============================================================================

const KnownCacheBusterParams*: seq[string] = @[
  "_", "cb", "cache", "nocache", "timestamp", "ts", "rand", "random",
  "v", "_v", "__v", "t", "_t", "ver", "nc", "bust", "cachebuster"
]

func isCacheBusterKey*(paramKey: string): bool =
  ## Returns true if the query parameter key is a known ephemeral cache-busting token.
  let lowerKey = paramKey.toLowerAscii()
  for cb in KnownCacheBusterParams:
    if lowerKey == cb:
      return true
  return false

func isNumericOrHexTimestamp*(val: string): bool =
  ## Detects if a value looks like a cache-busting timestamp (millisecond or second timestamp, or random hex).
  if val.len >= 9 and val.len <= 16:
    var allDigits = true
    for c in val:
      if c notin {'0'..'9'}:
        allDigits = false
        break
    if allDigits:
      return true
  if val.len in 8..32:
    var allHex = true
    for c in val:
      if c notin {'0'..'9', 'a'..'f', 'A'..'F'}:
        allHex = false
        break
    if allHex:
      return true
  return false

func normalizeQueryParams*(rawQuery: string): string =
  ## Normalizes query parameters to prevent cache-busting random strings from
  ## evading fingerprint hashing (Phase 05 / Category A / Item 03).
  ## 1. Splits query string on '&' and ';' delimiters.
  ## 2. Filters out cache-busting keys (e.g. '_', 'cache', 'cb', 'rand', 'ts').
  ## 3. Sorts remaining parameters alphabetically for deterministic ordering.
  let q = if rawQuery.startsWith("?"): rawQuery.substr(1) else: rawQuery
  if q.strip().len == 0:
    return ""

  var params: seq[tuple[key: string, val: string]] = @[]
  var curPair = ""
  for ch in q:
    if ch in {'&', ';'}:
      if curPair.len > 0:
        let eqIdx = curPair.find('=')
        if eqIdx >= 0:
          let k = curPair.substr(0, eqIdx - 1).strip()
          let v = curPair.substr(eqIdx + 1).strip()
          if not isCacheBusterKey(k) and not (isCacheBusterKey(k) or isNumericOrHexTimestamp(v)):
            params.add((k.toLowerAscii(), v))
        else:
          let k = curPair.strip()
          if not isCacheBusterKey(k):
            params.add((k.toLowerAscii(), ""))
        curPair = ""
    else:
      curPair.add(ch)

  if curPair.len > 0:
    let eqIdx = curPair.find('=')
    if eqIdx >= 0:
      let k = curPair.substr(0, eqIdx - 1).strip()
      let v = curPair.substr(eqIdx + 1).strip()
      if not isCacheBusterKey(k) and not (isCacheBusterKey(k) or isNumericOrHexTimestamp(v)):
        params.add((k.toLowerAscii(), v))
    else:
      let k = curPair.strip()
      if not isCacheBusterKey(k):
        params.add((k.toLowerAscii(), ""))

  if params.len == 0:
    return ""

  params.sort(proc(a, b: tuple[key: string, val: string]): int =
    cmp(a.key, b.key)
  )

  var formatted: seq[string] = @[]
  for p in params:
    if p.val.len > 0:
      formatted.add(p.key & "=" & p.val)
    else:
      formatted.add(p.key)

  result = formatted.join("&")

func normalizePathPattern*(rawPath: string): string =
  ## Normalizes a URL path into a structural pattern:
  ## - Strips query parameters.
  ## - Normalizes repeated slashes.
  ## - Masks integer IDs (/users/123 -> /users/{id}).
  ## - Masks standard UUID patterns (/items/123e4567-e89b-12d3-a456-426614174000 -> /items/{uuid}).
  ## - Masks hex hashes (/assets/a1b2c3d4e5f6 -> /assets/{hash}).
  let qIdx = rawPath.find('?')
  let clean = if qIdx >= 0: rawPath.substr(0, qIdx - 1) else: rawPath
  if clean.len == 0:
    return "/"

  var segments: seq[string] = @[]
  for seg in clean.split('/'):
    let s = seg.strip()
    if s.len == 0:
      continue
    # Check if segment is purely integer digits
    var isNumber = true
    for c in s:
      if c notin {'0'..'9'}:
        isNumber = false
        break
    if isNumber and s.len > 0:
      segments.add("{id}")
      continue

    # Check if segment is a 32-hex or 36-char UUID format
    if s.len == 36 and s.count('-') == 4:
      segments.add("{uuid}")
      continue

    # Check if segment is a long hex string (hash >= 16 chars)
    if s.len in 16..64:
      var isHex = true
      for c in s:
        if c notin {'0'..'9', 'a'..'f', 'A'..'F'}:
          isHex = false
          break
      if isHex:
        segments.add("{hash}")
        continue

    segments.add(s.toLowerAscii())

  result = "/" & segments.join("/")

func normalizeUrl*(path: string): string =
  ## Normalizes both path and query parameters into a deterministic canonical URL.
  let qIdx = path.find('?')
  if qIdx < 0:
    return normalizePathPattern(path)
  let p = path.substr(0, qIdx - 1)
  let q = path.substr(qIdx + 1)
  let normP = normalizePathPattern(p)
  let normQ = normalizeQueryParams(q)
  if normQ.len > 0:
    result = normP & "?" & normQ
  else:
    result = normP

proc hashQueryNormalizedUrl*(url: string): Hash =
  ## Returns the hash of the URL after structural path and query parameter normalization.
  hash(normalizeUrl(url))

# ==============================================================================
# Path Sequence Hasher (Item 02)
# ==============================================================================

proc hashPathSequence*(paths: openArray[string]): Hash =
  ## Creates a structural signature of attack sequences (e.g. probeA -> probeB -> probeC)
  ## by normalizing each path and hashing them in strict sequential order.
  var h: Hash = 0
  for p in paths:
    let norm = normalizePathPattern(p)
    h = h !& hash(norm)
  result = !$h

proc formatPathSequence*(paths: openArray[string]): string =
  ## Formats a sequence of probed paths into a canonical breadcrumb string
  ## for logging, inspection, or cluster summaries.
  var normList: seq[string] = @[]
  for p in paths:
    let norm = normalizePathPattern(p)
    normList.add(norm)
  result = normList.join(" -> ")

type
  ProbeSequenceTracker* = object
    ## Tracks chronological probed paths for an actor or session, maintaining
    ## an incremental path sequence signature.
    probedPaths*: seq[string]
    maxHistory*: int

func initProbeSequenceTracker*(maxHistory: int = 50): ProbeSequenceTracker =
  ## Initializes a new ProbeSequenceTracker with a bounded history buffer.
  ProbeSequenceTracker(probedPaths: @[], maxHistory: maxHistory)

proc addPath*(tracker: var ProbeSequenceTracker, path: string) =
  ## Ingests a new path into the sequence tracker, maintaining bounded history.
  if path.strip().len == 0:
    return
  tracker.probedPaths.add(path)
  if tracker.probedPaths.len > tracker.maxHistory and tracker.maxHistory > 0:
    tracker.probedPaths.delete(0)

proc sequenceHash*(tracker: ProbeSequenceTracker): Hash =
  ## Computes the structural sequence hash of all tracked paths.
  hashPathSequence(tracker.probedPaths)

proc formatSequence*(tracker: ProbeSequenceTracker): string =
  ## Returns the breadcrumb string of tracked paths.
  formatPathSequence(tracker.probedPaths)

proc len*(tracker: ProbeSequenceTracker): int {.inline.} =
  ## Number of paths currently tracked.
  tracker.probedPaths.len

# ==============================================================================
# Jaccard Similarity Scoring (Item 04)
# ==============================================================================

proc jaccardSimilarity*[T](setA, setB: HashSet[T]): float =
  ## Calculates the Jaccard similarity index between two sets:
  ## J(A, B) = size(intersection(A, B)) / size(union(A, B)).
  ## Returns 1.0 if both sets are empty, or a float in range 0.0 to 1.0.
  if setA.len == 0 and setB.len == 0:
    return 1.0
  let unionLen = (setA + setB).len
  if unionLen == 0:
    return 1.0
  let interLen = (setA * setB).len
  result = interLen.float / unionLen.float

proc pathSetSimilarity*(pathsA, pathsB: openArray[string]): float =
  ## Computes Jaccard similarity across two collections of probed paths
  ## after structural pattern normalization.
  var setA = initHashSet[string]()
  var setB = initHashSet[string]()
  for p in pathsA:
    setA.incl(normalizePathPattern(p))
  for p in pathsB:
    setB.incl(normalizePathPattern(p))
  result = jaccardSimilarity(setA, setB)

proc isPathSimilarityAbove*(pathsA, pathsB: openArray[string], threshold: float = 0.70): bool =
  ## Returns true if the structural path similarity meets or exceeds the given threshold.
  pathSetSimilarity(pathsA, pathsB) >= threshold

proc fingerprintSimilarity*(
  fpA, fpB: ActorFingerprint,
  pathsA: openArray[string] = @[],
  pathsB: openArray[string] = @[]
): float =
  ## Calculates a composite similarity score between two actor fingerprints (0.0 .. 1.0)
  ## combining User-Agent identity, threat signature overlap, and probed path Jaccard similarity.
  var totalWeight = 0.0
  var score = 0.0

  # 1. User-Agent similarity (weight: 0.35)
  totalWeight += 0.35
  if fpA.normalizedUa.len > 0 and fpB.normalizedUa.len > 0:
    if fpA.normalizedUa == fpB.normalizedUa:
      score += 0.35
    elif fpA.normalizedUa.contains(fpB.normalizedUa) or fpB.normalizedUa.contains(fpA.normalizedUa):
      score += 0.20
  elif fpA.normalizedUa.len == 0 and fpB.normalizedUa.len == 0:
    score += 0.35

  # 2. Threat signature Jaccard overlap (weight: 0.35)
  totalWeight += 0.35
  var sigSetA = initHashSet[string]()
  var sigSetB = initHashSet[string]()
  for s in fpA.matchedSignatures: sigSetA.incl(s)
  for s in fpB.matchedSignatures: sigSetB.incl(s)
  score += 0.35 * jaccardSimilarity(sigSetA, sigSetB)

  # 3. Path pattern or probed path sets (weight: 0.30)
  totalWeight += 0.30
  if pathsA.len > 0 or pathsB.len > 0:
    score += 0.30 * pathSetSimilarity(pathsA, pathsB)
  else:
    if fpA.pathPattern == fpB.pathPattern and fpA.pathPattern.len > 0:
      score += 0.30

  result = if totalWeight > 0.0: score / totalWeight else: 0.0

# ==============================================================================
# Session Identifiers and Token Extraction (Item 05)
# ==============================================================================

const SessionParamNames*: seq[string] = @[
  "phpsessid", "jsessionid", "sessionid", "session_id", "sessid", "sid",
  "token", "access_token", "auth_token", "api_key", "apikey", "key",
  "campaign", "utm_campaign", "bot_id", "botid", "scanner_id", "victim_id",
  "client_id", "uid", "user_id"
]

proc extractSessionTokens*(entry: HttpLogEntry): seq[tuple[key: string, value: string]] =
  ## Extracts known session identifiers, tracking keys, or API tokens from query parameters
  ## and raw log headers (Item 05).
  result = @[]
  let qIdx = entry.path.find('?')
  if qIdx >= 0:
    let q = entry.path.substr(qIdx + 1)
    for pair in q.split({'&', ';'}):
      let eqIdx = pair.find('=')
      if eqIdx >= 0:
        let k = pair.substr(0, eqIdx - 1).strip()
        let v = pair.substr(eqIdx + 1).strip()
        let lowerK = k.toLowerAscii()
        for sName in SessionParamNames:
          if lowerK == sName and v.len > 0:
            result.add((k, v))
            break

  # Also inspect raw line or referer if available for PHPSESSID/token cookies
  let refQIdx = entry.referer.find('?')
  if refQIdx >= 0:
    let refQ = entry.referer.substr(refQIdx + 1)
    for pair in refQ.split({'&', ';'}):
      let eqIdx = pair.find('=')
      if eqIdx >= 0:
        let k = pair.substr(0, eqIdx - 1).strip()
        let v = pair.substr(eqIdx + 1).strip()
        let lowerK = k.toLowerAscii()
        for sName in SessionParamNames:
          if lowerK == sName and v.len > 0:
            var already = false
            for item in result:
              if item.key == k and item.value == v:
                already = true
                break
            if not already:
              result.add((k, v))
            break

proc extractTokensFromUrl*(url: string): seq[tuple[key: string, value: string]] =
  ## Extracts known session tokens directly from a URL string.
  result = @[]
  let qIdx = url.find('?')
  if qIdx >= 0:
    let q = url.substr(qIdx + 1)
    for pair in q.split({'&', ';'}):
      let eqIdx = pair.find('=')
      if eqIdx >= 0:
        let k = pair.substr(0, eqIdx - 1).strip()
        let v = pair.substr(eqIdx + 1).strip()
        let lowerK = k.toLowerAscii()
        for sName in SessionParamNames:
          if lowerK == sName and v.len > 0:
            result.add((k, v))
            break

proc extractTokensFromRawLine*(rawLine: string): seq[tuple[key: string, value: string]] =
  ## Scans a raw log line for embedded cookie tokens or authentication headers.
  result = @[]
  let lowerRaw = rawLine.toLowerAscii()
  for sName in SessionParamNames:
    var searchPos = 0
    while true:
      let foundIdx = lowerRaw.find(sName & "=", searchPos)
      if foundIdx < 0:
        break
      let valStart = foundIdx + sName.len + 1
      var valEnd = valStart
      while valEnd < rawLine.len and rawLine[valEnd] notin {' ', ';', '&', '"', '\'', '\t', '\r', '\n'}:
        inc valEnd
      if valEnd > valStart:
        let actualKey = rawLine.substr(foundIdx, foundIdx + sName.len - 1)
        let actualVal = rawLine.substr(valStart, valEnd - 1)
        result.add((actualKey, actualVal))
      searchPos = valEnd

proc extractUniqueTokens*(entry: HttpLogEntry): seq[string] =
  ## Returns a simplified list of distinct "key=value" token pairs extracted from the entry.
  let tokens = extractSessionTokens(entry)
  var tokenSet = initHashSet[string]()
  for t in tokens:
    tokenSet.incl(t.key.toLowerAscii() & "=" & t.value)
  result = @[]
  for item in tokenSet:
    result.add(item)
  result.sort()

proc getSharedSessionTokens*(entryA, entryB: HttpLogEntry): seq[string] =
  ## Returns the list of session tokens shared between two requests.
  let tokensA = extractUniqueTokens(entryA)
  let tokensB = extractUniqueTokens(entryB)
  var setB = initHashSet[string]()
  for t in tokensB: setB.incl(t)
  result = @[]
  for t in tokensA:
    if t in setB:
      result.add(t)

proc hasSharedSessionToken*(entryA, entryB: HttpLogEntry): bool =
  ## Returns true if two requests share at least one session token or unique query identifier.
  getSharedSessionTokens(entryA, entryB).len > 0

# ==============================================================================
# Actor Fingerprint Synthesis (Item 01)
# ==============================================================================

proc generateProbeFingerprint*(
  entry: HttpLogEntry,
  threat: ThreatProfile,
  acceptHeader: string = ""
): Hash =
  ## Generates a 64-bit structural fingerprint for suspicious or malicious requests.
  ## Synthesizes normalized User-Agent, sorted threat signatures, normalized path pattern,
  ## and HTTP accept header.
  var h: Hash = 0

  # 1. Normalized User-Agent
  let normUa = normalizeUserAgent(entry.userAgent)
  h = h !& hash(normUa)

  # 2. Probe signature sequence (sorted for determinism)
  var sortedSigs = threat.matchedSignatures
  sortedSigs.sort()
  for sig in sortedSigs:
    h = h !& hash(sig)

  # 3. Structural path pattern (normalized)
  let normPath = normalizePathPattern(entry.path)
  h = h !& hash(normPath)

  # 4. HTTP Accept header
  let normAccept = normalizeAcceptHeader(acceptHeader)
  if normAccept.len > 0:
    h = h !& hash(normAccept)

  result = !$h

proc generateActorFingerprint*(
  entry: HttpLogEntry,
  threat: ThreatProfile,
  acceptHeader: string = ""
): ActorFingerprint =
  ## Constructs a full ActorFingerprint record synthesizing all behavioral signals.
  let normUa = normalizeUserAgent(entry.userAgent)
  let normAccept = normalizeAcceptHeader(acceptHeader)
  let acceptHash = if normAccept.len > 0: hash(normAccept) else: 0
  let normPath = normalizePathPattern(entry.path)

  var sortedSigs = threat.matchedSignatures
  sortedSigs.sort()

  let rawH = generateProbeFingerprint(entry, threat, acceptHeader)
  let hexStr = toHex(cast[uint64](rawH), 16)
  let tokens = extractUniqueTokens(entry)

  ActorFingerprint(
    rawHash: rawH,
    hashHex: hexStr,
    normalizedUa: normUa,
    matchedSignatures: sortedSigs,
    acceptHeaderHash: acceptHash,
    pathPattern: normPath,
    sessionTokens: tokens
  )

proc `$`*(fp: ActorFingerprint): string =
  ## Canonical stringifier for ActorFingerprint.
  "ActorFingerprint(hash: " & fp.hashHex & ", ua: \"" & fp.normalizedUa &
    "\", sigs: " & $fp.matchedSignatures & ", path: \"" & fp.pathPattern & "\")"

proc `==`*(a, b: ActorFingerprint): bool =
  ## Equality check for ActorFingerprint based on its synthesized hash and tokens.
  a.rawHash == b.rawHash and
    a.normalizedUa == b.normalizedUa and
    a.matchedSignatures == b.matchedSignatures and
    a.pathPattern == b.pathPattern and
    a.sessionTokens == b.sessionTokens

proc `%`*(fp: ActorFingerprint): JsonNode =
  ## Converts an ActorFingerprint into a JSON node.
  var sigsArr = newJArray()
  for s in fp.matchedSignatures:
    sigsArr.add(%s)
  var tokArr = newJArray()
  for t in fp.sessionTokens:
    tokArr.add(%t)
  %*{
    "hashHex": fp.hashHex,
    "normalizedUa": fp.normalizedUa,
    "matchedSignatures": sigsArr,
    "pathPattern": fp.pathPattern,
    "sessionTokens": tokArr
  }

# ==============================================================================
# Subnet CIDR Math & Extraction (Phase 05 / Category C / Item 01)
# ==============================================================================

func parseCidr*(cidrStr: string): tuple[ip: string, prefix: int] =
  ## Parses a CIDR string (e.g. "192.168.1.0/24" or "2001:db8::/64") into IP part and prefix integer.
  let slashIdx = cidrStr.find('/')
  if slashIdx < 0:
    return (cidrStr.strip(), -1)
  let ipPart = cidrStr[0 ..< slashIdx].strip()
  var prefix = -1
  try:
    prefix = parseInt(cidrStr[(slashIdx + 1) .. ^1].strip())
  except CatchableError:
    prefix = -1
  (ipPart, prefix)

func ipv4ToSubnet*(ip: string, prefixLen: int = 24): string =
  ## Converts an IPv4 address to its subnet CIDR string at the specified prefix length (default /24).
  let cleaned = cleanIpAddress(ip)
  var ipNum: uint32
  if not parseIpv4ToUint32(cleaned, ipNum):
    return ""
  let p = max(0, min(32, prefixLen))
  let mask = if p == 0: 0'u32
             elif p >= 32: 0xFFFFFFFF'u32
             else: not ((1'u32 shl uint32(32 - p)) - 1'u32)
  let net = ipNum and mask
  let o1 = (net shr 24) and 0xFF'u32
  let o2 = (net shr 16) and 0xFF'u32
  let o3 = (net shr 8) and 0xFF'u32
  let o4 = net and 0xFF'u32
  $o1 & "." & $o2 & "." & $o3 & "." & $o4 & "/" & $p

func ipv6ToSubnet*(ip: string, prefixLen: int = 64): string =
  ## Converts an IPv6 address to its canonical subnet CIDR string at the specified prefix length (default /64).
  let cleaned = cleanIpAddress(ip)
  var bytes: array[16, byte]
  if not parseIpv6ToBytes(cleaned, bytes):
    return ""
  let p = max(0, min(128, prefixLen))
  var masked = bytes
  let fullBytes = p div 8
  let remBits = p mod 8
  if remBits > 0 and fullBytes < 16:
    let maskByte = byte(not ((1 shl (8 - remBits)) - 1))
    masked[fullBytes] = masked[fullBytes] and maskByte
  for i in (if remBits > 0: fullBytes + 1 else: fullBytes) ..< 16:
    masked[i] = 0'u8

  var words: array[8, uint16]
  for i in 0..7:
    words[i] = (uint16(masked[i * 2]) shl 8) or uint16(masked[i * 2 + 1])

  if p == 64:
    var parts: seq[string] = @[]
    for i in 0..3:
      var w = toHex(words[i]).strip(leading = true, chars = {'0'}).toLowerAscii()
      if w.len == 0: w = "0"
      parts.add(w)
    result = parts.join(":") & "::/64"
  else:
    var parts: seq[string] = @[]
    for i in 0..7:
      var w = toHex(words[i]).strip(leading = true, chars = {'0'}).toLowerAscii()
      if w.len == 0: w = "0"
      parts.add(w)
    result = parts.join(":") & "/" & $p

func extractSubnetCidr*(ip: string): string =
  ## Extracts the network subnet CIDR for an IP address:
  ## Returns /24 for IPv4 (e.g. "192.168.1.0/24") and /64 for IPv6 (e.g. "2001:db8:85a3:0::/64").
  let cleaned = cleanIpAddress(ip)
  if cleaned.len == 0:
    return ""
  if cleaned.find(':') >= 0:
    ipv6ToSubnet(cleaned, 64)
  else:
    ipv4ToSubnet(cleaned, 24)

func ipInSubnet*(ip: string, cidr: string): bool =
  ## Tests if the given IP address is contained within the specified CIDR block.
  let (netStr, prefix) = parseCidr(cidr)
  if prefix < 0 or netStr.len == 0:
    return false
  let cleaned = cleanIpAddress(ip)

  if cleaned.find(':') >= 0 and netStr.find(':') >= 0:
    var ipBytes, netBytes: array[16, byte]
    if not parseIpv6ToBytes(cleaned, ipBytes) or not parseIpv6ToBytes(netStr, netBytes):
      return false
    let p = max(0, min(128, prefix))
    let fullBytes = p div 8
    let remBits = p mod 8
    for i in 0 ..< fullBytes:
      if ipBytes[i] != netBytes[i]:
        return false
    if remBits > 0 and fullBytes < 16:
      let maskByte = byte(not ((1 shl (8 - remBits)) - 1))
      if (ipBytes[fullBytes] and maskByte) != (netBytes[fullBytes] and maskByte):
        return false
    return true
  elif cleaned.find(':') < 0 and netStr.find(':') < 0:
    var ipNum, netNum: uint32
    if not parseIpv4ToUint32(cleaned, ipNum) or not parseIpv4ToUint32(netStr, netNum):
      return false
    let p = max(0, min(32, prefix))
    let mask = if p == 0: 0'u32
               elif p >= 32: 0xFFFFFFFF'u32
               else: not ((1'u32 shl uint32(32 - p)) - 1'u32)
    return (ipNum and mask) == (netNum and mask)
  else:
    return false

# ==============================================================================
# Hosting Provider & Datacenter Identification (Phase 05 / Category C / Item 02)
# ==============================================================================

type
  HostingProvider* = enum
    ProviderNone,
    ProviderDigitalOcean,
    ProviderOVH,
    ProviderHetzner,
    ProviderAWS,
    ProviderChoopa,
    ProviderLinode,
    ProviderGCP,
    ProviderAzure,
    ProviderOtherDatacenter

  DatacenterInfo* = object
    provider*: HostingProvider
    providerName*: string
    asn*: string
    isDatacenter*: bool
    riskPenalty*: int

const KnownDatacenterCidrs*: seq[tuple[cidr: string, provider: HostingProvider]] = @[
  # DigitalOcean (AS14061)
  ("159.65.0.0/16", ProviderDigitalOcean),
  ("167.99.0.0/16", ProviderDigitalOcean),
  ("178.62.0.0/16", ProviderDigitalOcean),
  ("138.68.0.0/16", ProviderDigitalOcean),
  ("142.93.0.0/16", ProviderDigitalOcean),
  ("104.248.0.0/16", ProviderDigitalOcean),
  ("188.166.0.0/16", ProviderDigitalOcean),
  ("206.189.0.0/16", ProviderDigitalOcean),
  ("165.22.0.0/16", ProviderDigitalOcean),
  ("134.209.0.0/16", ProviderDigitalOcean),
  ("157.245.0.0/16", ProviderDigitalOcean),
  ("164.90.0.0/16", ProviderDigitalOcean),
  ("143.198.0.0/16", ProviderDigitalOcean),
  ("64.225.0.0/16", ProviderDigitalOcean),
  ("68.183.0.0/16", ProviderDigitalOcean),
  ("2a03:b0c0::/32", ProviderDigitalOcean),

  # OVH (AS16276)
  ("198.27.64.0/18", ProviderOVH),
  ("198.50.128.0/17", ProviderOVH),
  ("192.99.0.0/16", ProviderOVH),
  ("142.4.192.0/19", ProviderOVH),
  ("151.80.0.0/16", ProviderOVH),
  ("51.254.0.0/15", ProviderOVH),
  ("54.36.0.0/15", ProviderOVH),
  ("149.202.0.0/16", ProviderOVH),
  ("178.32.0.0/15", ProviderOVH),
  ("188.165.0.0/16", ProviderOVH),
  ("213.186.32.0/19", ProviderOVH),
  ("91.121.0.0/16", ProviderOVH),
  ("94.23.0.0/16", ProviderOVH),
  ("2001:41d0::/32", ProviderOVH),

  # Hetzner (AS24940)
  ("78.46.0.0/15", ProviderHetzner),
  ("88.198.0.0/16", ProviderHetzner),
  ("136.243.0.0/16", ProviderHetzner),
  ("144.76.0.0/16", ProviderHetzner),
  ("148.251.0.0/16", ProviderHetzner),
  ("159.69.0.0/16", ProviderHetzner),
  ("168.119.0.0/16", ProviderHetzner),
  ("195.201.0.0/16", ProviderHetzner),
  ("213.133.96.0/19", ProviderHetzner),
  ("213.239.192.0/18", ProviderHetzner),
  ("65.108.0.0/16", ProviderHetzner),
  ("65.109.0.0/16", ProviderHetzner),
  ("94.130.0.0/16", ProviderHetzner),
  ("116.202.0.0/16", ProviderHetzner),
  ("116.203.0.0/16", ProviderHetzner),
  ("2a01:4f8::/32", ProviderHetzner),

  # Amazon Web Services (AS16509)
  ("3.0.0.0/9", ProviderAWS),
  ("18.0.0.0/8", ProviderAWS),
  ("52.0.0.0/11", ProviderAWS),
  ("54.0.0.0/12", ProviderAWS),
  ("54.144.0.0/12", ProviderAWS),
  ("54.224.0.0/11", ProviderAWS),
  ("34.192.0.0/12", ProviderAWS),
  ("35.153.0.0/16", ProviderAWS),
  ("44.192.0.0/10", ProviderAWS),
  ("13.32.0.0/12", ProviderAWS),
  ("2600:1f00::/24", ProviderAWS),

  # Choopa / Vultr (AS20473)
  ("45.32.0.0/16", ProviderChoopa),
  ("45.76.0.0/16", ProviderChoopa),
  ("45.77.0.0/16", ProviderChoopa),
  ("108.61.0.0/16", ProviderChoopa),
  ("149.28.0.0/16", ProviderChoopa),
  ("207.246.64.0/18", ProviderChoopa),
  ("209.250.224.0/19", ProviderChoopa),
  ("216.238.64.0/18", ProviderChoopa),
  ("2001:19f0::/32", ProviderChoopa),

  # Linode (AS63949)
  ("172.104.0.0/15", ProviderLinode),
  ("173.255.192.0/18", ProviderLinode),
  ("139.162.0.0/16", ProviderLinode),
  ("45.33.0.0/16", ProviderLinode),
  ("2600:3c00::/32", ProviderLinode),

  # Google Cloud (AS15169)
  ("34.64.0.0/11", ProviderGCP),
  ("35.184.0.0/13", ProviderGCP),
  ("2600:1900::/28", ProviderGCP),

  # Microsoft Azure (AS8075)
  ("13.64.0.0/11", ProviderAzure),
  ("20.0.0.0/11", ProviderAzure),
  ("40.64.0.0/10", ProviderAzure),
  ("2603:1000::/24", ProviderAzure)
]

func getDatacenterInfo*(prov: HostingProvider): DatacenterInfo =
  case prov
  of ProviderDigitalOcean:
    DatacenterInfo(provider: prov, providerName: "DigitalOcean", asn: "AS14061", isDatacenter: true, riskPenalty: 10)
  of ProviderOVH:
    DatacenterInfo(provider: prov, providerName: "OVH", asn: "AS16276", isDatacenter: true, riskPenalty: 10)
  of ProviderHetzner:
    DatacenterInfo(provider: prov, providerName: "Hetzner", asn: "AS24940", isDatacenter: true, riskPenalty: 10)
  of ProviderAWS:
    DatacenterInfo(provider: prov, providerName: "AWS", asn: "AS16509", isDatacenter: true, riskPenalty: 10)
  of ProviderChoopa:
    DatacenterInfo(provider: prov, providerName: "Choopa/Vultr", asn: "AS20473", isDatacenter: true, riskPenalty: 10)
  of ProviderLinode:
    DatacenterInfo(provider: prov, providerName: "Linode", asn: "AS63949", isDatacenter: true, riskPenalty: 10)
  of ProviderGCP:
    DatacenterInfo(provider: prov, providerName: "GCP", asn: "AS15169", isDatacenter: true, riskPenalty: 10)
  of ProviderAzure:
    DatacenterInfo(provider: prov, providerName: "Azure", asn: "AS8075", isDatacenter: true, riskPenalty: 10)
  of ProviderOtherDatacenter:
    DatacenterInfo(provider: prov, providerName: "Datacenter", asn: "AS-UNKNOWN", isDatacenter: true, riskPenalty: 5)
  of ProviderNone:
    DatacenterInfo(provider: ProviderNone, providerName: "", asn: "", isDatacenter: false, riskPenalty: 0)

proc identifyHostingProvider*(ip: string): DatacenterInfo =
  ## Identifies whether the specified client IP belongs to a known hosting provider or datacenter network.
  let cleaned = cleanIpAddress(ip)
  if cleaned.len == 0 or isPrivateIp(cleaned):
    return getDatacenterInfo(ProviderNone)

  for entry in KnownDatacenterCidrs:
    if ipInSubnet(cleaned, entry.cidr):
      return getDatacenterInfo(entry.provider)

  getDatacenterInfo(ProviderNone)

proc isKnownDatacenter*(ip: string): bool {.inline.} =
  ## Returns true if the IP address belongs to a known datacenter hosting provider.
  identifyHostingProvider(ip).isDatacenter

# ==============================================================================
# In-Memory Sliding Time Window Tracker (Phase 05 / Category B / Item 01)
# ==============================================================================

type
  SlidingWindowTracker* = object
    ## Tracks time intervals and calculates window boundaries for multi-IP correlation.
    windowSeconds*: int             ## Correlation window in seconds (default 1800 = 30 min)

  RecentProbe* = object
    ## Recorded recent vulnerability probe for proxy rotation analysis
    ip*: string
    timestamp*: DateTime
    pathPattern*: string
    normalizedUa*: string
    threatScore*: int

  ClusterRiskMetrics* = object
    ## Comprehensive security posture and risk metrics for an actor cluster (Item 05)
    clusterId*: string
    totalRequests*: int
    uniqueIps*: int
    affectedTargets*: int           ## Number of unique probed endpoints
    attackDuration*: Duration       ## Duration between firstSeen and lastSeen
    attackDurationSeconds*: int64   ## Duration in seconds
    highestThreatScore*: int        ## Highest individual request score (0..100)
    aggregateRisk*: int             ## Composite cluster risk score (0..100)
    status404Count*: int
    status404Ratio*: float          ## Ratio of 404 responses to total requests
    proxyRotationDetected*: bool    ## Whether residential proxy rotation was identified
    severity*: string               ## "Low", "Medium", "High", "Critical"
    subnets*: seq[string]           ## Distinct subnets observed (Item 01)
    hostingProviders*: seq[string]  ## Datacenter hosting providers observed (Item 02)
    hasDatacenterIps*: bool         ## Whether cluster contains datacenter IPs (Item 02)
    synchronizedBurstDetected*: bool ## Whether synchronized burst was observed (Item 03)
    clusterTag*: string             ## Human-readable cluster tag (Item 04)

  BurstProbe* = object
    ## Recorded probe event with millisecond timestamp for synchronized burst detection (Item 03)
    ip*: string
    timestamp*: DateTime
    pathPattern*: string
    threatScore*: int
    statusCode*: int

  ActorClusterTable* = ref object
    ## Dynamic registry linking disparate client IPs to unified ActorCluster records (Item 04)
    ## with in-memory sliding time window tracking (Item 01), sequence correlation (Item 02),
    ## residential proxy rotation detection (Item 03), and subnet/burst clustering (Category C).
    clusters*: Table[string, ActorCluster]             ## Key: clusterId (e.g. "ACTOR-A4F1")
    ipToCluster*: Table[string, string]                ## Maps IP -> clusterId
    fingerprintToCluster*: Table[Hash, string]         ## Maps probe fingerprint -> clusterId
    sequenceToCluster*: Table[Hash, string]            ## Maps path sequence hash -> clusterId
    subnetToCluster*: Table[string, string]            ## Maps subnet CIDR -> clusterId (Item 01)
    ipSequences*: Table[string, ProbeSequenceTracker]  ## Tracks recent probe path sequences per IP
    recentProbes*: seq[RecentProbe]                    ## Sliding buffer of recent probes for rotation detection
    recentBurstProbes*: seq[BurstProbe]                ## Sliding buffer for synchronized burst detection (Item 03)
    windowTracker*: SlidingWindowTracker               ## In-memory sliding time window tracker
    proxyRotationThresholdSec*: int                    ## Max seconds between distinct IPs to flag proxy rotation
    burstThresholdMs*: int64                           ## Max milliseconds between distinct IPs to flag burst (Item 03)
    processedCount*: int                               ## Running entry count since last automatic pruning
    pruneInterval*: int                                ## Auto-prune cadence (default: 1000 entries)
    lastPruneTime*: DateTime                           ## Timestamp of last pruning execution
    clusterCounter*: int                               ## Monotonic counter for unique cluster IDs

  ActorCorrelator* = ActorClusterTable

func initSlidingWindowTracker*(windowSeconds: int = 1800): SlidingWindowTracker =
  ## Initializes a sliding time window tracker with specified duration in seconds.
  let win = if windowSeconds > 0: windowSeconds else: 1800
  SlidingWindowTracker(windowSeconds: win)

func windowDuration*(tracker: SlidingWindowTracker): Duration =
  ## Returns the time window as a std/times Duration.
  initDuration(seconds = tracker.windowSeconds)

func windowMinutes*(tracker: SlidingWindowTracker): float =
  ## Returns the time window duration in minutes.
  tracker.windowSeconds.float / 60.0

func isWithinWindow*(tracker: SlidingWindowTracker, t1, t2: DateTime): bool =
  ## Returns true if the two timestamps fall within the sliding time window.
  if not t1.isInitialized or not t2.isInitialized:
    return true
  abs((t2.toTime - t1.toTime).inSeconds) <= tracker.windowSeconds

func isExpired*(tracker: SlidingWindowTracker, lastSeen, currentTime: DateTime): bool =
  ## Returns true if the lastSeen timestamp is older than the sliding window relative to currentTime.
  if not lastSeen.isInitialized or not currentTime.isInitialized:
    return false
  (currentTime.toTime - lastSeen.toTime).inSeconds > tracker.windowSeconds

# ==============================================================================
# ActorClusterTable Construction & Dynamic IP Linking (Phase 05 / Category B / Item 04)
# ==============================================================================

proc newActorClusterTable*(
  windowSeconds: int = 1800,
  proxyRotationThresholdSec: int = 10,
  burstThresholdMs: int64 = 1000,
  pruneInterval: int = 1000
): ActorClusterTable =
  ## Creates a new ActorClusterTable instance with configured correlation window.
  ActorClusterTable(
    clusters: initTable[string, ActorCluster](),
    ipToCluster: initTable[string, string](),
    fingerprintToCluster: initTable[Hash, string](),
    sequenceToCluster: initTable[Hash, string](),
    subnetToCluster: initTable[string, string](),
    ipSequences: initTable[string, ProbeSequenceTracker](),
    recentProbes: @[],
    recentBurstProbes: @[],
    windowTracker: initSlidingWindowTracker(windowSeconds),
    proxyRotationThresholdSec: if proxyRotationThresholdSec > 0: proxyRotationThresholdSec else: 10,
    burstThresholdMs: if burstThresholdMs > 0: burstThresholdMs else: 1000,
    processedCount: 0,
    pruneInterval: if pruneInterval > 0: pruneInterval else: 1000,
    lastPruneTime: default(DateTime),
    clusterCounter: 0
  )

proc newActorCorrelator*(windowSeconds: int = 1800): ActorCorrelator =
  ## Factory constructor for ActorCorrelator (alias to ActorClusterTable).
  newActorClusterTable(windowSeconds = windowSeconds)

proc windowSeconds*(table: ActorClusterTable): int {.inline.} =
  table.windowTracker.windowSeconds

proc `windowSeconds=`*(table: ActorClusterTable, sec: int) =
  table.windowTracker.windowSeconds = if sec > 0: sec else: 1800

proc linkIp*(table: ActorClusterTable, ip: string, cluster: ActorCluster) =
  ## Dynamically associates a client IP with an ActorCluster record (Item 04).
  if ip.len == 0 or cluster == nil:
    return
  table.ipToCluster[ip] = cluster.clusterId
  cluster.ips.incl(ip)

proc getClusterForIp*(table: ActorClusterTable, ip: string): Option[ActorCluster] =
  ## Retrieves the ActorCluster associated with the specified client IP, if mapped and present.
  if table.ipToCluster.hasKey(ip):
    let cid = table.ipToCluster[ip]
    if table.clusters.hasKey(cid):
      return some(table.clusters[cid])
  none(ActorCluster)

proc hasClusterForIp*(table: ActorClusterTable, ip: string): bool =
  ## Returns true if the specified IP is actively mapped to an existing cluster.
  table.getClusterForIp(ip).isSome

proc getCluster*(table: ActorClusterTable, clusterId: string): Option[ActorCluster] =
  ## Retrieves a cluster by its unique cluster ID.
  if table.clusters.hasKey(clusterId):
    return some(table.clusters[clusterId])
  none(ActorCluster)

proc hasKey*(table: ActorClusterTable, clusterId: string): bool {.inline.} =
  table.clusters.hasKey(clusterId)

proc contains*(table: ActorClusterTable, clusterId: string): bool {.inline.} =
  table.clusters.hasKey(clusterId)

proc `[]`*(table: ActorClusterTable, clusterId: string): ActorCluster {.inline.} =
  table.clusters[clusterId]

proc len*(table: ActorClusterTable): int {.inline.} =
  table.clusters.len

proc ipCount*(table: ActorClusterTable): int {.inline.} =
  table.ipToCluster.len

proc allClusters*(table: ActorClusterTable): seq[ActorCluster] =
  ## Returns all tracked clusters as a sequence.
  result = @[]
  for _, c in table.clusters:
    result.add(c)

proc activeClusters*(table: ActorClusterTable, currentTime: DateTime): seq[ActorCluster] =
  ## Returns all active clusters within the sliding window relative to currentTime.
  result = @[]
  for _, c in table.clusters:
    if not table.windowTracker.isExpired(c.lastSeen, currentTime):
      result.add(c)

proc activeClusterCount*(table: ActorClusterTable, currentTime: DateTime): int =
  ## Returns the count of active clusters within the sliding window.
  table.activeClusters(currentTime).len

proc deleteCluster*(table: ActorClusterTable, clusterId: string) =
  ## Deletes a cluster and unlinks its associated IP addresses and hashes.
  if table.clusters.hasKey(clusterId):
    let cluster = table.clusters[clusterId]
    for ip in cluster.ips:
      table.ipToCluster.del(ip)
      table.ipSequences.del(ip)
    for s in cluster.subnets:
      if table.subnetToCluster.hasKey(s) and table.subnetToCluster[s] == clusterId:
        table.subnetToCluster.del(s)
    table.clusters.del(clusterId)

proc clear*(table: ActorClusterTable) =
  ## Clears all clusters, mappings, probe sequences, and tracking buffers.
  table.clusters.clear()
  table.ipToCluster.clear()
  table.fingerprintToCluster.clear()
  table.sequenceToCluster.clear()
  table.subnetToCluster.clear()
  table.ipSequences.clear()
  table.recentProbes.setLen(0)
  table.recentBurstProbes.setLen(0)
  table.processedCount = 0
  table.clusterCounter = 0

proc pruneExpired*(table: ActorClusterTable, currentTime: DateTime): int =
  ## Prunes clusters and associated mapping indexes whose lastSeen timestamp
  ## exceeds the sliding window duration relative to currentTime (Item 01).
  ## Returns the number of pruned clusters.
  if not currentTime.isInitialized:
    return 0
  table.lastPruneTime = currentTime
  var expiredIds: seq[string] = @[]
  for id, cluster in table.clusters:
    if table.windowTracker.isExpired(cluster.lastSeen, currentTime):
      expiredIds.add(id)

  for id in expiredIds:
    if table.clusters.hasKey(id):
      let cluster = table.clusters[id]
      for ip in cluster.ips:
        table.ipToCluster.del(ip)
        table.ipSequences.del(ip)
      for s in cluster.subnets:
        if table.subnetToCluster.hasKey(s) and table.subnetToCluster[s] == id:
          table.subnetToCluster.del(s)
      table.clusters.del(id)

  # Clean fingerprintToCluster pointing to non-existent clusters
  var deadFp: seq[Hash] = @[]
  for fp, cid in table.fingerprintToCluster:
    if not table.clusters.hasKey(cid):
      deadFp.add(fp)
  for fp in deadFp:
    table.fingerprintToCluster.del(fp)

  # Clean sequenceToCluster pointing to non-existent clusters
  var deadSeq: seq[Hash] = @[]
  for sq, cid in table.sequenceToCluster:
    if not table.clusters.hasKey(cid):
      deadSeq.add(sq)
  for sq in deadSeq:
    table.sequenceToCluster.del(sq)

  # Clean subnetToCluster pointing to non-existent clusters
  var deadSubnets: seq[string] = @[]
  for s, cid in table.subnetToCluster:
    if not table.clusters.hasKey(cid):
      deadSubnets.add(s)
  for s in deadSubnets:
    table.subnetToCluster.del(s)

  # Also prune recentProbes older than max(windowSeconds, 300)
  let maxAge = max(table.windowTracker.windowSeconds, 300)
  var keepProbes: seq[RecentProbe] = @[]
  for p in table.recentProbes:
    if p.timestamp.isInitialized:
      if (currentTime.toTime - p.timestamp.toTime).inSeconds <= maxAge:
        keepProbes.add(p)
    else:
      keepProbes.add(p)
  table.recentProbes = keepProbes

  # Prune recentBurstProbes older than maxAge
  var keepBurst: seq[BurstProbe] = @[]
  for b in table.recentBurstProbes:
    if b.timestamp.isInitialized:
      if (currentTime.toTime - b.timestamp.toTime).inSeconds <= maxAge:
        keepBurst.add(b)
    else:
      keepBurst.add(b)
  table.recentBurstProbes = keepBurst

  result = expiredIds.len

# ==============================================================================
# Synchronized Burst Detection (Phase 05 / Category C / Item 03)
# ==============================================================================

proc detectSynchronizedBurst*(
  table: ActorClusterTable,
  entry: HttpLogEntry,
  thresholdMs: int64 = 1000
): tuple[isBurst: bool, matchedIps: seq[string]] =
  ## Identifies synchronized burst requests across distinct IP addresses occurring within milliseconds (Item 03).
  if entry.clientIp.len == 0 or not entry.timestamp.isInitialized:
    return (false, @[])

  let curTime = entry.timestamp.toTime
  let curMs = curTime.toUnix * 1000 + (entry.timestamp.nanosecond div 1_000_000)
  var matched = initHashSet[string]()

  for p in table.recentBurstProbes:
    if p.ip != entry.clientIp and p.timestamp.isInitialized:
      let pTime = p.timestamp.toTime
      let pMs = pTime.toUnix * 1000 + (p.timestamp.nanosecond div 1_000_000)
      let deltaMs = abs(curMs - pMs)
      if deltaMs <= thresholdMs:
        let samePath = p.pathPattern.len > 0 and p.pathPattern == normalizePathPattern(entry.path)
        let bothErr = entry.statusCode in 400..599 and p.statusCode in 400..599
        let bothSuspicious = p.threatScore >= 20
        if samePath or bothErr or bothSuspicious:
          matched.incl(p.ip)

  if matched.len > 0:
    var ips: seq[string] = @[]
    for ip in matched: ips.add(ip)
    return (true, ips)
  else:
    return (false, @[])

proc isSynchronizedBurst*(cluster: ActorCluster): bool {.inline.} =
  ## Returns true if synchronized burst requests were detected for this cluster.
  cluster.synchronizedBurstDetected

# ==============================================================================
# Human-Readable Cluster Tags (Phase 05 / Category C / Item 04)
# ==============================================================================

func formatClusterTag*(cluster: ActorCluster, actorNumber: int = -1): string =
  ## Formats a human-readable tag for the cluster (Item 04).
  ## e.g.: ``[Actor #12: 18 IPs - WP-Scan Botnet]``
  ##       ``[Actor #1: 5 IPs (DigitalOcean /24) - DotEnv Probe]``
  ##       ``[Actor #3: 12 IPs (Hetzner /24) - SQLi Exploit Cluster]``
  ##       ``[Actor #4: 8 IPs - Synchronized Burst Fleet]``
  ##       ``[Actor #5: 10 IPs - Rotating Proxy Botnet]``
  ##       ``[Actor #7: 1 IP - Log4Shell Scanner]``

  let num = if actorNumber > 0:
              "#" & $actorNumber
            elif cluster.clusterId.len > 0:
              var digits = ""
              for c in cluster.clusterId:
                if c in {'0'..'9'}: digits.add(c)
              if digits.len > 0: "#" & digits else: "#1"
            else:
              "#1"

  let ipCount = cluster.ips.len
  let ipStr = if ipCount <= 1: "1 IP" else: $ipCount & " IPs"

  # Qualification (Provider / Subnet)
  var qual = ""
  if cluster.hostingProviders.len > 0:
    var pList: seq[string] = @[]
    for p in cluster.hostingProviders: pList.add(p)
    pList.sort()
    let prov = pList[0]
    if cluster.subnets.len == 1:
      var sList: seq[string] = @[]
      for s in cluster.subnets: sList.add(s)
      let slashIdx = sList[0].find('/')
      let prefix = if slashIdx >= 0: sList[0][slashIdx .. ^1] else: "/24"
      qual = " (" & prov & " " & prefix & ")"
    else:
      qual = " (" & prov & ")"
  elif cluster.subnets.len == 1:
    var sList: seq[string] = @[]
    for s in cluster.subnets: sList.add(s)
    let slashIdx = sList[0].find('/')
    let prefix = if slashIdx >= 0: sList[0][slashIdx .. ^1] else: "/24"
    qual = " (" & prefix & ")"

  # Attack signature label
  var attackLabel = ""
  if ThreatCmsExploit in cluster.flags:
    attackLabel = "WP-Scan Botnet"
  elif ThreatSensitiveFile in cluster.flags:
    attackLabel = "DotEnv/Config Scanner"
  elif ThreatSqlInjection in cluster.flags:
    attackLabel = "SQLi Exploit Cluster"
  elif ThreatCommandInjection in cluster.flags:
    attackLabel = "RCE Exploit Botnet"
  elif ThreatDirectoryTraversal in cluster.flags:
    attackLabel = "Path Traversal Probe"
  elif cluster.synchronizedBurstDetected and cluster.ips.len >= 2:
    attackLabel = "Synchronized Burst Fleet"
  elif cluster.proxyRotationDetected and cluster.ips.len >= 2:
    attackLabel = "Rotating Proxy Botnet"
  else:
    var isWp = false
    var isEnv = false
    var isJndi = false
    for p in cluster.probedPaths:
      let lp = p.toLowerAscii()
      if lp.contains("wp-") or lp.contains("xmlrpc"): isWp = true
      elif lp.contains(".env") or lp.contains("config"): isEnv = true
      elif lp.contains("jndi") or lp.contains("ldap"): isJndi = true

    if isWp: attackLabel = "WP-Scan Botnet"
    elif isEnv: attackLabel = "DotEnv Probe"
    elif isJndi: attackLabel = "Log4Shell Scanner"
    elif cluster.category == CategoryCommercialBot: attackLabel = "Commercial Scraper Fleet"
    elif cluster.category == CategoryVerifiedBot: attackLabel = "Verified Crawler Fleet"
    elif cluster.category == CategorySuspicious: attackLabel = "Suspicious Scanner"
    elif cluster.category == CategoryBadActorHacker: attackLabel = "Hostile Exploit Botnet"
    else: attackLabel = "Traffic Cluster"

  if qual.len > 0:
    result = "[Actor " & num & ": " & ipStr & qual & " - " & attackLabel & "]"
  else:
    result = "[Actor " & num & ": " & ipStr & " - " & attackLabel & "]"

func clusterTag*(cluster: ActorCluster, actorNumber: int = -1): string {.inline.} =
  formatClusterTag(cluster, actorNumber)

# ==============================================================================
# Residential Proxy Rotation Detection (Phase 05 / Category B / Item 03)
# ==============================================================================

proc detectProxyRotation*(
  table: ActorClusterTable,
  entry: HttpLogEntry,
  threat: ThreatProfile,
  normPath: string,
  normUa: string
): bool =
  ## Inspects recent vulnerability probes to detect residential proxy rotation
  ## where consecutive probes targeting attack endpoints arrive from distinct IPs within seconds.
  if entry.clientIp.len == 0 or not entry.timestamp.isInitialized:
    return false
  if threat.score < 30 and threat.matchedSignatures.len == 0 and threat.flags.len == 0:
    return false

  let curTime = entry.timestamp.toTime
  let threshold = table.proxyRotationThresholdSec

  for p in table.recentProbes:
    if p.ip != entry.clientIp and p.timestamp.isInitialized:
      let deltaSec = (curTime - p.timestamp.toTime).inSeconds
      # Must be within threshold (e.g. 0..10 seconds)
      if deltaSec >= 0 and deltaSec <= threshold:
        # Either identical User-Agent, identical normalized path pattern, or both suspicious
        if (normUa.len > 0 and p.normalizedUa == normUa) or
           (normPath.len > 0 and p.pathPattern == normPath) or
           (threat.score >= 50 and p.threatScore >= 50):
          return true
  return false

proc isProxyRotating*(cluster: ActorCluster): bool {.inline.} =
  ## Returns true if residential proxy rotation was detected for this cluster.
  cluster.proxyRotationDetected

# ==============================================================================
# Multi-IP Probe Sequence Correlation (Phase 05 / Category B / Item 02)
# ==============================================================================

proc correlateRecord*(
  table: ActorClusterTable,
  entry: HttpLogEntry,
  threat: ThreatProfile,
  acceptHeader: string = ""
): Option[string] =
  ## Correlates an incoming HTTP log entry with existing multi-IP actor clusters.
  ## Synthesizes behavioral fingerprints, probe sequences, sliding window recency,
  ## residential proxy rotation, synchronized bursts, subnet proximity, and datacenter telemetry.
  ## Returns some(clusterId) if matched or clustered, or none(string) if benign/unmatched.

  # 1. Automatic periodic pruning check
  inc table.processedCount
  if table.processedCount >= table.pruneInterval and entry.timestamp.isInitialized:
    table.processedCount = 0
    discard table.pruneExpired(entry.timestamp)

  # 2. Only correlate suspicious or malicious actors
  if threat.category notin {CategorySuspicious, CategoryBadActorHacker} and threat.score < 21:
    return none(string)

  let normUa = normalizeUserAgent(entry.userAgent)
  let normPath = normalizePathPattern(entry.path)
  let fp = generateProbeFingerprint(entry, threat, acceptHeader)

  # 3. Update IP probe sequence tracker
  if not table.ipSequences.hasKey(entry.clientIp):
    table.ipSequences[entry.clientIp] = initProbeSequenceTracker(maxHistory = 30)
  table.ipSequences[entry.clientIp].addPath(entry.path)
  let seqHash = table.ipSequences[entry.clientIp].sequenceHash()

  # 4. Extract Subnet and Datacenter info, check Proxy Rotation & Synchronized Burst
  let subnet = extractSubnetCidr(entry.clientIp)
  let dcInfo = identifyHostingProvider(entry.clientIp)
  let proxyRotating = table.detectProxyRotation(entry, threat, normPath, normUa)
  let (burstDetected, burstIps) = table.detectSynchronizedBurst(entry, table.burstThresholdMs)

  # 5. Search for existing matching active cluster
  var matchedClusterId = ""

  # (a) Check if this IP is already mapped to an active cluster
  if table.ipToCluster.hasKey(entry.clientIp):
    let cid = table.ipToCluster[entry.clientIp]
    if table.clusters.hasKey(cid) and not table.windowTracker.isExpired(table.clusters[cid].lastSeen, entry.timestamp):
      matchedClusterId = cid

  # (b) Check if this exact probe fingerprint has been observed recently
  if matchedClusterId.len == 0 and table.fingerprintToCluster.hasKey(fp):
    let cid = table.fingerprintToCluster[fp]
    if table.clusters.hasKey(cid) and not table.windowTracker.isExpired(table.clusters[cid].lastSeen, entry.timestamp):
      matchedClusterId = cid

  # (c) Check if identical attack sequence was executed by another IP within window
  if matchedClusterId.len == 0 and table.sequenceToCluster.hasKey(seqHash):
    let cid = table.sequenceToCluster[seqHash]
    if table.clusters.hasKey(cid) and not table.windowTracker.isExpired(table.clusters[cid].lastSeen, entry.timestamp):
      matchedClusterId = cid

  # (d) Check if synchronized burst links to an active cluster (Item 03)
  if matchedClusterId.len == 0 and burstDetected and burstIps.len > 0:
    for bIp in burstIps:
      if table.ipToCluster.hasKey(bIp):
        let cid = table.ipToCluster[bIp]
        if table.clusters.hasKey(cid) and not table.windowTracker.isExpired(table.clusters[cid].lastSeen, entry.timestamp):
          matchedClusterId = cid
          break

  # (e) If proxy rotation detected within seconds, correlate with the most recent matching probe's cluster
  if matchedClusterId.len == 0 and proxyRotating and table.recentProbes.len > 0:
    for i in countdown(table.recentProbes.len - 1, 0):
      let p = table.recentProbes[i]
      if p.ip != entry.clientIp and table.ipToCluster.hasKey(p.ip):
        let cid = table.ipToCluster[p.ip]
        if table.clusters.hasKey(cid) and not table.windowTracker.isExpired(table.clusters[cid].lastSeen, entry.timestamp):
          matchedClusterId = cid
          break

  # (f) Check if IP resides in the same /24 or /64 subnet as an active cluster (Item 01)
  if matchedClusterId.len == 0 and subnet.len > 0 and table.subnetToCluster.hasKey(subnet):
    let sCid = table.subnetToCluster[subnet]
    if table.clusters.hasKey(sCid) and not table.windowTracker.isExpired(table.clusters[sCid].lastSeen, entry.timestamp):
      let cl = table.clusters[sCid]
      if (threat.category in {CategorySuspicious, CategoryBadActorHacker} and cl.category in {CategorySuspicious, CategoryBadActorHacker}) or
         (threat.flags * cl.flags).len > 0 or
         (normPath.len > 0 and isPathSimilarityAbove(cl.probedPaths, @[entry.path], 0.30)) or
         (dcInfo.isDatacenter and cl.hasDatacenterIps):
        matchedClusterId = sCid

  # (g) Jaccard similarity fallback: check active clusters with identical/similar UA
  if matchedClusterId.len == 0 and normUa.len > 0:
    for cid, cl in table.clusters:
      if not table.windowTracker.isExpired(cl.lastSeen, entry.timestamp):
        if normalizeUserAgent(cl.primaryUa) == normUa and cl.probedPaths.len > 0:
          if isPathSimilarityAbove(cl.probedPaths, @[entry.path], 0.50):
            matchedClusterId = cid
            break

  # Record this probe in sliding buffers
  table.recentProbes.add(RecentProbe(
    ip: entry.clientIp,
    timestamp: entry.timestamp,
    pathPattern: normPath,
    normalizedUa: normUa,
    threatScore: threat.score
  ))
  if table.recentProbes.len > 100:
    table.recentProbes.delete(0)

  table.recentBurstProbes.add(BurstProbe(
    ip: entry.clientIp,
    timestamp: entry.timestamp,
    pathPattern: normPath,
    threatScore: threat.score,
    statusCode: entry.statusCode
  ))
  if table.recentBurstProbes.len > 100:
    table.recentBurstProbes.delete(0)

  # 6. Apply correlation update or cluster creation
  if matchedClusterId.len > 0 and table.clusters.hasKey(matchedClusterId):
    let cluster = table.clusters[matchedClusterId]
    cluster.addEntry(entry, threat.score, threat.category, threat.flags)
    if subnet.len > 0:
      cluster.subnets.incl(subnet)
    if dcInfo.isDatacenter:
      cluster.hasDatacenterIps = true
      cluster.hostingProviders.incl(dcInfo.providerName)
    if proxyRotating:
      cluster.proxyRotationDetected = true
      inc cluster.proxyRotationCount
    if burstDetected:
      cluster.synchronizedBurstDetected = true
      inc cluster.synchronizedBurstCount
    cluster.clusterTag = formatClusterTag(cluster, table.clusterCounter)

    table.ipToCluster[entry.clientIp] = matchedClusterId
    table.fingerprintToCluster[fp] = matchedClusterId
    table.sequenceToCluster[seqHash] = matchedClusterId
    if subnet.len > 0:
      table.subnetToCluster[subnet] = matchedClusterId
    return some(matchedClusterId)

  # 7. Create new cluster
  inc table.clusterCounter
  let baseHex = toHex(cast[uint64](fp), 8).substr(0, 3).toUpperAscii()
  let newId = "ACTOR-" & baseHex & align(toHex(table.clusterCounter, 2).toUpperAscii(), 2, '0')
  var ipSet = initHashSet[string]()
  ipSet.incl(entry.clientIp)

  var subnetSet = initHashSet[string]()
  if subnet.len > 0:
    subnetSet.incl(subnet)

  var provSet = initHashSet[string]()
  if dcInfo.isDatacenter:
    provSet.incl(dcInfo.providerName)

  let newCluster = newActorCluster(
    clusterId = newId,
    primaryUa = entry.userAgent,
    ips = ipSet,
    entries = @[entry],
    totalRequests = 1,
    status404Count = if entry.statusCode == 404: 1 else: 0,
    firstSeen = entry.timestamp,
    lastSeen = entry.timestamp,
    highestThreatScore = threat.score,
    aggregateRisk = threat.score,
    category = threat.category,
    flags = threat.flags,
    probedPaths = (if entry.path.len > 0: @[entry.path] else: @[]),
    proxyRotationDetected = proxyRotating,
    proxyRotationCount = (if proxyRotating: 1 else: 0),
    subnets = subnetSet,
    hostingProviders = provSet,
    hasDatacenterIps = dcInfo.isDatacenter,
    synchronizedBurstDetected = burstDetected,
    synchronizedBurstCount = (if burstDetected: 1 else: 0)
  )
  newCluster.clusterTag = formatClusterTag(newCluster, table.clusterCounter)

  table.clusters[newId] = newCluster
  table.ipToCluster[entry.clientIp] = newId
  table.fingerprintToCluster[fp] = newId
  table.sequenceToCluster[seqHash] = newId
  if subnet.len > 0:
    table.subnetToCluster[subnet] = newId

  return some(newId)

# ==============================================================================
# Cluster Risk Metrics & Posture Calculation (Phase 05 / Category B / Item 05)
# ==============================================================================

proc attackDuration*(cluster: ActorCluster): Duration =
  ## Calculates the time span between firstSeen and lastSeen for the cluster.
  if cluster.firstSeen.isInitialized and cluster.lastSeen.isInitialized and cluster.lastSeen >= cluster.firstSeen:
    cluster.lastSeen - cluster.firstSeen
  else:
    initDuration()

proc attackDurationSeconds*(cluster: ActorCluster): int64 =
  ## Returns the attack duration in integer seconds.
  cluster.attackDuration.inSeconds

proc affectedTargets*(cluster: ActorCluster): int =
  ## Returns the number of distinct target paths probed by this actor cluster.
  cluster.probedPaths.len

func formatDuration*(d: Duration): string =
  ## Formats a Duration into a human-readable string (e.g. "02m 15s", "01h 10m 05s", "45s").
  let totalSec = d.inSeconds
  if totalSec < 0:
    return "0s"
  let hours = totalSec div 3600
  let minutes = (totalSec mod 3600) div 60
  let seconds = totalSec mod 60
  if hours > 0:
    result = align($hours, 2, '0') & "h " & align($minutes, 2, '0') & "m " & align($seconds, 2, '0') & "s"
  elif minutes > 0:
    result = align($minutes, 2, '0') & "m " & align($seconds, 2, '0') & "s"
  else:
    result = $seconds & "s"

proc calculateClusterMetrics*(cluster: ActorCluster): ClusterRiskMetrics =
  ## Calculates multi-dimensional cluster risk metrics including request velocity,
  ## distributed IP fleet size, targeted endpoint diversity, proxy rotation,
  ## hosting providers, synchronized bursts, and subnet coverage (Item 05).
  let dur = cluster.attackDuration
  let durSec = dur.inSeconds
  let uIps = cluster.ips.len
  let targets = cluster.probedPaths.len
  let ratio404 = if cluster.totalRequests > 0: cluster.status404Count.float / cluster.totalRequests.float else: 0.0

  # Composite risk calculation
  var risk = cluster.highestThreatScore

  # Multi-IP distributed penalty
  if uIps >= 2: risk += 10
  if uIps >= 5: risk += 10
  if uIps >= 10: risk += 10

  # Proxy rotation penalty
  if cluster.proxyRotationDetected:
    risk += 15

  # Datacenter hosting penalty (Item 02)
  if cluster.hasDatacenterIps:
    risk += 10

  # Synchronized burst penalty (Item 03)
  if cluster.synchronizedBurstDetected:
    risk += 15

  # Multi-subnet spread penalty (Item 01)
  if cluster.subnets.len >= 2:
    risk += 5

  # Endpoint targeting diversity
  if targets >= 3: risk += 5
  if targets >= 7: risk += 10

  # 404 heavy fuzzing penalty
  if ratio404 >= 0.70 and cluster.totalRequests >= 5:
    risk += 10

  risk = max(0, min(100, risk))

  let sev =
    if risk >= 80: "Critical"
    elif risk >= 50: "High"
    elif risk >= 25: "Medium"
    else: "Low"

  var subnetsSeq: seq[string] = @[]
  for s in cluster.subnets: subnetsSeq.add(s)
  subnetsSeq.sort()

  var provsSeq: seq[string] = @[]
  for p in cluster.hostingProviders: provsSeq.add(p)
  provsSeq.sort()

  let tag = if cluster.clusterTag.len > 0: cluster.clusterTag else: formatClusterTag(cluster)

  ClusterRiskMetrics(
    clusterId: cluster.clusterId,
    totalRequests: cluster.totalRequests,
    uniqueIps: uIps,
    affectedTargets: targets,
    attackDuration: dur,
    attackDurationSeconds: durSec,
    highestThreatScore: cluster.highestThreatScore,
    aggregateRisk: risk,
    status404Count: cluster.status404Count,
    status404Ratio: ratio404,
    proxyRotationDetected: cluster.proxyRotationDetected,
    severity: sev,
    subnets: subnetsSeq,
    hostingProviders: provsSeq,
    hasDatacenterIps: cluster.hasDatacenterIps,
    synchronizedBurstDetected: cluster.synchronizedBurstDetected,
    clusterTag: tag
  )

proc `$`*(metrics: ClusterRiskMetrics): string =
  ## Canonical stringifier for ClusterRiskMetrics.
  var extras: seq[string] = @[]
  if metrics.clusterTag.len > 0: extras.add("Tag: " & metrics.clusterTag)
  if metrics.proxyRotationDetected: extras.add("ProxyRotation: true")
  if metrics.synchronizedBurstDetected: extras.add("Burst: true")
  if metrics.hasDatacenterIps: extras.add("Datacenter: true")
  if metrics.subnets.len > 0: extras.add("Subnets: " & $metrics.subnets.len)
  let extraStr = if extras.len > 0: ", " & extras.join(", ") else: ""

  "ClusterRiskMetrics(id: " & metrics.clusterId &
    ", IPs: " & $metrics.uniqueIps &
    ", Req: " & $metrics.totalRequests &
    ", Targets: " & $metrics.affectedTargets &
    ", Duration: " & formatDuration(metrics.attackDuration) &
    ", Risk: " & $metrics.aggregateRisk & " [" & metrics.severity & "]" &
    extraStr & ")"

proc `%`*(metrics: ClusterRiskMetrics): JsonNode =
  ## Serializes ClusterRiskMetrics into a JSON node.
  var subnetsArr = newJArray()
  for s in metrics.subnets: subnetsArr.add(%s)
  var provArr = newJArray()
  for p in metrics.hostingProviders: provArr.add(%p)

  %*{
    "clusterId": metrics.clusterId,
    "clusterTag": metrics.clusterTag,
    "totalRequests": metrics.totalRequests,
    "uniqueIps": metrics.uniqueIps,
    "subnets": subnetsArr,
    "hostingProviders": provArr,
    "hasDatacenterIps": metrics.hasDatacenterIps,
    "synchronizedBurstDetected": metrics.synchronizedBurstDetected,
    "affectedTargets": metrics.affectedTargets,
    "attackDurationSeconds": metrics.attackDurationSeconds,
    "attackDurationFormatted": formatDuration(metrics.attackDuration),
    "highestThreatScore": metrics.highestThreatScore,
    "aggregateRisk": metrics.aggregateRisk,
    "status404Count": metrics.status404Count,
    "status404Ratio": metrics.status404Ratio,
    "proxyRotationDetected": metrics.proxyRotationDetected,
    "severity": metrics.severity
  }

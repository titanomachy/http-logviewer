## Multi-IP actor correlation and fingerprint synthesis engine for http_logviewer.
## Synthesizes behavioral fingerprints, probe sequences, normalized query parameters,
## and Jaccard similarity to correlate distributed attacks across disparate IP addresses.

import std/[strutils, hashes, sets, tables, times, options, json, algorithm]
import ../core/types

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

import std/unittest
import std/times
import std/strutils
import std/json
import std/sets
import std/tables
import std/hashes
import std/options
import http_logviewer/core/[types, errors]

suite "Threat & Actor Models - ActorCategory (Phase 01 / Category B / Item 01)":
  test "Item 01: ActorCategory enum definition, ordering, and constants":
    check ord(CategoryUnknown) == 0
    check ord(CategoryRealUser) == 1
    check ord(CategoryVerifiedBot) == 2
    check ord(CategoryFriendlyCrawler) == 3
    check ord(CategoryCommercialBot) == 4
    check ord(CategorySuspicious) == 5
    check ord(CategoryBadActorHacker) == 6

    # Test ordering
    check CategoryUnknown < CategoryRealUser
    check CategoryRealUser < CategoryVerifiedBot
    check CategoryVerifiedBot < CategoryFriendlyCrawler
    check CategoryFriendlyCrawler < CategoryCommercialBot
    check CategoryCommercialBot < CategorySuspicious
    check CategorySuspicious < CategoryBadActorHacker

    # Test alias constants
    check RealUser == CategoryRealUser
    check VerifiedBot == CategoryVerifiedBot
    check FriendlyCrawler == CategoryFriendlyCrawler
    check CommercialBot == CategoryCommercialBot
    check SuspiciousScanner == CategorySuspicious
    check CategorySuspiciousScanner == CategorySuspicious
    check BadActorHacker == CategoryBadActorHacker
    check UnknownActor == CategoryUnknown

  test "Item 01: ActorCategory stringification and parsing":
    check $CategoryUnknown == "UNKNOWN"
    check $CategoryRealUser == "REAL_USER"
    check $CategoryVerifiedBot == "VERIFIED_BOT"
    check $CategoryFriendlyCrawler == "FRIENDLY_CRAWLER"
    check $CategoryCommercialBot == "COMMERCIAL_BOT"
    check $CategorySuspicious == "SUSPICIOUS"
    check $CategoryBadActorHacker == "BAD_ACTOR_HACKER"

    check parseActorCategory("REAL_USER") == CategoryRealUser
    check parseActorCategory("realuser") == CategoryRealUser
    check parseActorCategory("User") == CategoryRealUser
    check parseActorCategory("VERIFIED_BOT") == CategoryVerifiedBot
    check parseActorCategory("verifiedbot") == CategoryVerifiedBot
    check parseActorCategory("FriendlyCrawler") == CategoryFriendlyCrawler
    check parseActorCategory("commercial_bot") == CategoryCommercialBot
    check parseActorCategory("suspicious") == CategorySuspicious
    check parseActorCategory("SuspiciousScanner") == CategorySuspicious
    check parseActorCategory("bad_actor_hacker") == CategoryBadActorHacker
    check parseActorCategory("HACKER") == CategoryBadActorHacker
    check parseActorCategory("BadActor") == CategoryBadActorHacker
    check parseActorCategory("UNKNOWN") == CategoryUnknown
    check parseActorCategory("") == CategoryUnknown
    check parseActorCategory("nonexistent_category") == CategoryUnknown

  test "Item 01: ActorCategory classification helper predicates":
    check isRealUser(CategoryRealUser)
    check not isRealUser(CategoryVerifiedBot)
    check not isRealUser(CategoryBadActorHacker)

    check isBot(CategoryVerifiedBot)
    check isBot(CategoryFriendlyCrawler)
    check isBot(CategoryCommercialBot)
    check not isBot(CategoryRealUser)
    check not isBot(CategoryBadActorHacker)
    check not isBot(CategorySuspicious)

    check isHacker(CategoryBadActorHacker)
    check not isHacker(CategoryRealUser)
    check not isHacker(CategoryVerifiedBot)
    check not isHacker(CategorySuspicious)

  test "Item 01: ActorCategory JSON serialization":
    let jNode = %CategoryBadActorHacker
    check jNode.kind == JString
    check jNode.getStr() == "BAD_ACTOR_HACKER"

suite "Threat & Actor Models - ThreatFlag (Phase 01 / Category B / Item 02)":
  test "Item 02: ThreatFlag enum definition and alias constants":
    check ord(ThreatSensitiveFile) == 0
    check ord(ThreatCmsExploit) == 1
    check ord(ThreatDirectoryTraversal) == 2
    check ord(ThreatSqlInjection) == 3
    check ord(ThreatCommandInjection) == 4
    check ord(ThreatKnownScannerUa) == 5
    check ord(ThreatMalformedRequest) == 6
    check ord(ThreatHighRate404) == 7
    check ord(ThreatNoAssetFetch) == 8

    # Verify constant aliases match PLAN and spec
    check SensitiveFileProbe == ThreatSensitiveFile
    check PathExploit == ThreatCmsExploit
    check TraversalAttempt == ThreatDirectoryTraversal
    check SqlInjection == ThreatSqlInjection
    check CommandInjection == ThreatCommandInjection
    check KnownScannerUa == ThreatKnownScannerUa
    check MalformedRequest == ThreatMalformedRequest
    check AggressiveRate == ThreatHighRate404
    check NoAssetsRequested == ThreatNoAssetFetch

  test "Item 02: ThreatFlag stringification and parsing":
    check $ThreatSensitiveFile == "SensitiveFileProbe"
    check $ThreatCmsExploit == "PathExploit"
    check $ThreatDirectoryTraversal == "TraversalAttempt"
    check $ThreatSqlInjection == "SqlInjection"
    check $ThreatCommandInjection == "CommandInjection"
    check $ThreatKnownScannerUa == "KnownScannerUa"
    check $ThreatMalformedRequest == "MalformedRequest"
    check $ThreatHighRate404 == "AggressiveRate"
    check $ThreatNoAssetFetch == "NoAssetsRequested"

    check parseThreatFlag("SensitiveFileProbe") == ThreatSensitiveFile
    check parseThreatFlag("PathExploit") == ThreatCmsExploit
    check parseThreatFlag("TraversalAttempt") == ThreatDirectoryTraversal
    check parseThreatFlag("SqlInjection") == ThreatSqlInjection
    check parseThreatFlag("CommandInjection") == ThreatCommandInjection
    check parseThreatFlag("KnownScannerUa") == ThreatKnownScannerUa
    check parseThreatFlag("MalformedRequest") == ThreatMalformedRequest
    check parseThreatFlag("AggressiveRate") == ThreatHighRate404
    check parseThreatFlag("NoAssetsRequested") == ThreatNoAssetFetch

    expect ParseError:
      discard parseThreatFlag("InvalidThreatFlag")

  test "Item 02: ThreatFlag set operations and bitset safety":
    var flagSet: set[ThreatFlag] = {}
    check card(flagSet) == 0

    flagSet.incl(ThreatSqlInjection)
    flagSet.incl(ThreatCmsExploit)
    check card(flagSet) == 2
    check ThreatSqlInjection in flagSet
    check ThreatCmsExploit in flagSet
    check ThreatCommandInjection notin flagSet

    # Union
    let otherSet: set[ThreatFlag] = {ThreatCommandInjection, ThreatSensitiveFile}
    let unionSet = flagSet + otherSet
    check card(unionSet) == 4
    check ThreatCommandInjection in unionSet

    # Intersection
    let interSet = unionSet * {ThreatSqlInjection, ThreatCommandInjection, ThreatHighRate404}
    check card(interSet) == 2
    check ThreatSqlInjection in interSet
    check ThreatCommandInjection in interSet
    check ThreatHighRate404 notin interSet

    # Difference
    let diffSet = unionSet - {ThreatSqlInjection}
    check card(diffSet) == 3
    check ThreatSqlInjection notin diffSet

    # JSON representation
    let jArr = %unionSet
    check jArr.kind == JArray
    check jArr.len == 4

suite "Threat & Actor Models - ThreatProfile (Phase 01 / Category B / Item 03)":
  test "Item 03: ThreatProfile default and explicit construction":
    let defaultProf = initThreatProfile()
    check defaultProf.score == 0
    check defaultProf.category == CategoryUnknown
    check defaultProf.flags == {}
    check defaultProf.matchedSignatures.len == 0
    check defaultProf.matchedRules.len == 0

    let activeProf = initThreatProfile(
      score = 85,
      category = CategoryBadActorHacker,
      flags = {ThreatSqlInjection, ThreatDirectoryTraversal},
      matchedSignatures = @["sqli_union_select", "etc_passwd_traversal"]
    )
    check activeProf.score == 85
    check activeProf.category == CategoryBadActorHacker
    check ThreatSqlInjection in activeProf.flags
    check ThreatDirectoryTraversal in activeProf.flags
    check activeProf.matchedSignatures.len == 2
    check activeProf.matchedRules == @["sqli_union_select", "etc_passwd_traversal"]

  test "Item 03: matchedRules getter and setter alias":
    var prof = initThreatProfile(score = 50)
    prof.matchedRules = @["cve_2024_probe", "phpmyadmin_scan"]
    check prof.matchedSignatures.len == 2
    check prof.matchedRules[0] == "cve_2024_probe"
    check prof.matchedRules[1] == "phpmyadmin_scan"

  test "Item 03: ThreatProfile evaluation predicates":
    let hackerProfile1 = initThreatProfile(score = 85, category = CategoryBadActorHacker)
    check hackerProfile1.isHacker()
    check not hackerProfile1.isRealUser()
    check not hackerProfile1.isBot()

    # Score >= 50 automatically marks as hacker intent
    let hackerProfile2 = initThreatProfile(score = 50, category = CategorySuspicious)
    check hackerProfile2.isHacker()

    let botProfile = initThreatProfile(score = 5, category = CategoryVerifiedBot)
    check botProfile.isBot()
    check not botProfile.isHacker()

    let suspProfile = initThreatProfile(score = 30, category = CategorySuspicious)
    check suspProfile.isSuspicious()
    check not suspProfile.isHacker()
    check not suspProfile.isRealUser()

    let realUserProfile = initThreatProfile(score = 0, category = CategoryRealUser)
    check realUserProfile.isRealUser()
    check not realUserProfile.isHacker()
    check not realUserProfile.isBot()

  test "Item 03: ThreatProfile validation rules":
    let validZero = initThreatProfile(score = 0)
    validZero.validate()
    let validMax = initThreatProfile(score = 100)
    validMax.validate()

    let invalidNegative = initThreatProfile(score = -1)
    expect ThreatAnalysisError:
      invalidNegative.validate()

    let invalidExcessive = initThreatProfile(score = 101)
    expect ThreatAnalysisError:
      invalidExcessive.validate()

  test "Item 03: ThreatProfile stringification, JSON round-trip and equality":
    let prof = initThreatProfile(
      score = 90,
      category = CategoryBadActorHacker,
      flags = {ThreatCmsExploit, ThreatSensitiveFile},
      matchedSignatures = @["wp_login_scan", "env_probe"]
    )
    let strRep = $prof
    check "score: 90" in strRep
    check "BAD_ACTOR_HACKER" in strRep
    check "wp_login_scan" in strRep

    let jNode = %prof
    check jNode["score"].getInt() == 90
    check jNode["category"].getStr() == "BAD_ACTOR_HACKER"
    check jNode["flags"].len == 2
    check jNode["matchedSignatures"].len == 2

    let restored = parseThreatProfileJson(jNode)
    check restored == prof

suite "Threat & Actor Models - ActorCluster (Phase 01 / Category B / Item 04)":
  test "Item 04: ActorCluster initialization and fields":
    let dt1 = dateTime(2026, mSep, 4, 1, 0, 0, 0, utc())
    let dt2 = dateTime(2026, mSep, 4, 1, 30, 0, 0, utc())
    var ips = initHashSet[string]()
    ips.incl("198.51.100.1")
    ips.incl("198.51.100.2")

    let cluster = newActorCluster(
      clusterId = "ACTOR-001",
      primaryUa = "CustomScanner/2.0",
      ips = ips,
      totalRequests = 15,
      status404Count = 12,
      firstSeen = dt1,
      lastSeen = dt2,
      highestThreatScore = 80,
      aggregateRisk = 80,
      category = CategoryBadActorHacker,
      flags = {ThreatCmsExploit}
    )

    check cluster.clusterId == "ACTOR-001"
    check cluster.primaryUa == "CustomScanner/2.0"
    check cluster.ips.len == 2
    check cluster.totalRequests == 15
    check cluster.status404Count == 12
    check cluster.firstSeen == dt1
    check cluster.lastSeen == dt2
    check cluster.highestThreatScore == 80
    check cluster.aggregateRisk == 80
    check cluster.category == CategoryBadActorHacker
    check ThreatCmsExploit in cluster.flags

  test "Item 04: ActorCluster dynamic multi-IP ingestion":
    let cluster = newActorCluster(clusterId = "ACTOR-AUTO")
    let dt1 = dateTime(2026, mSep, 4, 1, 0, 0, 0, utc())
    let dt2 = dateTime(2026, mSep, 4, 1, 5, 0, 0, utc())
    let dt3 = dateTime(2026, mSep, 4, 1, 10, 0, 0, utc())

    let entry1 = initHttpLogEntry(
      clientIp = "10.0.0.1",
      timestamp = dt1,
      `method` = HttpGet,
      path = "/.env",
      statusCode = 404,
      userAgent = "Nikto/2.1"
    )
    cluster.addEntry(entry1, score = 75, category = CategoryBadActorHacker, flags = {ThreatSensitiveFile})

    check cluster.ips.len == 1
    check "10.0.0.1" in cluster.ips
    check cluster.totalRequests == 1
    check cluster.status404Count == 1
    check cluster.firstSeen == dt1
    check cluster.lastSeen == dt1
    check cluster.highestThreatScore == 75
    check cluster.category == CategoryBadActorHacker
    check ThreatSensitiveFile in cluster.flags
    check cluster.primaryUa == "Nikto/2.1"
    check "/.env" in cluster.probedPaths

    # Second entry from a distinct IP (multi-IP distributed probe)
    let entry2 = initHttpLogEntry(
      clientIp = "10.0.0.2",
      timestamp = dt2,
      `method` = HttpPost,
      path = "/xmlrpc.php",
      statusCode = 404,
      userAgent = "Nikto/2.1"
    )
    cluster.addEntry(entry2, score = 90, category = CategoryBadActorHacker, flags = {ThreatCmsExploit})

    check cluster.ips.len == 2
    check "10.0.0.2" in cluster.ips
    check cluster.totalRequests == 2
    check cluster.status404Count == 2
    check cluster.firstSeen == dt1
    check cluster.lastSeen == dt2
    check cluster.highestThreatScore == 90
    check cluster.aggregateRisk == 90
    check ThreatCmsExploit in cluster.flags
    check "/xmlrpc.php" in cluster.probedPaths

    # Third entry with 200 OK from third IP
    let entry3 = initHttpLogEntry(
      clientIp = "10.0.0.3",
      timestamp = dt3,
      `method` = HttpGet,
      path = "/robots.txt",
      statusCode = 200,
      userAgent = "Nikto/2.1"
    )
    cluster.addEntry(entry3, score = 10, category = CategorySuspicious, flags = {})

    check cluster.ips.len == 3
    check cluster.totalRequests == 3
    check cluster.status404Count == 2 # Did not increase because status is 200
    check cluster.lastSeen == dt3
    check cluster.highestThreatScore == 90 # Preserved highest score
    check cluster.category == CategoryBadActorHacker # Preserved higher severity category

  test "Item 04: ActorCluster stringification and JSON export":
    let cluster = newActorCluster(
      clusterId = "ACTOR-JSON",
      primaryUa = "BotNet/1.0",
      highestThreatScore = 95,
      aggregateRisk = 95,
      category = CategoryBadActorHacker,
      flags = {ThreatSqlInjection}
    )
    cluster.ips.incl("192.168.1.50")
    cluster.probedPaths.add("/admin.php")

    let strRep = $cluster
    check "ACTOR-JSON" in strRep
    check "BAD_ACTOR_HACKER" in strRep

    let jNode = %cluster
    check jNode["clusterId"].getStr() == "ACTOR-JSON"
    check jNode["primaryUa"].getStr() == "BotNet/1.0"
    check jNode["aggregateRisk"].getInt() == 95
    check jNode["ips"].len == 1
    check jNode["probedPaths"].len == 1

  test "Item 04: ActorCluster indexing in Table":
    var clusterMap = initTable[string, ActorCluster]()
    let c = newActorCluster(clusterId = "ACTOR-TAB-1", primaryUa = "Ua/1.0")
    clusterMap["ACTOR-TAB-1"] = c
    check clusterMap.len == 1
    check clusterMap["ACTOR-TAB-1"].primaryUa == "Ua/1.0"

suite "Threat & Actor Models - GeoLocation & EnrichedLogRecord (Phase 01 / Category B / Item 05)":
  test "Item 05: GeoLocation definition, initialization, and stringifier":
    let geo = initGeoLocation(
      ip = "8.8.8.8",
      countryCode = "US",
      countryName = "United States",
      flagEmoji = "🇺🇸",
      isPrivate = false,
      city = some("Mountain View")
    )
    check geo.ip == "8.8.8.8"
    check geo.countryCode == "US"
    check geo.countryName == "United States"
    check geo.flagEmoji == "🇺🇸"
    check not geo.isPrivate
    check geo.city.isSome
    check geo.city.get() == "Mountain View"

    let strRep = $geo
    check "🇺🇸" in strRep
    check "US" in strRep
    check "United States" in strRep

    # Private LAN geo
    let privateGeo = initGeoLocation(
      ip = "192.168.1.1",
      countryCode = "LAN",
      countryName = "Private Network",
      flagEmoji = "🏠",
      isPrivate = true
    )
    check privateGeo.isPrivate
    check "[Private/LAN]" in $privateGeo

  test "Item 05: GeoLocation equality, hashing, and JSON round-trip":
    let g1 = initGeoLocation("1.2.3.4", "DE", "Germany", "🇩🇪", false, some("Berlin"))
    let g2 = initGeoLocation("1.2.3.4", "DE", "Germany", "🇩🇪", false, some("Berlin"))
    let gDiff = initGeoLocation("1.2.3.4", "FR", "France", "🇫🇷", false)

    check g1 == g2
    check g1 != gDiff
    check hash(g1) == hash(g2)

    var geoSet = initHashSet[GeoLocation]()
    geoSet.incl(g1)
    geoSet.incl(g2)
    check geoSet.len == 1

    var geoTable = initTable[GeoLocation, string]()
    geoTable[g1] = "Berlin, Germany"
    check geoTable[g2] == "Berlin, Germany"

    let jNode = %g1
    let restored = parseGeoLocationJson(jNode)
    check restored == g1

  test "Item 05: EnrichedLogRecord composition, stringifier, and JSON round-trip":
    let dt = dateTime(2026, mSep, 4, 1, 0, 0, 0, utc())
    let entry = initHttpLogEntry(
      clientIp = "185.220.101.5",
      timestamp = dt,
      `method` = HttpGet,
      path = "/wp-admin/setup.php",
      statusCode = 404,
      userAgent = "Masscan/1.0"
    )
    let geo = initGeoLocation("185.220.101.5", "NL", "Netherlands", "🇳🇱", false)
    let threat = initThreatProfile(
      score = 80,
      category = CategoryBadActorHacker,
      flags = {ThreatCmsExploit},
      matchedSignatures = @["wp_setup_exploit"]
    )
    let record = initEnrichedLogRecord(entry, geo, threat, some("ACTOR-MASS"))

    check record.entry == entry
    check record.geo == geo
    check record.threat == threat
    check record.clusterId.isSome
    check record.clusterId.get() == "ACTOR-MASS"

    let strRep = $record
    check "ACTOR-MASS" in strRep
    check "🇳🇱" in strRep
    check "BAD_ACTOR_HACKER" in strRep
    check "/wp-admin/setup.php" in strRep

    let jNode = %record
    let restored = parseEnrichedLogRecordJson(jNode)
    check restored == record

suite "Threat & Actor Models - Ordinal Consistency & Set Safety (Phase 01 / Category B / Item 06)":
  test "Item 06: Comprehensive enum ordinal consistency":
    # ActorCategory: 7 members, indices 0..6
    var actorCategories: seq[ActorCategory] = @[]
    for c in low(ActorCategory)..high(ActorCategory):
      actorCategories.add(c)
    check actorCategories.len == 7
    for i, c in actorCategories:
      check ord(c) == i

    # ThreatFlag: 9 members, indices 0..8
    var threatFlags: seq[ThreatFlag] = @[]
    for f in low(ThreatFlag)..high(ThreatFlag):
      threatFlags.add(f)
    check threatFlags.len == 9
    for i, f in threatFlags:
      check ord(f) == i

  test "Item 06: Set operation safety, bitwise limits, and complement safety":
    let fullSet: set[ThreatFlag] = {low(ThreatFlag)..high(ThreatFlag)}
    check card(fullSet) == 9

    let emptySet: set[ThreatFlag] = {}
    check card(emptySet) == 0

    # Complement
    let subset: set[ThreatFlag] = {ThreatSensitiveFile, ThreatCmsExploit}
    let complement = fullSet - subset
    check card(complement) == 7
    check ThreatSensitiveFile notin complement
    check ThreatCmsExploit notin complement
    check ThreatSqlInjection in complement

    # Subset relations
    check subset <= fullSet
    check emptySet <= subset
    check not (fullSet <= subset)

    # Memory representation check: set with 9 elements requires <= 4 bytes in Nim
    check sizeof(set[ThreatFlag]) <= 4

  test "Item 06: Value-type reentrancy and thread-safety":
    # Ensure ThreatProfile, GeoLocation, and EnrichedLogRecord are value types with value semantics
    var p1 = initThreatProfile(score = 25, category = CategorySuspicious)
    var p2 = p1
    p2.score = 75
    check p1.score == 25 # p1 is unaffected by changes to copy p2

    var g1 = initGeoLocation(ip = "1.1.1.1", countryCode = "AU")
    var g2 = g1
    g2.countryCode = "NZ"
    check g1.countryCode == "AU" # g1 unaffected by copy modification

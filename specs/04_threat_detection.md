# Specification 04: Rogue Bot & Bad Actor Detection Engine

## 1. Overview & Objective
This specification defines the threat classification and heuristic analysis engine for `http_logviewer`.
The analyzer inspects incoming `HttpLogEntry` records and calculates a composite **Risk Score (0–100)** and **ActorCategory** (`RealUser`, `VerifiedBot`, `FriendlyCrawler`, `CommercialBot`, `SuspiciousScanner`, `BadActorHacker`).
Implementation target: `src/http_logviewer/analyzer/signatures.nim`, `src/http_logviewer/analyzer/useragents.nim`, and `src/http_logviewer/analyzer/classifier.nim`.

---

## 2. Signature Databases (`signatures.nim`)

### 2.1 Sensitive File & Config Probes
A high-confidence indicator of hostile intent is probing for environment secrets, keys, and backups:
```nim
const SensitiveFileSignatures* = [
  "/.env", "/.git/config", "/.git/HEAD", "/.aws/credentials",
  "/wp-config.php", "/config.json", "/docker-compose.yml",
  "/id_rsa", "/id_dsa", "/id_ecdsa", "/.ssh/id_rsa",
  "/web.config", "/settings.py", "/database.yml",
  "/backup.sql", "/dump.sql", "/db.sql", "/backup.tar.gz",
  "/phpinfo.php", "/info.php", "/actuator/health", "/actuator/env"
]
```

### 2.2 Content Management System (CMS) & Web Admin Exploits
```nim
const CmsExploitSignatures* = [
  "/wp-login.php", "/xmlrpc.php", "/wp-admin/", "/wp-includes/",
  "/phpmyadmin", "/pma/", "/admin/pma/", "/mysql/",
  "/setup.php", "/install.php", "/boaform/admin/",
  "/solr/admin/", "/telescope/requests", "/debug/default/view"
]
```

### 2.3 Injection & Traversal Patterns (Regex / Normalized Scan)
```nim
const TraversalPatterns* = [
  "../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f", "%252e%252e%252f"
]

const SqlInjectionPatterns* = [
  "union+select", "union%20select", "select%20from", "information_schema",
  "' or '1'='1", "' or 1=1", "waitfor delay", "benchmark(", "sleep("
]

const CommandInjectionPatterns* = [
  ";id", "|id", "`id`", "$(whoami)", ";whoami", "|whoami",
  "/bin/sh", "/bin/bash", "cmd.exe", "${jndi:ldap", "${jndi:rmi"
]
```

---

## 3. User-Agent Taxonomy Engine (`useragents.nim`)

### 3.1 Known Offensive Tools & Scanners (Definite Hacker)
```nim
const OffensiveScannerUas* = [
  "sqlmap", "nikto", "masscan", "zgrab", "nuclei", "gobuster",
  "dirbuster", "nmap", "wpscan", "havij", "acunetix", "nessus",
  "qualys", "openvas", "arachni", "hydra", "medusa"
]
```

### 3.2 Verified Search Engine Bots (Legitimate)
```nim
const SearchEngineBots* = [
  ("googlebot", CategoryVerifiedBot),
  ("bingbot", CategoryVerifiedBot),
  ("duckduckbot", CategoryVerifiedBot),
  ("yandexbot", CategoryVerifiedBot),
  ("baiduspider", CategoryVerifiedBot),
  ("applebot", CategoryVerifiedBot)
]
```

### 3.3 Commercial & SEO Crawlers (Benign / Commercial Bots)
```nim
const CommercialCrawlers* = [
  ("ahrefsbot", CategoryCommercialBot),
  ("semrushbot", CategoryCommercialBot),
  ("mj12bot", CategoryCommercialBot),
  ("dotbot", CategoryCommercialBot),
  ("screaming frog", CategoryCommercialBot)
]
```

### 3.4 Automated Scripting Libraries (Suspicious unless authenticated)
```nim
const ScriptLibraries* = [
  "python-requests", "curl/", "wget/", "go-http-client", "aiohttp",
  "httpx", "urllib", "libwww-perl", "php/", "postmanruntime"
]
```

---

## 4. Heuristic Scoring Engine (`classifier.nim`)

### 4.1 Scoring Formula
The classifier computes an integer score from 0 to 100 based on weighted criteria:

| Trigger / Metric | Weight (Points) | ThreatFlag Triggered |
| :--- | :--- | :--- |
| Sensitive file probe (`.env`, `.git/config`, etc.) | +60 pts | `ThreatSensitiveFile` |
| Command injection / JNDI / RCE pattern | +75 pts | `ThreatCommandInjection` |
| SQL injection syntax in URI / query | +70 pts | `ThreatSqlInjection` |
| Directory traversal sequence (`../`) | +65 pts | `ThreatDirectoryTraversal` |
| CMS exploit probe (`wp-login.php`, `xmlrpc.php`) | +45 pts | `ThreatCmsExploit` |
| Offensive scanner User-Agent (`sqlmap`, `nikto`, etc.) | +80 pts | `ThreatKnownScannerUa` |
| Automated script User-Agent (`curl`, `python-requests`) | +20 pts | `ThreatSuspicious` |
| Empty / Missing User-Agent string | +15 pts | `ThreatMalformedRequest` |
| HTTP Status 404 on administrative path | +25 pts | `ThreatHighRate404` |
| Missing Referer on non-GET / non-HTML endpoint | +10 pts | `ThreatNoAssetFetch` |

### 4.2 Score to Category Mapping
```nim
proc evaluateThreat*(entry: HttpLogEntry): ThreatProfile =
  var score = 0
  var flags: set[ThreatFlag] = {}
  var matched: seq[string] = @[]
  
  # Check User-Agent first
  let uaLower = entry.userAgent.toLowerAscii()
  for (bot, cat) in SearchEngineBots:
    if bot in uaLower:
      return ThreatProfile(score: 0, category: cat, flags: {}, matchedSignatures: @[bot])
      
  for offensive in OffensiveScannerUas:
    if offensive in uaLower:
      score += 80
      flags.incl(ThreatKnownScannerUa)
      matched.add("Scanner:" & offensive)

  # Check Path Signatures
  let pathLower = entry.path.toLowerAscii()
  for sensitive in SensitiveFileSignatures:
    if sensitive in pathLower:
      score += 60
      flags.incl(ThreatSensitiveFile)
      matched.add("Sensitive:" & sensitive)
      
  for exploit in CmsExploitSignatures:
    if exploit in pathLower:
      score += 45
      flags.incl(ThreatCmsExploit)
      matched.add("CMS:" & exploit)

  for traversal in TraversalPatterns:
    if traversal in pathLower:
      score += 65
      flags.incl(ThreatDirectoryTraversal)
      matched.add("Traversal:" & traversal)

  for sqli in SqlInjectionPatterns:
    if sqli in pathLower:
      score += 70
      flags.incl(ThreatSqlInjection)
      matched.add("SQLi:" & sqli)

  for cmd in CommandInjectionPatterns:
    if cmd in pathLower:
      score += 75
      flags.incl(ThreatCommandInjection)
      matched.add("CmdInjection")

  # Cap score at 100
  let finalScore = min(100, score)
  
  # Determine Category
  var category: ActorCategory
  if finalScore >= 50:
    category = CategoryBadActorHacker
  elif finalScore >= 20:
    category = CategorySuspicious
  elif isCommercialCrawler(uaLower):
    category = CategoryCommercialBot
  else:
    category = CategoryRealUser

  return ThreatProfile(
    score: finalScore,
    category: category,
    flags: flags,
    matchedSignatures: matched
  )
```

---

## 5. False Positive Mitigation
1. Do not flag standard static assets (`.js`, `.css`, `.png`, `.jpg`, `.svg`, `.ico`, `.woff2`) as suspicious even if they result in a 404.
2. Allow query parameters with common word combinations unless strict SQL syntax (`SELECT`, `UNION`, `CONCAT`) is present.
3. Treat verified search engines (Googlebot, Bingbot) as `CategoryVerifiedBot` unless they exhibit severe path exploits.

---

## 6. Acceptance Criteria
- Unit tests in `tests/t_classifier.nim` verify that requests to `/.env`, `/wp-login.php`, or containing `union+select` produce `CategoryBadActorHacker` with score >= 50.
- Normal visitor requests (e.g., `GET /about-us` returning 200) yield `CategoryRealUser` and score < 15.
- Tests verify all offensive scanners in `OffensiveScannerUas` are flagged.

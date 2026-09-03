# Specification 06: Terminal Presentation & Color-Coded Rendering Engine

## 1. Overview & Objective
This specification defines the terminal rendering and visual presentation engine for `http_logviewer`.
The visual design must satisfy the user's primary formatting requirements:
1. **Background-Colored HTTP Response Codes**: Apply striking ANSI background colors to HTTP status codes (specifically bright red background for `404`, red/magenta for `5xx`, yellow for `3xx`, green for `2xx`).
2. **Flag with Country Name**: Clearly display the Unicode regional indicator flag and 2-letter ISO country code.
3. **Intent Badges**: Visually highlight `[REAL USER]`, `[GOOD BOT]`, `[SCRAPER]`, and `[HACKER]`.
4. **Grouped Actor Display**: Render an organized view grouping distinct IP addresses under their unified actor campaign.

Implementation target: `src/http_logviewer/renderer/styles.nim` and `src/http_logviewer/renderer/terminal.nim`.

---

## 2. ANSI Status Code Styling Matrix (`styles.nim`)

To provide immediate visual clarity, HTTP response codes are rendered with bold foreground text on high-contrast colored backgrounds:

```nim
import std/strutils

const
  Reset* = "\e[0m"
  Bold*  = "\e[1m"
  Dim*   = "\e[2m"

  # Status Code Background Colors
  BgRedBold*     = "\e[41;97;1m"    # 404 Not Found (Red background, bright white bold text)
  BgDarkRed*     = "\e[41;37m"      # 400, 401, 403 Forbidden (Red background, white text)
  BgBrightRed*   = "\e[101;97;1m"   # 500, 502, 503 Server Error (Bright red bg, white bold text)
  BgGreen*       = "\e[42;30m"      # 200, 201, 204 Success (Green background, black text)
  BgYellow*      = "\e[43;30m"      # 301, 302, 304 Redirect (Yellow background, black text)
  BgGray*        = "\e[100;97m"     # Other / Unknown

  # Intent Badges
  BadgeReal*     = "\e[32m[REAL USER]\e[0m"
  BadgeGoodBot*  = "\e[36m[GOOD BOT ]\e[0m"
  BadgeScraper*  = "\e[33m[SCRAPER  ]\e[0m"
  BadgeSuspicious* = "\e[38;5;208m[SUSPICIOUS]\e[0m"
  BadgeHacker*   = "\e[41;97;1m[ HACKER! ]\e[0m"

proc formatStatusCode*(code: int, colorize = true): string =
  ## Renders a 3-digit HTTP status code with high-contrast background coloring.
  let text = " " & $code & " "
  if not colorize:
    return text

  case code
  of 200..299:
    return BgGreen & text & Reset
  of 300..399:
    return BgYellow & text & Reset
  of 404:
    # Specifically required: Bold white on red background
    return BgRedBold & text & Reset
  of 400..499:
    return BgDarkRed & text & Reset
  of 500..599:
    return BgBrightRed & text & Reset
  else:
    return BgGray & text & Reset
```

---

## 3. Streaming Log View Layout (`terminal.nim`)

When streaming logs (via file or `tail -f` pipe), each event is formatted into aligned columns:

```
+---------------------------------------------------------------------------------------------------------------+
| TIME     | GEO   | STATUS | INTENT       | CLIENT IP       | METHOD PATH                 | USER-AGENT         |
+---------------------------------------------------------------------------------------------------------------+
| 13:55:01 | 🇺🇸 US | [200]  | [REAL USER]  | 172.56.21.89    | GET /blog/welcome           | Mozilla/5.0...     |
| 13:55:02 | 🇩🇪 DE | [404]  | [ HACKER! ]  | 194.26.29.112   | GET /.env                   | python-requests... |
| 13:55:03 | 🇳🇱 NL | [404]  | [ HACKER! ]  | 45.154.255.8    | GET /wp-login.php           | Mozilla/5.0...     |
| 13:55:04 | 🇺🇸 US | [200]  | [GOOD BOT ]  | 66.249.66.1     | GET /robots.txt             | Googlebot/2.1...   |
+---------------------------------------------------------------------------------------------------------------+
```

### Rendering Procedure:
```nim
proc renderStreamLine*(record: EnrichedLogRecord, colorize: bool): string =
  let timeStr = record.entry.timestamp.format("HH:mm:ss")
  let geoStr  = record.geo.flagEmoji & " " & record.geo.countryCode
  let statusStr = formatStatusCode(record.entry.statusCode, colorize)
  let intentBadge = formatIntentBadge(record.threat.category, colorize)
  let ipStr = alignLeft(record.entry.clientIp, 15)
  let reqStr = $record.entry.method & " " & record.entry.path
  
  # Format with fixed column widths
  result = "$1  $2  $3  $4  $5  $6" % [
    timeStr, geoStr, statusStr, intentBadge, ipStr, reqStr
  ]
```

---

## 4. Grouped Multi-IP Actor View

When `--group-actors` is enabled or in summary mode, render correlated multi-IP clusters:

```
================================================================================
CRITICAL ACTOR CLUSTER: [ACTOR-7F3A] - WordPress & Secret Probe Botnet
--------------------------------------------------------------------------------
Risk Level      : [ HACKER! ] (Score: 95/100)
Total Requests  : 48 requests (48 x [ 404 ])
Distinct IPs    : 6 IPs across 3 countries:
                  - 45.154.255.8   (🇳🇱 NL - Netherlands)
                  - 194.26.29.112  (🇩🇪 DE - Germany)
                  - 185.220.101.5  (🇩🇪 DE - Germany)
                  - 193.32.161.20  (🇷🇺 RU - Russian Federation)
                  - 193.32.161.21  (🇷🇺 RU - Russian Federation)
                  - 193.32.161.22  (🇷🇺 RU - Russian Federation)
Primary UA      : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Probed Paths    : /.env
                  /wp-config.php
                  /wp-login.php
                  /xmlrpc.php
                  /actuator/env
First Seen      : 2026-10-10 13:50:12
Last Seen       : 2026-10-10 13:58:45
================================================================================
```

---

## 5. Terminal Color Safety & NO_COLOR Compliance
1. Check `std/terminal.isatty(stdout)`: If stdout is redirected (e.g. `http_logviewer access.log > output.txt`), automatically disable ANSI color codes unless `--color=always` is explicitly passed.
2. Respect the standard `NO_COLOR` environment variable: If `getEnv("NO_COLOR").len > 0`, default `colorOutput = false`.

---

## 6. Acceptance Criteria
- Unit tests in `tests/t_renderer.nim` verify that `formatStatusCode(404, true)` includes the exact ANSI sequence `\e[41;97;1m 404 \e[0m`.
- Verify that status codes `200`, `301`, `404`, and `500` generate correct ANSI sequences.
- Verify that `--no-color` cleanly suppresses all ANSI control codes.

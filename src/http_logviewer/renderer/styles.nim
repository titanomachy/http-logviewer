## ANSI escape styling, color definitions, and HTTP status code badge formatters.
## Implements Phase 06 / Category A requirements for high-contrast background-colored
## HTTP status codes, terminal color detection, and monochromatic fallback modes.

import std/[strutils, os, terminal, options, unicode]
import ../core/[types, config]

const
  Reset* = "\e[0m"
  Bold*  = "\e[1m"
  Dim*   = "\e[2m"
  Italic* = "\e[3m"
  Underline* = "\e[4m"
  Blink* = "\e[5m"

  # Foreground Text Colors
  FgBlack*       = "\e[30m"
  FgRed*         = "\e[31m"
  FgGreen*       = "\e[32m"
  FgYellow*      = "\e[33m"
  FgBlue*        = "\e[34m"
  FgMagenta*     = "\e[35m"
  FgCyan*        = "\e[36m"
  FgWhite*       = "\e[37m"
  FgGray*        = "\e[90m"
  FgBrightRed*   = "\e[91m"
  FgBrightGreen* = "\e[92m"
  FgBrightYellow* = "\e[93m"
  FgBrightBlue*  = "\e[94m"
  FgBrightMagenta* = "\e[95m"
  FgBrightCyan*  = "\e[96m"
  FgBrightWhite* = "\e[97m"
  FgBrightRedBold* = "\e[91;1m"
  FgOrange*      = "\e[38;5;208m"

  # HTTP Status Code Background Colors (per Spec 06 / Phase 06)
  BgRedBold*     = "\e[41;97;1m"    ## 404 Not Found (Red background, bright white bold text)
  BgMagenta*     = "\e[45;97m"      ## 401, 403 Forbidden (Magenta background, white text)
  BgDarkRed*     = "\e[41;37m"      ## 400..499 other client errors (Red background, white text)
  BgBrightRed*   = "\e[101;97;1m"   ## 500, 502, 503 Server Error (Bright red bg, white bold text)
  BgGreen*       = "\e[42;30m"      ## 200, 201, 204 Success (Green background, black text)
  BgYellow*      = "\e[43;30m"      ## 301, 302, 304 Redirect (Yellow background, black text)
  BgCyan*        = "\e[46;30m"      ## Alternative cyan background
  BgBlue*        = "\e[44;97m"      ## 1xx Informational (Blue background, white text)
  BgGray*        = "\e[100;97m"     ## Other / Unknown status codes (Gray background, white text)

  # Intent Category Badges (Colored)
  BadgeReal*       = "\e[32m[REAL USER]\e[0m"
  BadgeGoodBot*    = "\e[36m[GOOD BOT ]\e[0m"
  BadgeFriendly*   = "\e[36m[FRIENDLY ]\e[0m"
  BadgeScraper*    = "\e[33m[SCRAPER  ]\e[0m"
  BadgeSuspicious* = "\e[38;5;208m[SUSPICIOUS]\e[0m"
  BadgeHacker*     = "\e[41;97;1m[ HACKER! ]\e[0m"
  BadgeUnknown*    = "\e[90m[ UNKNOWN ]\e[0m"

  # Intent Category Badges (Monochromatic plain text)
  BadgeRealMono*       = "[REAL USER]"
  BadgeGoodBotMono*    = "[GOOD BOT ]"
  BadgeFriendlyMono*   = "[FRIENDLY ]"
  BadgeScraperMono*    = "[SCRAPER  ]"
  BadgeSuspiciousMono* = "[SUSPICIOUS]"
  BadgeHackerMono*     = "[ HACKER! ]"
  BadgeUnknownMono*    = "[ UNKNOWN ]"

proc formatStatusCode*(code: int, colorize: bool = true): string =
  ## Renders a 3-digit HTTP status code with high-contrast background coloring.
  ##
  ## Format Mapping:
  ## - 404: Bright White on Red background (`\e[41;97;1m 404 \e[0m`)
  ## - 401, 403: White on Magenta background (`\e[45;97m 403 \e[0m`)
  ## - Other 4xx: White on Red background (`\e[41;37m 400 \e[0m`)
  ## - 5xx: Bright White on Bright Red background (`\e[101;97;1m 500 \e[0m`)
  ## - 2xx: Black on Green background (`\e[42;30m 200 \e[0m`)
  ## - 3xx: Black on Yellow background (`\e[43;30m 301 \e[0m`)
  ## - 1xx: White on Blue background (`\e[44;97m 100 \e[0m`)
  ## - Other: White on Gray background (`\e[100;97m ??? \e[0m`)
  ##
  ## If `colorize` is false, returns plain padded string `" <code> "`.
  let text = " " & $code & " "
  if not colorize:
    return text

  case code
  of 200..299:
    BgGreen & text & Reset
  of 300..399:
    BgYellow & text & Reset
  of 404:
    BgRedBold & text & Reset
  of 401, 403:
    BgMagenta & text & Reset
  of 400, 402, 405..499:
    BgDarkRed & text & Reset
  of 500..599:
    BgBrightRed & text & Reset
  of 100..199:
    BgBlue & text & Reset
  else:
    BgGray & text & Reset

proc stripAnsi*(s: string): string =
  ## Strips all ANSI escape sequences (`\e[...m`) from a string.
  result = newStringOfCap(s.len)
  var i = 0
  while i < s.len:
    if s[i] == '\e' and i + 1 < s.len and s[i + 1] == '[':
      i += 2
      while i < s.len and s[i] notin {'m', 'A'..'Z', 'a'..'z'}:
        inc i
      if i < s.len:
        inc i # Skip terminating char (e.g. 'm')
    else:
      result.add(s[i])
      inc i

proc detectColorSupport*(isAttyOverride: Option[bool] = none(bool)): bool =
  ## Automatically detects whether the current environment supports ANSI color output.
  ## Evaluates:
  ## 1. Standard NO_COLOR specification (https://no-color.org)
  ## 2. Dumb or raw terminal types ($TERM)
  ## 3. TTY status of standard output (stdout.isatty)
  ## 4. Windows Terminal / ANSICON environment detection
  if getEnv("NO_COLOR").len > 0:
    return false

  let term = getEnv("TERM").toLowerAscii().strip()
  if term == "dumb" or term == "raw":
    return false

  let isAtty = if isAttyOverride.isSome: isAttyOverride.get() else: terminal.isatty(stdout)
  if not isAtty:
    return false

  when defined(windows):
    # Windows Terminal, ConEmu, ANSICON, or modern conhost with VT processing
    if getEnv("WT_SESSION").len > 0 or getEnv("ANSICON").len > 0 or
       getEnv("ConEmuANSI") == "ON" or term.len > 0:
      return true
    return false
  else:
    return true

proc shouldColorize*(mode: ColorMode = ColorModeAuto, isAttyOverride: Option[bool] = none(bool)): bool =
  ## Determines whether color output should be enabled based on user ColorMode policy
  ## and environment detection.
  case mode
  of ColorModeAlways:
    true
  of ColorModeNever:
    false
  of ColorModeAuto:
    detectColorSupport(isAttyOverride)

proc formatIntentBadge*(category: ActorCategory, colorize: bool = true): string =
  ## Formats visitor category intent badge.
  ##
  ## Categories:
  ## - RealUser: `[REAL USER]` in green
  ## - VerifiedBot: `[GOOD BOT ]` in cyan
  ## - FriendlyCrawler: `[FRIENDLY ]` in cyan
  ## - CommercialBot: `[SCRAPER  ]` in yellow
  ## - SuspiciousScanner: `[SUSPICIOUS]` in orange
  ## - BadActorHacker: `[ HACKER! ]` in bold white on red background
  ## - Unknown: `[ UNKNOWN ]` in gray
  if not colorize:
    case category
    of CategoryRealUser: BadgeRealMono
    of CategoryVerifiedBot: BadgeGoodBotMono
    of CategoryFriendlyCrawler: BadgeFriendlyMono
    of CategoryCommercialBot: BadgeScraperMono
    of CategorySuspicious: BadgeSuspiciousMono
    of CategoryBadActorHacker: BadgeHackerMono
    of CategoryUnknown: BadgeUnknownMono
  else:
    case category
    of CategoryRealUser: BadgeReal
    of CategoryVerifiedBot: BadgeGoodBot
    of CategoryFriendlyCrawler: BadgeFriendly
    of CategoryCommercialBot: BadgeScraper
    of CategorySuspicious: BadgeSuspicious
    of CategoryBadActorHacker: BadgeHacker
    of CategoryUnknown: BadgeUnknown

proc formatIntentBadge*(threat: ThreatProfile, colorize: bool = true): string {.inline.} =
  ## Convenience overload extracting category from ThreatProfile.
  formatIntentBadge(threat.category, colorize)

func isRegionalIndicatorRune*(r: Rune): bool {.inline.} =
  ## Returns true if the rune is a Unicode Regional Indicator Symbol (0x1F1E6..0x1F1FF).
  int(r) in 0x1F1E6..0x1F1FF

func isEmojiRune*(r: Rune): bool {.inline.} =
  ## Returns true if rune is in common emoji Unicode ranges.
  let cp = int(r)
  (cp in 0x1F300..0x1F9FF) or (cp in 0x2600..0x26FF) or (cp in 0x2700..0x27BF) or (cp in 0x1FA00..0x1FAFF)

proc terminalDisplayWidth*(s: string): int =
  ## Calculates the visible visual column width of a string rendered in a monospace terminal.
  ## Strips ANSI escape sequences and accounts for 2-column wide Unicode emoji symbols
  ## and regional indicator flag pairs (e.g. 🇺🇸 = 2 columns).
  let clean = stripAnsi(s)
  var width = 0
  var regionalIndicatorCount = 0

  for r in runes(clean):
    let cp = int(r)
    if cp in [0xFE0E, 0xFE0F]:
      # Variation selectors (invisible display width)
      discard
    elif isRegionalIndicatorRune(r):
      inc regionalIndicatorCount
      if regionalIndicatorCount == 2:
        # A pair of regional indicator runes forms one 2-column flag emoji
        width += 2
        regionalIndicatorCount = 0
    elif isEmojiRune(r):
      # Standalone emoji symbols (e.g. 🏠, 🌐, 🧅) occupy 2 monospace terminal columns
      width += 2
    elif cp in 0x00..0x1F or cp == 0x7F:
      # Control characters
      discard
    else:
      # ASCII and standard Latin / Unicode characters occupy 1 column
      if regionalIndicatorCount == 1:
        # Dangling single regional indicator
        width += 1
        regionalIndicatorCount = 0
      width += 1

  if regionalIndicatorCount == 1:
    width += 1

  result = width

proc alignColumn*(s: string, targetWidth: int, alignRight: bool = false): string =
  ## Aligns string `s` to occupy exactly `targetWidth` terminal columns,
  ## accurately taking into account ANSI escape sequences and multi-byte / emoji widths.
  let visual = terminalDisplayWidth(s)
  if visual >= targetWidth:
    return s
  let pad = repeat(' ', targetWidth - visual)
  if alignRight:
    result = pad & s
  else:
    result = s & pad

proc formatCountryColumn*(countryCode: string, flagEmoji: string = "", useEmoji: bool = true, width: int = 7): string =
  ## Formats country flag and country code into aligned columns (e.g. "🇺🇸 US  ", `[US] US`).
  let code = countryCode.strip().toUpperAscii()
  let displayedCode = if code.len == 2:
                        code
                      elif code in ["LAN", "LOCAL"]:
                        "LO"
                      elif code.len > 0:
                        code[0..min(1, code.len - 1)]
                      else:
                        "--"

  let raw = if useEmoji:
    let flag = if flagEmoji.len > 0: flagEmoji else: (
      case displayedCode
      of "LO": "🏠"
      of "T1": "🧅"
      of "A1": "🕵️"
      of "EU": "\u{1F1EA}\u{1F1FA}"
      of "UK": "\u{1F1EC}\u{1F1E7}"
      else:
        if displayedCode.len == 2 and displayedCode[0] in 'A'..'Z' and displayedCode[1] in 'A'..'Z':
          let c1 = ord(displayedCode[0]) - ord('A') + 0x1F1E6
          let c2 = ord(displayedCode[1]) - ord('A') + 0x1F1E6
          toUTF8(Rune(c1)) & toUTF8(Rune(c2))
        else:
          "🌐"
    )
    flag & " " & displayedCode
  else:
    "[" & displayedCode & "] " & displayedCode

  alignColumn(raw, width)

proc formatCountryColumn*(geo: GeoLocation, useEmoji: bool = true, width: int = 7): string =
  ## Overload accepting a GeoLocation object.
  formatCountryColumn(geo.countryCode, geo.flagEmoji, useEmoji = useEmoji, width = width)

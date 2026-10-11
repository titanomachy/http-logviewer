## ANSI escape styling, color definitions, and HTTP status code badge formatters.
## Implements Phase 06 / Category A requirements for high-contrast background-colored
## HTTP status codes, terminal color detection, and monochromatic fallback modes.

import std/[strutils, os, options, unicode]
import terminal_style, terminal_screen
import ../core/[types, config]

const
  Reset* = termClear
  Bold*  = termBold
  Dim*   = termDim
  Italic* = termItalic
  Underline* = termUnderline
  Blink* = termBlink

  # Foreground Text Colors
  FgBlack*       = termBlack
  FgRed*         = termRed
  FgGreen*       = termGreen
  FgYellow*      = termYellow
  FgBlue*        = termBlue
  FgMagenta*     = termMagenta
  FgCyan*        = termCyan
  FgWhite*       = termWhite
  FgGray*        = termBrightBlack
  FgBrightRed*   = termBrightRed
  FgBrightGreen* = termBrightGreen
  FgBrightYellow* = termBrightYellow
  FgBrightBlue*  = termBrightBlue
  FgBrightMagenta* = termBrightMagenta
  FgBrightCyan*  = termBrightCyan
  FgBrightWhite* = termBrightWhite
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
  BadgeWhitelisted* = "\e[107;32m[WHITELISTED]\e[0m"
  BadgeGoodBot*    = "\e[36m[GOOD BOT ]\e[0m"
  BadgeFriendly*   = "\e[36m[FRIENDLY ]\e[0m"
  BadgeScraper*    = "\e[33m[SCRAPER  ]\e[0m"
  BadgeSuspicious* = "\e[38;5;208m[SUSPICIOUS]\e[0m"
  BadgeCracker*    = "\e[41;97;1m[ CRACKER!]\e[0m"
  BadgeHacker*     = BadgeCracker
  BadgeUnknown*    = "\e[90m[ UNKNOWN ]\e[0m"

  # Intent Category Badges (Monochromatic plain text)
  BadgeRealMono*       = "[REAL USER]"
  BadgeWhitelistedMono* = "[WHITELISTED]"
  BadgeGoodBotMono*    = "[GOOD BOT ]"
  BadgeFriendlyMono*   = "[FRIENDLY ]"
  BadgeScraperMono*    = "[SCRAPER  ]"
  BadgeSuspiciousMono* = "[SUSPICIOUS]"
  BadgeCrackerMono*    = "[ CRACKER!]"
  BadgeHackerMono*     = BadgeCrackerMono
  BadgeUnknownMono*    = "[ UNKNOWN ]"

func formatStatusCode*(code: int, colorize: bool = true): string =
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

func stripAnsi*(s: string): string =
  ## Strips all ANSI escape sequences (`\e[...m`) from a string using terminal_style.
  terminal_style.stripAnsi(s)

proc detectColorSupport*(isAttyOverride: Option[bool] = none(bool)): bool =
  ## Automatically detects whether the current environment supports ANSI color output.
  ## Evaluates:
  ## 1. Standard NO_COLOR specification (https://no-color.org)
  ## 2. Dumb or raw terminal types ($TERM)
  ## 3. TTY status of standard output (terminal_screen.isTerminal)
  ## 4. Windows Terminal / ANSICON environment detection
  if getEnv("NO_COLOR").len > 0:
    return false

  let term = getEnv("TERM").toLowerAscii().strip()
  if term == "dumb" or term == "raw":
    return false

  let isAtty = if isAttyOverride.isSome: isAttyOverride.get() else: terminal_screen.isTerminal(stdout)
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

func formatIntentBadge*(category: ActorCategory, colorize: bool = true): string =
  ## Formats visitor category intent badge.
  ##
  ## Categories:
  ## - RealUser: `[REAL USER]` in green
  ## - VerifiedBot: `[GOOD BOT ]` in cyan
  ## - FriendlyCrawler: `[FRIENDLY ]` in cyan
  ## - CommercialBot: `[SCRAPER  ]` in yellow
  ## - SuspiciousScanner: `[SUSPICIOUS]` in orange
  ## - BadActorHacker / Cracker: `[ CRACKER!]` in bold white on red background
  ## - Unknown: `[ UNKNOWN ]` in gray
  if not colorize:
    case category
    of CategoryRealUser: BadgeRealMono
    of CategoryVerifiedBot: BadgeGoodBotMono
    of CategoryFriendlyCrawler: BadgeFriendlyMono
    of CategoryCommercialBot: BadgeScraperMono
    of CategorySuspicious: BadgeSuspiciousMono
    of CategoryBadActorHacker: BadgeCrackerMono
    of CategoryUnknown: BadgeUnknownMono
  else:
    case category
    of CategoryRealUser: BadgeReal
    of CategoryVerifiedBot: BadgeGoodBot
    of CategoryFriendlyCrawler: BadgeFriendly
    of CategoryCommercialBot: BadgeScraper
    of CategorySuspicious: BadgeSuspicious
    of CategoryBadActorHacker: BadgeCracker
    of CategoryUnknown: BadgeUnknown

func formatIntentBadge*(threat: ThreatProfile, colorize: bool = true): string {.inline.} =
  ## Shows explicit trust separately from inferred visitor intent.
  if threat.whitelisted:
    if colorize: BadgeWhitelisted else: BadgeWhitelistedMono
  else:
    formatIntentBadge(threat.category, colorize)

func isRegionalIndicatorRune*(r: Rune): bool {.inline.} =
  ## Returns true if the rune is a Unicode Regional Indicator Symbol (0x1F1E6..0x1F1FF).
  int(r) in 0x1F1E6..0x1F1FF

func isEmojiRune*(r: Rune): bool {.inline.} =
  ## Returns true if rune is in common emoji Unicode ranges.
  let cp = int(r)
  (cp in 0x1F300..0x1F9FF) or (cp in 0x2600..0x26FF) or (cp in 0x2700..0x27BF) or (cp in 0x1FA00..0x1FAFF)

func terminalDisplayWidth*(s: string): int =
  ## Calculates the visible visual column width of a string rendered in a monospace terminal
  ## using terminal_style.
  terminal_style.displayWidth(s)

func alignColumn*(s: string, targetWidth: int, alignRight: bool = false): string =
  ## Aligns string `s` to occupy exactly `targetWidth` terminal columns,
  ## accurately taking into account ANSI escape sequences and multi-byte / emoji widths
  ## using terminal_style.padAnsi.
  terminal_style.padAnsi(s, targetWidth, if alignRight: TextAlignment.alignRight else: TextAlignment.alignLeft)

func formatCountryColumn*(countryCode: string, flagEmoji: string = "", useEmoji: bool = true, width: int = 7): string =
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

func formatCountryColumn*(geo: GeoLocation, useEmoji: bool = true, width: int = 7): string =
  ## Overload accepting a GeoLocation object.
  formatCountryColumn(geo.countryCode, geo.flagEmoji, useEmoji = useEmoji, width = width)

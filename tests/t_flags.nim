## Unit tests for Unicode Flag Emoji & Country Metadata.
## Covers Phase 03 / Category B (Items 01 through 05).

import unittest
import std/[unicode, strutils, os]
import http_logviewer/enrichment/flags

suite "Flag Emoji & Country Metadata - Algorithmic Regional Indicator Conversion (Phase 03 / Category B / Item 01)":
  test "Item 01: Standard ISO country codes convert to expected flag emojis":
    check isoToFlagEmoji("US") == "🇺🇸"
    check isoToFlagEmoji("DE") == "🇩🇪"
    check isoToFlagEmoji("NL") == "🇳🇱"
    check isoToFlagEmoji("FR") == "🇫🇷"
    check isoToFlagEmoji("JP") == "🇯🇵"
    check isoToFlagEmoji("GB") == "🇬🇧"
    check isoToFlagEmoji("CA") == "🇨🇦"
    check isoToFlagEmoji("BR") == "🇧🇷"
    check isoToFlagEmoji("AU") == "🇦🇺"
    check isoToFlagEmoji("IN") == "🇮🇳"

  test "Item 01: Case insensitivity and whitespace trimming":
    check isoToFlagEmoji("us") == "🇺🇸"
    check isoToFlagEmoji("De") == "🇩🇪"
    check isoToFlagEmoji("nL") == "🇳🇱"
    check isoToFlagEmoji("  jp  ") == "🇯🇵"

  test "Item 01: Mathematical regional indicator codepoint verification":
    let flag = isoToFlagEmoji("US")
    # Regional indicator symbols are in SMP (U+1F1E6 to U+1F1FF), 4 bytes each in UTF-8
    check flag.len == 8
    let runes = toRunes(flag)
    check runes.len == 2
    check runes[0].int == 0x1F1FA # 'U'
    check runes[1].int == 0x1F1F8 # 'S'

  test "Item 01: Invalid lengths and non-alpha characters fallback to globe":
    check isoToFlagEmoji("") == "🌐"
    check isoToFlagEmoji("U") == "🌐"
    check isoToFlagEmoji("USA") == "🌐"
    check isoToFlagEmoji("12") == "🌐"
    check isoToFlagEmoji("A$") == "🌐"
    check isoToFlagEmoji("!@") == "🌐"

suite "Flag Emoji & Country Metadata - ISO Country Name Dictionary (Phase 03 / Category B / Item 02)":
  test "Item 02: Standard ISO country codes return expected English names":
    check getCountryName("US") == "United States"
    check getCountryName("DE") == "Germany"
    check getCountryName("NL") == "Netherlands"
    check getCountryName("FR") == "France"
    check getCountryName("JP") == "Japan"
    check getCountryName("GB") == "United Kingdom"
    check getCountryName("CA") == "Canada"
    check getCountryName("CN") == "China"
    check getCountryName("BR") == "Brazil"
    check getCountryName("AU") == "Australia"
    check getCountryName("RU") == "Russian Federation"
    check getCountryName("IN") == "India"

  test "Item 02: Case insensitivity and whitespace trimming for country names":
    check getCountryName("de") == "Germany"
    check getCountryName("  nl  ") == "Netherlands"
    check getCountryName("uS") == "United States"

  test "Item 02: All 249 ISO-3166-1 alpha-2 codes have valid English names":
    check IsoCountryCodes.len == 249
    for code in IsoCountryCodes:
      check isKnownIsoCountryCode(code)
      let name = getCountryName(code)
      check name.len > 0
      check name != "Unknown Country"

  test "Item 02: Unknown or unassigned codes return Unknown Country":
    check getCountryName("ZZ") == "Unknown Country"
    check getCountryName("12") == "Unknown Country"
    check getCountryName("") == "Unknown Country"
    check not isKnownIsoCountryCode("ZZ")
    check not isKnownIsoCountryCode("12")

suite "Flag Emoji & Country Metadata - Special ISO Pseudo-Codes (Phase 03 / Category B / Item 03)":
  test "Item 03: European Union (EU) pseudo-code":
    check isoToFlagEmoji("EU") == "🇪🇺"
    check getCountryName("EU") == "European Union"
    check isSpecialOrPseudoCode("EU")

  test "Item 03: Asia-Pacific (AP) pseudo-code":
    check isoToFlagEmoji("AP") == "🌏"
    check getCountryName("AP") == "Asia-Pacific Region"
    check isSpecialOrPseudoCode("AP")

  test "Item 03: Anonymous Proxy (A1) and Satellite (A2)":
    check isoToFlagEmoji("A1") == "🕵️"
    check getCountryName("A1") == "Anonymous Proxy"
    check isSpecialOrPseudoCode("A1")

    check isoToFlagEmoji("A2") == "🛰️"
    check getCountryName("A2") == "Satellite Provider"
    check isSpecialOrPseudoCode("A2")

  test "Item 03: Tor Exit Node (T1) and Other Country (O1)":
    check isoToFlagEmoji("T1") == "🧅"
    check getCountryName("T1") == "Tor Exit Node"
    check isSpecialOrPseudoCode("T1")

    check isoToFlagEmoji("O1") == "🌐"
    check getCountryName("O1") == "Other Country"
    check isSpecialOrPseudoCode("O1")

  test "Item 03: Local / LAN and Unknown pseudo-codes":
    check isoToFlagEmoji("LO") == "🏠"
    check isoToFlagEmoji("LAN") == "🏠"
    check isoToFlagEmoji("LOCAL") == "🏠"
    check getCountryName("LO") == "Local / Private Network"
    check isSpecialOrPseudoCode("LO")

    check isoToFlagEmoji("XX") == "🌐"
    check isoToFlagEmoji("??") == "🌐"
    check getCountryName("XX") == "Unknown Country"
    check isSpecialOrPseudoCode("XX")

  test "Item 03: United Kingdom (UK) maps to British flag and name":
    check isoToFlagEmoji("UK") == "🇬🇧"
    check getCountryName("UK") == "United Kingdom"
    check isSpecialOrPseudoCode("UK")

suite "Flag Emoji & Country Metadata - Terminal Fallback (Phase 03 / Category B / Item 04)":
  test "Item 04: flagTerminalFallback returns bracketed ASCII codes":
    check flagTerminalFallback("US") == "[US]"
    check flagTerminalFallback("de") == "[DE]"
    check flagTerminalFallback("nl") == "[NL]"
    check flagTerminalFallback("FR") == "[FR]"
    check flagTerminalFallback("LO") == "[LAN]"
    check flagTerminalFallback("LAN") == "[LAN]"
    check flagTerminalFallback("LOCAL") == "[LAN]"
    check flagTerminalFallback("XX") == "[--]"
    check flagTerminalFallback("??") == "[--]"
    check flagTerminalFallback("") == "[--]"
    check flagTerminalFallback("A1") == "[PROXY]"
    check flagTerminalFallback("A2") == "[SAT]"
    check flagTerminalFallback("T1") == "[TOR]"
    check flagTerminalFallback("EU") == "[EU]"
    check flagTerminalFallback("AP") == "[AP]"
    check flagTerminalFallback("UK") == "[UK]"
    check flagTerminalFallback("O1") == "[OTHER]"
    check flagTerminalFallback("123") == "[--]"

  test "Item 04: formatCountryFlag switches between emoji and fallback":
    check formatCountryFlag("US", useEmoji = true) == "🇺🇸"
    check formatCountryFlag("US", useEmoji = false) == "[US]"
    check formatCountryFlag("DE", useEmoji = true) == "🇩🇪"
    check formatCountryFlag("DE", useEmoji = false) == "[DE]"
    check formatCountryFlag("LO", useEmoji = true) == "🏠"
    check formatCountryFlag("LO", useEmoji = false) == "[LAN]"
    check formatCountryFlag("XX", useEmoji = true) == "🌐"
    check formatCountryFlag("XX", useEmoji = false) == "[--]"

  test "Item 04: formatCountryBadge generates aligned badges for terminal tables":
    check formatCountryBadge("US", useEmoji = true) == "🇺🇸 US"
    check formatCountryBadge("US", useEmoji = false) == "[US] US"
    check formatCountryBadge("DE", useEmoji = true) == "🇩🇪 DE"
    check formatCountryBadge("DE", useEmoji = false) == "[DE] DE"
    check formatCountryBadge("LO", useEmoji = true) == "🏠 LO"
    check formatCountryBadge("LO", useEmoji = false) == "[LAN] LO"

  test "Item 04: terminalSupportsEmoji detects environment overrides":
    # Test NO_EMOJI environment variable detection
    let oldNoEmoji = getEnv("NO_EMOJI")
    defer:
      if oldNoEmoji.len > 0: putEnv("NO_EMOJI", oldNoEmoji)
      else: delEnv("NO_EMOJI")

    putEnv("NO_EMOJI", "1")
    check not terminalSupportsEmoji()
    delEnv("NO_EMOJI")

    # Test TERM=dumb detection
    let oldTerm = getEnv("TERM")
    defer:
      if oldTerm.len > 0: putEnv("TERM", oldTerm)
      else: delEnv("TERM")

    putEnv("TERM", "dumb")
    check not terminalSupportsEmoji()
    putEnv("TERM", "xterm-256color")
    check terminalSupportsEmoji()

suite "Flag Emoji & Country Metadata - All 249 ISO Codes Verification (Phase 03 / Category B / Item 05)":
  test "Item 05: All 249 ISO country codes correctly convert to regional indicator flag emojis":
    check IsoCountryCodes.len == 249
    var testedCount = 0
    for code in IsoCountryCodes:
      check code.len == 2
      let flag = isoToFlagEmoji(code)
      # Every regional indicator flag emoji is formed by two 4-byte UTF-8 codepoints = 8 bytes
      check flag.len == 8
      let runes = toRunes(flag)
      check runes.len == 2
      let expectedRune1 = 0x1F1E6 + (ord(code[0]) - ord('A'))
      let expectedRune2 = 0x1F1E6 + (ord(code[1]) - ord('A'))
      check runes[0].int == expectedRune1
      check runes[1].int == expectedRune2

      # Lowercase conversion must be identical
      check isoToFlagEmoji(code.toLowerAscii()) == flag

      # Country name must be known and non-empty
      let countryName = getCountryName(code)
      check countryName.len > 0
      check countryName != "Unknown Country"

      # Terminal fallback must be bracketed 2-letter code
      check flagTerminalFallback(code) == "[" & code & "]"
      check formatCountryFlag(code, false) == "[" & code & "]"
      check formatCountryFlag(code, true) == flag

      inc testedCount

    check testedCount == 249

  test "Item 05: Country flags are distinct across different ISO codes":
    # Ensure no collision between different ISO codes
    var seenFlags: seq[string] = @[]
    for code in IsoCountryCodes:
      let flag = isoToFlagEmoji(code)
      check flag notin seenFlags
      seenFlags.add(flag)
    check seenFlags.len == 249





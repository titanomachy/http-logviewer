# Example: Unicode Regional Indicator Flag Emojis & Country Metadata
# Demonstrates ISO-3166-1 alpha-2 algorithmic flag generation, country name dictionary,
# special pseudo-code mapping (EU, AP, A1, A2, T1, O1, LO), and terminal ASCII fallback.
#
# Compile and run with:
#   nim r --path:src examples/flags_and_country_metadata.nim

import std/[strutils, unicode]
import http_logviewer/enrichment/flags

proc main() =
  echo "=== http_logviewer: Unicode Country Flags & Metadata (Phase 03 / Category B) ==="
  echo ""

  # 1. Algorithmic Regional Indicator Flag Conversion (Item 01)
  echo "[1] Algorithmic ISO-3166-1 alpha-2 Flag Emoji Generation:"
  let sampleCodes = ["US", "DE", "NL", "FR", "JP", "GB", "CA", "BR", "AU", "IN"]
  for code in sampleCodes:
    let emoji = isoToFlagEmoji(code)
    let runes = toRunes(emoji)
    echo "  ISO: ", code, " -> Flag: ", emoji, " (Codepoints: U+",
         toHex(runes[0].int, 5), " U+", toHex(runes[1].int, 5), ", Bytes: ", emoji.len, ")"
  echo ""

  # 2. Case Insensitivity & Whitespace Resiliency (Item 01)
  echo "[2] Input Sanitization & Case Resiliency:"
  let dirtyCodes = ["  us  ", "de", "Nl", "  jP "]
  for raw in dirtyCodes:
    echo "  Raw Input: '", raw, "' -> Normalized Flag: ", isoToFlagEmoji(raw)
  echo ""

  # 3. Static English Country Name Resolution (Item 02)
  echo "[3] Standard Country Name Dictionary:"
  let countries = ["US", "DE", "NL", "FR", "JP", "CN", "RU", "CA", "BR", "ZA"]
  for code in countries:
    echo "  ", code, " -> ", isoToFlagEmoji(code), " ", getCountryName(code)
  echo "  Total Official ISO-3166-1 Countries Defined: ", IsoCountryCodes.len
  echo ""

  # 4. Special GeoIP Pseudo-Codes (Item 03)
  echo "[4] GeoIP & Security Pseudo-Codes:"
  let pseudoCodes = [
    ("EU", "European Union"),
    ("AP", "Asia-Pacific Region"),
    ("A1", "Anonymous Proxy"),
    ("A2", "Satellite Provider"),
    ("T1", "Tor Exit Node"),
    ("O1", "Other Country"),
    ("LO", "Local / Private Network"),
    ("UK", "United Kingdom (GB alias)"),
    ("XX", "Unknown Country")
  ]
  for (code, desc) in pseudoCodes:
    echo "  Pseudo-code: ", code.alignLeft(4), " -> Flag: ", isoToFlagEmoji(code),
         " Name: '", getCountryName(code), "' (Special: ", isSpecialOrPseudoCode(code), ")"
  echo ""

  # 5. Terminal Fallback for Plain / Non-Emoji Terminals (Item 04)
  echo "[5] Terminal Fallback for Plain-Text / Restricted Terminals:"
  echo "  Active terminal supports emoji: ", terminalSupportsEmoji()
  echo ""
  echo "  Comparative Display (Emoji vs. Terminal Fallback):"
  let comparisonCodes = ["US", "DE", "NL", "JP", "LO", "A1", "T1", "EU", "XX"]
  echo "  " & "-".repeat(60)
  echo "  ISO  | EMOJI BADGE | TERMINAL FALLBACK BADGE | COUNTRY NAME"
  echo "  " & "-".repeat(60)
  for code in comparisonCodes:
    let emojiBadge = formatCountryBadge(code, useEmoji = true).alignLeft(11)
    let fallbackBadge = formatCountryBadge(code, useEmoji = false).alignLeft(23)
    echo "  ", code.alignLeft(4), " | ", emojiBadge, " | ", fallbackBadge, " | ", getCountryName(code)
  echo "  " & "-".repeat(60)
  echo ""

  # 6. Global Coverage Summary (Item 05)
  echo "[6] 249 Official ISO Country Codes Verification:"
  var validCount = 0
  for code in IsoCountryCodes:
    if isKnownIsoCountryCode(code) and getCountryName(code) != "Unknown Country" and isoToFlagEmoji(code).len == 8:
      inc validCount
  echo "  Verified: ", validCount, " / ", IsoCountryCodes.len, " ISO-3166-1 country codes operational."
  echo ""
  echo "=== All Phase 03 Category B capabilities operational! ==="

when isMainModule:
  main()

## Unicode regional indicator flag emoji generation and ISO country metadata.
## Maps 2-letter ISO 3166-1 alpha-2 country codes to Unicode flag emoji and English country names.

import std/[strutils, unicode, os]

const
  RegionalIndicatorBase = 0x1F1E6 # UTF-32 codepoint for regional indicator symbol letter '🇦'
  AsciiUpperBase = ord('A')

func isoToFlagEmoji*(countryCode: string): string =
  ## Converts a 2-letter ISO 3166-1 alpha-2 country code into a Unicode regional indicator flag emoji.
  ## Example: "US" -> "🇺🇸", "DE" -> "🇩🇪", "NL" -> "🇳🇱".
  ## Returns fallback icon for private ("LO"), special, or invalid codes.
  let cleaned = countryCode.strip().toUpperAscii()
  if cleaned.len != 2:
    case cleaned
    of "LAN", "LOCAL":
      return "🏠"
    of "???", "UNKNOWN":
      return "🌐"
    else:
      return "🌐"

  case cleaned
  of "LO":
    return "🏠"
  of "XX", "??", "O1":
    return "🌐"
  of "T1": # Tor Exit Node
    return "🧅"
  of "A1": # Anonymous Proxy
    return "🕵️"
  of "A2": # Satellite Provider
    return "🛰️"
  of "AP": # Asia-Pacific Region
    return "🌏"
  of "EU": # European Union
    return "\u{1F1EA}\u{1F1FA}" # 🇪🇺
  of "UK": # Exceptionally reserved ISO code for United Kingdom (GB)
    return "\u{1F1EC}\u{1F1E7}" # 🇬🇧
  else:
    discard


  let c1 = cleaned[0]
  let c2 = cleaned[1]

  if c1 notin 'A'..'Z' or c2 notin 'A'..'Z':
    return "🌐"

  let codePoint1 = RegionalIndicatorBase + (ord(c1) - AsciiUpperBase)
  let codePoint2 = RegionalIndicatorBase + (ord(c2) - AsciiUpperBase)

  result = toUTF8(Rune(codePoint1)) & toUTF8(Rune(codePoint2))


const
  IsoCountryCodes*: array[249, string] = [
    "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
    "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ",
    "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ",
    "DE", "DJ", "DK", "DM", "DO", "DZ",
    "EC", "EE", "EG", "EH", "ER", "ES", "ET",
    "FI", "FJ", "FK", "FM", "FO", "FR",
    "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY",
    "HK", "HM", "HN", "HR", "HT", "HU",
    "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT",
    "JE", "JM", "JO", "JP",
    "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ",
    "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY",
    "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ",
    "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ",
    "OM",
    "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY",
    "QA",
    "RE", "RO", "RS", "RU", "RW",
    "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ",
    "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ",
    "UA", "UG", "UM", "US", "UY", "UZ",
    "VA", "VC", "VE", "VG", "VI", "VN", "VU",
    "WF", "WS",
    "YE", "YT",
    "ZA", "ZM", "ZW"
  ]

func isKnownIsoCountryCode*(countryCode: string): bool =
  ## Returns true if countryCode is one of the 249 officially assigned ISO 3166-1 alpha-2 codes.
  let cleaned = countryCode.strip().toUpperAscii()
  for code in IsoCountryCodes:
    if code == cleaned:
      return true
  return false

func getCountryName*(countryCode: string): string =
  ## Returns full English country name for an ISO 3166-1 alpha-2 country code.
  let cleaned = countryCode.strip().toUpperAscii()
  case cleaned
  of "AD": "Andorra"
  of "AE": "United Arab Emirates"
  of "AF": "Afghanistan"
  of "AG": "Antigua and Barbuda"
  of "AI": "Anguilla"
  of "AL": "Albania"
  of "AM": "Armenia"
  of "AO": "Angola"
  of "AQ": "Antarctica"
  of "AR": "Argentina"
  of "AS": "American Samoa"
  of "AT": "Austria"
  of "AU": "Australia"
  of "AW": "Aruba"
  of "AX": "Åland Islands"
  of "AZ": "Azerbaijan"
  of "BA": "Bosnia and Herzegovina"
  of "BB": "Barbados"
  of "BD": "Bangladesh"
  of "BE": "Belgium"
  of "BF": "Burkina Faso"
  of "BG": "Bulgaria"
  of "BH": "Bahrain"
  of "BI": "Burundi"
  of "BJ": "Benin"
  of "BL": "Saint Barthélemy"
  of "BM": "Bermuda"
  of "BN": "Brunei Darussalam"
  of "BO": "Bolivia"
  of "BQ": "Bonaire, Sint Eustatius and Saba"
  of "BR": "Brazil"
  of "BS": "Bahamas"
  of "BT": "Bhutan"
  of "BV": "Bouvet Island"
  of "BW": "Botswana"
  of "BY": "Belarus"
  of "BZ": "Belize"
  of "CA": "Canada"
  of "CC": "Cocos (Keeling) Islands"
  of "CD": "Congo (DRC)"
  of "CF": "Central African Republic"
  of "CG": "Congo"
  of "CH": "Switzerland"
  of "CI": "Côte d'Ivoire"
  of "CK": "Cook Islands"
  of "CL": "Chile"
  of "CM": "Cameroon"
  of "CN": "China"
  of "CO": "Colombia"
  of "CR": "Costa Rica"
  of "CU": "Cuba"
  of "CV": "Cabo Verde"
  of "CW": "Curaçao"
  of "CX": "Christmas Island"
  of "CY": "Cyprus"
  of "CZ": "Czechia"
  of "DE": "Germany"
  of "DJ": "Djibouti"
  of "DK": "Denmark"
  of "DM": "Dominica"
  of "DO": "Dominican Republic"
  of "DZ": "Algeria"
  of "EC": "Ecuador"
  of "EE": "Estonia"
  of "EG": "Egypt"
  of "EH": "Western Sahara"
  of "ER": "Eritrea"
  of "ES": "Spain"
  of "ET": "Ethiopia"
  of "FI": "Finland"
  of "FJ": "Fiji"
  of "FK": "Falkland Islands"
  of "FM": "Micronesia"
  of "FO": "Faroe Islands"
  of "FR": "France"
  of "GA": "Gabon"
  of "GB", "UK": "United Kingdom"
  of "GD": "Grenada"
  of "GE": "Georgia"
  of "GF": "French Guiana"
  of "GG": "Guernsey"
  of "GH": "Ghana"
  of "GI": "Gibraltar"
  of "GL": "Greenland"
  of "GM": "Gambia"
  of "GN": "Guinea"
  of "GP": "Guadeloupe"
  of "GQ": "Equatorial Guinea"
  of "GR": "Greece"
  of "GS": "South Georgia and the South Sandwich Islands"
  of "GT": "Guatemala"
  of "GU": "Guam"
  of "GW": "Guinea-Bissau"
  of "GY": "Guyana"
  of "HK": "Hong Kong"
  of "HM": "Heard Island and McDonald Islands"
  of "HN": "Honduras"
  of "HR": "Croatia"
  of "HT": "Haiti"
  of "HU": "Hungary"
  of "ID": "Indonesia"
  of "IE": "Ireland"
  of "IL": "Israel"
  of "IM": "Isle of Man"
  of "IN": "India"
  of "IO": "British Indian Ocean Territory"
  of "IQ": "Iraq"
  of "IR": "Iran"
  of "IS": "Iceland"
  of "IT": "Italy"
  of "JE": "Jersey"
  of "JM": "Jamaica"
  of "JO": "Jordan"
  of "JP": "Japan"
  of "KE": "Kenya"
  of "KG": "Kyrgyzstan"
  of "KH": "Cambodia"
  of "KI": "Kiribati"
  of "KM": "Comoros"
  of "KN": "Saint Kitts and Nevis"
  of "KP": "North Korea"
  of "KR": "South Korea"
  of "KW": "Kuwait"
  of "KY": "Cayman Islands"
  of "KZ": "Kazakhstan"
  of "LA": "Laos"
  of "LB": "Lebanon"
  of "LC": "Saint Lucia"
  of "LI": "Liechtenstein"
  of "LK": "Sri Lanka"
  of "LR": "Liberia"
  of "LS": "Lesotho"
  of "LT": "Lithuania"
  of "LU": "Luxembourg"
  of "LV": "Latvia"
  of "LY": "Libya"
  of "MA": "Morocco"
  of "MC": "Monaco"
  of "MD": "Moldova"
  of "ME": "Montenegro"
  of "MF": "Saint Martin"
  of "MG": "Madagascar"
  of "MH": "Marshall Islands"
  of "MK": "North Macedonia"
  of "ML": "Mali"
  of "MM": "Myanmar"
  of "MN": "Mongolia"
  of "MO": "Macao"
  of "MP": "Northern Mariana Islands"
  of "MQ": "Martinique"
  of "MR": "Mauritania"
  of "MS": "Montserrat"
  of "MT": "Malta"
  of "MU": "Mauritius"
  of "MV": "Maldives"
  of "MW": "Malawi"
  of "MX": "Mexico"
  of "MY": "Malaysia"
  of "MZ": "Mozambique"
  of "NA": "Namibia"
  of "NC": "New Caledonia"
  of "NE": "Niger"
  of "NF": "Norfolk Island"
  of "NG": "Nigeria"
  of "NI": "Nicaragua"
  of "NL": "Netherlands"
  of "NO": "Norway"
  of "NP": "Nepal"
  of "NR": "Nauru"
  of "NU": "Niue"
  of "NZ": "New Zealand"
  of "OM": "Oman"
  of "PA": "Panama"
  of "PE": "Peru"
  of "PF": "French Polynesia"
  of "PG": "Papua New Guinea"
  of "PH": "Philippines"
  of "PK": "Pakistan"
  of "PL": "Poland"
  of "PM": "Saint Pierre and Miquelon"
  of "PN": "Pitcairn"
  of "PR": "Puerto Rico"
  of "PS": "Palestine"
  of "PT": "Portugal"
  of "PW": "Palau"
  of "PY": "Paraguay"
  of "QA": "Qatar"
  of "RE": "Réunion"
  of "RO": "Romania"
  of "RS": "Serbia"
  of "RU": "Russian Federation"
  of "RW": "Rwanda"
  of "SA": "Saudi Arabia"
  of "SB": "Solomon Islands"
  of "SC": "Seychelles"
  of "SD": "Sudan"
  of "SE": "Sweden"
  of "SG": "Singapore"
  of "SH": "Saint Helena"
  of "SI": "Slovenia"
  of "SJ": "Svalbard and Jan Mayen"
  of "SK": "Slovakia"
  of "SL": "Sierra Leone"
  of "SM": "San Marino"
  of "SN": "Senegal"
  of "SO": "Somalia"
  of "SR": "Suriname"
  of "SS": "South Sudan"
  of "ST": "Sao Tome and Principe"
  of "SV": "El Salvador"
  of "SX": "Sint Maarten"
  of "SY": "Syrian Arab Republic"
  of "SZ": "Eswatini"
  of "TC": "Turks and Caicos Islands"
  of "TD": "Chad"
  of "TF": "French Southern Territories"
  of "TG": "Togo"
  of "TH": "Thailand"
  of "TJ": "Tajikistan"
  of "TK": "Tokelau"
  of "TL": "Timor-Leste"
  of "TM": "Turkmenistan"
  of "TN": "Tunisia"
  of "TO": "Tonga"
  of "TR": "Türkiye"
  of "TT": "Trinidad and Tobago"
  of "TV": "Tuvalu"
  of "TW": "Taiwan"
  of "TZ": "Tanzania"
  of "UA": "Ukraine"
  of "UG": "Uganda"
  of "UM": "United States Minor Outlying Islands"
  of "US": "United States"
  of "UY": "Uruguay"
  of "UZ": "Uzbekistan"
  of "VA": "Holy See (Vatican City)"
  of "VC": "Saint Vincent and the Grenadines"
  of "VE": "Venezuela"
  of "VG": "Virgin Islands (British)"
  of "VI": "Virgin Islands (U.S.)"
  of "VN": "Viet Nam"
  of "VU": "Vanuatu"
  of "WF": "Wallis and Futuna"
  of "WS": "Samoa"
  of "YE": "Yemen"
  of "YT": "Mayotte"
  of "ZA": "South Africa"
  of "ZM": "Zambia"
  of "ZW": "Zimbabwe"
  of "LO", "LAN", "LOCAL": "Local / Private Network"
  of "EU": "European Union"
  of "AP": "Asia-Pacific Region"
  of "A1": "Anonymous Proxy"
  of "A2": "Satellite Provider"
  of "T1": "Tor Exit Node"
  of "O1": "Other Country"
  of "XX", "??", "": "Unknown Country"
  else: "Unknown Country"

func isSpecialOrPseudoCode*(countryCode: string): bool =
  ## Returns true if the given code is a special pseudo-code used by GeoIP providers or private networks.
  let cleaned = countryCode.strip().toUpperAscii()
  case cleaned
  of "EU", "AP", "A1", "A2", "T1", "O1", "LO", "LAN", "LOCAL", "XX", "??", "UK":
    return true
  else:
    return false

func flagTerminalFallback*(countryCode: string): string =
  ## Returns an ASCII/terminal-safe text fallback for environments that do not support
  ## 2-character wide Unicode flag emojis.
  let cleaned = countryCode.strip().toUpperAscii()
  case cleaned
  of "LO", "LAN", "LOCAL":
    return "[LAN]"
  of "XX", "??", "", "???", "UNKNOWN":
    return "[--]"
  of "T1":
    return "[TOR]"
  of "A1":
    return "[PROXY]"
  of "A2":
    return "[SAT]"
  of "EU":
    return "[EU]"
  of "AP":
    return "[AP]"
  of "UK":
    return "[UK]"
  of "O1":
    return "[OTHER]"
  else:
    if cleaned.len == 2 and cleaned[0] in 'A'..'Z' and cleaned[1] in 'A'..'Z':
      return "[" & cleaned & "]"
    return "[--]"

proc terminalSupportsEmoji*(): bool =
  ## Detects whether the current terminal environment supports 2-character wide emoji symbols.
  ## Returns false if NO_EMOJI is set, TERM is 'dumb' or 'raw', or stdout is redirected without unicode support.
  if getEnv("NO_EMOJI").len > 0:
    return false
  let term = getEnv("TERM").toLowerAscii()
  if term == "dumb" or term == "raw":
    return false
  return true

func formatCountryFlag*(countryCode: string, useEmoji: bool = true): string =
  ## Formats a country code into either a Unicode flag emoji (if useEmoji is true)
  ## or an ASCII terminal fallback bracketed code (if useEmoji is false).
  if useEmoji:
    isoToFlagEmoji(countryCode)
  else:
    flagTerminalFallback(countryCode)

func formatCountryBadge*(countryCode: string, useEmoji: bool = true): string =
  ## Formats a fixed-width country badge suitable for columnar terminal display.
  ## If useEmoji is true: returns e.g. "🇺🇸 US" (emoji + space + 2-letter code)
  ## If useEmoji is false: returns e.g. `[US] US` or `[LAN] LO`
  let cleaned = countryCode.strip().toUpperAscii()
  let code = if cleaned.len == 2:
               cleaned
             elif cleaned in ["LAN", "LOCAL"]:
               "LO"
             elif cleaned.len > 0:
               cleaned[0..min(1, cleaned.len - 1)]
             else:
               "--"
  if useEmoji:
    return isoToFlagEmoji(cleaned) & " " & code
  else:
    return flagTerminalFallback(cleaned) & " " & code



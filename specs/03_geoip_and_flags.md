# Specification 03: GeoIP Enrichment & Country Flag Resolution

## 1. Overview & Objective
This specification defines the geolocation enrichment module and Unicode flag generation engine for `http_logviewer`.
Every HTTP log entry client IP must be mapped to its country of origin, displaying:
1. **Unicode Regional Indicator Flag Emoji** (e.g., `🇺🇸`, `🇩🇪`, `🇳🇱`, `🇯🇵`).
2. **ISO 3166-1 alpha-2 Country Code** (e.g., `US`, `DE`, `NL`, `JP`).
3. **Full Country Name** (e.g., "United States", "Germany").
4. **Special Handling for Local / Private Networks** (e.g., `🏠 Local / LAN`).

Implementation target: `src/http_logviewer/enrichment/flags.nim` and `src/http_logviewer/enrichment/geoip.nim`.

---

## 2. Unicode Flag Emoji Generation (`flags.nim`)

### 2.1 Algorithmic Regional Indicator Conversion
Unicode represents country flags using pairs of Regional Indicator Symbol letters (`U+1F1E6` for Regional Indicator Symbol Letter A through `U+1F1FF` for Z).
The conversion from a 2-letter ISO code to a flag emoji is computed mathematically:

```nim
const
  RegionalIndicatorBase = 0x1F1E6 # UTF-32 codepoint for '🇦'
  AsciiUpperBase = ord('A')

proc isoToFlagEmoji*(countryCode: string): string =
  ## Converts a 2-letter ISO 3166-1 alpha-2 country code into a Unicode flag emoji.
  ## Example: "US" -> "🇺🇸", "DE" -> "🇩🇪"
  if countryCode.len != 2:
    return "🌐" # Fallback globe icon
  
  let c1 = countryCode[0].toUpperAscii()
  let c2 = countryCode[1].toUpperAscii()
  
  if c1 notin 'A'..'Z' or c2 notin 'A'..'Z':
    return "🌐"
    
  let codePoint1 = RegionalIndicatorBase + (ord(c1) - AsciiUpperBase)
  let codePoint2 = RegionalIndicatorBase + (ord(c2) - AsciiUpperBase)
  
  # Encode UTF-32 codepoints into UTF-8 string
  result = toUtf8(codePoint1) & toUtf8(codePoint2)
```

### 2.2 ISO Code to Country Name Dictionary
Provide a static table mapping standard ISO-3166-1 codes to English country names:
```nim
proc getCountryName*(countryCode: string): string =
  case countryCode.toUpperAscii()
  of "US": "United States"
  of "DE": "Germany"
  of "GB", "UK": "United Kingdom"
  of "FR": "France"
  of "NL": "Netherlands"
  of "CA": "Canada"
  of "CN": "China"
  of "RU": "Russian Federation"
  of "JP": "Japan"
  of "BR": "Brazil"
  of "IN": "India"
  of "AU": "Australia"
  # Comprehensive dictionary covers top 249 ISO countries
  else: "Unknown Country"
```

---

## 3. Bogon, Private, and Local IP Detection (`geoip.nim`)

Before querying any external GeoIP database, detect local, loopback, and private IPs:
```nim
proc isPrivateIp*(ip: string): bool =
  ## Returns true if the IP belongs to RFC 1918, Loopback, Link-Local, or Carrier-grade NAT
  if ip == "127.0.0.1" or ip == "::1" or ip == "localhost":
    return true
  if ip.startsWith("10.") or ip.startsWith("192.168."):
    return true
  if ip.startsWith("172."):
    # Check 172.16.0.0/12
    var octet2: int
    if parseOctet2(ip, octet2) and octet2 in 16..31:
      return true
  if ip.startsWith("169.254."): # Link-local
    return true
  if ip.startsWith("100.64."):  # CGNAT
    return true
  return false
```

When `isPrivateIp(ip)` is true, return:
```nim
GeoLocation(
  ip: ip,
  countryCode: "LO",
  countryName: "Local / Private Network",
  flagEmoji: "🏠",
  isPrivate: true
)
```

---

## 4. GeoIP Lookup Engine & Caching

### 4.1 Lookup Provider Interface
```nim
type
  GeoIpEngine* = ref object
    cache: Table[string, GeoLocation]
    maxCacheEntries: int
    dbPath: Option[string]

proc newGeoIpEngine*(customDbPath: Option[string] = none(string)): GeoIpEngine
proc lookup*(engine: GeoIpEngine, ip: string): GeoLocation
```

### 4.2 Database Discovery & Fallback
The engine must search for offline MaxMind MMDB databases (`GeoLite2-Country.mmdb`) in order of priority:
1. Custom path provided via `--geoip-db=<path>`.
2. Current working directory: `./GeoLite2-Country.mmdb`.
3. System directories:
   - `/usr/share/GeoIP/GeoLite2-Country.mmdb`
   - `/var/lib/GeoIP/GeoLite2-Country.mmdb`
   - `/etc/GeoIP/GeoLite2-Country.mmdb`
4. Embedded Fallback: If no `.mmdb` file is present, provide a built-in static CIDR lookup table mapping prominent cloud/botnet IP ranges (AWS, DigitalOcean, Cloudflare, OVH, Hetzner) to their base countries, and return `"XX"` (Unknown) with a `"🌐"` icon for unmapped ranges without erroring.

### 4.3 High-Performance LRU Memory Cache
Because web traffic from repeated IPs (or heavy scanning bots) generates thousands of requests, cache lookup results in an in-memory hash table. Limit cache size to 50,000 entries using an eviction strategy when capacity is reached.

---

## 5. Acceptance Criteria
- Unit tests in `tests/t_geoip.nim` verify that private IPs (`10.x`, `192.168.x`, `127.0.0.1`) return `"🏠"` without attempting database lookups.
- Tests verify that `isoToFlagEmoji("US")` yields `"🇺🇸"`, `"DE"` yields `"🇩🇪"`, and `"NL"` yields `"🇳🇱"`.
- Performance: Cached lookups take < 100 nanoseconds per query.

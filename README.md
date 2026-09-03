# http_logviewer

High-performance HTTP log viewer and rogue bot detector written in Nim. `http_logviewer` ingests standard HTTP access logs (Common Log Format, Combined Nginx/Apache, Caddy, JSON) and provides real-time enriched terminal output with threat intelligence, country flags, background-colored status badges, and distributed multi-IP actor correlation.

## Key Features

- **Country Flag & GeoIP Enrichment**: Automatically resolves IP addresses to country codes, full country names, and Unicode regional indicator flag emojis (e.g., `🇺🇸 US`, `🇩🇪 DE`, `🇳🇱 NL`, `🏠 LAN`).
- **Visitor Intent Classification**: Instantly distinguishes legitimate human visitors (`REAL_USER`) from verified search engines (`VERIFIED_BOT`), friendly crawlers (`FRIENDLY_CRAWLER`), commercial scrapers (`COMMERCIAL_BOT`), suspicious scanners (`SUSPICIOUS`), and malicious vulnerability probes (`BAD_ACTOR_HACKER`).
- **High-Visibility HTTP Status Badges**: Background-colored ANSI styling to make errors and anomalies instantly identifiable in scrolling logs (bold white on red for `404`, magenta/red for `500`/`502`, yellow for `3xx`, green for `2xx`).
- **Multi-IP Distributed Actor Correlation**: Correlates requests originating from rotating IP addresses and proxies that belong to the exact same botnet campaign or attacker using temporal heuristics, User-Agent telemetry, and probe sequence fingerprinting.
- **Zero External Runtime Dependencies**: Built entirely on Nim's high-performance standard library with low memory overhead and $O(1)$ streaming capability.

---

## Platform Support

`http_logviewer` is tested and supported on:
- **Linux**: Standard POSIX terminal with ANSI/VT220 true-color support.
- **Windows**: Windows Terminal and PowerShell (ANSI escape code support required).
- **macOS**: Terminal.app, iTerm2, and modern POSIX terminal emulators.

---

## Requirements

- **Nim**: Version 2.2.10 or newer (tested with ARC/ORC memory management).
- **Dependencies**: None required for core runtime and CLI.
- **Asciinema & Agg** (Optional development tooling): For recording terminal asciicasts and rendering documentation GIFs.

---

## Architecture Overview

```
                      +-----------------------------+
                      |   HTTP Log Source           |
                      | (File, Pipe STDIN, tail -f) |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |  1. Ingestion & Parser      |
                      |  (CLF, Combined, JSON)      |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |  2. GeoIP & ASN Enrichment  |
                      |  (ISO Code, Flag Emoji)     |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |  3. Threat Classifier       |
                      |  (OWASP Top 10, Scanners)   |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |  4. Actor Correlator        |
                      |  (Multi-IP Cluster Engine)  |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |  5. Terminal Renderer       |
                      |  (ANSI Badges, Tables, TUI) |
                      +-----------------------------+
```

---

## Table of Contents

- [Platform Support](#platform-support)
- [Requirements](#requirements)
- [Architecture Overview](#architecture-overview)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [API Overview](#api-overview)
  - [Core Log Entry Models](#1-core-log-entry-models)
  - [Threat and Actor Domain Models](#2-threat-and-actor-domain-models)
  - [Configuration and State Models](#3-configuration-and-state-models)
  - [Log Format Detection & Parsers](#4-log-format-detection--parsers)
- [Examples](#examples)
- [Development and Documentation](#development-and-documentation)
- [Attribution and License](#attribution-and-license)

---

## Installation

Clone the repository and build using Nimble:

```bash
git clone https://github.com/titanomachy/http-logviewer.git
cd http-logviewer
nimble build
```

The resulting binary will be placed inside `build/http_logviewer`. All compiler intermediate files are isolated to `build/nimcache/`.

---

## Quick Start

Execute the pre-built test suite to verify all modules:

```bash
nimble test
```

To run a standalone example demonstrating domain model capabilities:

```bash
nim r --path:src examples/threat_and_actor_models.nim
```

---

## API Overview

The library exposes clean, type-safe Nim APIs organized into modular layers:

| Component | Source Module | Primary Types & Concepts | Description |
| :--- | :--- | :--- | :--- |
| [Log Entry Models](#1-core-log-entry-models) | `http_logviewer/core/types` | `HttpLogEntry`, `HttpMethod` | Normalized representation of parsed HTTP log lines, status codes, and HTTP verbs |
| [Threat & Actor Models](#2-threat-and-actor-domain-models) | `http_logviewer/core/types` | `ActorCategory`, `ThreatFlag`, `ThreatProfile`, `ActorCluster`, `GeoLocation`, `EnrichedLogRecord` | Threat intelligence scoring, atomic exploit flags, bot detection, and multi-IP correlation clusters |
| [Configuration & State Models](#3-configuration-and-state-models) | `http_logviewer/core/config`, `http_logviewer/cli/args` | `ViewerConfig`, `FilterCriteria`, `OutputFormat`, `LogFormat`, `ColorMode`, `CliOptions` | Runtime session configuration, granular traffic filtering criteria, format negotiation, and CLI option mapping |
| [Log Format Detection & Parsers](#4-log-format-detection--parsers) | `http_logviewer/parser/formats` | `parseClfLine`, `parseCombinedLine`, `parseNginxLine`, `parseJsonLine`, `parseLine`, `detectLogFormat`, `HttpStatusClass` | High-performance low-allocation parsers for W3C CLF, Nginx/Apache Combined, Caddy JSON, format auto-detection, and HTTP status code token classification |
| Error Hierarchy | `http_logviewer/core/errors` | `HttpLogViewerError`, `ParseError`, `ThreatAnalysisError`, `ConfigError` | Robust exception hierarchy derived from `CatchableError` |

---

### 1. Core Log Entry Models

Provides normalized representation of parsed HTTP requests, method parsing, JSON serialization, and set/table interoperability:

```nim
import std/times
import http_logviewer/core/types

let entry = initHttpLogEntry(
  clientIp = "192.168.1.100",
  timestamp = now().utc,
  `method` = HttpGet,
  path = "/index.html",
  statusCode = 200,
  bytesSent = 4096,
  referer = "https://example.com",
  userAgent = "Mozilla/5.0"
)

echo "Single-line format: ", entry
echo entry.pretty()
```

Compile and run this example:
```bash
nim r --path:src examples/log_entry_models.nim
```

---

### 2. Threat and Actor Domain Models

Enables classification of visitor intent, tracking of atomic attack indicators (e.g. SQLi, CMS exploits, path traversal), and correlation of disparate IP addresses belonging to the same distributed botnet:

```nim
import std/[times, sets, options, json]
import http_logviewer/core/types

# 1. Threat scoring
let threat = initThreatProfile(
  score = 92,
  category = CategoryBadActorHacker,
  flags = {ThreatCmsExploit, ThreatSensitiveFile},
  matchedSignatures = @["wp_login_probe", "env_credential_harvest"]
)
assert threat.isHacker()

# 2. Geolocation with flag emojis
let geo = initGeoLocation(
  ip = "185.220.101.5",
  countryCode = "NL",
  countryName = "Netherlands",
  flagEmoji = "🇳🇱"
)

# 3. Multi-IP Actor Clustering
let cluster = newActorCluster(clusterId = "ACTOR-WP-BOTNET", primaryUa = "Masscan/1.3")
let log1 = initHttpLogEntry(clientIp = "185.220.101.5", `method` = HttpPost, path = "/wp-login.php", statusCode = 404)
cluster.addEntry(log1, score = 80, category = CategoryBadActorHacker, flags = {ThreatCmsExploit})

# 4. Enriched pipeline event
let enriched = initEnrichedLogRecord(log1, geo, threat, some(cluster.clusterId))
echo enriched
```

#### Terminal Demonstration

The recording below illustrates visitor categorization, threat profiling, multi-IP cluster tracking, and JSON serialization in action:

![Threat and Actor Domain Models](docs/images/threat_and_actor_models.gif)

> *Source session recording:* [`docs/recordings/threat_and_actor_models.cast`](docs/recordings/threat_and_actor_models.cast) *(recorded with Asciinema, rendered via Agg with JetBrainsMono Nerd Font Mono)*.

Compile and run this example:
```bash
nim r --path:src examples/threat_and_actor_models.nim
```

---

### 3. Configuration and State Models

Manages runtime execution modes, input/output format negotiation, multi-dimensional traffic filtering criteria, CLI option parsing, and bidirectional JSON configuration serialization:

```nim
import std/options
import http_logviewer/core/[types, config]
import http_logviewer/cli/args

# 1. Production defaults
let cfg = defaultViewerConfig()
assert cfg.logFilePath == "-"
assert cfg.colorOutput == true
assert cfg.outputFormat == FormatStreamTable

# 2. Granular filtering criteria
let criteria = initFilterCriteria(
  minThreatScore = 50,
  statusWhitelist = [401, 403, 404, 500],
  countryWhitelist = ["US", "DE", "NL"],
  categories = {CategoryBadActorHacker, CategorySuspicious}
)
assert criteria.allowsStatus(404)
assert not criteria.allowsStatus(200)

# 3. CLI command-line parsing and mapping to ViewerConfig
let cliArgs = ["-f", "--filter=hacker", "--min-score=70", "--group-actors", "/var/log/nginx/access.log"]
let runtimeCfg = parseCommandLine(cliArgs)
assert runtimeCfg.follow == true
assert runtimeCfg.minThreatScore == 70
assert runtimeCfg.enableGrouping == true
```

#### Terminal Demonstration

The recording below illustrates runtime configuration inspection, filter criteria evaluation, CLI flag parsing, JSON round-trip serialization, and validation boundary enforcement in action:

![Configuration and State Models](docs/images/configuration_and_state_models.gif)

> *Source session recording:* [`docs/recordings/configuration_and_state_models.cast`](docs/recordings/configuration_and_state_models.cast) *(recorded with Asciinema, rendered via Agg with JetBrainsMono Nerd Font Mono)*.

Compile and run this example:
```bash
nim r --path:src examples/configuration_and_state_models.nim
```

---

### 4. Log Format Detection & Parsers

High-performance zero-allocation log parsers supporting W3C Common Log Format (CLF), Nginx and Apache Combined format, structured JSON access logs (Nginx flat and Caddy nested schemas), format auto-detection, and HTTP status code classification:

```nim
import std/options
import http_logviewer/core/[types, config]
import http_logviewer/parser/formats

# 1. Format auto-detection across sample lines
let line = "192.168.1.100 - - [10/Oct/2026:13:55:36 +0200] \"GET /index.html HTTP/1.1\" 200 2326 \"https://example.com\" \"Mozilla/5.0\""
let detectedFormat = detectLogFormatLine(line)
assert detectedFormat == LogFormatCombined

# 2. Parsing Combined format (with Referer and User-Agent)
var entry: HttpLogEntry
assert parseCombinedLine(line, entry)
assert entry.clientIp == "192.168.1.100"
assert entry.statusCode == 200
assert entry.referer == "https://example.com"
assert entry.userAgent == "Mozilla/5.0"

# 3. Parsing structured JSON access logs (supporting Caddy nested and Nginx flat schemas)
let jsonLine = """{"client_ip": "1.2.3.4", "timestamp": "2026-10-10T13:55:36Z", "method": "GET", "uri": "/api/v1", "status": 200, "bytes": 1024}"""
var jsonEntry: HttpLogEntry
assert parseJsonLine(jsonLine, jsonEntry)
assert jsonEntry.clientIp == "1.2.3.4"

# 4. Status code classification and canonical descriptions
assert statusClass(404) == StatusClientError
assert isClientError(404)
assert statusDescription(404) == "Not Found"

# 5. Unified line parser with automatic format detection
var autoEntry: HttpLogEntry
assert parseLine(line, autoEntry, LogFormatAuto)
assert autoEntry.statusCode == 200
```

#### Terminal Demonstration

The recording below illustrates format auto-detection, Common Log Format (CLF) parsing, Combined format parsing with referer/user-agent extraction, Caddy JSON parsing, and HTTP status classification in action:

![Log Format Detection and Parsing](docs/images/format_detection_and_parsing.gif)

> *Source session recording:* [`docs/recordings/format_detection_and_parsing.cast`](docs/recordings/format_detection_and_parsing.cast) *(recorded with Asciinema, rendered via Agg with JetBrainsMono Nerd Font Mono)*.

Compile and run this example:
```bash
nim r --path:src examples/format_detection_and_parsing.nim
```

---

## Examples

The `examples/` folder provides executable demonstrations of each pipeline layer:

- [`examples/basic_usage.nim`](examples/basic_usage.nim): Baseline library imports and configuration sanity check.
- [`examples/log_entry_models.nim`](examples/log_entry_models.nim): Detailed usage of `HttpLogEntry`, `HttpMethod`, stringifiers, and JSON round-tripping.
- [`examples/threat_and_actor_models.nim`](examples/threat_and_actor_models.nim): Comprehensive threat scoring, geolocation enrichment, and multi-IP cluster correlation.
- [`examples/configuration_and_state_models.nim`](examples/configuration_and_state_models.nim): Runtime session configuration, granular traffic filter criteria, CLI argument parsing, and JSON configuration serialization.
- [`examples/format_detection_and_parsing.nim`](examples/format_detection_and_parsing.nim): High-performance log parsing across CLF, Combined, and JSON formats, format auto-detection, and HTTP status code token classification.
- [`examples/pipeline_scaffolding.nim`](examples/pipeline_scaffolding.nim): Cross-module pipeline event envelope demonstration.

---

## Development and Documentation

Common developer workflows supported by Nimble:

```bash
# Run unit and integration test suite
nimble test

# Run CI sanity check script
nimble ci

# Generate HTML documentation into build/docs/
nimble docs

# Clean all build artifacts and nimcache
nimble clean
```

All build targets, intermediate C files, and generated HTML documentation reside strictly in the `build/` directory.

---

## Attribution and License

- Licensed under the [MIT License](LICENSE).
- Developed in Nim for maximum throughput, low memory footprint, and high-visibility terminal security auditing.

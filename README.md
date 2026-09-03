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
| Error Hierarchy | `http_logviewer/core/errors` | `HttpLogViewerError`, `ParseError`, `ThreatAnalysisError` | Robust exception hierarchy derived from `CatchableError` |

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

## Examples

The `examples/` folder provides executable demonstrations of each pipeline layer:

- [`examples/basic_usage.nim`](examples/basic_usage.nim): Baseline library imports and configuration sanity check.
- [`examples/log_entry_models.nim`](examples/log_entry_models.nim): Detailed usage of `HttpLogEntry`, `HttpMethod`, stringifiers, and JSON round-tripping.
- [`examples/threat_and_actor_models.nim`](examples/threat_and_actor_models.nim): Comprehensive threat scoring, geolocation enrichment, and multi-IP cluster correlation.
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

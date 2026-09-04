# Changelog

All notable changes to the `http_logviewer` project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Phase 00: Project Initialization & Build System Configuration
##### Category A: Nimble & Compiler Configuration
- Configured `http_logviewer.nimble` with `binDir = "build"` and entry point `src/http_logviewer.nim`.
- Isolated intermediate compiler outputs in root `nim.cfg` via `--nimcache:"build/nimcache"` and `--outdir:"build"`.
- Added Nimble tasks for `build`, `release`, `debug`, `test`, `ci`, `doc`, and `clean`.
- Verified clean build output isolation in `build/http_logviewer`.
- Configured `.gitignore` for isolated build directories and temporary files.

##### Category B: Directory Scaffolding & Tooling Prelude
- Scaffolded modular source directory tree: `src/http_logviewer/{core, parser, enrichment, analyzer, renderer, cli}`.
- Scaffolded test fixtures directory: `tests/fixtures` with sample access logs.
- Implemented robust error handling hierarchy and assertion templates in `src/http_logviewer/core/errors.nim` and `prelude.nim`, inheriting from `CatchableError` (`HttpLogViewerError`, `ParseError`, `GeoIpError`, `ThreatAnalysisError`, `ConfigError`, `RenderError`, `PipelineError`).
- Configured automated CI sanity check script `scripts/ci_check.sh` and Nimble `ci` task.
- Implemented end-to-end hello-world pipeline and cross-module import verification tests (`tests/t_scaffolding.nim`, `tests/t_prelude.nim`, `tests/t_pipeline_hello.nim`).
- Created pipeline scaffolding example in `examples/pipeline_scaffolding.nim`.

#### Phase 01: Core Architecture & Data Models
##### Category A: Log Entry Models & Enums
- Defined `HttpMethod` enum (`HttpGet`, `HttpPost`, `HttpPut`, `HttpDelete`, `HttpHead`, `HttpOptions`, `HttpPatch`, `HttpConnect`, `HttpTrace`, `HttpOther`, `HttpUnknown`) with case-insensitive token parser and canonical stringifier.
- Defined `HttpLogEntry` object representing normalized HTTP access lines with IP, timestamp, method, path, status code, bytes sent, referer, User-Agent, and raw log lines.
- Implemented single-line `$` stringifier and multi-line `pretty()` structured formatter for `HttpLogEntry`.
- Implemented structured JSON serialization and deserialization (`%` and `parseHttpLogEntryJson`) for `HttpLogEntry`.
- Implemented value equality `==` and custom 64-bit `hash` procedures supporting `HashSet` and `Table` deduplication.
- Implemented validation routines (`isValid`, `validate`) verifying IP presence and standard HTTP status code bounds (100..599).
- Added unit tests in `tests/t_core_types.nim` covering edge cases including IPv6 addresses, large 64-bit byte counts, and URL-escaped characters.
- Created standalone runnable code example in `examples/log_entry_models.nim`.

##### Category B: Threat & Actor Domain Models
- Defined `ActorCategory` enum (`CategoryUnknown`, `CategoryRealUser`, `CategoryVerifiedBot`, `CategoryFriendlyCrawler`, `CategoryCommercialBot`, `CategorySuspicious`, `CategoryBadActorHacker`) and helper predicates (`isBot`, `isHacker`, `isRealUser`).
- Defined `ThreatFlag` enum (`ThreatSensitiveFile`, `ThreatCmsExploit`, `ThreatDirectoryTraversal`, `ThreatSqlInjection`, `ThreatCommandInjection`, `ThreatKnownScannerUa`, `ThreatMalformedRequest`, `ThreatHighRate404`, `ThreatNoAssetFetch`) and alias constants (`PathExploit`, `SqlInjection`, `CommandInjection`, `TraversalAttempt`, `SensitiveFileProbe`, `KnownScannerUa`, `AggressiveRate`, `NoAssetsRequested`).
- Defined `ThreatProfile` object (`score`, `category`, `flags`, `matchedSignatures` / `matchedRules`) with threat evaluation predicates (`isHacker`, `isBot`, `isSuspicious`, `isRealUser`), range validation (0..100), and JSON serialization.
- Defined `ActorCluster` reference object (`clusterId`, `primaryUa`, `ips`, `entries`, `firstSeen`, `lastSeen`, `highestThreatScore`, `aggregateRisk`, `category`, `flags`, `probedPaths`) and dynamic multi-IP ingestion procedure (`addEntry`).
- Defined `GeoLocation` record (`ip`, `countryCode`, `countryName`, `flagEmoji`, `isPrivate`, `city`) with Unicode regional indicator flag support and private LAN detection.
- Defined `EnrichedLogRecord` envelope uniting log entry, geolocation, threat profile, and cluster ID for pipeline presentation.
- Added comprehensive unit tests in `tests/t_threat_actor_models.nim` validating enum ordinals, set operations (`incl`, `excl`, union, intersection, difference, complement), bitset safety, and JSON round-tripping.
- Created executable example in `examples/threat_and_actor_models.nim`.
- Recorded terminal asciicast (`docs/recordings/threat_and_actor_models.cast`) and generated high-resolution animated GIF (`docs/images/threat_and_actor_models.gif`) with Asciinema and Agg.

##### Category C: Configuration & State Models
- Defined `ViewerConfig` object in `src/http_logviewer/core/config.nim` with settings for log format, color mode, live tailing, filtering thresholds, and multi-IP grouping mode.
- Defined presentation and format enums: `OutputFormat` (`FormatStreamTable`, `FormatJson`, `FormatGroupedSummary`), `LogFormat` (`LogFormatAuto`, `LogFormatClf`, `LogFormatCombined`, `LogFormatNginx`, `LogFormatJson`), and `ColorMode` (`ColorModeAuto`, `ColorModeAlways`, `ColorModeNever`) with stringifiers and robust parsers.
- Defined `FilterCriteria` object supporting minimum threat score threshold, status code whitelist/blacklist, ISO country code whitelist/blacklist, actor category filters, and composite matching helpers (`allowsScore`, `allowsStatus`, `allowsCountry`, `allowsCategory`, `matches`).
- Implemented default configuration loader `defaultViewerConfig()` with sensible production defaults, configuration validation routines (`validate`, `isValid`), and bidirectional JSON serialization/deserialization (`%`, `parseViewerConfigJson`, `loadViewerConfigJson`).
- Implemented CLI option mapping structs (`CliOptions`, `CliOptionKind`, `CliOptionDef`) and argument parsers (`parseCliArgs`, `toViewerConfig`, `parseCommandLine`, `parseCommandLineArgs`) in `src/http_logviewer/cli/args.nim`.
- Implemented unit test suite in `tests/t_config.nim` verifying configuration construction, enum parsing, filtering logic, validation boundary constraints, JSON round-tripping, and CLI flag handling.
- Created runnable code example in `examples/configuration_and_state_models.nim`.
- Recorded terminal asciicast (`docs/recordings/configuration_and_state_models.cast`) and generated animated GIF (`docs/images/configuration_and_state_models.gif`) with Asciinema and Agg.

#### Phase 02: High-Performance Log Ingestion & Parsing Engine
##### Category A: Format Detection & Standard Formats
- Implemented W3C Common Log Format (CLF) parser using fast `parseutils` slicing in `src/http_logviewer/parser/formats.nim` (`parseClfLine`).
- Implemented Nginx and Apache Combined Log Format parser (`parseCombinedLine`, `parseNginxLine`) with escape-aware quoted token extraction for Referer and User-Agent fields.
- Implemented log format auto-detection heuristic (`detectLogFormatLine`, `detectLogFormat`) inspecting leading lines to identify JSON, Combined, or CLF formats.
- Implemented structured JSON access log parser (`parseJsonLine`) supporting flat Nginx JSON schemas and Caddy nested schemas with float/integer UNIX timestamps and header array lookups.
- Implemented robust HTTP method and status code token parser (`parseHttpMethodToken`, `parseStatusCode`), RFC status class categorizer (`HttpStatusClass`, `statusClass`), boolean status predicates (`isSuccess`, `isRedirect`, `isClientError`, `isServerError`, `isNotFound`, `isForbidden`), and canonical reason phrases (`statusDescription`).
- Provided unified high-level pipeline line parser (`parseLine`) with automatic format detection and graceful fallback resilience.
- Added comprehensive unit and integration test suite in `tests/t_parser.nim` with real-world Nginx and Apache log fixtures (`tests/fixtures/combined.log`, `tests/fixtures/clf.log`).
- Created runnable example in `examples/format_detection_and_parsing.nim`.
- Recorded terminal asciicast (`docs/recordings/format_detection_and_parsing.cast`) and generated animated demo GIF (`docs/images/format_detection_and_parsing.gif`) with Asciinema and Agg.

##### Category B: Streaming Ingestion & Pipe Support
- Implemented `StreamReader` reference type supporting buffered low-allocation reading from files, STDIN pipes (`-` or `stdin`), custom in-memory streams (`std/streams.Stream`), and transparent gzip archives.
- Implemented live file tailing (`-f / --follow`) with `readLineFollow` polling for file growth, handling log file truncation (`copytruncate`), clearing C stdio EOF states via `clearerr`, and recovering from log rotation (inode/device changes).
- Added native transparent gzip decompression stream reader for `.log.gz` archives and gzip-compressed streams using system `zlib` C bindings (`gzopen`, `gzread`, `gzwrite`, `gzclose`), including `isGzipFile` and `writeGzipFile` utilities.
- Ensured memory usage remains strictly $O(1)$ during continuous high-throughput streaming of multi-gigabyte log files using reusable line and chunk buffers.
- Implemented high-level stream orchestrators `streamLogLines` and `streamRawLines` supporting progress callbacks, cancellation procs (`shouldStop`), and malformed line tracking.
- Added throughput benchmarking utility `benchmarkParsingThroughput`, achieving > 400,000 lines/second on standard Combined log lines (exceeding the 100,000 lines/sec target).
- Added unit and integration test suite in `tests/t_stream_engine.nim` covering buffered reading, live file tailing, truncation recovery, gzip reading from fixtures (`tests/fixtures/combined.log.gz`), O(1) memory bounds, and throughput benchmarks.
- Created runnable example in `examples/streaming_and_pipe_ingestion.nim`.
- Recorded terminal asciicast (`docs/recordings/streaming_and_pipe_ingestion.cast`) and generated animated demo GIF (`docs/images/streaming_and_pipe_ingestion.gif`) with Asciinema and Agg using JetBrainsMono Nerd Font Mono.

##### Category C: Parsing Fault-Tolerance & Edge Cases
- Implemented robust string sanitizers `sanitizeUtf8` and `sanitizeControlChars` in `src/http_logviewer/parser/formats.nim` to scrub invalid byte sequences, raw null bytes, ANSI escape sequences (`\x1b`), and terminal control characters without crashing.
- Implemented lookahead quoted token extractors (`parseRequestQuotedString`, `parseRefererQuotedString`, `parseUserAgentQuotedString`) handling both escaped quotes and unescaped interior quotes in URI paths, query strings, and User-Agent headers.
- Implemented `cleanIpAddress`, `isIpv4Address`, `isIpv6Address`, and `isValidIpAddress` in `src/http_logviewer/parser/formats.nim` supporting IPv4 and IPv6 normalization, stripping port numbers (`:8080`), bracket enclosures (`[2001:db8::1]:443`), interface scope identifiers (`%eth0`), surrounding quotes, and extracting client IPs from comma-separated `X-Forwarded-For` proxy chains.
- Implemented locale month normalization (`normalizeMonthToken`, `normalizeLogDateString`) supporting German (`Okt`, `Mrz`), Dutch (`mrt`, `mei`), French (`févr.`, `août`), Spanish (`Dic`, `Ene`), and numeric month formats, along with robust support for negative timezone offsets (`-0700`, `-05:00`), named timezones (`UTC`, `GMT`), and ISO fractional seconds in `parseLogDateTime`.
- Added malformed line tracking to `StreamReader` (`unparsedLines`, `parsedEntries`) and implemented `ParsingDiagnostics` in `src/http_logviewer/parser/engine.nim` supporting success/malformed counters and optional stderr diagnostic warning output.
- Added comprehensive unit and stress tests in `tests/t_parser.nim` and `tests/t_stream_engine.nim` covering adversarial OWASP payloads, SQL injection strings, raw binary noise, non-log formats (HTML, Java stack traces, SQL, syslog), and truncated lines at every token boundary.
- Created runnable example in `examples/parsing_fault_tolerance.nim`.
- Recorded terminal asciicast (`docs/recordings/parsing_fault_tolerance.cast`) and generated animated demo GIF (`docs/images/parsing_fault_tolerance.gif`) with Asciinema and Agg using JetBrainsMono Nerd Font Mono.

#### Phase 03: GeoIP Enrichment & Country Flag Resolution
##### Category A: IP-to-Country Lookup Engine
- Designed polymorphic `GeoIpProvider` interface with abstract base lookup dispatch and implemented unified `GeoIpEngine` in `src/http_logviewer/enrichment/geoip.nim`.
- Implemented zero-dependency offline binary MaxMind DB (`.mmdb`) parser (`MmdbGeoIpProvider`) supporting 24-bit, 28-bit, and 32-bit binary trees, data pointer resolution, metadata inspection, and country/city resolution.
- Implemented embedded offline CIDR fallback database (`CidrGeoIpProvider`) mapping prominent public clouds and global networks (Google, Cloudflare, AWS, Azure, Hetzner, OVH, DigitalOcean, Netherlands, China, Russia, Japan, etc.) with zero external file dependencies.
- Implemented RFC 1918, Loopback, Link-Local, CGNAT, and IPv6 private/ULA bogon detection (`isPrivateIp`), instantly mapping local traffic to `🏠 LO (Local / Private Network)` with zero database overhead.
- Implemented high-performance $O(1)$ LRU memory cache (`LruCache`, `CachedGeoIpProvider`) with configurable entry limits (default 50,000 entries), sub-100ns lookup latency, and hit/miss telemetry tracking.
- Implemented automatic database discovery (`discoverMmdbPath`) searching custom paths (`--geoip-db`), current working directory, and standard system paths (`/usr/share/GeoIP/`, `/var/lib/GeoIP/`, `/etc/GeoIP/`).
- Added ISO 3166-1 alpha-2 regional indicator symbol flag emoji converter (`isoToFlagEmoji`) and country dictionary (`getCountryName`) in `src/http_logviewer/enrichment/flags.nim`.
- Added comprehensive unit and integration test suite in `tests/t_geoip.nim` verifying provider dispatch, synthetic MMDB parsing, CIDR lookups, private IP classification, LRU eviction, and benchmark latency.
- Created standalone runnable code example in `examples/ip_to_country_lookup.nim`.
- Recorded terminal asciicast (`docs/recordings/ip_to_country_lookup.cast`) and rendered high-resolution animated demo GIF (`docs/images/ip_to_country_lookup.gif`) with Asciinema and Agg.

##### Category B: Unicode Flag Emoji & Country Metadata
- Implemented algorithmic ISO 3166-1 alpha-2 to Unicode regional indicator symbol converter (`isoToFlagEmoji`) mathematically transforming 2-letter codes into 8-byte UTF-8 emoji flags (`US` -> `🇺🇸`, `DE` -> `🇩🇪`, `NL` -> `🇳🇱`).
- Implemented static English country name mapping dictionary (`getCountryName`) covering all 249 official ISO 3166-1 alpha-2 countries and territories with whitespace trimming and case insensitivity.
- Exported constant `IsoCountryCodes` containing all 249 official ISO 3166-1 alpha-2 codes and validation predicate `isKnownIsoCountryCode`.
- Implemented robust handling for special GeoIP and security pseudo-codes (`EU` -> `🇪🇺`, `AP` -> `🌏`, `A1` -> `🕵️`, `A2` -> `🛰️`, `T1` -> `🧅`, `O1` -> `🌐`, `LO` -> `🏠`, `UK` -> `🇬🇧`, `XX` -> `🌐`), along with `isSpecialOrPseudoCode`.
- Implemented terminal fallback routines for plain-text, dumb, and restricted console environments (`flagTerminalFallback`, `formatCountryFlag`, `formatCountryBadge`, `terminalSupportsEmoji`), respecting `NO_EMOJI` and `TERM=dumb`.
- Created comprehensive unit test suite in `tests/t_flags.nim` validating algorithmic flag generation, mathematical codepoints, all 249 ISO codes, pseudo-codes, terminal fallbacks, and environment overrides.
- Created standalone runnable code example in `examples/flags_and_country_metadata.nim`.
- Recorded terminal asciicast (`docs/recordings/flags_and_country_metadata.cast`) and rendered animated demo GIF (`docs/images/flags_and_country_metadata.gif`) with Asciinema and Agg using JetBrainsMono Nerd Font Mono.

##### Category C: Bogon, Private, and Loopback IP Handling
- Implemented high-precision RFC 1918 private IPv4 subnet detection (`isRfc1918Private`, `isRfc1918Ip`) with exact boundary validation for `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`, including support for IPv4-mapped IPv6 formats (Item 01).
- Implemented loopback and link-local range detection (`isLoopbackIp`, `isLinkLocalIp`) supporting IPv4 `127.0.0.0/8`, IPv6 `::1`, `localhost` aliases, IPv4 link-local `169.254.0.0/16`, IPv6 link-local unicast `fe80::/10`, and network interface scope stripping (`%eth0`) (Item 02).
- Implemented carrier-grade NAT (`isCgnatIp`, `100.64.0.0/10`), IPv6 Unique Local Address (`isUniqueLocalIp`, `fc00::/7`), multicast group detection (`isMulticastIp`, `224.0.0.0/4`, `ff00::/8`), and unroutable bogon / reserved / documentation detection (`isBogonIp`, `isDocumentationIp`, `0.0.0.0/8`, `240.0.0.0/4`, `255.255.255.255`, TEST-NET-1/2/3, `2001:db8::/32`).
- Implemented architectural subnet topology classifier (`classifyIpSubnet`) and human-readable descriptions (`subnetDescription`) mapping addresses to `IpSubnetKind` enum values.
- Implemented distinct visual markers and badges for local/internal traffic (`formatLocalTrafficMarker`, `formatPrivateIpBadge`, `makeEnrichedPrivateLocation`) rendering `🏠 Local / Private LAN` (or ASCII `[LAN] Local / Private LAN`) and annotating subnet kinds without database lookups (Item 03).
- Added comprehensive unit test suite in `tests/t_bogon_private_ip.nim` covering RFC 1918 subnet boundaries, loopback/link-local ranges, CGNAT, multicast, ULA, bogon/reserved subnets, and GeoIpEngine short-circuiting (Item 04).
- Created standalone runnable code example in `examples/bogon_and_private_ip.nim`.
- Recorded terminal asciicast (`docs/recordings/bogon_and_private_ip.cast`) and rendered high-resolution animated demo GIF (`docs/images/bogon_and_private_ip.gif`) using Asciinema and Agg with JetBrainsMono Nerd Font Mono.


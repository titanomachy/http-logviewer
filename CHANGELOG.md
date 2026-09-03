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

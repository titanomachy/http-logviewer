# HTTP LogViewer Specifications (`specs/`)

Welcome to the specification documentation for **`http_logviewer`**. This directory contains detailed, modular technical specifications designed for an AI model or developer to implement the codebase systematically.

## Project Vision & Core Capabilities
`http_logviewer` is a high-performance HTTP access log viewer and threat detection tool written in **Nim (>= 2.2.10)**. Its purpose is to ingest web server logs (Nginx, Apache, Caddy, JSON, or pipes from `tail -f`), parse them with minimal overhead, enrich them with GeoIP data and Unicode country flags, classify visitor intent (real user vs. search engine vs. commercial scraper vs. malicious hacker), highlight HTTP response status codes with vivid ANSI background colors (e.g., bold red background on 404s), and correlate disparate IP addresses to expose coordinated botnets and multi-IP scanning campaigns.

---

## Specifications Directory Index

| Spec File | Title & Focus | Corresponds to PLAN1.md |
| :--- | :--- | :--- |
| [`00_build_and_configuration.md`](file:///home/joa/Code/packages/http-logviewer/specs/00_build_and_configuration.md) | Build system, Nimble setup, `build/` isolation, compiler flags | Phase 00 |
| [`01_core_types.md`](file:///home/joa/Code/packages/http-logviewer/specs/01_core_types.md) | Data schemas, domain types, enums, records, and memory models | Phase 01 |
| [`02_log_parsing.md`](file:///home/joa/Code/packages/http-logviewer/specs/02_log_parsing.md) | Multi-format log parsing (CLF, Combined, Nginx, JSON), streaming | Phase 02 |
| [`03_geoip_and_flags.md`](file:///home/joa/Code/packages/http-logviewer/specs/03_geoip_and_flags.md) | GeoIP enrichment, ISO country flag emojis, bogon/private IP handling | Phase 03 |
| [`04_threat_detection.md`](file:///home/joa/Code/packages/http-logviewer/specs/04_threat_detection.md) | Threat signature matching, User-Agent classification, heuristic scoring | Phase 04 |
| [`05_actor_correlation.md`](file:///home/joa/Code/packages/http-logviewer/specs/05_actor_correlation.md) | Multi-IP actor clustering, attack sequence fingerprinting, botnet grouping | Phase 05 |
| [`06_terminal_ui.md`](file:///home/joa/Code/packages/http-logviewer/specs/06_terminal_ui.md) | ANSI rendering, background status code colors, stream & grouped views | Phase 06 |
| [`07_cli_and_integration.md`](file:///home/joa/Code/packages/http-logviewer/specs/07_cli_and_integration.md) | CLI argument parser, pipeline wiring, streaming loops, library API | Phase 07 |
| [`08_code_review_and_quality.md`](file:///home/joa/Code/packages/http-logviewer/specs/08_code_review_and_quality.md) | Final code quality review rubric, memory safety (ARC/ORC), benchmarks | Phase 08 |

---

## Instructions for Implementing Models / Engineers

When tasked with implementing this system, adhere strictly to the following standards:

1. **Strict Build Isolation**:
   - Never write compiled binaries or compiler cache directories to the workspace root.
   - All builds must route to `build/` (`binDir = "build"`, `nim.cfg` `--nimcache:"build/nimcache"`).
2. **Modern Idiomatic Nim (2.2+)**:
   - Use `func` for side-effect-free pure functions.
   - Prefer value semantics and immutable `let` bindings over mutable `var` where practical.
   - Compile cleanly with modern memory management (`--mm:orc` or `--mm:arc`).
   - Use zero-allocation parsing (`std/parseutils`, `openArray[char]`, string slicing) in the critical path.
3. **No Unhandled Crashes**:
   - Log files frequently contain corrupted characters, binary payloads, and truncated lines. The parser must never crash on malformed input. Use `catchableError` and graceful fallbacks.
4. **ANSI Safety**:
   - When stdout is not a TTY or `--no-color` is set, strip all ANSI codes cleanly.
5. **Implementation Order**:
   - Follow the numbered specification files in order from `00` through `08`. Each spec builds on the foundational types and modules defined in preceding specs.

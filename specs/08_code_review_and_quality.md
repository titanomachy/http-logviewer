# Specification 08: Final Code Review & Code Quality Assurance

## 1. Overview & Purpose
This specification establishes the quality gates, architectural rubrics, and automated audit procedures required to conduct the **Final Code Review** for `http_logviewer` (Phase 08 in `PLANS/PLAN1.md`).
Any implementation model or developer completing the project must pass every checklist item in this specification before the codebase is considered production-ready.

---

## 2. Code Quality Audit Checklist

### 2.1 Idiomatic Nim (2.2+) & Architectural Integrity
- [ ] **Pure Functions**: Side-effect-free calculations (e.g. `isoToFlagEmoji`, `formatStatusCode`, `generateProbeFingerprint`, `parseHttpMethod`) are declared using `func` rather than `proc`.
- [ ] **Immutability First**: Default to `let` bindings for all parsed tokens, records, and configuration objects. `var` is reserved strictly for accumulators and token indices in parsing loops.
- [ ] **No Monolithic Modules**: Each module has a single responsibility. Core types are cleanly separated from parser, analysis, and presentation logic.
- [ ] **Zero Circular Imports**: Module dependency graph is strictly acyclic: `core` <- `{parser, enrichment}` <- `analyzer` <- `renderer` <- `cli` <- `http_logviewer.nim`.
- [ ] **Catchable Exceptions**: All custom exceptions inherit from `CatchableError`. No unhandled `Defect` exceptions can be triggered by external untrusted log input.
- [ ] **Self-Documenting Code**: All public types, fields, and procs carry Nim doc comments (`##`) and are capable of compiling clean HTML docs via `nimble doc`.

### 2.2 Memory Safety & Allocation Efficiency
- [ ] **Deterministic ARC/ORC Verification**: The application builds cleanly and passes all test suites under `--mm:orc` with zero memory leaks.
- [ ] **Low-Allocation Tokenization**: The parsing hot-path in `parseCombinedLine` uses `std/parseutils` (`parseUntil`, `skipUntil`) instead of `strutils.split()`, avoiding intermediate sequence allocations for every log line.
- [ ] **Bounded Memory Retention**:
  - The GeoIP LRU cache is capped at a maximum of 50,000 entries.
  - The `ActorCorrelator` prunes expired clusters older than `windowSeconds` to prevent memory leaks during perpetual `tail -f` streaming.
- [ ] **Resource Cleanup**: All file streams and sockets use `defer: stream.close()` or deterministic RAII lifetime wrappers.
- [ ] **AddressSanitizer Validation**: Compiling with `--passC:-fsanitize=address --passL:-fsanitize=address` produces no heap buffer overflows or use-after-free conditions.

### 2.3 Terminal & Security Hardening
- [ ] **Terminal Escape Injection Defense**: Malicious User-Agent strings or request URIs containing raw ANSI control sequences (e.g. `\e[2J` or cursor-manipulation escapes) must be sanitized before echoing to the terminal to prevent terminal hijacking.
- [ ] **Oversized Line Handling**: Truncate lines exceeding 64KB to avoid memory exhaustion from denial-of-service payloads.
- [ ] **Case-Insensitive Signature Matching**: Attack patterns (`/.env`, `/wp-login.php`, `UNION SELECT`) match correctly regardless of URL encoding or upper/lower case mixing.
- [ ] **Bogon & Private IP Protection**: Loopback (`127.0.0.1`, `::1`) and private LAN addresses (`10.x`, `192.168.x`) must never trigger external network requests or cause lookup crashes.

### 2.4 Threat Classifier Precision (False Positive Audit)
- [ ] **Real User Protection**: Legitimate visitors making normal HTTP GET requests for static pages and assets (`/index.html`, `/assets/app.js`, `/style.css`) must never receive a risk score >= 20.
- [ ] **Accidental 404 Protection**: A single 404 for a missing image or broken link on a legitimate page must NOT classify a user as a hacker.
- [ ] **Verified Bot Exemption**: Known search crawlers (`Googlebot`, `bingbot`) must be categorized as `CategoryVerifiedBot` and not penalized for rapid indexing.

---

## 3. Performance & Release Gate Thresholds

| Metric | Target Threshold | Validation Command / Method |
| :--- | :--- | :--- |
| **Parsing Throughput** | >= 100,000 lines/second | Benchmark script with 1M line combined log |
| **GeoIP Cache Hit Rate** | >= 90% on repeated traffic | Statistical counter in `GeoIpEngine` |
| **Memory Footprint** | <= 50 MB resident RSS | Monitored during 1-hour live stream simulation |
| **Binary Size** | <= 5 MB (stripped release) | `ls -lh build/http_logviewer` with `-d:release` |
| **Build Isolation** | 100% of outputs in `build/` | Clean repo check: `git status --porcelain` |
| **Test Pass Rate** | 100% passing tests | `nimble test` |

---

## 4. Final Code Review Report Format
At the conclusion of implementation, the reviewing engineer or model must generate a **Code Quality Summary Report** confirming:

```markdown
# Final Code Quality Summary Report

## 1. Architectural Compliance
- [PASS/FAIL] Separation of Concerns
- [PASS/FAIL] Dependency Acyclicity
- [PASS/FAIL] Idiomatic Nim 2.2 Standards

## 2. Memory & Performance Audit
- [PASS/FAIL] Zero memory leaks under --mm:orc
- [PASS/FAIL] Throughput achieved: [X] lines/sec (Target: > 100,000)
- [PASS/FAIL] Peak memory usage: [X] MB (Target: < 50 MB)

## 3. Security & Detection Accuracy
- [PASS/FAIL] Terminal escape sanitization verified
- [PASS/FAIL] Zero false positives on legitimate sample logs
- [PASS/FAIL] Multi-IP botnet correlation successfully demonstrated

## 4. Build System Verification
- [PASS/FAIL] All outputs isolated to build/
- [PASS/FAIL] Release binary size: [X] MB (Target: < 5 MB)

## 5. Reviewer Sign-Off & Recommendations
[Detailed notes and feedback on code quality]
```

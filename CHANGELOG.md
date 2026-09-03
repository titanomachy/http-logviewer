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

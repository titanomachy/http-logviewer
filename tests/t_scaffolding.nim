import unittest, os
import http_logviewer
import http_logviewer/prelude

suite "Directory Scaffolding & Tooling Prelude (Spec 00 / Category B)":
  test "Item 01: Scaffold source directory tree":
    check dirExists("src/http_logviewer/core")
    check dirExists("src/http_logviewer/parser")
    check dirExists("src/http_logviewer/enrichment")
    check dirExists("src/http_logviewer/analyzer")
    check dirExists("src/http_logviewer/renderer")
    check dirExists("src/http_logviewer/cli")

  test "Item 02: Scaffold tests directory: tests/fixtures":
    check dirExists("tests/fixtures")
    check fileExists("tests/fixtures/.gitkeep") or fileExists("tests/fixtures/sample.log")

  test "Item 03: Base error types and assertions in common prelude module":
    check ParseError is HttpLogViewerError
    check HttpLogViewerError is CatchableError
    ensure(true, "assertion should hold")
    expect HttpLogViewerError:
      ensure(false, "should fail with HttpLogViewerError")

  test "Item 04: Continuous integration check script configured and executable":
    check fileExists("scripts/ci_check.sh")
    let perms = getFilePermissions("scripts/ci_check.sh")
    check fpUserExec in perms

  test "Item 05: Minimal hello-world pipeline cross-module imports":
    let result = runHelloPipeline("ping")
    check result == "[analyzer] ping + enriched + analyzed"

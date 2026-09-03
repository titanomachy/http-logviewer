import unittest
import http_logviewer
import http_logviewer/core/[prelude, types]
import http_logviewer/parser/engine
import http_logviewer/enrichment/geoip
import http_logviewer/analyzer/classifier
import http_logviewer/renderer/terminal
import http_logviewer/cli/args

suite "Hello-World Pipeline & Cross-Module Verification (Spec 00 / Category B)":
  test "Item 05: Individual module functions and types":
    let p = parseHello("log_data")
    check p.message == "log_data"
    check p.stage == "parser"

    let e = enrichHello(p)
    check e.stage == "enrichment"
    check e.message == "log_data + enriched"

    let a = analyzeHello(e)
    check a.stage == "analyzer"
    check a.message == "log_data + enriched + analyzed"

    let r = renderHello(a)
    check r == "[analyzer] log_data + enriched + analyzed"

    let c = cliHello("status")
    check c == "CLI: status"

  test "Item 05: End-to-end hello pipeline cross-module execution":
    let output = runHelloPipeline("sample_traffic")
    check output == "[analyzer] sample_traffic + enriched + analyzed"

  test "Item 05: Pipeline input validation raises ParseError on empty input":
    expect ParseError:
      discard runHelloPipeline("")

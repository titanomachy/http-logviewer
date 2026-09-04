## Main entry point and library interface for http_logviewer.
## High-performance HTTP log analyzer CLI tool and library.

import http_logviewer/core/[prelude, types, config]
import http_logviewer/parser/[engine, formats]
import http_logviewer/enrichment/[geoip, flags]
import http_logviewer/analyzer/[classifier, signatures]
import http_logviewer/renderer/terminal
import http_logviewer/cli/args
import http_logviewer/submodule

export prelude, types, config, engine, formats, geoip, flags, classifier, signatures, terminal, args, submodule

proc runHelloPipeline*(input: string = "pipeline_init"): string =
  ## Runs a minimal end-to-end hello pipeline through all core modules.
  let parsed = parseHello(input)
  let enriched = enrichHello(parsed)
  let analyzed = analyzeHello(enriched)
  result = renderHello(analyzed)

when isMainModule:
  echo(getWelcomeMessage())
  echo(cliHello("ready"))
  echo(runHelloPipeline("http_logviewer"))

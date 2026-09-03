# Example: Architecture Scaffolding & Pipeline Flow
# Demonstrates cross-module pipeline invocation and error assertions.
#
# Compile and run with:
#   nim r --path:src examples/pipeline_scaffolding.nim

import http_logviewer
import http_logviewer/core/prelude

proc main() =
  echo "=== http_logviewer Scaffolding & Pipeline Example ==="
  
  # 1. Pipeline execution across core, parser, enrichment, analyzer, and renderer
  let sampleInput = "127.0.0.1 GET /index.html 200"
  echo "Input event: ", sampleInput
  
  let pipelineResult = runHelloPipeline(sampleInput)
  echo "Pipeline output: ", pipelineResult
  
  # 2. Error handling and assertion safety
  try:
    ensureParse(sampleInput.len > 0, "Valid line syntax")
    echo "Assertion check: passed successfully"
  except ParseError as e:
    echo "Caught expected ParseError: ", e.msg

when isMainModule:
  main()

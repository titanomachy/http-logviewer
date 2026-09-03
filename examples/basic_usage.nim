# Example: Basic usage and entry point demonstration for http_logviewer
# Compile and run with:
#   nim r --path:src examples/basic_usage.nim

import http_logviewer/submodule

proc main() =
  echo "http_logviewer example runner"
  echo "Status: ", getWelcomeMessage()

when isMainModule:
  main()

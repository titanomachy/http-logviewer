## Ingestion and parser engine module for http_logviewer.

import ../core/[prelude, types]
import formats
export formats

func parseHello*(input: string): PipelineMessage =
  ## Parses input into a pipeline message; raises ParseError if empty.
  ensureParse(input.len > 0, "Input cannot be empty")
  initPipelineMessage(input, "parser")

## Terminal rendering and layout formatting module for http_logviewer.

import ../core/types

func renderHello*(msg: PipelineMessage): string =
  ## Formats the final pipeline output string for terminal presentation.
  "[" & msg.stage & "] " & msg.message

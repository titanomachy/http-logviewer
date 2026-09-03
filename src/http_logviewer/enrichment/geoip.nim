## Geolocation and metadata enrichment module for http_logviewer.

import ../core/types

func enrichHello*(msg: PipelineMessage): PipelineMessage =
  ## Simulates enriching a pipeline message with metadata.
  initPipelineMessage(msg.message & " + enriched", "enrichment")

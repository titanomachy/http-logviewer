## Foundational domain types for the http_logviewer pipeline.

type
  PipelineMessage* = object
    ## Minimal pipeline message envelope verifying cross-module flow.
    message*: string
    stage*: string

func initPipelineMessage*(msg: string, stage: string = "core"): PipelineMessage =
  ## Initializes a new pipeline message.
  PipelineMessage(message: msg, stage: stage)

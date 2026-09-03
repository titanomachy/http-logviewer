## Core error types and validation assertions for http_logviewer.
## All custom exceptions inherit from CatchableError to guarantee
## robust recovery and prevent unhandled defect crashes.

type
  HttpLogViewerError* = object of CatchableError
    ## Base exception type for all errors originating within http_logviewer.

  ParseError* = object of HttpLogViewerError
    ## Raised when a log line or token cannot be parsed into the expected format.

  GeoIpError* = object of HttpLogViewerError
    ## Raised when an error occurs while opening or querying the GeoIP database.

  ThreatAnalysisError* = object of HttpLogViewerError
    ## Raised when an anomaly or threat classification fails during rule evaluation.

  ConfigError* = object of HttpLogViewerError
    ## Raised when configuration parameters or CLI arguments are invalid.

  RenderError* = object of HttpLogViewerError
    ## Raised when rendering or terminal styling encounters an unrecoverable state.

  PipelineError* = object of HttpLogViewerError
    ## Raised when streaming ingestion or cross-module pipeline orchestration fails.

template ensure*(condition: bool, msg: string) =
  ## Asserts that `condition` is true; otherwise raises an HttpLogViewerError.
  if not condition:
    raise newException(HttpLogViewerError, msg)

template ensure*(condition: bool, msg: string, errType: typedesc) =
  ## Asserts that `condition` is true; otherwise raises an exception of `errType`.
  if not condition:
    raise newException(errType, msg)

template ensureParse*(condition: bool, msg: string) =
  ## Convenience assertion template raising `ParseError` on failure.
  ensure(condition, msg, ParseError)

template ensureConfig*(condition: bool, msg: string) =
  ## Convenience assertion template raising `ConfigError` on failure.
  ensure(condition, msg, ConfigError)

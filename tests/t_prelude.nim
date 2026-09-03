import unittest
import http_logviewer/prelude

suite "Common Prelude & Error Hierarchy (Spec 00 / Category B)":
  test "Item 03: Error inheritance structure":
    check ParseError is HttpLogViewerError
    check GeoIpError is HttpLogViewerError
    check ThreatAnalysisError is HttpLogViewerError
    check ConfigError is HttpLogViewerError
    check RenderError is HttpLogViewerError
    check PipelineError is HttpLogViewerError
    check HttpLogViewerError is CatchableError

  test "Item 03: Raising and catching specific errors under base type":
    expect ParseError:
      raise (ref ParseError)(msg: "Invalid log line syntax")

    var caught = false
    try:
      raise (ref ConfigError)(msg: "Bad configuration")
    except HttpLogViewerError as e:
      caught = true
      check e.msg == "Bad configuration"
    check caught

  test "Item 03: Assertion template ensure":
    # Should not raise when true
    ensure(1 == 1, "Should pass")

    # Should raise HttpLogViewerError by default
    expect HttpLogViewerError:
      ensure(1 == 2, "1 must equal 2")

    # Should raise specified error type
    expect GeoIpError:
      ensure(false, "Geo database missing", GeoIpError)

  test "Item 03: Assertion templates ensureParse and ensureConfig":
    ensureParse(true, "All valid")
    expect ParseError:
      ensureParse(false, "Unparseable line")

    ensureConfig(true, "Config valid")
    expect ConfigError:
      ensureConfig(false, "Missing logfile flag")

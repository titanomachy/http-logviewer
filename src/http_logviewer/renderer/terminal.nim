## Terminal rendering and layout formatting module for http_logviewer.
## Implements Phase 06 terminal presentation, streaming line output,
## column alignment, and status badge integration.

import std/[strutils, times]
import ../core/types
import styles

export styles

func renderHello*(msg: PipelineMessage): string =
  ## Formats the final pipeline output string for terminal presentation.
  "[" & msg.stage & "] " & msg.message

proc renderStreamLine*(
  record: EnrichedLogRecord,
  colorize: bool = true,
  useEmoji: bool = true,
  maxWidth: int = 0
): string =
  ## Formats a single EnrichedLogRecord into an aligned columnar stream line:
  ## `[TIME] [GEO+FLAG] [STATUS] [INTENT] [IP] [METHOD PATH] [USER_AGENT]`
  let timeStr = if record.entry.timestamp.isInitialized:
                  record.entry.timestamp.format("HH:mm:ss")
                else:
                  "--:--:--"
  let geoStr = formatCountryColumn(record.geo, useEmoji = useEmoji, width = 7)
  let statusStr = formatStatusCode(record.entry.statusCode, colorize)
  let intentBadge = formatIntentBadge(record.threat.category, colorize)
  let ipStr = alignLeft(if record.entry.clientIp.len > 0: record.entry.clientIp else: "-", 15)
  let reqStr = $record.entry.method & " " & record.entry.path
  let uaStr = if record.entry.userAgent.len > 0: record.entry.userAgent else: "-"

  result = "$1  $2  $3  $4  $5  $6  $7" % [
    timeStr, geoStr, statusStr, intentBadge, ipStr, reqStr, uaStr
  ]

  if maxWidth > 0:
    let visWidth = terminalDisplayWidth(result)
    if visWidth > maxWidth:
      # If maxWidth is constrained and colorize is off, we can cleanly truncate
      if not colorize and result.len > maxWidth:
        result = result[0..maxWidth - 1]

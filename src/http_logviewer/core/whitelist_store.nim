## Persistent trusted IP storage using nim-sqlite.
## Database access happens at startup or during explicit management commands.

import std/[os, appdirs]
import nim_sqlite
import config, errors

proc defaultStateDbPath*(): string =
  ## Uses the platform's per-user application data directory (XDG_DATA_HOME on Linux).
  string(appdirs.getDataDir()) / "http_logviewer" / "state.sqlite3"

proc validateStateDbPath*(path: string) =
  ensureConfig(path.len > 0 and '\0' notin path and path != ":memory:",
    "--state-db requires a persistent database file path")
  ensureConfig(not dirExists(path), "State database path is a directory: '" & path & "'")

proc openWhitelistDb(path: string, create: bool): DbConn =
  validateStateDbPath(path)
  if create:
    let parent = path.parentDir()
    if parent.len > 0:
      createDir(parent)
  result = openDatabase(path, mode = if create: dbReadWrite else: dbRead)
  try:
    result.exec("PRAGMA busy_timeout = 5000")
    if create:
      result.exec("""CREATE TABLE IF NOT EXISTS whitelisted_ips (
        ip TEXT PRIMARY KEY NOT NULL,
        added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )""")
  except CatchableError:
    result.close()
    raise

proc loadWhitelistedIps*(path: string): seq[string] =
  ## Missing databases mean an empty whitelist; existing databases are opened read-only.
  validateStateDbPath(path)
  if not fileExists(path):
    return @[]
  let db = openWhitelistDb(path, create = false)
  defer: db.close()
  for row in db.iterate("SELECT ip FROM whitelisted_ips ORDER BY ip"):
    let (ip,) = row.unpack((string,))
    result.add(normalizeWhitelistIp(ip))

proc saveWhitelistedIps*(path: string, ips: openArray[string]) =
  ## Adds exact canonical addresses atomically; repeated additions are idempotent.
  var normalized: seq[string] = @[]
  for ip in ips:
    normalized.add(normalizeWhitelistIp(ip))
  let db = openWhitelistDb(path, create = true)
  defer: db.close()
  db.transaction:
    for ip in normalized:
      db.exec("INSERT OR IGNORE INTO whitelisted_ips(ip) VALUES(?)", ip)

proc removeWhitelistedIps*(path: string, ips: openArray[string]) =
  ## Removes saved addresses atomically without creating a database if absent.
  var normalized: seq[string] = @[]
  for ip in ips:
    normalized.add(normalizeWhitelistIp(ip))
  validateStateDbPath(path)
  if not fileExists(path):
    return
  let db = openWhitelistDb(path, create = true)
  defer: db.close()
  db.transaction:
    for ip in normalized:
      db.exec("DELETE FROM whitelisted_ips WHERE ip = ?", ip)

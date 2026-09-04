# Package

version       = "0.1.0"
author        = "titanomachy"
description   = "High-performance HTTP log viewer and rogue bot detector"
license       = "MIT"
srcDir        = "src"
binDir        = "build"
installExt    = @["nim"]
bin           = @["http_logviewer"]

# Dependencies
requires "nim >= 2.2.10"

# Tasks
task build, "Build http_logviewer binary":
  exec "nim c --outdir:build src/http_logviewer.nim"

task release, "Build optimized release binary":
  exec "nim c -d:release --opt:speed --outdir:build src/http_logviewer.nim"

task debug, "Build debug binary with line tracking":
  exec "nim c -d:debug --outdir:build src/http_logviewer.nim"

task test, "Run unit tests":
  exec "nim c -r tests/test_all.nim"

task ci, "Run CI pre-commit and sanity tests":
  exec "bash scripts/ci_check.sh"

task docs, "Generate HTML documentation":
  exec "nim doc --project --outdir:build/docs src/http_logviewer.nim"

task clean, "Clean all build artifacts":
  rmDir "build/nimcache"
  if dirExists("build/docs"):
    rmDir "build/docs"
  rmFile "build/http_logviewer"
  if fileExists("build/test1"):
    rmFile "build/test1"
  if fileExists("build/t_build_config"):
    rmFile "build/t_build_config"
  if fileExists("build/t_scaffolding"):
    rmFile "build/t_scaffolding"
  if fileExists("build/t_prelude"):
    rmFile "build/t_prelude"
  if fileExists("build/t_core_types"):
    rmFile "build/t_core_types"
  if fileExists("build/t_parser"):
    rmFile "build/t_parser"
  if fileExists("build/t_stream_engine"):
    rmFile "build/t_stream_engine"
  if fileExists("build/t_geoip"):
    rmFile "build/t_geoip"
  if fileExists("build/t_flags"):
    rmFile "build/t_flags"
  if fileExists("build/t_bogon_private_ip"):
    rmFile "build/t_bogon_private_ip"
  if fileExists("build/t_signatures"):
    rmFile "build/t_signatures"
  if fileExists("build/test_all"):
    rmFile "build/test_all"

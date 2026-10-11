# Package

version       = "0.1.3"
author        = "titanomachy"
description   = "High-performance HTTP log viewer and rogue bot detector"
license       = "MIT"
srcDir        = "src"
binDir        = "build"
installExt    = @["nim", "sh", "ps1"]
bin           = @["http_logviewer", "hlv"]

# Dependencies
requires "nim >= 2.2.10"
requires "nim_sqlite >= 0.4.0"
requires "terminal_style >= 0.1.1"
requires "terminal_screen >= 0.1.1"
requires "terminal_table >= 0.1.1"
requires "terminal_layout >= 0.1.1"
requires "terminal_status >= 0.1.1"

# Tasks
before install:
  let scriptDir = if dirExists("src"): "src/http_logviewer/cli" else: "http_logviewer/cli"
  when defined(windows):
    exec "powershell -Command \"& './" & scriptDir & "/check_hlv.ps1'\""
  else:
    let userShell = getEnv("SHELL", "/bin/sh")
    if userShell.endsWith("/bash") or userShell.endsWith("/zsh"):
      exec "'" & userShell.replace("'", "'\\''") & "' -ic '. ./" & scriptDir & "/check_hlv.sh'"
    else:
      exec "sh " & scriptDir & "/check_hlv.sh"

task build, "Build http_logviewer and hlv binaries":
  for command in ["http_logviewer", "hlv"]:
    exec "nim c --out:build/" & command & " src/" & command & ".nim"

task release, "Build optimized release binary":
  for command in ["http_logviewer", "hlv"]:
    exec "nim c -d:release --opt:speed --out:build/" & command & " src/" & command & ".nim"

task debug, "Build debug binary with line tracking":
  for command in ["http_logviewer", "hlv"]:
    exec "nim c -d:debug --out:build/" & command & " src/" & command & ".nim"

task test, "Run unit tests":
  exec "nim c -r tests/test_all.nim"
  when not defined(windows):
    exec "bash tests/test_hlv_install.sh"

task ci, "Run CI pre-commit and sanity tests":
  exec "bash scripts/ci_check.sh"

task docs, "Generate HTML documentation":
  exec "nim doc --project --outdir:build/docs src/http_logviewer.nim"

task clean, "Clean all build artifacts":
  rmDir "build/nimcache"
  if dirExists("build/docs"):
    rmDir "build/docs"
  rmFile "build/http_logviewer"
  if fileExists("build/hlv"):
    rmFile "build/hlv"
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
  if fileExists("build/t_useragents"):
    rmFile "build/t_useragents"
  if fileExists("build/t_classifier"):
    rmFile "build/t_classifier"
  if fileExists("build/t_correlator"):
    rmFile "build/t_correlator"
  if fileExists("build/t_code_quality"):
    rmFile "build/t_code_quality"
  if fileExists("build/t_memory_safety"):
    rmFile "build/t_memory_safety"
  if fileExists("build/test_all"):
    rmFile "build/test_all"

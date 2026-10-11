# Package

version       = "0.1.2"
author        = "titanomachy"
description   = "High-performance HTTP log viewer and rogue bot detector"
license       = "MIT"
srcDir        = "src"
binDir        = "build"
installExt    = @["nim"]
bin           = @["http_logviewer"]

# Dependencies
requires "nim >= 2.2.10"
requires "nim_sqlite >= 0.4.0"
requires "terminal_style >= 0.1.1"
requires "terminal_screen >= 0.1.1"
requires "terminal_table >= 0.1.1"
requires "terminal_layout >= 0.1.1"
requires "terminal_status >= 0.1.1"

# Tasks
task shortcut, "Install the optional hlv shortcut after checking for conflicts":
  when defined(windows):
    exec "powershell -Command \"& './scripts/install_hlv.ps1'\""
  else:
    # An interactive shell loads configured aliases and functions. Source the
    # script directly to also check aliases defined only in the current session.
    let userShell = getEnv("SHELL", "/bin/sh")
    if userShell.endsWith("/bash") or userShell.endsWith("/zsh"):
      exec "'" & userShell.replace("'", "'\\''") & "' -ic '. ./scripts/install_hlv.sh'"
    else:
      echo "Run this in Bash or Zsh to check your current aliases and functions:"
      echo ". ./scripts/install_hlv.sh"

task build, "Build http_logviewer binary":
  exec "nim c --outdir:build src/http_logviewer.nim"

task release, "Build optimized release binary":
  exec "nim c -d:release --opt:speed --outdir:build src/http_logviewer.nim"

task debug, "Build debug binary with line tracking":
  exec "nim c -d:debug --outdir:build src/http_logviewer.nim"

task test, "Run unit tests":
  exec "nim c -r tests/test_all.nim"
  when not defined(windows):
    exec "bash tests/test_shortcut.sh"

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

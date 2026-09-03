import unittest, os, strutils

suite "Build & Configuration (Spec 00)":
  test "Item 01: http_logviewer.nimble configuration":
    check fileExists("http_logviewer.nimble")
    let content = readFile("http_logviewer.nimble")
    var hasBinDir = false
    var hasBin = false
    var hasSrcDir = false
    for line in content.splitLines():
      let stripped = line.strip()
      if stripped.startsWith("binDir") and "\"build\"" in stripped:
        hasBinDir = true
      if stripped.startsWith("bin") and "@[\"http_logviewer\"]" in stripped:
        hasBin = true
      if stripped.startsWith("srcDir") and "\"src\"" in stripped:
        hasSrcDir = true
    check hasBinDir
    check hasBin
    check hasSrcDir
    check fileExists("src/http_logviewer.nim")

  test "Item 02: nim.cfg compiler cache and outdir configuration":
    check fileExists("nim.cfg")
    let content = readFile("nim.cfg")
    check "--nimcache:\"build/nimcache\"" in content
    check "--outdir:\"build\"" in content
    check "--mm:orc" in content

  test "Item 03: Nimble tasks for build, release, test, and clean":
    check fileExists("http_logviewer.nimble")
    let content = readFile("http_logviewer.nimble")
    check "task build," in content or "task build " in content
    check "task release," in content or "task release " in content
    check "task test," in content or "task test " in content
    check "task clean," in content or "task clean " in content
    check "build/nimcache" in content
    check "build/http_logviewer" in content

  test "Item 04: Verify build outputs executable in build/ and leaves root clean":
    check fileExists("build/http_logviewer")
    check not fileExists("http_logviewer")
    check not dirExists("nimcache")
    check not dirExists("src/nimcache")

  test "Item 05: .gitignore entries":
    check fileExists(".gitignore")
    let gitignore = readFile(".gitignore")
    check "build/*" in gitignore
    check "nimcache/" in gitignore
    check "*.swp" in gitignore

#!/usr/bin/env bash
set -euo pipefail

echo "==> [CI Check] 1. Checking environment dependencies..."
command -v nim >/dev/null 2>&1 || { echo "Nim is not installed"; exit 1; }
command -v nimble >/dev/null 2>&1 || { echo "Nimble is not installed"; exit 1; }

echo "==> [CI Check] 2. Cleaning build artifacts..."
nimble clean

echo "==> [CI Check] 3. Building http_logviewer..."
nimble build

if [ ! -f "build/http_logviewer" ]; then
    echo "ERROR: Expected binary build/http_logviewer was not found!"
    exit 1
fi

echo "==> [CI Check] 4. Running test suite..."
nimble test

echo "==> [CI Check] 5. Verifying build isolation..."
if [ -f "http_logviewer" ]; then
    echo "ERROR: Binary leaked into root directory!"
    exit 1
fi
if [ -d "nimcache" ]; then
    echo "ERROR: nimcache directory leaked into root directory!"
    exit 1
fi
if [ -d "src/nimcache" ]; then
    echo "ERROR: nimcache directory leaked into src/ directory!"
    exit 1
fi

echo "==> [CI Check] 6. Verifying binary execution..."
./build/http_logviewer >/dev/null 2>&1 || { echo "Failed to execute build/http_logviewer"; exit 1; }

echo "==> [CI Check] All CI sanity checks passed successfully!"

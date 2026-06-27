#!/usr/bin/env bash
# Time-limited fuzz runs for event parsing. Exits non-zero on panic or test failure.
set -euo pipefail

FUZZTIME="${FUZZTIME:-30s}"
PKG="./events/"

echo "Running FuzzCStr (${FUZZTIME})..."
go test -fuzz=FuzzCStr -fuzztime="${FUZZTIME}" "${PKG}"

echo "Running FuzzWriteEventData (${FUZZTIME})..."
go test -fuzz=FuzzWriteEventData -fuzztime="${FUZZTIME}" "${PKG}"

echo "All fuzz targets completed with no panics."

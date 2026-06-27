#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${root}"

if ! command -v gremlins >/dev/null 2>&1; then
  echo "gremlins not found; install with: go install github.com/go-gremlins/gremlins/cmd/gremlins@latest" >&2
  exit 1
fi

# Gremlins expects a package path, not a wildcard suffix (./techs/... fails).
exec gremlins unleash --tags="" ./techs "$@"

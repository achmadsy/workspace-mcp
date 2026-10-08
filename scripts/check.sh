#!/bin/sh
# Format check, vet and tests with the project-local Go toolchain.
# Usage: scripts/check.sh [extra go test flags]
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
sh scripts/bootstrap-go.sh >/dev/null
export GOROOT="$ROOT/.tools/go" PATH="$ROOT/.tools/go/bin:$PATH" GOTOOLCHAIN=local
# Tests create files with explicit modes; a stable umask keeps results the same everywhere.
umask 022
unformatted="$(gofmt -l cmd internal)"
if [ -n "$unformatted" ]; then
  echo "gofmt needed:" >&2
  echo "$unformatted" >&2
  exit 1
fi
go vet ./...
go test ./... "$@"

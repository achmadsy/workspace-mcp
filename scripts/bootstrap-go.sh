#!/bin/sh
# Download official Go toolchain into project-local .tools/ (no system changes).
set -e
GO_VERSION="${GO_VERSION:-1.25.0}"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64) GO_ARCH=amd64 ;;
  aarch64|arm64) GO_ARCH=arm64 ;;
  *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
esac
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOLS="$ROOT/.tools"
TARBALL="go$GO_VERSION.linux-$GO_ARCH.tar.gz"
URL="https://go.dev/dl/$TARBALL"
mkdir -p "$TOOLS"
if [ -x "$TOOLS/go/bin/go" ] && GOROOT= "$TOOLS/go/bin/go" version 2>/dev/null | grep -q "go$GO_VERSION"; then
  GOROOT="$TOOLS/go"
  PATH="$TOOLS/go/bin:$PATH"
  export GOROOT PATH
  exit 0
fi
cd "$TOOLS"
curl -fsSLO "$URL"
EXPECTED="$(curl -fsSL "https://go.dev/dl/?mode=json&include=all" | python3 -c "
import json,sys
data=json.load(sys.stdin)
for rel in data:
    for f in rel.get('files',[]):
        if f['filename']=='$TARBALL':
            print(f['sha256'])
")"
ACTUAL="$(sha256sum "$TARBALL" | cut -d' ' -f1)"
if [ -z "$EXPECTED" ]; then
  echo "could not fetch checksum for $TARBALL" >&2
  exit 1
fi
if [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "checksum mismatch: expected $EXPECTED got $ACTUAL" >&2
  rm -f "$TARBALL"
  exit 1
fi
rm -rf "$TOOLS/go"
tar -xzf "$TARBALL"
rm -f "$TARBALL"
GOROOT="$TOOLS/go"
PATH="$TOOLS/go/bin:$PATH"
export GOROOT PATH
"$TOOLS/go/bin/go" version

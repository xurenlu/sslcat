#!/usr/bin/env bash
set -euo pipefail

VER=${VER:-1.0.0}
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
mkdir -p dist
ARCHIVE="sslcat_${VER}_darwin_arm64"

echo "==> Building darwin/arm64"
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 \
  go build -trimpath -ldflags "-s -w -X main.version=${VER} -X main.build=${GIT_SHA}" \
  -o "dist/sslcat" main.go

( cd dist && tar -czf "${ARCHIVE}.tar.gz" "sslcat" && rm -f "sslcat" )
echo "OK: dist/${ARCHIVE}.tar.gz"



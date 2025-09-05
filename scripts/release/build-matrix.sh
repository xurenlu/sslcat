#!/usr/bin/env bash
set -euo pipefail

# withssl: 多架构批量构建脚本
# 使用：VER=1.0.0 scripts/release/build-matrix.sh

VER=${VER:-1.0.0}
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)

MATRIX=(
  linux/amd64
  linux/arm64
  linux/arm/v7
  darwin/amd64
  darwin/arm64
  windows/amd64
  windows/arm64
)

mkdir -p dist

for T in "${MATRIX[@]}"; do
  IFS=/ read -r GOOS GOARCH GOARMV <<<"$T"
  EXT=""; GOARM=""; BIN="withssl_${VER}_${GOOS}_${GOARCH}"
  [[ "$GOOS" == windows ]] && EXT=.exe
  [[ "$GOARMV" == v7 ]] && GOARM=7

  echo "==> Building $GOOS/$GOARCH ${GOARM:+GOARM=$GOARM}"
  CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" GOARM="$GOARM" \
    go build -trimpath \
      -ldflags "-s -w -X main.version=${VER} -X main.build=${GIT_SHA}" \
      -o "dist/${BIN}${EXT}" main.go

  if [[ "$GOOS" == windows ]]; then
    ( cd dist && zip -q "${BIN}.zip" "${BIN}${EXT}" && rm -f "${BIN}${EXT}" )
  else
    ( cd dist && tar -czf "${BIN}.tar.gz" "${BIN}${EXT}" && rm -f "${BIN}${EXT}" )
  fi
done

( cd dist && shasum -a 256 * > sha256sum.txt ) || true
echo "Done. Artifacts in ./dist"



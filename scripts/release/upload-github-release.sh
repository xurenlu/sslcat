#!/usr/bin/env bash
set -euo pipefail

# 需要已安装 gh (GitHub CLI) 且已 gh auth login

VER=${VER:-1.0.4}
TAG="v${VER}"

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI 未安装，请先安装 gh" >&2
  exit 1
fi

if [ ! -d dist ]; then
  echo "dist 目录不存在，请先执行构建" >&2
  exit 1
fi

GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)

echo "==> 创建/更新 GitHub Release ${TAG}"
gh release create "${TAG}" dist/* -t "sslcat ${TAG}" -n "Release ${TAG} (commit ${GIT_SHA})" || \
gh release upload "${TAG}" dist/* --clobber

echo "Done."



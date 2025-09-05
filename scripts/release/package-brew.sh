#!/usr/bin/env bash
set -euo pipefail

# 生成 Homebrew 公式（本地文件），用户可上传到自有 tap 仓库

VER=${VER:-1.0.1}
SHA256=${SHA256:-}
TAP_DIR=${TAP_DIR:-build/homebrew-tap}
REPO=${REPO:-xurenlu/sslcat}

mkdir -p "$TAP_DIR/Formula"

if [ -z "$SHA256" ]; then
  echo "请先上传 macOS 二进制并获得 sha256，设置 SHA256=... 再运行本脚本" >&2
  exit 1
fi

cat > "$TAP_DIR/Formula/withssl.rb" <<EOF
class Withssl < Formula
  desc "SSLcat reverse proxy with auto TLS and web panel"
  homepage "https://github.com/${REPO}"
  version "${VER}"
  url "https://github.com/${REPO}/releases/download/v#{version}/withssl_#{version}_darwin_arm64.tar.gz"
  sha256 "${SHA256}"

  def install
    bin.install "withssl"
  end
end
EOF

echo "OK: Homebrew formula at $TAP_DIR/Formula/withssl.rb"



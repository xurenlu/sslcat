#!/usr/bin/env bash
set -euo pipefail

VER=${VER:-1.0.1}
PKGDIR=build/deb
DEST=dist/withssl_${VER}_linux_amd64.deb
BIN=withssl

rm -rf "$PKGDIR" && mkdir -p "$PKGDIR/DEBIAN" "$PKGDIR/opt/sslcat" "$PKGDIR/etc/sslcat" "$PKGDIR/lib/systemd/system"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=${VER}" -o "$PKGDIR/opt/sslcat/$BIN" main.go
cp withssl.conf "$PKGDIR/etc/sslcat/withssl.conf" || true

cat > "$PKGDIR/DEBIAN/control" <<EOF
Package: withssl
Version: ${VER}
Section: net
Priority: optional
Architecture: amd64
Maintainer: withssl
Description: SSLcat reverse proxy with auto TLS and web panel
EOF

cat > "$PKGDIR/lib/systemd/system/withssl.service" <<'EOF'
[Unit]
Description=SSLcat Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/sslcat/withssl --config /etc/sslcat/withssl.conf
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

fakeroot dpkg-deb --build "$PKGDIR" "$DEST"
echo "OK: $DEST"


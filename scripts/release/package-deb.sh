#!/usr/bin/env bash
set -euo pipefail

VER=${VER:-1.0.4}
PKGDIR=build/deb
DEST=dist/sslcat_${VER}_linux_amd64.deb
BIN=sslcat

rm -rf "$PKGDIR" && mkdir -p "$PKGDIR/DEBIAN" "$PKGDIR/opt/sslcat" "$PKGDIR/etc/sslcat" "$PKGDIR/lib/systemd/system"

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=${VER}" -o "$PKGDIR/opt/sslcat/$BIN" main.go
cp sslcat.conf "$PKGDIR/etc/sslcat/sslcat.conf" 2>/dev/null || true

cat > "$PKGDIR/DEBIAN/control" <<EOF
Package: sslcat
Version: ${VER}
Section: net
Priority: optional
Architecture: amd64
Maintainer: sslcat
Description: SSLcat reverse proxy with auto TLS and web panel
EOF

cat > "$PKGDIR/lib/systemd/system/sslcat.service" <<'EOF'
[Unit]
Description=SSLcat Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/sslcat/sslcat --config /etc/sslcat/sslcat.conf
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

fakeroot dpkg-deb --build "$PKGDIR" "$DEST"
echo "OK: $DEST"


#!/usr/bin/env bash
set -euo pipefail

# 生成 RPM 包（x86_64）
# 依赖：rpmbuild

VER=${VER:-1.0.4}
TOP=build/rpm
DEST_RPM=dist/sslcat_${VER}_x86_64.rpm

rm -rf "$TOP" && mkdir -p "$TOP"/{BUILD,RPMS,SRPMS,SOURCES,SPECS} dist

echo "==> Building linux/amd64 binary"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=${VER}" -o "$TOP/SOURCES/sslcat" main.go

echo "==> Preparing sources"
cp -f sslcat.conf "$TOP/SOURCES/sslcat.conf" 2>/dev/null || true
cat > "$TOP/SOURCES/sslcat.service" <<'EOF'
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

echo "==> Writing spec"
cat > "$TOP/SPECS/sslcat.spec" <<EOF
Name:           sslcat
Version:        ${VER}
Release:        1%{?dist}
Summary:        SSLcat reverse proxy with auto TLS and web panel
License:        MIT
URL:            https://github.com/xurenlu/sslcat
BuildArch:      x86_64

%define _unitdir /usr/lib/systemd/system

%description
SSLcat reverse proxy with auto TLS and web panel.

%prep
%build
%install
mkdir -p %{buildroot}/opt/sslcat
install -m 0755 %{_sourcedir}/sslcat %{buildroot}/opt/sslcat/sslcat
mkdir -p %{buildroot}/etc/sslcat
if [ -f %{_sourcedir}/sslcat.conf ]; then install -m 0644 %{_sourcedir}/sslcat.conf %{buildroot}/etc/sslcat/sslcat.conf; fi
mkdir -p %{buildroot}%{_unitdir}
install -m 0644 %{_sourcedir}/sslcat.service %{buildroot}%{_unitdir}/sslcat.service

%post
/bin/systemctl daemon-reload >/dev/null 2>&1 || true

%preun
if [ $1 -eq 0 ]; then /bin/systemctl stop sslcat >/dev/null 2>&1 || true; fi

%postun
/bin/systemctl daemon-reload >/dev/null 2>&1 || true

%files
/opt/sslcat/sslcat
/etc/sslcat/sslcat.conf
%{_unitdir}/sslcat.service

%changelog
* $(date "+%a %b %d %Y") sslcat <noreply@example.com> - ${VER}-1
- Initial RPM
EOF

echo "==> Building RPM"
rpmbuild --define "_topdir $(pwd)/$TOP" -bb "$TOP/SPECS/sslcat.spec"
cp "$TOP/RPMS/x86_64/sslcat-${VER}-1.x86_64.rpm" "$DEST_RPM"
echo "OK: $DEST_RPM"



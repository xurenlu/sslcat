#!/usr/bin/env bash
set -euo pipefail

# 生成 RPM 包（x86_64）
# 依赖：rpmbuild

VER=${VER:-1.0.1}
TOP=build/rpm
DEST_RPM=dist/withssl_${VER}_x86_64.rpm

rm -rf "$TOP" && mkdir -p "$TOP"/{BUILD,RPMS,SRPMS,SOURCES,SPECS} dist

echo "==> Building linux/amd64 binary"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=${VER}" -o "$TOP/SOURCES/withssl" main.go

echo "==> Preparing sources"
cp -f withssl.conf "$TOP/SOURCES/withssl.conf" 2>/dev/null || true
cat > "$TOP/SOURCES/withssl.service" <<'EOF'
[Unit]
Description=WithSSL Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/withssl/withssl --config /etc/withssl/withssl.conf
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
EOF

echo "==> Writing spec"
cat > "$TOP/SPECS/withssl.spec" <<EOF
Name:           withssl
Version:        ${VER}
Release:        1%{?dist}
Summary:        WithSSL reverse proxy with auto TLS and web panel
License:        MIT
URL:            https://github.com/xurenlu/withssl
BuildArch:      x86_64

%define _unitdir /usr/lib/systemd/system

%description
WithSSL reverse proxy with auto TLS and web panel.

%prep
%build
%install
mkdir -p %{buildroot}/opt/withssl
install -m 0755 %{_sourcedir}/withssl %{buildroot}/opt/withssl/withssl
mkdir -p %{buildroot}/etc/withssl
if [ -f %{_sourcedir}/withssl.conf ]; then install -m 0644 %{_sourcedir}/withssl.conf %{buildroot}/etc/withssl/withssl.conf; fi
mkdir -p %{buildroot}%{_unitdir}
install -m 0644 %{_sourcedir}/withssl.service %{buildroot}%{_unitdir}/withssl.service

%post
/bin/systemctl daemon-reload >/dev/null 2>&1 || true

%preun
if [ $1 -eq 0 ]; then /bin/systemctl stop withssl >/dev/null 2>&1 || true; fi

%postun
/bin/systemctl daemon-reload >/dev/null 2>&1 || true

%files
/opt/withssl/withssl
/etc/withssl/withssl.conf
%{_unitdir}/withssl.service

%changelog
* $(date "+%a %b %d %Y") withssl <noreply@example.com> - ${VER}-1
- Initial RPM
EOF

echo "==> Building RPM"
rpmbuild --define "_topdir $(pwd)/$TOP" -bb "$TOP/SPECS/withssl.spec"
cp "$TOP/RPMS/x86_64/withssl-${VER}-1.x86_64.rpm" "$DEST_RPM"
echo "OK: $DEST_RPM"



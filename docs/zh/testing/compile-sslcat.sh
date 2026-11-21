#!/bin/bash

# 在测试服务器上编译 SSLcat

set -e

SERVER="root@sg2.shifen.de"
SSLCAT_DIR="/opt/sslcat"
BUILD_TYPE="${1:-cgo}"  # cgo 或 standard

echo "🔨 开始编译 SSLcat (类型: $BUILD_TYPE)..."

ssh $SERVER bash << ENDSSH
set -e

cd $SSLCAT_DIR

echo "📥 更新代码..."
if [ -d ".git" ]; then
    git pull || echo "Git pull 失败，继续使用当前代码"
else
    echo "⚠️  不是 Git 仓库，使用当前代码"
fi

# SSH 会话不继承 setup 脚本的 PATH；每次都显式选择合格的工具链。
GO_REQUIRED_VERSION="1.27.4"
go_version_at_least() {
    local current=\${1#go} minimum=\${2#go}
    local pattern='^([0-9]+)\.([0-9]+)(\.([0-9]+))?$'
    local -a current_parts minimum_parts
    local index
    [[ \$current =~ \$pattern ]] || return 1
    current_parts=("\${BASH_REMATCH[1]}" "\${BASH_REMATCH[2]}" "\${BASH_REMATCH[4]:-0}")
    [[ \$minimum =~ \$pattern ]] || return 1
    minimum_parts=("\${BASH_REMATCH[1]}" "\${BASH_REMATCH[2]}" "\${BASH_REMATCH[4]:-0}")
    for index in 0 1 2; do
        if (( 10#\${current_parts[index]} > 10#\${minimum_parts[index]} )); then
            return 0
        elif (( 10#\${current_parts[index]} < 10#\${minimum_parts[index]} )); then
            return 1
        fi
    done
    return 0
}

go_toolchain_usable() {
    local go_root=\$1 version_output current_go_version tool_dir
    [[ -x "\$go_root/bin/go" && -d "\$go_root/src/runtime" ]] || return 1
    version_output=\$(env GOROOT="\$go_root" GOTOOLCHAIN=local "\$go_root/bin/go" version) || return 1
    read -r _ _ current_go_version _ <<< "\$version_output"
    go_version_at_least "\$current_go_version" "\$GO_REQUIRED_VERSION" || return 1
    tool_dir=\$(env GOROOT="\$go_root" GOTOOLCHAIN=local "\$go_root/bin/go" env GOTOOLDIR) || return 1
    [[ "\$tool_dir" == "\$go_root"/pkg/tool/* && -x "\$tool_dir/compile" && -x "\$tool_dir/link" ]]
}

select_go_toolchain() {
    local system_go go_root version_output current_go_version
    system_go=\$(command -v go) || system_go=""
    if [[ -n "\$system_go" ]] && version_output=\$(env -u GOROOT GOTOOLCHAIN=local "\$system_go" version); then
        read -r _ _ current_go_version _ <<< "\$version_output"
        if go_version_at_least "\$current_go_version" "\$GO_REQUIRED_VERSION" &&
            go_root=\$(env -u GOROOT GOTOOLCHAIN=local "\$system_go" env GOROOT) &&
            go_toolchain_usable "\$go_root"; then
            export GOROOT="\$go_root"
            export PATH="\$GOROOT/bin:\$PATH" GOTOOLCHAIN=local
            hash -r
            return 0
        fi
    fi
    go_root="/opt/sslcat-toolchains/go\${GO_REQUIRED_VERSION}"
    if go_toolchain_usable "\$go_root"; then
        export GOROOT="\$go_root"
        export PATH="\$GOROOT/bin:\$PATH" GOTOOLCHAIN=local
        hash -r
        return 0
    fi
    return 1
}

export PATH=\$PATH:/usr/local/go/bin
select_go_toolchain || {
    echo "没有可用的 Go \$GO_REQUIRED_VERSION 或更高稳定版本，请先运行 setup-test-server.sh" >&2
    exit 1
}
echo "使用 Go 工具链: \$GOROOT"
echo "📦 下载依赖..."
go mod download
go mod tidy

echo "🏗️  构建前端..."
if [ -f "scripts/build-frontend.sh" ]; then
    bash scripts/build-frontend.sh || echo "前端构建失败，继续"
fi

echo "🔨 编译二进制文件..."
if [ "$BUILD_TYPE" = "cgo" ]; then
    # 使用 Docker 编译 CGO 版本
    if [ -f "Makefile" ]; then
        make docker-cgo-extract || {
            echo "Docker CGO 编译失败，尝试标准编译..."
            make build-linux
        }
    else
        GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o build/sslcat-linux-amd64 main.go
    fi
else
    # 标准编译
    if [ -f "Makefile" ]; then
        make build-linux
    else
        GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o build/sslcat-linux-amd64 main.go
    fi
fi

echo "✅ 编译完成"
ls -lh build/sslcat-linux-amd64* || ls -lh sslcat-linux-amd64*

ENDSSH

echo "✅ SSLcat 编译完成！"


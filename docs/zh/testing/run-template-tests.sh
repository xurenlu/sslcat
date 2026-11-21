#!/bin/bash

# 运行模板测试脚本
# 在 sg2.shifen.de 上执行模板测试

set -e

SERVER="root@sg2.shifen.de"
SSLCAT_DIR="/opt/sslcat"
TEST_DIR="/opt/sslcat-test"
PRIORITY="${1:-all}"  # all, high, medium, low

echo "🧪 开始运行模板测试 (优先级: $PRIORITY)..."

# 同步代码到服务器（如果需要）
echo "📥 同步代码到服务器..."
rsync -avz --exclude 'node_modules' --exclude '.git' \
    ./ $SERVER:$SSLCAT_DIR/ || {
    echo "⚠️  rsync 失败，使用现有代码"
}

# 在服务器上执行测试
ssh $SERVER bash << ENDSSH
set -e

cd $SSLCAT_DIR

echo "🔧 设置环境变量..."
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
export GOPATH=/opt/go
export GOBIN=\$GOPATH/bin

echo "📦 编译测试工具..."
cd tools/test-templates
go mod tidy
go build -o test-templates .

echo "🧪 开始测试..."

# 创建输出目录
mkdir -p $TEST_DIR/results

# 根据优先级运行测试
if [ "$PRIORITY" = "all" ]; then
    echo "测试所有优先级的模板..."
    ./test-templates \
        --templates-dir ../../internal/runner/templates/builtin \
        --parallel 2 \
        --timeout 10m \
        --base-port 20000 \
        --output-dir $TEST_DIR/results \
        --cleanup
else
    echo "测试 $PRIORITY 优先级的模板..."
    ./test-templates \
        --templates-dir ../../internal/runner/templates/builtin \
        --priority $PRIORITY \
        --parallel 2 \
        --timeout 10m \
        --base-port 20000 \
        --output-dir $TEST_DIR/results \
        --cleanup
fi

echo "✅ 测试完成"
echo "📄 结果文件: $TEST_DIR/results/test-results.json"

ENDSSH

# 下载测试结果
echo "📥 下载测试结果..."
scp $SERVER:$TEST_DIR/results/test-results.json ./test-results.json || {
    echo "⚠️  下载测试结果失败"
}

echo "✅ 测试完成！"
echo "📄 测试结果已保存到: ./test-results.json"


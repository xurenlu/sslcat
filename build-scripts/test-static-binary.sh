#!/bin/bash

# 这个脚本用于在 Linux 系统上测试静态链接二进制文件

echo "=========================================="
echo "测试 sslcat-static-linux-amd64 二进制文件"
echo "=========================================="
echo ""

# 检查文件是否存在
if [ ! -f "./sslcat-static-linux-amd64" ]; then
    echo "❌ 文件不存在: ./sslcat-static-linux-amd64"
    exit 1
fi

echo "✅ 文件存在"
echo ""

# 1. 查看文件类型
echo "1️⃣  文件类型："
file ./sslcat-static-linux-amd64
echo ""

# 2. 查看文件大小
echo "2️⃣  文件大小："
ls -lh ./sslcat-static-linux-amd64
echo ""

# 3. 检查动态链接依赖（最关键的测试）
echo "3️⃣  动态链接依赖检查："
if command -v ldd &> /dev/null; then
    ldd ./sslcat-static-linux-amd64 || echo "✅ 完全静态链接，无任何动态依赖！"
else
    echo "⚠️  ldd 命令不可用"
fi
echo ""

# 4. 检查 ELF 解释器（静态链接的二进制文件不应该有解释器）
echo "4️⃣  ELF 解释器检查："
if command -v readelf &> /dev/null; then
    INTERP=$(readelf -l ./sslcat-static-linux-amd64 | grep "program interpreter")
    if [ -z "$INTERP" ]; then
        echo "✅ 无 ELF 解释器 - 这是完全静态链接的二进制文件"
    else
        echo "⚠️  发现 ELF 解释器："
        echo "$INTERP"
    fi
else
    echo "⚠️  readelf 命令不可用"
fi
echo ""

# 5. 检查是否包含 musl 或 glibc 字符串
echo "5️⃣  检查 libc 类型标识："
if strings ./sslcat-static-linux-amd64 | grep -q "musl libc"; then
    echo "📝 发现 'musl libc' 字符串（这只是编译时使用的工具链标识）"
elif strings ./sslcat-static-linux-amd64 | grep -q "GNU C Library"; then
    echo "📝 发现 'GNU C Library' 字符串"
else
    echo "✅ 未发现明显的 libc 标识"
fi
echo ""

# 6. 尝试运行版本检查
echo "6️⃣  尝试运行二进制文件："
chmod +x ./sslcat-static-linux-amd64
./sslcat-static-linux-amd64 -version 2>&1 | head -5
EXIT_CODE=$?
echo ""
echo "退出码: $EXIT_CODE"
echo ""

# 总结
echo "=========================================="
echo "测试总结"
echo "=========================================="
echo ""
echo "这个二进制文件的特点："
echo "  1. 使用 musl-cross 工具链编译"
echo "  2. 所有 C 库代码（包括 musl libc）都被静态链接到二进制文件中"
echo "  3. 运行时不需要系统上安装 musl 或 glibc"
echo "  4. 可以在任何 Linux 发行版上运行"
echo ""
echo "关键点："
echo "  - musl-cross 只是编译工具，不是运行时依赖"
echo "  - 静态链接意味着所有代码都在二进制文件内部"
echo "  - 目标系统不需要安装任何特定的 libc"
echo ""


#!/bin/bash
# SSLcat 测试环境初始化脚本

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "🚀 初始化 SSLcat 测试环境..."
echo "项目根目录: $PROJECT_ROOT"

cd "$PROJECT_ROOT"

# 颜色定义
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# 1. 创建测试数据目录
echo -e "${BLUE}📁 创建测试数据目录...${NC}"
mkdir -p test-data/{certs,keys,logs,cdn-cache,users}
mkdir -p tests/fixtures/backend-{a,b,c}
mkdir -p tests/images
mkdir -p tests/results

# 2. 创建管理员密码文件
echo -e "${BLUE}🔑 设置管理员密码...${NC}"
echo "TestAdmin@2024" > test-data/admin_password.txt
chmod 600 test-data/admin_password.txt
echo -e "${GREEN}✅ 管理员密码已设置: TestAdmin@2024${NC}"

# 3. 创建测试后端内容
echo -e "${BLUE}📄 创建测试后端内容...${NC}"

# Backend A
cat > tests/fixtures/backend-a/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Backend A</title></head>
<body>
  <h1>Backend A</h1>
  <p>Server: A</p>
  <p>Time: <script>document.write(new Date().toISOString())</script></p>
</body>
</html>
EOF

cat > tests/fixtures/backend-a/health << 'EOF'
OK
EOF

# Backend B
cat > tests/fixtures/backend-b/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Backend B</title></head>
<body>
  <h1>Backend B</h1>
  <p>Server: B</p>
  <p>Time: <script>document.write(new Date().toISOString())</script></p>
</body>
</html>
EOF

cat > tests/fixtures/backend-b/health << 'EOF'
OK
EOF

# Backend C
cat > tests/fixtures/backend-c/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Backend C</title></head>
<body>
  <h1>Backend C</h1>
  <p>Server: C</p>
  <p>Time: <script>document.write(new Date().toISOString())</script></p>
</body>
</html>
EOF

cat > tests/fixtures/backend-c/health << 'EOF'
OK
EOF

echo -e "${GREEN}✅ 测试后端内容已创建${NC}"

# 4. 创建测试图片（用于图片优化测试）
echo -e "${BLUE}🖼️  创建测试图片...${NC}"

# 如果没有 convert 命令，提示用户
if command -v convert >/dev/null 2>&1; then
    # 创建不同格式和大小的测试图片
    convert -size 2000x1500 xc:blue tests/images/test-large.jpg
    convert -size 800x600 xc:green tests/images/test-medium.png
    convert -size 400x300 xc:red tests/images/test-small.jpg
    echo -e "${GREEN}✅ 测试图片已创建${NC}"
else
    echo -e "${YELLOW}⚠️  ImageMagick 未安装，跳过图片创建${NC}"
    echo -e "${YELLOW}   可选：brew install imagemagick${NC}"
fi

# 5. 创建 POE API 配置文件模板（如果用户要测试 AI 功能）
echo -e "${BLUE}🤖 创建 POE API 配置模板...${NC}"
cat > tests/poe-config.example.json << 'EOF'
{
  "poe_api_key": "your-poe-api-key-here",
  "model": "GPT-4-Turbo",
  "endpoint": "https://api.poe.com/bot/"
}
EOF

echo -e "${YELLOW}💡 如需测试 AI 功能，请：${NC}"
echo -e "   1. 复制 tests/poe-config.example.json 为 tests/poe-config.json"
echo -e "   2. 填入你的 POE API Key"

# 6. 创建环境变量文件
echo -e "${BLUE}📝 创建测试环境变量...${NC}"
cat > tests/.env.test << 'EOF'
# SSLcat 测试环境变量
SSLCAT_BASE_URL=http://localhost:8080
SSLCAT_ADMIN_PREFIX=/sslcat-panel
SSLCAT_ADMIN_USER=admin
SSLCAT_ADMIN_PASS=TestAdmin@2024

# 后端服务器
BACKEND_A_URL=http://backend-a
BACKEND_B_URL=http://backend-b
BACKEND_C_URL=http://backend-c

# 测试域名（需要在 /etc/hosts 中配置）
TEST_DOMAIN_A=test-a.local
TEST_DOMAIN_LB=test-lb.local

# 测试选项
TEST_SKIP_SSL=true
TEST_VERBOSE=true
TEST_OUTPUT_DIR=./tests/results
EOF

echo -e "${GREEN}✅ 环境变量文件已创建${NC}"

# 7. 提示用户配置 hosts
echo ""
echo -e "${YELLOW}⚠️  请将以下内容添加到 /etc/hosts：${NC}"
echo -e "${YELLOW}127.0.0.1  test-a.local test-lb.local${NC}"
echo ""

# 8. 显示完成信息
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ 测试环境初始化完成！${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}📋 下一步操作：${NC}"
echo -e "1. 启动测试环境:"
echo -e "   ${YELLOW}docker-compose -f docker-compose.test.yml up -d${NC}"
echo ""
echo -e "2. 等待服务启动 (约10秒):"
echo -e "   ${YELLOW}docker-compose -f docker-compose.test.yml ps${NC}"
echo ""
echo -e "3. 运行测试:"
echo -e "   ${YELLOW}bash tests/scripts/run-all-tests.sh${NC}"
echo ""
echo -e "4. 查看测试结果:"
echo -e "   ${YELLOW}cat tests/results/test-summary.txt${NC}"
echo ""
echo -e "${BLUE}📚 测试文档: tests/TESTING.md${NC}"


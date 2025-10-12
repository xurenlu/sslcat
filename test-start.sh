#!/bin/bash
# SSLcat 测试环境一键启动脚本

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}   SSLcat 测试环境一键启动${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# 1. 初始化测试环境
echo -e "${BLUE}📋 步骤 1/4: 初始化测试环境${NC}"
bash tests/scripts/init-test-env.sh

echo ""
echo -e "${BLUE}📋 步骤 2/4: 启动 Docker 容器${NC}"
docker-compose -f docker-compose.test.yml down -v 2>/dev/null || true
docker-compose -f docker-compose.test.yml up -d

echo ""
echo -e "${BLUE}📋 步骤 3/4: 等待服务就绪${NC}"
sleep 15

# 检查容器状态
docker-compose -f docker-compose.test.yml ps

echo ""
echo -e "${BLUE}📋 步骤 4/4: 运行API测试${NC}"
bash tests/scripts/run-all-tests.sh

# 显示结果
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✅ 测试完成！${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${BLUE}📊 查看测试结果：${NC}"
echo -e "   cat tests/results/test-summary.txt"
echo ""
echo -e "${BLUE}📝 查看详细日志：${NC}"
echo -e "   cat tests/results/test.log"
echo ""
echo -e "${BLUE}🐳 查看容器日志：${NC}"
echo -e "   docker-compose -f docker-compose.test.yml logs sslcat"
echo ""
echo -e "${BLUE}🛑 停止测试环境：${NC}"
echo -e "   docker-compose -f docker-compose.test.yml down"
echo ""


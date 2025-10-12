# SSLcat 自动化测试

## 🚀 快速开始

```bash
# 一键运行所有测试
bash test-start.sh
```

## 📚 文档

详细文档请查看：[TESTING.md](TESTING.md)

## 🎯 测试覆盖

- ✅ 认证和基础 API
- ✅ 代理规则管理
- ✅ 用户权限管理
- ✅ 安全功能
- ✅ AI 安全分析（支持 POE API）
- ✅ 图片优化
- ✅ 负载均衡和会话保持

**总计**: 42+ 个自动化测试

## 🤖 AI 测试（POE）

如需测试 AI 功能：

1. 复制配置模板:
   ```bash
   cp poe-config.example.json poe-config.json
   ```

2. 填入你的 POE API Key

3. 运行测试:
   ```bash
   bash scripts/test-ai-security.sh
   ```

## 📊 查看结果

```bash
# 测试摘要
cat results/test-summary.txt

# 详细日志
cat results/test.log
```


# SSLcat API 自动化测试指南

> 🧪 **版本**: v1.3.13-rc2  
> 📅 **最后更新**: 2024年10月12日  
> ✅ **状态**: 完整测试套件

---

## 📋 目录

1. [测试概述](#测试概述)
2. [快速开始](#快速开始)
3. [测试环境](#测试环境)
4. [测试模块](#测试模块)
5. [AI功能测试](#ai功能测试)
6. [自定义测试](#自定义测试)

---

## 🎯 测试概述

SSLcat 提供完整的自动化测试套件，基于 Docker 环境，覆盖所有 API 功能。

### 测试覆盖范围

| 模块 | 测试数 | 覆盖功能 |
|------|--------|---------|
| **认证和基础** | 8个 | 登录、登出、用户信息、统计、配置 |
| **代理规则** | 6个 | 增删改查、负载均衡配置 |
| **用户管理** | 6个 | 用户增删改、密码修改、日志查询 |
| **安全功能** | 8个 | IP封禁、安全事件、TLS指纹、审计 |
| **AI安全** | 5个 | 配置、测试、分析（支持POE） |
| **图片优化** | 6个 | 配置、统计、缓存、实际优化 |
| **功能测试** | 3个 | 压缩、负载均衡、会话保持 |

**总计**: 42+ 个自动化测试

### 排除的功能

❌ **SSL 证书申请** - 需要公网 IP 和真实域名，无法在测试环境模拟  
✅ **其他 SSL 功能** - 上传、删除、导入导出等都可以测试

---

## 🚀 快速开始

### 一键运行所有测试

```bash
# 运行完整测试（初始化 + 启动 + 测试）
bash test-start.sh
```

这会：
1. ✅ 初始化测试环境
2. ✅ 启动 Docker 容器（SSLcat + 3个测试后端）
3. ✅ 等待服务就绪
4. ✅ 运行所有 API 测试
5. ✅ 生成测试报告

### 手动步骤

```bash
# 1. 初始化环境
bash tests/scripts/init-test-env.sh

# 2. 启动 Docker
docker-compose -f docker-compose.test.yml up -d

# 3. 等待服务启动（约15秒）
sleep 15

# 4. 运行测试
bash tests/scripts/run-all-tests.sh

# 5. 查看结果
cat tests/results/test-summary.txt
```

---

## 🏗️ 测试环境

### Docker Compose 架构

```
┌─────────────┐
│   SSLcat    │ :8080 (HTTP), :2222 (SSH)
│  (待测试)    │
└──────┬──────┘
       │
       ├─────┐─────┐
       │     │     │
  ┌────▼──┐ ┌▼────┐ ┌▼────┐
  │Backend│ │Backend│ │Backend│
  │   A   │ │   B  │ │   C  │
  └───────┘ └──────┘ └──────┘
   (Nginx)  (Nginx) (Nginx)
```

### 服务列表

| 服务 | 容器名 | 端口 | 说明 |
|------|--------|------|------|
| **sslcat** | sslcat-test | 8080, 2222 | 待测试的 SSLcat 实例 |
| **backend-a** | backend-a | 80 | 测试后端 A |
| **backend-b** | backend-b | 80 | 测试后端 B |
| **backend-c** | backend-c | 80 | 测试后端 C |

### 测试数据

```
tests/
├── .env.test              # 测试环境变量
├── fixtures/              # 测试数据
│   ├── backend-a/        # 后端 A 的静态文件
│   ├── backend-b/        # 后端 B 的静态文件
│   └── backend-c/        # 后端 C 的静态文件
├── images/               # 测试图片
├── results/              # 测试结果
│   ├── test.log         # 详细日志
│   └── test-summary.txt # 测试摘要
├── poe-config.json       # POE API 配置（可选）
└── scripts/              # 测试脚本
    ├── test-lib.sh      # 测试工具库
    ├── test-auth.sh     # 认证测试
    ├── test-proxy.sh    # 代理测试
    ├── test-users.sh    # 用户测试
    ├── test-security.sh # 安全测试
    ├── test-ai-security.sh # AI测试
    ├── test-image-opt.sh   # 图片优化测试
    └── run-all-tests.sh    # 主测试脚本
```

---

## 🧪 测试模块

### 1. 认证和基础 API (`test-auth.sh`)

```bash
bash tests/scripts/test-auth.sh
```

**测试内容**:
- ✅ 未认证访问（应返回401）
- ✅ 登录
- ✅ 获取当前用户信息
- ✅ 获取系统统计
- ✅ 获取配置
- ✅ Prometheus 指标
- ✅ 登出
- ✅ 登出后访问（应返回401）

### 2. 代理规则管理 (`test-proxy.sh`)

```bash
bash tests/scripts/test-proxy.sh
```

**测试内容**:
- ✅ 获取代理规则列表
- ✅ 添加代理规则
- ✅ 获取单个规则
- ✅ 更新代理规则
- ✅ 删除代理规则
- ✅ 负载均衡配置

### 3. 用户权限管理 (`test-users.sh`)

```bash
bash tests/scripts/test-users.sh
```

**测试内容**:
- ✅ 获取用户列表
- ✅ 添加普通用户
- ✅ 修改密码
- ✅ 恢复密码
- ✅ 删除用户
- ✅ 获取用户日志

### 4. 安全功能 (`test-security.sh`)

```bash
bash tests/scripts/test-security.sh
```

**测试内容**:
- ✅ 获取安全事件
- ✅ 获取安全统计
- ✅ 获取封禁IP列表
- ✅ 封禁IP
- ✅ 解封IP
- ✅ TLS 指纹统计
- ✅ 攻击统计
- ✅ 审计日志

### 5. 图片优化 (`test-image-opt.sh`)

```bash
bash tests/scripts/test-image-opt.sh
```

**测试内容**:
- ✅ 获取配置
- ✅ 启用/禁用
- ✅ 获取统计
- ✅ WebP 转换测试
- ✅ 尺寸调整测试
- ✅ 清空缓存

---

## 🤖 AI 功能测试

### 使用 POE API 测试

#### 第 1 步：获取 POE API Key

1. 访问 https://poe.com
2. 注册/登录
3. 访问 API 设置页面
4. 创建 API Key

#### 第 2 步：配置测试

```bash
# 复制配置模板
cp tests/poe-config.example.json tests/poe-config.json

# 编辑配置
nano tests/poe-config.json
```

填入你的 API Key:

```json
{
  "poe_api_key": "your-actual-poe-api-key",
  "model": "GPT-4-Turbo",
  "endpoint": "https://api.poe.com/bot/"
}
```

#### 第 3 步：运行 AI 测试

```bash
bash tests/scripts/test-ai-security.sh
```

**测试内容**:
- ✅ 获取 AI 配置
- ✅ 配置 POE API
- ✅ 测试 AI 连接
- ✅ 触发安全分析
- ✅ 查看分析结果

---

## 🛠️ 自定义测试

### 添加新的测试模块

1. 创建测试脚本:

```bash
# tests/scripts/test-my-feature.sh
#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

test_section "我的功能测试"

# 你的测试
test_authenticated_api "测试我的API" "GET" "/api/my-feature" "" "200"

log "${GREEN}✅ 我的功能测试完成${NC}"
```

2. 在主测试脚本中添加:

编辑 `tests/scripts/run-all-tests.sh`，在 `test_modules` 数组中添加:

```bash
"test-my-feature.sh    我的功能"
```

### 使用测试工具库

```bash
# 加载工具库
source tests/scripts/test-lib.sh

# 初始化
init_test

# 登录
test_login

# 测试 API
test_authenticated_api "测试名称" "METHOD" "/endpoint" "数据" "期望状态码"

# 示例
test_authenticated_api "获取配置" "GET" "/api/settings" "" "200"
test_authenticated_api "更新配置" "POST" "/api/settings/update" \
    '{"key":"value"}' "200"

# 打印摘要
print_summary

# 保存报告
save_report
```

---

## 📊 测试报告

### 测试摘要

测试完成后自动生成 `tests/results/test-summary.txt`:

```
SSLcat API 测试报告
====================
测试时间: 2024-10-12 12:00:00
总测试数: 42
通过: 40
失败: 2
通过率: 95.2%

详细日志: tests/results/test.log
```

### 详细日志

`tests/results/test.log` 包含所有测试的详细输出：

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
认证和基础功能测试
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ PASS 未认证访问 - 应返回401 (HTTP 401)
✅ PASS 登录测试 (HTTP 200)
✅ PASS 获取当前用户 (HTTP 200)
...
```

---

## 🔍 故障排查

### 问题 1: Docker 容器启动失败

```bash
# 查看容器状态
docker-compose -f docker-compose.test.yml ps

# 查看日志
docker-compose -f docker-compose.test.yml logs sslcat

# 重新构建
docker-compose -f docker-compose.test.yml build --no-cache
docker-compose -f docker-compose.test.yml up -d
```

### 问题 2: 测试失败

```bash
# 查看详细日志
cat tests/results/test.log

# 查看最后的响应
cat tests/results/last-response.json

# 手动测试单个 API
curl -X POST http://localhost:8080/sslcat-panel/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"TestAdmin@2024"}'
```

### 问题 3: 服务无法访问

```bash
# 检查端口
lsof -i :8080

# 检查 hosts 配置
cat /etc/hosts | grep test-

# 添加 hosts（如果缺失）
echo "127.0.0.1  test-a.local test-lb.local" | sudo tee -a /etc/hosts
```

---

## 📚 测试脚本API

### test_api

```bash
test_api "测试名称" "HTTP方法" "端点" "数据" "期望状态码"
```

**示例**:
```bash
test_api "登录" "POST" "/api/auth/login" \
    '{"username":"admin","password":"pass"}' "200"
```

### test_authenticated_api

```bash
test_authenticated_api "测试名称" "HTTP方法" "端点" "数据" "期望状态码"
```

自动带上认证 Cookie。

### wait_for_service

```bash
wait_for_service  # 等待 SSLcat 启动
```

### print_summary

```bash
print_summary  # 打印测试结果摘要
```

### save_report

```bash
save_report  # 保存测试报告到文件
```

---

## 🎯 CI/CD 集成

### GitHub Actions

```yaml
name: API Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run API Tests
        run: |
          bash test-start.sh
      
      - name: Upload Test Results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: test-results
          path: tests/results/
```

### GitLab CI

```yaml
test:
  image: docker:latest
  services:
    - docker:dind
  script:
    - bash test-start.sh
  artifacts:
    paths:
      - tests/results/
    when: always
```

---

## 💡 最佳实践

### ✅ 推荐做法

1. **每次发布前运行完整测试**
   ```bash
   bash test-start.sh
   ```

2. **开发时只运行相关模块**
   ```bash
   # 只测试代理功能
   bash tests/scripts/test-proxy.sh
   ```

3. **保留测试日志**
   ```bash
   # 按日期保存
   cp tests/results/test-summary.txt \
      tests/results/test-$(date +%Y%m%d).txt
   ```

4. **定期更新测试**
   - 新增 API 后立即添加测试
   - 修改 API 后更新对应测试

### ❌ 避免的做法

1. ❌ 在生产环境运行测试
2. ❌ 使用生产数据库测试
3. ❌ 跳过测试直接发布

---

## 🎉 总结

通过这套测试体系，你可以：

✅ **一键测试** - 运行 `bash test-start.sh` 即可  
✅ **完整覆盖** - 42+ 个测试覆盖所有主要 API  
✅ **Docker 隔离** - 独立测试环境，不影响生产  
✅ **POE 支持** - AI 功能可使用 POE API 测试  
✅ **自动报告** - 测试结果自动生成  
✅ **易于扩展** - 添加新测试非常简单  

现在你有了一个**企业级的 API 测试套件**！🚀

---

*最后更新: 2024年10月12日*


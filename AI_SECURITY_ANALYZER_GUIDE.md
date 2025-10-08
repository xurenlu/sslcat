# AI 智能安全分析系统使用指南

## 📌 功能简介

SSLcat 现在集成了基于 GPT-4 mini 的智能安全分析系统，可以自动分析安全日志、识别威胁模式，并在检测到可疑活动时自动发送邮件通知。

### 核心优势

1. **🤖 智能分析**：使用 AI 识别复杂的攻击模式，而不仅仅是简单的阈值判断
2. **📊 全局视角**：综合分析多维度数据（IP、UA、地理位置、时间模式等）
3. **💡 可操作建议**：不只是报警，还提供具体的安全建议
4. **🎯 准确度高**：通过上下文理解减少误报，标注置信度
5. **💰 成本可控**：使用 GPT-4 mini 模型，单次分析成本约 $0.001-0.01

---

## 📋 工作原理

```
┌─────────────────┐
│  数据收集器      │
│  每小时收集：    │
│  - DDoS 攻击     │
│  - 可疑 IP       │
│  - 异常 UA       │
│  - 流量模式      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  数据聚合        │
│  生成摘要：      │
│  - 攻击类型统计  │
│  - Top攻击者    │
│  - 异常User-Agent│
│  - 错误率        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  GPT-4 mini     │
│  AI 分析：       │
│  - 模式识别      │
│  - 威胁评估      │
│  - 生成建议      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  威胁分级        │
│  - Low          │
│  - Medium       │
│  - High         │
│  - Critical     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  邮件通知        │
│  Medium 及以上   │
│  自动发送邮件    │
└─────────────────┘
```

---

## 🔧 配置方法

### 1. 获取 API Key

你有多种选择：

#### 选项 A：OpenAI 官方 API
前往 [https://platform.openai.com/api-keys](https://platform.openai.com/api-keys) 创建 API Key。
- **优点**：直连，稳定性最好
- **缺点**：成本较高
- **推荐模型**：gpt-4o-mini

#### 选项 B：POE API ⭐ 推荐
前往 [https://poe.com/api_key](https://poe.com/api_key) 创建 API Key。
- **优点**：包月套餐，成本更低，支持多种模型
- **缺点**：需要 POE 订阅（$20/月）
- **推荐模型**：GPT-4-Turbo 或 Claude-3-Sonnet
- **详细指南**：参见 [POE_INTEGRATION_GUIDE.md](./POE_INTEGRATION_GUIDE.md)

#### 选项 C：其他兼容平台
- Azure OpenAI Service
- 本地部署（Ollama、LocalAI）
- 任何 OpenAI 兼容的 API

**重要：** API Key 非常敏感，请妥善保管，不要提交到 Git！

### 2. 配置文件示例

#### 使用 OpenAI

在 `sslcat.conf` 中添加以下配置：

```json
{
  "ai_security": {
    "enabled": true,
    "api_key": "sk-proj-xxxxxxxxxxxxxxxxxxxx",
    "model": "gpt-4o-mini",
    "check_interval": "1h",
    "analysis_window": "1h",
    "max_tokens": 2000,
    "temperature": 0.3,
    "min_events": 10,
    "notify_on_threat": true,
    "min_threat_level": "medium"
  },
```

#### 使用 POE（推荐）

```json
{
  "ai_security": {
    "enabled": true,
    "api_key": "poe-xxxxxxxxxxxxxxxx",
    "api_endpoint": "https://api.poe.com/v1/chat/completions",
    "model": "GPT-4-Turbo",  // 或 "Claude-3-Sonnet"
    "check_interval": "1h",
    "analysis_window": "1h",
    "max_tokens": 2000,
    "temperature": 0.3,
    "min_events": 10,
    "notify_on_threat": true,
    "min_threat_level": "medium"
  },
  
  "notification": {
    "enabled": true,
    "channels": {
      "email": {
        "enabled": true,
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "smtp_user": "alerts@example.com",
        "smtp_password": "your-password",
        "from": "alerts@example.com",
        "to": ["admin@example.com", "security@example.com"]
      }
    }
  }
}
```

### 3. 配置参数说明

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | false | 是否启用 AI 安全分析 |
| `api_key` | string | - | OpenAI API Key（必填） |
| `api_endpoint` | string | OpenAI | API 端点（可选，支持兼容接口） |
| `model` | string | gpt-4o-mini | 使用的模型 |
| `check_interval` | duration | 1h | 检查间隔（1h, 2h, 30m 等） |
| `analysis_window` | duration | 1h | 分析的时间窗口 |
| `max_tokens` | int | 2000 | 最大 token 数 |
| `temperature` | float | 0.3 | 温度参数（0-1，越低越精确） |
| `min_events` | int | 10 | 最少事件数才进行分析 |
| `notify_on_threat` | bool | true | 检测到威胁时是否通知 |
| `min_threat_level` | string | medium | 最低通知威胁等级 |

---

## 🎯 AI 提示词设计

### 系统提示词

系统使用精心设计的提示词，让 GPT 扮演专业的网络安全分析专家：

```
你是一个专业的网络安全分析专家，专门负责分析 Web 服务器的安全日志和攻击模式。

你的任务：
1. 分析提供的安全数据，识别潜在的安全威胁和异常行为
2. 评估威胁等级（low, medium, high, critical）
3. 提供具体的威胁描述和风险评估
4. 给出可操作的安全建议

分析重点：
- DDoS 攻击模式：识别大规模、高频率的请求模式
- 扫描行为：识别针对常见漏洞路径的探测（如 .env, wp-admin, phpmyadmin 等）
- 异常 User-Agent：识别爬虫、扫描工具、恶意软件特征
- 地理位置异常：识别来自高风险地区的集中攻击
- 时间模式异常：识别非正常时段的流量激增
- IP 信誉：识别已知恶意 IP 或云服务器 IP（常用于攻击）
- 请求特征：识别 SQL 注入、XSS、路径遍历等攻击尝试
...
```

### 用户提示词

动态生成，包含实际的安全数据：

```
请分析以下时段的安全数据：14:00 至 15:00

## 基础统计
- 总请求数: 15234
- 被封禁 IP 数: 12
- 可疑 IP 数: 45
- 错误率: 8.5%

## 攻击事件摘要
- 类型: rate_limit, 次数: 125, 拦截: 120, 严重程度: high
  主要攻击 IP: 18.181.147.37, 23.94.12.58, 45.142.213.99

- 类型: suspicious_ua, 次数: 89, 拦截: 0, 严重程度: medium
  主要攻击 IP: 103.53.171.24, 185.220.101.67

## 高频攻击者 TOP 5
1. IP: 18.181.147.37
   - 请求数: 3266, 被拦截: 5 次, 请求速率: 54.4 req/min
   - 攻击类型: rate_limit, suspicious_pattern
   - 地理位置: Tokyo, Japan

...
```

### 输出格式

AI 返回标准的 JSON 格式：

```json
{
  "threat_level": "high",
  "summary": "检测到针对性的 DDoS 攻击，来自日本的单个 IP 持续高频请求",
  "threats": [
    {
      "type": "ddos_attack",
      "severity": "high",
      "description": "IP 18.181.147.37 在 1 分钟内发送了 3266 次请求，远超正常阈值",
      "indicators": ["18.181.147.37", "54.4 req/min"],
      "confidence": 0.95,
      "action": "建议立即封禁该 IP，并检查是否有其他相关 IP"
    }
  ],
  "recommendations": [
    "将 18.181.147.37 加入永久黑名单",
    "检查该 IP 访问的 URL 模式，确认攻击目标",
    "考虑限制来自日本的请求速率（如果不是目标市场）"
  ],
  "confidence": 0.90
}
```

---

## 📧 通知示例

当检测到威胁时，你会收到类似这样的邮件：

```
主题: AI 安全分析 - HIGH 威胁

AI 安全分析报告 - 14:00 至 15:00

威胁等级: HIGH
置信度: 90%

总结: 检测到针对性的 DDoS 攻击，来自日本的单个 IP 持续高频请求

发现的威胁:
1. [HIGH] ddos_attack
   描述: IP 18.181.147.37 在 1 分钟内发送了 3266 次请求，远超正常阈值
   指标: 18.181.147.37, 54.4 req/min
   建议: 建议立即封禁该 IP，并检查是否有其他相关 IP

2. [MEDIUM] port_scan
   描述: 检测到多个 IP 在短时间内访问了大量不存在的路径
   指标: /.env, /wp-admin, /phpmyadmin
   建议: 这是典型的扫描行为，建议启用 WAF 规则拦截

安全建议:
1. 将 18.181.147.37 加入永久黑名单
2. 检查该 IP 访问的 URL 模式，确认攻击目标
3. 考虑限制来自日本的请求速率（如果不是目标市场）
4. 启用针对扫描行为的 WAF 规则

分析时间: 2025-10-08 15:05:32
```

---

## 💰 成本估算

### OpenAI 直连定价

| 模型 | 输入 | 输出 | 每月成本（每小时）|
|------|------|------|-----------------|
| GPT-4 mini | $0.150/1M | $0.600/1M | $0.7-2 |
| GPT-3.5 Turbo | $0.5/1M | $1.5/1M | $0.3-0.8 |
| GPT-4 Turbo | $10/1M | $30/1M | $5-8 |

### POE 包月定价（推荐）

| 套餐 | 月费 | 适用场景 |
|------|------|---------|
| POE 订阅 | $20/月 | 无限制使用多种模型 |
| POE 专业版 | $50/月 | 企业级使用 |

### 成本对比

**小型站点**（1-5个域名）：
- OpenAI GPT-4 mini：$0.7-2/月 ⭐ 最便宜
- POE 订阅：$20/月（但可用 GPT-4）

**中大型站点**（5+个域名）或**需要高准确度**：
- POE 订阅：$20/月 ⭐ 性价比最高
- 可使用 GPT-4-Turbo、Claude-3-Opus 等高级模型

**结论**：
- 小规模：OpenAI GPT-4 mini
- 中大规模：POE 订阅（更划算）

---

## 🚀 启动和测试

### 1. 启动服务

```bash
# 编译
go build -o sslcat main.go

# 启动
./sslcat
```

### 2. 查看日志

```bash
# 查看 AI 分析日志
tail -f logs/sslcat.log | grep "ai_security"
```

你会看到类似这样的日志：

```
[INFO] ai_security: AI 安全分析器已启动，检查间隔: 1h
[INFO] ai_security: 开始执行 AI 安全分析...
[INFO] ai_security: GPT API 调用成功，使用 tokens: 1245
[INFO] ai_security: AI 分析完成，威胁等级: medium，置信度: 0.85
[INFO] ai_security: AI 安全分析通知已发送
```

### 3. 手动触发分析

可以通过 API 手动触发分析（用于测试）：

```bash
curl -X POST http://localhost/api/security/analyze \
  -H "Authorization: Bearer your-token"
```

---

## 🎨 自定义提示词

如果你想自定义 AI 的分析逻辑，可以修改 `internal/ai/security_analyzer.go` 中的 `buildSystemPrompt()` 函数。

例如，你可以：
- 添加特定行业的威胁特征（如金融、电商）
- 调整威胁等级的判断标准
- 添加特定的检测规则
- 自定义输出格式

---

## 🔒 安全建议

### 1. API Key 保护

- ❌ 不要将 API Key 提交到 Git
- ✅ 使用环境变量：`export OPENAI_API_KEY="sk-..."`
- ✅ 使用专用的配置文件（添加到 .gitignore）
- ✅ 定期轮换 API Key

### 2. 速率限制

OpenAI 有速率限制，建议：
- 检查间隔不要小于 30 分钟
- 设置 `min_events` 避免无意义的分析
- 监控 API 使用量

### 3. 数据隐私

虽然发送给 GPT 的数据已经过聚合和脱敏，但如果你处理的是极其敏感的数据，建议：
- 自建兼容 OpenAI API 的本地模型（如 Ollama）
- 修改数据收集器，进一步脱敏

---

## 🐛 故障排查

### 问题 1：AI 分析未启动

检查：
1. `ai_security.enabled` 是否为 `true`
2. `api_key` 是否正确配置
3. 查看日志是否有错误信息

### 问题 2：未收到通知邮件

检查：
1. `notification.enabled` 是否为 `true`
2. SMTP 配置是否正确
3. `min_threat_level` 设置是否过高
4. 查看日志是否有发送失败的记录

### 问题 3：API 调用失败

可能原因：
1. API Key 无效或过期
2. 网络连接问题（无法访问 OpenAI API）
3. 速率限制（请求过于频繁）
4. API 账户余额不足

解决方法：
```bash
# 测试 API Key
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"
```

### 问题 4：分析结果不准确

可能原因：
1. 数据量太少（低于 `min_events`）
2. 提示词需要优化
3. 温度参数过高（增加随机性）

解决方法：
- 调低 `temperature` 到 0.1-0.3
- 增加 `analysis_window` 获取更多数据
- 自定义提示词

---

## 🎯 最佳实践

1. **初期测试**：先设置较高的 `min_threat_level`（如 high），避免邮件轰炸
2. **逐步调整**：根据实际效果逐步降低阈值
3. **定期审查**：定期检查 AI 的分析结果，优化提示词
4. **成本监控**：在 OpenAI 后台设置使用量告警
5. **备用方案**：保留传统的阈值告警作为备用

---

## 📚 相关文档

- [DDoS 检测修复](./DDOS_DETECTION_FIX.md)
- [Localhost 认证绕过修复](./SECURITY_FIX_LOCALHOST_BYPASS.md)
- [通知系统配置](./GIT_DEPLOY_NOTIFICATION_INTEGRATION.md)

---

## 🤝 反馈和改进

如果你有任何建议或发现问题，欢迎：
1. 提交 Issue
2. 优化提示词并分享
3. 贡献代码改进

---

**祝你使用愉快！🎉**


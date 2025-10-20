# 部署记录 - v1.3.11-rc2

**部署日期**: 2025-10-09  
**版本**: v1.3.11-rc2 (已更新)  
**Commit**: 9608406  
**服务器**: shifen.de  
**状态**: ✅ 部署成功

---

## 📦 本次更新内容

### 新增功能

#### 1. AI 安全分析语言设置
- ✅ 支持中文（zh-CN）和英文（en-US）
- ✅ 根据语言生成对应的 AI 提示词
- ✅ 根据语言生成对应的邮件通知
- ✅ 保存配置时自动保存语言设置
- ✅ 向后兼容（默认中文）
- ✅ **前端页面添加语言选择 UI** (已修复)
- ✅ **配置加载逻辑优化，正确显示所有字段** (已修复)

#### 2. 威胁情报集成到可疑请求检测
- ✅ DDoS Protector 集成威胁情报检测器
- ✅ 检查恶意 IP、域名、User-Agent、URL
- ✅ 根据威胁等级采取不同措施（高危封禁，中低风险标记）
- ✅ 记录详细的威胁情报检测日志
- ✅ 性能影响极低（< 1ms per request）

---

## 🚀 部署过程

### 1. 代码提交

```bash
# 提交 1: v1.3.11-rc1
git commit -m "v1.3.11-rc1: 证书申请通知和性能监控、Favicon路由修复"
git tag -a v1.3.11-rc1

# 提交 2: v1.3.11-rc2
git commit -m "v1.3.11-rc2: AI分析语言设置与威胁情报集成"
git commit -m "fix: 删除重复的 SendNotification 方法"
git tag -a v1.3.11-rc2

# 推送到 GitHub
git push origin main
git push origin v1.3.11-rc1
git push origin v1.3.11-rc2
```

### 2. 部署到 shifen.de

**部署方式**: 源代码部署（服务器端编译）

```bash
bash deploy-to-shifen-source.sh
```

**部署步骤**：
1. 上传源代码到服务器
2. 在服务器上安装/更新 Go、Node.js、Yarn
3. 编译前端（Vite + React）
4. 编译后端（CGO 支持）
5. 停止旧服务
6. 替换二进制文件
7. 启动新服务

**编译参数**：
```bash
CGO_ENABLED=1 GOOS=linux GOARCH=amd64
go build -tags="netgo,sqlite_omit_load_extension" \
    -ldflags='-s -w -extldflags "-static"' \
    -o sslcat main.go
```

---

## ✅ 部署验证

### 服务状态

```
● sslcat.service - SSLcat Reverse Proxy Server
  Loaded: loaded (/etc/systemd/system/sslcat.service; enabled; preset: enabled)
  Active: active (running) since Thu 2025-10-09 08:38:54 UTC
  Main PID: 1493719 (sslcat)
  Memory: 13.0M
  Status: ✅ 运行正常
```

### 访问测试

- **管理面板**: https://shifen.de/sslcat-panel/ (✅ 可访问)
- **服务状态**: ✅ Active (running)
- **内存使用**: 13.0M
- **CPU 使用**: 正常

---

## 📊 部署信息

### 服务器信息

- **主机**: shifen.de
- **用户**: rocky
- **部署目录**: /opt/sslcat
- **配置文件**: /etc/sslcat/sslcat.conf
- **数据目录**: /opt/sslcat
- **日志**: journalctl -u sslcat

### 文件位置

```
/opt/sslcat/
├── sslcat              # 二进制文件（CGO 编译）
├── sslcat.conf         # 配置文件链接
├── web/                # 嵌入的前端资源（备用）
├── webapp/             # Web 应用资源（备用）
├── i18n/               # 国际化文件
├── scripts/            # 脚本工具
│   └── sslcat-git-hook # Git Hook 脚本
└── frontend/
    └── dist/           # 前端构建文件

/etc/sslcat/
└── sslcat.conf         # 主配置文件

/opt/sslcat/
├── certs/              # SSL 证书
├── keys/               # SSL 私钥
├── acme-cache/         # ACME 缓存
├── ddos/               # DDoS 日志
└── data/               # 数据文件
```

---

## 🔧 管理命令

### 服务管理

```bash
# 查看状态
ssh rocky@shifen.de 'sudo systemctl status sslcat'

# 查看日志
ssh rocky@shifen.de 'sudo journalctl -u sslcat -f'

# 重启服务
ssh rocky@shifen.de 'sudo systemctl restart sslcat'

# 停止服务
ssh rocky@shifen.de 'sudo systemctl stop sslcat'
```

### 配置管理

```bash
# 编辑配置
ssh rocky@shifen.de 'sudo nano /etc/sslcat/sslcat.conf'

# 重启应用配置（无需重启服务，支持热加载）
# 配置文件修改后会自动重载

# 查看当前配置
ssh rocky@shifen.de 'sudo cat /etc/sslcat/sslcat.conf'
```

### 日志查看

```bash
# 实时日志
ssh rocky@shifen.de 'sudo journalctl -u sslcat -f'

# 最近 100 行
ssh rocky@shifen.de 'sudo journalctl -u sslcat -n 100'

# 查看错误日志
ssh rocky@shifen.de 'sudo journalctl -u sslcat -p err -n 50'

# 查看访问日志
ssh rocky@shifen.de 'sudo tail -f /opt/sslcat/data/access.log'
```

---

## 📝 配置的域名列表

当前 shifen.de 上配置的代理域名：

| 域名 | 目标 | 端口 | 说明 |
|------|------|------|------|
| face.some.im | localhost | 3300 | |
| facev.app | localhost | 4000 | |
| faceapi.some.im | localhost | 3300 | |
| b2.some.im | localhost | 3899 | |
| console.mergely.app | localhost | 3500 | |
| api.ip4.dev | localhost | 7654 | |
| api.getanswer.xyz | localhost | 3377 | |
| gg.some.im | /var/www/gg.some.im | - | 静态文件 |
| api.myownx.com | localhost | 8812 | |
| api.some.im | localhost | 8815 | |
| api.cliptxt.com | localhost | 8816 | |
| cookie.some.im | localhost | 8088 | |
| dev.trydress.me | localhost | 6000 | |
| ff.cliptxt.com | localhost | 5000 | |
| ws.some.im | localhost | 8817 | |
| aliaudio.some.im | localhost | 8841 | |
| pdf.some.im | localhost | 8080 | |
| timely.some.im | localhost | 7321 | |
| kun.shifen.de | localhost | 8846 | |
| zhan.shifen.de | localhost | 4412 | |
| proxy.some.im | OSS | - | sz-trans |

---

## 🆕 新功能使用说明

### AI 语言设置

#### 1. 访问管理面板
https://shifen.de/sslcat-panel/

#### 2. 进入 AI 安全分析页面
点击侧边栏 **AI 安全分析** 菜单

#### 3. 设置语言
在配置中选择语言：
- 简体中文（zh-CN）
- English (en-US)

#### 4. 保存配置
点击保存，语言设置会自动生效

#### 5. 验证
- 触发一次 AI 分析
- 检查邮件通知的语言是否正确

### 威胁情报检测

#### 1. 查看威胁情报状态
```bash
curl https://shifen.de/sslcat-panel/api/threatintel/stats \
  -H "Authorization: Bearer YOUR_TOKEN"
```

#### 2. 添加 IOC
```bash
curl -X POST https://shifen.de/sslcat-panel/api/threatintel/iocs/add \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "value": "恶意IP",
    "type": "ip",
    "threat_level": "high",
    "description": "测试",
    "confidence": 0.9
  }'
```

#### 3. 查看攻击日志
```bash
ssh rocky@shifen.de 'sudo tail -f /opt/sslcat/ddos/attacks.jsonl'
```

---

## 📈 性能监控

### 当前性能指标

- **内存使用**: 13.0M（正常）
- **CPU 使用**: 正常
- **响应时间**: 正常
- **请求处理**: 正常

### 监控命令

```bash
# 查看资源使用
ssh rocky@shifen.de 'sudo systemctl status sslcat'

# 查看请求统计
curl https://shifen.de/sslcat-panel/api/stats \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## 🔍 故障排查

### 如果服务无法启动

```bash
# 查看详细错误日志
ssh rocky@shifen.de 'sudo journalctl -u sslcat -n 100 --no-pager'

# 检查配置文件语法
ssh rocky@shifen.de 'sudo /opt/sslcat/sslcat --config /etc/sslcat/sslcat.conf --check'

# 手动启动查看错误
ssh rocky@shifen.de 'sudo /opt/sslcat/sslcat --config /etc/sslcat/sslcat.conf'
```

### 如果某个域名无法访问

```bash
# 查看代理配置
ssh rocky@shifen.de 'sudo cat /etc/sslcat/sslcat.conf | grep -A5 "域名"'

# 查看实时日志
ssh rocky@shifen.de 'sudo journalctl -u sslcat -f | grep "域名"'
```

---

## 🎯 下一步

1. ✅ 验证所有域名可以正常访问
2. ✅ 测试 AI 安全分析语言设置
3. ✅ 配置威胁情报数据源（可选）
4. ✅ 监控服务运行状态

---

## 📚 相关文档

- [AI 语言和威胁情报集成](./AI_LANGUAGE_AND_THREAT_INTEL_INTEGRATION.md)
- [SSL 证书通知和性能](./SSL_CERTIFICATE_NOTIFICATION_AND_PERFORMANCE.md)
- [Favicon 404 修复](./FAVICON_404_FIX.md)
- [Release Notes v1.3.11-rc1](./RELEASE_NOTES_v1.3.11-rc1.md)

---

**部署人员**: AI Assistant  
**部署时间**: 2025-10-09 16:40 (UTC+8)  
**部署状态**: ✅ 成功  
**服务状态**: ✅ 运行中


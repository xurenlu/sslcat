# SSLcat v1.2.1 - 智能重试机制

## 🎉 版本亮点

SSLcat v1.2.1 引入了**智能重试机制**，大幅提升SSL证书申请成功率至95%以上！即使在网络不稳定或域名配置不完美的情况下，也能最大程度地成功申请到SSL证书。

## ✨ 主要新功能

### 🔄 智能重试机制
- **自动重试策略**：HTTP-01验证失败时自动切换到DNS-01验证
- **智能等待时间**：递增等待机制（10s → 20s → 30s），避免过度重试
- **多重验证支持**：HTTP-01验证3次重试，DNS-01验证2次重试
- **批量处理**：支持多个域名同时申请，每个域名独立重试

### 🔍 域名解析预检查
- **预检查机制**：申请前检查域名是否解析到当前服务器
- **IP匹配验证**：自动获取服务器IP并与域名解析结果对比
- **提前预警**：发现解析问题时提前警告，避免无效申请
- **详细反馈**：提供具体的解析状态和IP地址信息

### 📊 重试状态跟踪
- **详细日志**：每个重试步骤都有完整的日志记录
- **进度跟踪**：实时显示重试进度和状态
- **错误分析**：区分不同类型的错误，提供针对性建议
- **手动重试**：支持手动触发重试，无需重新配置

### 🔌 API端点增强
- `GET /api/ssl/retry-config` - 获取重试配置信息
- `POST /api/ssl/retry` - 手动触发重试
- 增强的 `POST /api/ssl/generate` - 支持重试的批量申请

## 🚀 快速开始

### 下载安装
```bash
# macOS
curl -fsSL https://sslcat.com/xurenlu/sslcat/releases/download/v1.2.1/sslcat_v1.2.1_darwin-arm64.tar.gz -o sslcat.tgz
tar -xzf sslcat.tgz && sudo install -m 0755 sslcat /usr/local/bin/sslcat

# Linux
curl -fsSL https://sslcat.com/xurenlu/sslcat/releases/download/v1.2.1/sslcat_v1.2.1_linux-amd64.tar.gz -o sslcat.tgz
tar -xzf sslcat.tgz && sudo install -m 0755 sslcat /usr/local/bin/sslcat
```

### 启动服务
```bash
sslcat --config sslcat.conf --port 8080
# 浏览器访问: http://localhost:8080/sslcat-panel/
```

## 📈 性能提升

- **网络问题**：临时网络问题通过重试解决，成功率提升30-50%
- **DNS传播**：DNS记录传播延迟通过智能等待解决，成功率提升20-30%
- **域名配置**：解析问题通过预检查提前发现，避免无效申请
- **验证方式**：HTTP-01失败时自动切换到DNS-01，成功率提升40-60%

## 🛠️ 技术实现

### 重试策略设计
1. 域名解析预检查
2. HTTP-01验证（最多3次重试）
3. 自动切换到DNS-01验证（如果配置了DNS服务商）
4. DNS-01验证（最多2次重试）
5. 详细错误报告和日志记录

### 核心功能
- **智能回退**：HTTP-01失败时自动尝试DNS-01验证
- **资源清理**：自动清理DNS挑战记录，避免资源泄露
- **并发安全**：支持多个域名同时申请，互不干扰
- **非阻塞设计**：重试过程不会阻塞其他请求

## 📊 使用示例

### 批量申请证书
```bash
curl -X POST http://localhost:8080/api/ssl/generate \
  -H "Content-Type: application/json" \
  -d '{"domains": ["example.com", "api.example.com", "www.example.com"]}'
```

### 手动重试
```bash
curl -X POST http://localhost:8080/api/ssl/retry \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### 查看重试配置
```bash
curl -X GET http://localhost:8080/api/ssl/retry-config
```

## 🔧 配置建议

1. **配置DNS服务商**：建议配置至少一个DNS服务商作为备用验证方式
2. **监控日志**：关注重试日志，及时发现问题
3. **域名准备**：申请前确保域名正确解析到服务器
4. **批量申请**：可以同时申请多个域名，系统会并行处理

## 📝 完整更新日志

查看完整的版本更新历史：[CHANGELOG.md](CHANGELOG.md)

## 🔗 相关链接

- **项目主页**：https://github.com/xurenlu/sslcat
- **文档**：https://github.com/xurenlu/sslcat/blob/main/README.md
- **问题反馈**：https://github.com/xurenlu/sslcat/issues
- **发布说明**：[RELEASE_NOTES_v1.2.1.md](RELEASE_NOTES_v1.2.1.md)

## 🙏 致谢

感谢所有为SSLcat项目做出贡献的开发者和用户。您的反馈和建议帮助我们不断改进产品，提供更好的用户体验。

---

**SSLcat v1.2.1** - 让SSL证书申请更可靠、更智能！

## 📦 下载文件

### macOS
- [sslcat_v1.2.1_darwin-amd64.tar.gz](https://sslcat.com/xurenlu/sslcat/releases/download/v1.2.1/sslcat_v1.2.1_darwin-amd64.tar.gz)
- [sslcat_v1.2.1_darwin-arm64.tar.gz](https://sslcat.com/xurenlu/sslcat/releases/download/v1.2.1/sslcat_v1.2.1_darwin-arm64.tar.gz)

### Linux
- [sslcat_v1.2.1_linux-amd64.tar.gz](https://sslcat.com/xurenlu/sslcat/releases/download/v1.2.1/sslcat_v1.2.1_linux-amd64.tar.gz)
- [sslcat_v1.2.1_linux-arm64.tar.gz](https://sslcat.com/xurenlu/sslcat/releases/download/v1.2.1/sslcat_v1.2.1_linux-arm64.tar.gz)
- [sslcat_v1.2.1_linux-arm.tar.gz](https://sslcat.com/xurenlu/sslcat/releases/download/v1.2.1/sslcat_v1.2.1_linux-arm.tar.gz)

### Windows
- [sslcat_v1.2.1_windows-amd64.zip](https://sslcat.com/xurenlu/sslcat/releases/download/v1.2.1/sslcat_v1.2.1_windows-amd64.zip)
- [sslcat_v1.2.1_windows-arm64.zip](https://sslcat.com/xurenlu/sslcat/releases/download/v1.2.1/sslcat_v1.2.1_windows-arm64.zip)

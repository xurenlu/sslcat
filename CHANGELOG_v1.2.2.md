# SSLcat v1.2.2 更新日志

**发布日期**: 2025-09-17  
**版本类型**: 补丁版本 (Bug Fix)

## 🐛 重要修复

### 阿里云OSS代理问题修复
- **问题**: 访问阿里云OSS时返回403 AccessDenied错误，HostId显示为`local.de:9933`
- **原因**: 
  - Host头部包含端口号（如`van-course.oss-ap-southeast-1.aliyuncs.com:80`）
  - `req.Host`和`Header['Host']`不同步导致Host信息泄露
  - 代理头部触发OSS的防盗链检查
- **解决方案**:
  - 智能Host头部处理：对云服务自动移除标准端口号（80/443）
  - 同步设置`req.Host`和`Header['Host']`，确保两者一致
  - 调整Director函数调用顺序，防止Host设置被覆盖
  - 对云服务完全避免设置代理头部，防止防盗链检查
  - 增强云服务检测，支持阿里云、AWS、腾讯云等

### 技术改进
- **云服务兼容性**: 扩展支持多种云存储服务
  - ✅ 阿里云OSS (aliyuncs.com)
  - ✅ AWS S3 (amazonaws.com)  
  - ✅ 腾讯云COS (qcloud.com, myqcloud.com)
- **头部清理策略**: 实现两阶段头部清理机制
  - 预清理：在请求处理早期清理代理头部
  - Director清理：在发送请求前再次确保清理彻底
- **日志增强**: 添加详细的Host字段追踪日志，便于调试

## 🔧 代码变更

### 核心文件修改
- `internal/proxy/manager.go`: 重构Host头部处理和代理头部清理逻辑
- `main.go`: 版本号更新至v1.2.2

### 关键函数改进
- `extractHostFromTarget()`: 智能处理云服务Host头部格式
- `ProxyRequest()`: 增强头部清理和云服务检测
- `Director函数`: 优化调用顺序和Host设置逻辑

## 📋 向后兼容性

- ✅ 普通HTTP代理功能不受影响
- ✅ IP地址后端代理功能不受影响  
- ✅ 非云服务域名代理功能不受影响
- ✅ 现有配置文件无需修改

## 🧪 测试验证

### 修复前的问题请求
```bash
curl -H 'Host: van-course.oss-ap-southeast-1.aliyuncs.com:80' \
     -H 'X-Forwarded-For: 127.0.0.1' \
     -H 'Referer: http://local.de:9933/questions/2025/09-16/a17.png' \
     'http://van-course.oss-ap-southeast-1.aliyuncs.com:80/favicon.ico'
```

### 修复后的正确请求
```bash
curl -H 'Host: van-course.oss-ap-southeast-1.aliyuncs.com' \
     'http://van-course.oss-ap-southeast-1.aliyuncs.com:80/favicon.ico'
```

## 🚀 部署说明

### 升级步骤
1. 停止服务: `systemctl stop sslcat`
2. 备份当前版本: `cp /opt/sslcat/sslcat /opt/sslcat/sslcat.backup`
3. 更新二进制文件: 下载v1.2.2版本并替换
4. 设置权限: `chmod +x /opt/sslcat/sslcat`
5. 启动服务: `systemctl start sslcat`

### 编译要求
```bash
# 为Linux服务器编译
GOOS=linux GOARCH=amd64 go build -o withssl-linux-amd64 main.go
```

## 📚 相关文档

- [阿里云OSS代理问题解决方案](阿里云OSS代理问题解决方案.md) - 详细的技术分析和解决方案
- [部署指南](DEPLOYMENT.md) - 完整的部署和运维文档

## 🔗 相关链接

- [GitHub Release](https://github.com/xurenlu/sslcat/releases/tag/v1.2.2)
- [问题报告](https://github.com/xurenlu/sslcat/issues)
- [功能请求](https://github.com/xurenlu/sslcat/issues/new?template=feature_request.md)

---

**提交ID**: 25bc4dd  
**主要贡献者**: xurenlu  
**测试环境**: macOS (开发), Linux x86_64 (生产)

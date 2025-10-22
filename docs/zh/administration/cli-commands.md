# CLI 命令

SSLcat 提供了全面的命令行界面，用于配置、管理和故障排查。

## 基本命令

### 启动 SSLcat
```bash
# 使用默认配置启动
sslcat

# 使用自定义配置文件启动
sslcat -config /path/to/sslcat.conf

# 指定主机和端口启动
sslcat -host 0.0.0.0 -port 80 -ssl-port 443

# 调试模式启动
sslcat -debug

# 指定日志级别启动
sslcat -log-level debug
```

### 配置管理
```bash
# 验证配置文件
sslcat -config sslcat.conf -validate

# 测试配置而不启动服务
sslcat -config sslcat.conf -test

# 显示当前配置
sslcat config show

# 显示配置摘要
sslcat config summary
```

## 用户管理命令

### 用户操作
```bash
# 创建用户
sslcat users create -username admin -email admin@example.com -role admin

# 列出所有用户
sslcat users list

# 更新用户信息
sslcat users update -username admin -role operator

# 删除用户
sslcat users delete -username old_user

# 重置用户密码
sslcat users reset-password -username admin
```

### 权限管理
```bash
# 查看用户权限
sslcat users permissions -username admin

# 更新用户权限
sslcat users permissions -username admin -permissions "config:read,users:write"

# 查看用户状态
sslcat users status -username admin
```

## 代理管理命令

### 代理规则
```bash
# 列出所有代理规则
sslcat proxy list

# 添加代理规则
sslcat proxy add -domain example.com -target http://localhost:8080 -ssl

# 更新代理规则
sslcat proxy update -id 1 -domain example.com -target http://localhost:3000

# 删除代理规则
sslcat proxy delete -id 1

# 测试代理规则
sslcat proxy test -domain example.com
```

### 代理状态
```bash
# 查看代理状态
sslcat proxy status

# 重新加载代理配置
sslcat proxy reload

# 验证代理配置
sslcat proxy validate
```

## SSL 证书管理

### 证书操作
```bash
# 申请新证书
sslcat ssl request -domain example.com -email admin@example.com

# 列出所有证书
sslcat ssl list

# 查看证书详情
sslcat ssl show -domain example.com

# 续期证书
sslcat ssl renew -domain example.com

# 删除证书
sslcat ssl delete -domain example.com
```

### 证书状态
```bash
# 检查证书状态
sslcat ssl status

# 验证证书
sslcat ssl verify -domain example.com

# 自动续期设置
sslcat ssl auto-renew -enable
```

## 系统管理命令

### 服务控制
```bash
# 启动服务
sslcat service start

# 停止服务
sslcat service stop

# 重启服务
sslcat service restart

# 服务状态
sslcat service status

# 重新加载配置
sslcat service reload
```

### 系统信息
```bash
# 显示版本信息
sslcat version

# 显示系统信息
sslcat system info

# 显示配置信息
sslcat system config

# 显示统计信息
sslcat system stats
```

## 监控和日志命令

### 日志管理
```bash
# 查看实时日志
sslcat logs tail

# 查看访问日志
sslcat logs access

# 查看错误日志
sslcat logs error

# 查看系统日志
sslcat logs system

# 清除日志
sslcat logs clear
```

### 监控命令
```bash
# 显示性能指标
sslcat metrics

# 显示连接统计
sslcat metrics connections

# 显示请求统计
sslcat metrics requests

# 显示错误统计
sslcat metrics errors
```

## 故障排查命令

### 诊断工具
```bash
# 系统诊断
sslcat diagnose

# 网络诊断
sslcat diagnose network

# SSL 诊断
sslcat diagnose ssl

# 配置诊断
sslcat diagnose config
```

### 调试命令
```bash
# 启用调试模式
sslcat debug -enable

# 查看调试信息
sslcat debug info

# 生成调试报告
sslcat debug report

# 禁用调试模式
sslcat debug -disable
```

## 高级命令

### 性能调优
```bash
# 显示性能建议
sslcat performance suggest

# 优化配置
sslcat performance optimize

# 性能测试
sslcat performance test

# 基准测试
sslcat performance benchmark
```

### 备份和恢复
```bash
# 备份配置
sslcat backup config -output /backup/sslcat-config.tar.gz

# 备份证书
sslcat backup certificates -output /backup/certificates.tar.gz

# 恢复配置
sslcat restore config -input /backup/sslcat-config.tar.gz

# 恢复证书
sslcat restore certificates -input /backup/certificates.tar.gz
```

## 环境变量

### 常用环境变量
```bash
# 配置文件路径
export SSLCAT_CONFIG=/etc/sslcat/sslcat.conf

# 日志级别
export SSLCAT_LOG_LEVEL=info

# 调试模式
export SSLCAT_DEBUG=true

# 数据目录
export SSLCAT_DATA_DIR=/opt/sslcat/data
```

## 命令选项

### 全局选项
```bash
# 配置文件
-config, -c string
    配置文件路径 (默认: sslcat.conf)

# 日志级别
-log-level string
    日志级别: debug, info, warn, error (默认: info)

# 调试模式
-debug
    启用调试模式

# 帮助信息
-help, -h
    显示帮助信息

# 版本信息
-version, -v
    显示版本信息
```

## 示例用法

### 基本使用
```bash
# 启动 SSLcat
sslcat -config /etc/sslcat/sslcat.conf

# 添加代理规则
sslcat proxy add -domain api.example.com -target http://localhost:3000

# 申请 SSL 证书
sslcat ssl request -domain example.com -email admin@example.com

# 查看系统状态
sslcat system info
```

### 高级使用
```bash
# 批量添加代理规则
for domain in api.example.com app.example.com; do
    sslcat proxy add -domain $domain -target http://localhost:8080
done

# 监控系统性能
sslcat metrics --watch

# 生成系统报告
sslcat debug report -output system-report.html
```

## 相关文档

- [用户管理](user-management.md)
- [Web 界面](web-interface.md)
- [配置参考](../reference/configuration-reference.md)
- [故障排查](../troubleshooting/common-issues.md)

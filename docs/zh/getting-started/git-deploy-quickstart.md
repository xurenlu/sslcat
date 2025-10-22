# Git 部署快速开始指南

## 前提条件

1. SSLcat 服务器正常运行
2. 有 SSH 访问权限
3. 已安装 Git 客户端

## 步骤 1: 设置 Git 用户

在服务器上创建 git 用户（如果还不存在）：

```bash
sudo useradd -r -s /bin/bash -m -d /home/git git
```

## 步骤 2: 启动 SSLcat

SSLcat 会自动配置 SSH 环境：

```bash
./sslcat
```

首次启动时，SSLcat 会：
- 创建 `/home/git/.ssh` 目录
- 生成 `authorized_keys` 文件
- 配置 SSHD 以使用 git-shell
- 创建 git-shell-commands 目录

## 步骤 3: 添加 SSH 公钥

### 方法 1: 通过 Web UI

1. 访问 `https://your-domain/admin/git-server`
2. 点击 "SSH 密钥" 标签
3. 添加你的 SSH 公钥

### 方法 2: 通过 API

```bash
# 获取你的公钥
cat ~/.ssh/id_rsa.pub

# 添加到 SSLcat
curl -X POST http://localhost:8080/admin/api/git-server/ssh-key/add \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "name": "my-laptop",
    "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB..."
  }'
```

## 步骤 4: 准备你的项目

确保你的项目包含以下文件之一：

**Node.js 项目**:
```json
// package.json
{
  "name": "myapp",
  "version": "1.0.0",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.18.0"
  }
}
```

**Python 项目**:
```python
# requirements.txt
flask==2.0.0
gunicorn==20.1.0

# app.py
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello from SSLcat!'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
```

**Go 项目**:
```go
// main.go
package main

import (
    "fmt"
    "net/http"
)

func main() {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Hello from SSLcat!")
    })
    http.ListenAndServe(":8000", nil)
}
```

**静态网站**:
```html
<!-- index.html -->
<!DOCTYPE html>
<html>
<head>
    <title>My Static Site</title>
</head>
<body>
    <h1>Hello from SSLcat!</h1>
</body>
</html>
```

## 步骤 5: Git 推送部署

```bash
# 在项目目录中
cd /path/to/your/project

# 初始化 Git 仓库（如果还没有）
git init
git add .
git commit -m "Initial commit"

# 添加 SSLcat 远程仓库
git remote add sslcat ssh://git@your-server/myapp

# 推送并部署
git push sslcat main
```

## 推送过程

当你执行 `git push` 时，会发生以下过程：

```
[你的电脑]
    |
    | git push
    v
[SSH 连接] -> git@your-server
    |
    | 验证 SSH 密钥
    v
[Pre-receive 钩子]
    |
    | 检查推送大小
    | 验证权限
    v
[Update 钩子]
    |
    | 记录分支更新
    v
[接收对象]
    |
    | 解包对象
    v
[Post-receive 钩子]
    |
    | 更新工作目录
    | 检测应用类型
    | 触发构建
    v
[构建和部署]
    |
    | Node.js: npm install && npm start
    | Python: pip install && python app.py
    | Go: go build && ./app
    | Static: 复制文件到 web 目录
    v
[应用运行]
```

## 步骤 6: 查看部署状态

### 方法 1: 通过 Web UI

访问 `https://your-domain/admin/git-server`

### 方法 2: 通过 API

```bash
# 查看应用列表
curl http://localhost:8080/admin/api/git-server/apps

# 查看应用详情
curl http://localhost:8080/admin/api/git-server/app?name=myapp

# 查看推送历史
curl http://localhost:8080/admin/api/git-server/push-history?app=myapp&limit=10
```

## 步骤 7: 访问你的应用

应用部署成功后，可以通过分配的域名访问：

```
http://myapp.your-domain.com:8001
```

或者通过配置的端口直接访问：

```
http://your-server-ip:8001
```

## 高级配置

### 设置环境变量

```bash
curl -X POST http://localhost:8080/admin/api/git-server/app/env?name=myapp \
  -H "Content-Type: application/json" \
  -d '{
    "env_vars": {
      "NODE_ENV": "production",
      "DATABASE_URL": "postgresql://...",
      "SECRET_KEY": "your-secret-key"
    }
  }'
```

### 绑定 SSH 密钥到特定应用

限制只有特定密钥可以推送到应用：

```bash
curl -X POST http://localhost:8080/admin/api/git-server/app/bind-key \
  -H "Content-Type: application/json" \
  -d '{
    "app_name": "myapp",
    "key_fingerprint": "AAAAB3NzaC1yc2EAAAADAQABAAAB"
  }'
```

### 自定义域名和端口

```bash
curl -X POST http://localhost:8080/admin/api/git-server/app/routing?name=myapp \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "myapp.example.com",
    "port": 8080
  }'
```

## 常见问题

### Q: 推送失败，提示 "Permission denied"

**A**: 检查 SSH 密钥是否正确添加到 SSLcat：

```bash
# 测试 SSH 连接
ssh -T git@your-server

# 应该看到类似输出：
# Interactive shell disabled.
```

### Q: 推送成功但应用未启动

**A**: 查看部署日志：

```bash
# 查看应用日志
curl http://localhost:8080/admin/api/git-server/logs?app=myapp&lines=100

# 或者直接在服务器上查看
tail -f /data/repos/myapp/logs/deploy-$(date +%Y-%m-%d).log
```

### Q: 如何更新已部署的应用？

**A**: 直接推送新的提交：

```bash
git add .
git commit -m "Update feature"
git push sslcat main
```

### Q: 推送大小超过限制怎么办？

**A**: 默认限制是 100MB。你可以：

1. 清理大文件
2. 使用 Git LFS
3. 修改 pre-receive 钩子中的 `MAX_SIZE` 变量

### Q: 如何回滚到之前的版本？

**A**: 目前需要手动回滚：

```bash
# 回滚到之前的提交
git reset --hard HEAD~1
git push -f sslcat main
```

## 示例项目

### Node.js + Express

```javascript
// server.js
const express = require('express');
const app = express();
const port = process.env.PORT || 8000;

app.get('/', (req, res) => {
  res.send('Hello from SSLcat!');
});

app.listen(port, '0.0.0.0', () => {
  console.log(`App listening on port ${port}`);
});
```

```json
// package.json
{
  "name": "myapp",
  "version": "1.0.0",
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.18.0"
  }
}
```

### Python + Flask

```python
# app.py
from flask import Flask
import os

app = Flask(__name__)
port = int(os.environ.get('PORT', 8000))

@app.route('/')
def hello():
    return 'Hello from SSLcat!'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port)
```

```
# requirements.txt
flask==2.0.0
```

## 下一步

- 阅读完整文档: `docs/git-deploy-ssh-implementation.md`
- 配置自动域名: 设置 DNS 解析
- 启用 SSL: 使用 Let's Encrypt 自动证书
- 设置监控: 配置健康检查和告警

## 支持

如有问题，请：

1. 查看日志文件
2. 检查 GitHub Issues
3. 联系技术支持

---

**祝你部署愉快！🚀**


# 部署 v1.3.5-rc24 指南

## 版本亮点 🎉

**Dokku 风格 Git 部署** - 现在可以直接 `git push` 自动创建应用了！

## 快速部署

### 步骤 1：更新 SSLcat 服务

```bash
# SSH 到服务器
ssh whatq.wxside.com

# 进入 SSLcat 目录
cd /opt/sslcat

# 拉取最新代码
git fetch origin
git checkout v1.3.5-rc24

# 编译
go build -o sslcat-new main.go

# 停止服务
sudo systemctl stop sslcat

# 替换二进制文件
sudo mv sslcat-new sslcat
sudo chmod +x sslcat

# 启动服务
sudo systemctl start sslcat

# 查看日志确认启动成功
sudo journalctl -u sslcat -f
```

### 步骤 2：安装 Git Hook Wrapper

```bash
# 在 SSLcat 目录下执行
cd /opt/sslcat
sudo ./scripts/install-git-hook.sh
```

**预期输出**:
```
==========================================
安装 SSLcat Git Hook Wrapper
==========================================

📋 复制 sslcat-git-hook 到 /usr/local/bin/sslcat-git-hook...
✅ sslcat-git-hook 已安装到: /usr/local/bin/sslcat-git-hook

...

✅ 安装成功！
现在可以添加 SSH 密钥了，新密钥将自动使用 Dokku 风格。
git push 时会自动创建不存在的应用！
```

### 步骤 3：删除旧应用并测试

```bash
# 删除之前创建失败的应用
curl -X DELETE "http://localhost:9942/sslcat-panel2/api/git-server/app/delete?name=p"

# 添加 SSH 密钥（如果还没有）
curl -X POST http://localhost:9942/sslcat-panel2/api/git-server/ssh-key/add \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-laptop",
    "public_key": "'"$(cat ~/.ssh/id_rsa.pub)"'"
  }'

# 查看密钥（应该看到 Dokku 风格格式）
curl http://localhost:9942/sslcat-panel2/api/git-server/ssh-keys
```

### 步骤 4：测试自动创建

在本地执行：

```bash
# 创建测试项目
mkdir test-auto-create
cd test-auto-create
git init

# 创建一个简单的 HTML 文件
echo "<h1>Hello SSLcat Auto-Deploy!</h1>" > index.html
git add .
git commit -m "Initial commit"

# 添加远程仓库（注意：不需要预先创建！）
git remote add sslcat git@whatq.wxside.com:test-auto.git

# 直接推送（应用会自动创建）
git push sslcat main
```

**预期输出**:
```
Enumerating objects: 3, done.
Counting objects: 100% (3/3), done.
Writing objects: 100% (3/3), 245 bytes, done.
Total 3 (delta 0), reused 0 (delta 0)
remote: [sslcat-git-hook] SSH_ORIGINAL_COMMAND: git-receive-pack 'test-auto.git'
remote: [sslcat-git-hook] KEY_NAME: my-laptop
remote: [sslcat-git-hook] Parsed command: git-receive-pack, app: test-auto
remote: [sslcat-git-hook] 应用 'test-auto' 不存在，正在自动创建...
remote: [sslcat-git-hook] ✓ 应用 'test-auto' 创建成功
remote: [sslcat-git-hook] ✓ 验证通过，应用已就绪
remote: [sslcat-git-hook] 应用 'test-auto' 已存在
remote: [sslcat-git-hook] 执行: git-receive-pack '/opt/sslcat/data/runners/git/test-auto/git/repo.git'
remote: 
remote: ╔═══════════════════════════════════════════════════════════════╗
remote: ║                    SSLcat Git Deploy                          ║
remote: ╚═══════════════════════════════════════════════════════════════╝
remote: 
remote: Application: test-auto
remote: Commit:      a3f2c1b - Initial commit
remote: ...部署日志...
To whatq.wxside.com:test-auto.git
 * [new branch]      main -> main
```

## 验证部署

### 检查应用列表

```bash
curl http://localhost:9942/sslcat-panel2/api/git-server/apps | jq
```

应该看到 `test-auto` 应用已创建。

### 检查 authorized_keys 格式

```bash
sudo cat /home/git/.ssh/authorized_keys
```

应该看到类似：
```
# my-laptop
command="/usr/local/bin/sslcat-git-hook my-laptop",no-agent-forwarding,no-user-rc,no-X11-forwarding,no-port-forwarding ssh-rsa AAAAB3NzaC1yc2E...
```

### 访问应用

```bash
# 如果配置了域名
curl https://test-auto.wxside.com

# 或者通过端口访问
curl http://whatq.wxside.com:8000  # 端口根据实际分配
```

## 故障排查

### 问题 1：wrapper 脚本找不到

**症状**:
```
bash: /usr/local/bin/sslcat-git-hook: No such file or directory
```

**解决**:
```bash
sudo ./scripts/install-git-hook.sh
```

### 问题 2：API 调用失败

**症状**:
```
remote: [sslcat-git-hook] ERROR: 创建应用失败
```

**检查**:
```bash
# 确认 SSLcat 服务运行
sudo systemctl status sslcat

# 测试 API
curl http://localhost:9942/sslcat-panel2/api/git-server/apps
```

### 问题 3：权限问题

**症状**:
```
remote: [sslcat-git-hook] ERROR: 仓库路径不存在
```

**解决**:
```bash
# 检查目录权限
ls -la /opt/sslcat/data/runners/git/

# 修复权限
sudo chown -R git:git /opt/sslcat/data/runners/git/
```

### 问题 4：查看详细日志

```bash
# SSLcat 服务日志
sudo journalctl -u sslcat -f

# SSH 认证日志
sudo tail -f /var/log/auth.log  # Debian/Ubuntu
sudo tail -f /var/log/secure    # CentOS/RHEL

# 启用 wrapper 调试
sudo nano /usr/local/bin/sslcat-git-hook
# 在开头添加: set -x
```

## 回滚方案

如果遇到问题需要回滚：

```bash
cd /opt/sslcat
git checkout v1.3.5-rc23  # 或其他稳定版本
go build -o sslcat-new main.go
sudo systemctl stop sslcat
sudo mv sslcat-new sslcat
sudo systemctl start sslcat
```

## 新功能使用

### 场景 1：快速部署新项目

```bash
git remote add deploy git@server:my-awesome-app.git
git push deploy main
# ✅ 应用自动创建并部署
```

### 场景 2：团队协作

```bash
# 团队成员 A 创建项目
git push deploy project-x.git main

# 团队成员 B 直接克隆和推送
git clone git@server:project-x.git
cd project-x
# 做修改...
git push
```

### 场景 3：CI/CD 集成

```yaml
# .github/workflows/deploy.yml
- name: Deploy to SSLcat
  run: |
    git remote add sslcat git@server:${{ github.event.repository.name }}.git
    git push sslcat main
```

## 与旧版本对比

| 功能 | v1.3.5-rc23 及之前 | v1.3.5-rc24 |
|------|-------------------|-------------|
| 创建应用 | 需要先通过 API/Web | ✅ git push 自动创建 |
| SSH 密钥格式 | 标准格式 | Dokku 风格（command=） |
| 安全限制 | 基础 | ✅ 完整的 SSH 限制选项 |
| 兼容性 | - | ✅ 向后兼容旧密钥 |

## 相关文档

- 📖 [Dokku 风格完整文档](DOKKU_STYLE_GIT_DEPLOY.md)
- 📖 [Git Deploy 快速入门](docs/git-deploy-quickstart.md)
- 📖 [故障排查指南](docs/troubleshooting.md)

## 反馈

如有问题或建议，请：
- 提交 GitHub Issue
- 或联系管理员

---

**部署成功后，享受 Dokku 风格的丝滑体验！** 🚀


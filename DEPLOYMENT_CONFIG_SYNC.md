# 部署配置文件同步说明

## 问题背景

在部署 SSLcat 到远程服务器时，如果远程服务器上的 `/etc/sslcat/sslcat.conf` 配置文件比本地的新，直接部署会导致线上的新配置被本地旧配置覆盖，造成配置丢失。

## 解决方案

### 1. 配置文件智能检查

现在所有部署脚本都会在部署前：

1. **检查远程配置文件是否存在**
2. **对比本地和远程配置的 MD5 值**
3. **比较配置文件的修改时间**

### 2. 交互式选择

当发现本地和远程配置不一致时，部署脚本会提供以下选项：

```
请选择操作：
  1) 使用本地配置覆盖远程（会备份远程配置）
  2) 保持远程配置不变，仅更新二进制文件
  3) 先查看差异后决定
  4) 用远程配置覆盖本地，然后继续部署
  5) 取消部署
```

### 3. 服务器端智能处理

在服务器端，`deploy-commands.sh` 脚本会：

- **配置相同**：跳过更新，节省时间
- **本地较新**：备份远程配置后更新
- **远程较新**：
  - 保留远程配置不变
  - 将本地配置保存为 `/etc/sslcat/sslcat.conf.local-upload.TIMESTAMP`
  - 提示用户手动合并配置

## 涉及的文件

### 通用脚本

- `scripts/deploy-config-check.sh` - 通用配置检查函数

### 部署脚本（已更新）

1. `deploy-to-shifen.sh` + `deploy-shifen/deploy-commands.sh`
2. `deploy-to-whatq.sh` + `deploy-whatq/deploy-commands.sh`
3. `deploy-to-s2.sh`（内嵌生成 deploy-commands.sh）

## 使用示例

### 场景 1：配置一致

```bash
$ ./deploy-to-shifen.sh
🔍 检查远程配置文件...
📥 发现远程配置文件，拉取进行对比...
✅ 本地配置与远程配置一致
```

### 场景 2：本地配置较新

```bash
$ ./deploy-to-shifen.sh
🔍 检查远程配置文件...
📥 发现远程配置文件，拉取进行对比...

⚠️  警告：本地配置与远程配置不一致！
   本地配置: deploy-shifen/sslcat.conf (MD5: abc123...)
   远程配置: /etc/sslcat/sslcat.conf (MD5: def456...)
   
   远程配置已保存到: /tmp/sslcat-deploy-check/sslcat.conf.remote

请选择操作：
  1) 使用本地配置覆盖远程（会备份远程配置）
  2) 保持远程配置不变，仅更新二进制文件
  3) 先查看差异后决定
  4) 用远程配置覆盖本地，然后继续部署
  5) 取消部署

请输入选项 [1-5]: 3

========== 配置文件差异 ==========
--- /tmp/sslcat-deploy-check/sslcat.conf.remote
+++ deploy-shifen/sslcat.conf
@@ -10,7 +10,7 @@
-  "http_port": 80,
+  "http_port": 8080,
=================================

查看差异后，是否继续部署？(使用本地配置) [y/N]: y
```

### 场景 3：远程配置较新（服务器端检测）

在服务器端执行部署时：

```bash
📝 配置文件...
⚠️  配置文件已存在，检查更新...
⚠️  警告：线上配置文件比本地新！
   线上修改时间: 2025-10-09 15:30:00
   本地修改时间: 2025-10-08 10:20:00

   已将本地配置保存到: /etc/sslcat/sslcat.conf.local-upload.20251009_153045
   线上配置保持不变，请手动合并配置文件
⏭️  跳过配置文件覆盖
```

## 配置合并指南

当远程配置较新时，需要手动合并：

```bash
# 1. SSH 到服务器
ssh user@server

# 2. 查看线上配置（当前使用的）
sudo cat /etc/sslcat/sslcat.conf

# 3. 查看本地上传的配置
sudo cat /etc/sslcat/sslcat.conf.local-upload.TIMESTAMP

# 4. 使用 diff 对比
sudo diff /etc/sslcat/sslcat.conf /etc/sslcat/sslcat.conf.local-upload.TIMESTAMP

# 5. 手动编辑合并
sudo nano /etc/sslcat/sslcat.conf

# 6. 重启服务使配置生效
sudo systemctl restart sslcat

# 7. 将合并后的配置拉取到本地
exit
scp user@server:/etc/sslcat/sslcat.conf deploy-shifen/sslcat.conf
```

## 备份文件说明

### 客户端备份

- `/tmp/sslcat-deploy-check/sslcat.conf.remote` - 临时拉取的远程配置（用于对比）

### 服务器端备份

- `/etc/sslcat/sslcat.conf.backup.TIMESTAMP` - 被覆盖前的旧配置备份
- `/etc/sslcat/sslcat.conf.local-upload.TIMESTAMP` - 从本地上传但未应用的配置

## 最佳实践

1. **部署前先拉取远程配置**：确保本地配置是最新的
   ```bash
   scp user@server:/etc/sslcat/sslcat.conf deploy-shifen/sslcat.conf
   ```

2. **使用版本控制**：将配置文件纳入 Git 管理，但注意敏感信息

3. **配置模板化**：对于不同服务器，使用配置模板 + 环境变量

4. **定期同步**：建立定期同步机制，避免配置偏移

5. **文档记录**：记录每次配置变更的原因和时间

## 技术细节

### MD5 计算

支持 Linux 和 macOS 两种命令：

```bash
# Linux
md5sum /etc/sslcat/sslcat.conf | awk '{print $1}'

# macOS
md5 -q /etc/sslcat/sslcat.conf
```

### 文件时间戳

使用 `stat` 命令获取修改时间：

```bash
# Linux
stat -c %Y /etc/sslcat/sslcat.conf

# macOS
stat -f %m /etc/sslcat/sslcat.conf
```

### 日期格式化

```bash
# Linux
date -d @TIMESTAMP

# macOS
date -r TIMESTAMP
```

## 故障排除

### 问题：无法连接到服务器

```bash
# 检查 SSH 连接
ssh user@server echo "Connection OK"
```

### 问题：权限不足

```bash
# 确保有 sudo 权限
sudo -v
```

### 问题：配置文件对比失败

```bash
# 手动拉取对比
scp user@server:/etc/sslcat/sslcat.conf /tmp/remote-config.conf
diff /tmp/remote-config.conf deploy-shifen/sslcat.conf
```

## 未来改进

1. **配置合并工具**：自动化配置合并过程
2. **配置版本管理**：在服务器端保存配置历史
3. **配置验证**：部署前验证配置文件的合法性
4. **回滚机制**：快速回滚到上一个可用配置

## 相关文档

- [部署指南](DEPLOYMENT.md)
- [配置文件说明](CONFIG_FILES.md)
- [Git 部署](DOKKU_STYLE_GIT_DEPLOY.md)


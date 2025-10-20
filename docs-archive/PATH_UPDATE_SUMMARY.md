# 配置示例文件路径更新总结

## 更新日期
2025-10-07

## 更新内容
已将所有配置示例文件（`*.conf.example`）中的相对路径改为绝对路径。

## 基础路径
`/Users/rocky/Sites/sslcat/`

## 已更新的文件

### 1. sslcat-advanced.conf.example ✅
**更新的路径：**
- `cert_dir`: `./data/ssl/certs` → `/Users/rocky/Sites/sslcat/data/ssl/certs`
- `key_dir`: `./data/ssl/keys` → `/Users/rocky/Sites/sslcat/data/ssl/keys`
- `block_file`: `./data/withssl.block` → `/Users/rocky/Sites/sslcat/data/withssl.block`
- `access_log.path`: `./logs/access.log` → `/Users/rocky/Sites/sslcat/logs/access.log`

### 2. sslcat-enterprise.conf.example ✅
**更新的路径：**
- `access_log_path`: `./data/access.log` → `/Users/rocky/Sites/sslcat/data/access.log`
- `cert_dir`: `./data/certs` → `/Users/rocky/Sites/sslcat/data/certs`
- `key_dir`: `./data/keys` → `/Users/rocky/Sites/sslcat/data/keys`
- `password_file`: `./data/admin.pass` → `/Users/rocky/Sites/sslcat/data/admin.pass`
- `cache_dir`: `./data/cache` → `/Users/rocky/Sites/sslcat/data/cache`
- `repos_dir`: `./data/repos` → `/Users/rocky/Sites/sslcat/data/repos`

### 3. sslcat-runners.conf.example ✅
**更新的路径：**
- `access_log_path`: `./data/access.log` → `/Users/rocky/Sites/sslcat/data/access.log`
- `cert_dir`: `./data/certs` → `/Users/rocky/Sites/sslcat/data/certs`
- `key_dir`: `./data/keys` → `/Users/rocky/Sites/sslcat/data/keys`
- `password_file`: `./data/admin.pass` → `/Users/rocky/Sites/sslcat/data/admin.pass`
- `totp_secret_file`: `./data/admin.totp` → `/Users/rocky/Sites/sslcat/data/admin.totp`
- `block_file`: `./data/sslcat.block` → `/Users/rocky/Sites/sslcat/data/sslcat.block`
- `cache_dir`: `./data/cache/static` → `/Users/rocky/Sites/sslcat/data/cache/static`
- `runners.local.work_dir`: `./data/runners/local` → `/Users/rocky/Sites/sslcat/data/runners/local`
- `runners.docker.work_dir`: `./data/runners/docker` → `/Users/rocky/Sites/sslcat/data/runners/docker`
- `runners.git.repos_dir`: `./data/runners/git` → `/Users/rocky/Sites/sslcat/data/runners/git`

### 4. sslcat-session-storage.conf.example ✅
**更新的路径：**
- `session.data_dir`: `./data` → `/Users/rocky/Sites/sslcat/data`
- `password_file`: `./data/admin.pass` → `/Users/rocky/Sites/sslcat/data/admin.pass`

### 5. sslcat-loadbalancer.conf.example ✅
**更新的路径：**
- `access_log_path`: `./data/access.log` → `/Users/rocky/Sites/sslcat/data/access.log`
- `cert_dir`: `./data/certs` → `/Users/rocky/Sites/sslcat/data/certs`
- `key_dir`: `./data/keys` → `/Users/rocky/Sites/sslcat/data/keys`
- `password_file`: `./data/admin.pass` → `/Users/rocky/Sites/sslcat/data/admin.pass`

### 6. sslcat-compression.conf.example ✅
**更新的路径：**
- `cert_dir`: `./data/certs` → `/Users/rocky/Sites/sslcat/data/certs`
- `key_dir`: `./data/keys` → `/Users/rocky/Sites/sslcat/data/keys`
- `password_file`: `./data/admin.pass` → `/Users/rocky/Sites/sslcat/data/admin.pass`

### 7. sslcat.conf.example ℹ️
**说明：** 此文件已使用绝对路径（`/opt/sslcat/`），无需修改。这是生产环境的标准路径。

## 路径映射表

| 相对路径 | 绝对路径 |
|---------|---------|
| `./data/` | `/Users/rocky/Sites/sslcat/data/` |
| `./data/access.log` | `/Users/rocky/Sites/sslcat/data/access.log` |
| `./data/certs` | `/Users/rocky/Sites/sslcat/data/certs` |
| `./data/keys` | `/Users/rocky/Sites/sslcat/data/keys` |
| `./data/admin.pass` | `/Users/rocky/Sites/sslcat/data/admin.pass` |
| `./data/admin.totp` | `/Users/rocky/Sites/sslcat/data/admin.totp` |
| `./data/sslcat.block` | `/Users/rocky/Sites/sslcat/data/sslcat.block` |
| `./data/withssl.block` | `/Users/rocky/Sites/sslcat/data/withssl.block` |
| `./data/cache` | `/Users/rocky/Sites/sslcat/data/cache` |
| `./data/cache/static` | `/Users/rocky/Sites/sslcat/data/cache/static` |
| `./data/repos` | `/Users/rocky/Sites/sslcat/data/repos` |
| `./data/runners/local` | `/Users/rocky/Sites/sslcat/data/runners/local` |
| `./data/runners/docker` | `/Users/rocky/Sites/sslcat/data/runners/docker` |
| `./data/runners/git` | `/Users/rocky/Sites/sslcat/data/runners/git` |
| `./data/ssl/certs` | `/Users/rocky/Sites/sslcat/data/ssl/certs` |
| `./data/ssl/keys` | `/Users/rocky/Sites/sslcat/data/ssl/keys` |
| `./logs/access.log` | `/Users/rocky/Sites/sslcat/logs/access.log` |

## 为什么使用绝对路径？

### 优点：
1. **明确性** - 不依赖于工作目录，路径始终指向相同位置
2. **可靠性** - 避免因工作目录变化导致的路径错误
3. **调试便利** - 更容易排查文件路径问题
4. **systemd 兼容** - 服务管理器不依赖工作目录设置

### 注意事项：
- 如果在不同机器上部署，需要根据实际安装路径修改这些绝对路径
- 或者使用环境变量来动态设置基础路径
- 生产环境建议使用标准路径如 `/opt/sslcat/`、`/etc/sslcat/` 等

## 使用示例

### 本地开发
```bash
cd /Users/rocky/Sites/sslcat
./sslcat -config=sslcat-runners.conf.example
```

### 生产部署
如果部署到其他服务器，需要修改配置文件中的路径：
```bash
# 方法 1: 使用 sed 批量替换
sed -i 's|/Users/rocky/Sites/sslcat|/opt/sslcat|g' sslcat.conf

# 方法 2: 手动编辑配置文件
vim sslcat.conf
```

## 验证

可以使用以下命令验证配置文件中的路径：
```bash
# 检查所有绝对路径
grep -r "/Users/rocky/Sites/sslcat" *.conf.example

# 检查是否还有相对路径
grep -r '\./data' *.conf.example
```

---

**更新完成时间**: 2025-10-07 14:15
**更新人员**: AI Assistant
**状态**: ✅ 完成




# WordPress 模板

WordPress 是世界上最流行的内容管理系统（CMS），支持博客、网站和在线商店。

## 功能特性

- ✅ 完整的 WordPress 安装
- ✅ MySQL 数据库（持久化存储）
- ✅ 可选 Redis 缓存支持
- ✅ 自动数据持久化（重启不丢失）
- ✅ 健康检查支持

## 默认凭证

部署后，系统会自动生成以下凭证：

- **数据库用户名**: `{app_name}_wp`
- **数据库密码**: 自动生成（18位随机密码）
- **数据库名**: `{app_name}_wp`
- **Root 密码**: 自动生成（20位随机密码）

## 首次访问

1. 访问 `http://{{PRIMARY_DOMAIN}}/wp-admin/install.php`
2. 按照安装向导完成 WordPress 配置
3. 设置管理员用户名和密码

## 数据持久化

所有数据存储在 Docker volumes 中：

- `wordpress_data`: WordPress 核心文件和配置（包括 wp-config.php）
- `wordpress_uploads`: 上传的文件和媒体
- `mysql_data`: MySQL 数据库文件

**重要**: 即使容器重启，所有数据（包括 wp-config.php）都会保留。

## 环境变量

- `WORDPRESS_DB_HOST`: MySQL 服务地址（自动设置）
- `WORDPRESS_DB_USER`: 数据库用户名（自动生成）
- `WORDPRESS_DB_PASSWORD`: 数据库密码（自动生成）
- `WORDPRESS_DB_NAME`: 数据库名（自动生成）

## 管理命令

```bash
# 查看日志
docker-compose -f docker-compose.yml -p sslcat-{app_name} logs -f

# 重启服务
docker-compose -f docker-compose.yml -p sslcat-{app_name} restart

# 停止服务
docker-compose -f docker-compose.yml -p sslcat-{app_name} stop
```

## 注意事项

1. 首次部署需要等待 MySQL 完全启动（约 30-60 秒）
2. WordPress 安装完成后，建议立即修改默认管理员密码
3. 如需启用 Redis 缓存，请在部署时选择"启用 Redis 缓存"选项


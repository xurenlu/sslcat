# ERPNext 模板

开源 ERP 系统，基于 Frappe 框架，功能完整，适合中小企业。

## 功能特性

- ✅ Web 应用服务
- ✅ 数据库服务
- ✅ 缓存服务
- ✅ 缓存服务
- ✅ 健康检查支持
- ✅ 数据持久化存储
- ✅ 多服务架构

## 默认凭证

部署后，系统会自动生成以下凭证：

- **mariadb 用户名**: {app_name}_erpnext
- **mariadb 密码**: 自动生成（18位随机密码）
- **mariadb 数据库名**: {app_name}_erpnext
- **mariadb Root 密码**: 自动生成（20位随机密码）

## 连接信息

- **主机**: `mariadb` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `3306`

## 首次访问

1. 访问 `http://{{PRIMARY_DOMAIN}}`
2. 按照安装向导完成配置
3. 使用系统生成的凭证登录

## 数据持久化

所有数据存储在 Docker volumes 中：

- `erpnext_sites`: erpnext 数据存储
- `erpnext_logs`: erpnext 数据存储
- `mariadb_data`: mariadb 数据存储
- `redis_cache_data`: redis-cache 数据文件
- `redis_queue_data`: redis-queue 数据文件
- `redis_socketio_data`: redis-socketio 数据文件

**重要**: 即使容器重启，所有数据都会保留。

## 环境变量

重要的环境变量（系统自动设置）：


## 管理命令

```bash
# 查看日志
docker-compose -f docker-compose.yml -p sslcat-{app_name} logs -f

# 重启服务
docker-compose -f docker-compose.yml -p sslcat-{app_name} restart

# 停止服务
docker-compose -f docker-compose.yml -p sslcat-{app_name} stop

# 启动服务
docker-compose -f docker-compose.yml -p sslcat-{app_name} up -d
```

## 注意事项

1. 更多信息请访问：https://erpnext.com/


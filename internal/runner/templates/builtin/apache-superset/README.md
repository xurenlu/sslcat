# Apache Superset (商业智能) 模板

现代化的商业智能（BI）平台，支持数据可视化、SQL查询、报表生成、数据探索等功能。

## 功能特性

- ✅ Web 应用服务
- ✅ 数据库服务
- ✅ 缓存服务
- ✅ 健康检查支持
- ✅ 数据持久化存储
- ✅ 多服务架构

## 默认凭证

部署后，系统会自动生成以下凭证：

- **postgres 用户名**: {app_name}_superset
- **postgres 密码**: 自动生成（18位随机密码）
- **postgres 数据库名**: {app_name}_superset
- **redis 密码**: 自动生成（16位随机密码）
- **superset Secret Key**: 自动生成（64位随机密钥）

## 连接信息

- **主机**: `postgres` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `5432`

## 首次访问

1. 访问 `http://{{PRIMARY_DOMAIN}}`
2. 按照安装向导完成配置
3. 使用系统生成的凭证登录

## 数据持久化

所有数据存储在 Docker volumes 中：

- `superset_data`: superset 数据存储
- `postgres_data`: postgres 数据文件
- `redis_data`: redis 数据文件

**重要**: 即使容器重启，所有数据都会保留。

## 环境变量

重要的环境变量（系统自动设置）：

- `DATABASE_URL`: 数据库连接字符串（自动生成）
- `REDIS_URL / REDIS_HOST`: Redis 连接信息（自动生成）

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

1. 更多信息请访问：https://superset.apache.org/


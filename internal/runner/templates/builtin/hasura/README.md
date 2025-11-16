# Hasura (GraphQL引擎) 模板

即时 GraphQL API 引擎，自动从 PostgreSQL 数据库生成 GraphQL API，支持实时订阅。

## 功能特性

- ✅ 数据库服务
- ✅ 健康检查支持
- ✅ 数据持久化存储
- ✅ 多服务架构

## 默认凭证

部署后，系统会自动生成以下凭证：

- **postgres 用户名**: {app_name}_hasura
- **postgres 密码**: 自动生成（18位随机密码）
- **postgres 数据库名**: {app_name}_hasura

## 连接信息

- **主机**: `postgres` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `5432`

## 数据持久化

所有数据存储在 Docker volumes 中：

- `hasura_data`: hasura 数据文件
- `postgres_data`: postgres 数据文件

**重要**: 即使容器重启，所有数据都会保留。

## 环境变量

重要的环境变量（系统自动设置）：

- `DATABASE_URL`: 数据库连接字符串（自动生成）

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

1. 更多信息请访问：https://hasura.io/


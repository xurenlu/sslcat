# PostgreSQL 模板

PostgreSQL 15 开源关系型数据库，支持 JSON、全文搜索、地理空间数据等高级特性。

## 功能特性

- ✅ PostgreSQL 15 数据库
- ✅ 数据持久化存储
- ✅ UTF8 编码支持
- ✅ 健康检查支持

## 默认凭证

部署后，系统会自动生成以下凭证：

- **数据库用户名**: `{app_name}_user`
- **数据库密码**: 自动生成（20位随机密码）
- **数据库名**: `{app_name}_db`

## 连接信息

- **主机**: `postgres` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `5432`
- **编码**: `UTF8`

## 数据持久化

所有数据存储在 Docker volume `postgres_data` 中，即使容器重启，数据也会保留。

## 管理命令

```bash
# 查看日志
docker-compose -f docker-compose.yml -p sslcat-{app_name} logs -f postgres

# 进入 PostgreSQL 命令行
docker-compose -f docker-compose.yml -p sslcat-{app_name} exec postgres psql -U {username} -d {database_name}

# 备份数据库
docker-compose -f docker-compose.yml -p sslcat-{app_name} exec postgres pg_dump -U {username} {database_name} > backup.sql
```


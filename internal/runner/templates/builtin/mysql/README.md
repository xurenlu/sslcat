# MySQL 模板

MySQL 8.0 关系型数据库，支持事务、外键、存储过程等高级特性。

## 功能特性

- ✅ MySQL 8.0 数据库
- ✅ 数据持久化存储
- ✅ UTF8MB4 字符集支持
- ✅ 健康检查支持

## 默认凭证

部署后，系统会自动生成以下凭证：

- **数据库用户名**: `{app_name}_user`
- **数据库密码**: 自动生成（20位随机密码）
- **数据库名**: `{app_name}_db`
- **Root 密码**: 自动生成（24位随机密码）

## 连接信息

- **主机**: `mysql` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `3306`
- **字符集**: `utf8mb4`
- **排序规则**: `utf8mb4_unicode_ci`

## 数据持久化

所有数据存储在 Docker volume `mysql_data` 中，即使容器重启，数据也会保留。

## 管理命令

```bash
# 查看日志
docker-compose -f docker-compose.yml -p sslcat-{app_name} logs -f mysql

# 进入 MySQL 命令行
docker-compose -f docker-compose.yml -p sslcat-{app_name} exec mysql mysql -u root -p

# 备份数据库
docker-compose -f docker-compose.yml -p sslcat-{app_name} exec mysql mysqldump -u root -p {database_name} > backup.sql
```


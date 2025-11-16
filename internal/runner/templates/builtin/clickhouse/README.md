# ClickHouse 模板

高性能列式数据库，专为 OLAP 分析场景设计，查询速度极快。

## 功能特性

- ✅ 数据库服务
- ✅ 健康检查支持
- ✅ 数据持久化存储

## 默认凭证

部署后，系统会自动生成以下凭证：

- **clickhouse 用户名**: default
- **clickhouse 密码**: 自动生成（18位随机密码）
- **clickhouse 数据库名**: {app_name}_db

## 连接信息

- **主机**: `clickhouse` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `8123`

## 数据持久化

所有数据存储在 Docker volumes 中：

- `clickhouse_data`: clickhouse 数据存储
- `clickhouse_logs`: clickhouse 数据存储

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

1. 首次部署需要等待数据库完全启动（约 30-60 秒）
2. 更多信息请访问：https://clickhouse.com/


# Loki 模板

日志聚合系统，类似 Prometheus，专为日志设计。

## 功能特性

- ✅ 数据库服务
- ✅ 健康检查支持
- ✅ 数据持久化存储

## 连接信息

- **主机**: `loki` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `3100`

## 数据持久化

所有数据存储在 Docker volumes 中：

- `loki_data`: loki 数据存储

**重要**: 即使容器重启，所有数据都会保留。

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

1. 更多信息请访问：https://grafana.com/oss/loki/


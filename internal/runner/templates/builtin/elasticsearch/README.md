# Elasticsearch 模板

强大的搜索引擎和数据分析平台，支持全文搜索、日志分析等。

## 功能特性

- ✅ 数据库服务
- ✅ 健康检查支持
- ✅ 数据持久化存储

## 连接信息

- **主机**: `elasticsearch` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `9200`

## 数据持久化

所有数据存储在 Docker volumes 中：

- `elasticsearch_data`: elasticsearch 数据文件

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
2. 更多信息请访问：https://www.elastic.co/elasticsearch/


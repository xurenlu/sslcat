# Meilisearch 模板

快速、易用的搜索引擎，支持即时搜索、拼写纠错等功能。

## 功能特性

- ✅ 数据库服务
- ✅ 健康检查支持
- ✅ 数据持久化存储

## 默认凭证

部署后，系统会自动生成以下凭证：


## 连接信息

- **主机**: `meilisearch` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `7700`

## 数据持久化

所有数据存储在 Docker volumes 中：

- `meilisearch_data`: meilisearch 数据文件

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
2. 更多信息请访问：https://www.meilisearch.com/


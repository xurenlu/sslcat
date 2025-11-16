# Milvus (向量数据库) 模板

开源向量数据库，专为 AI 应用设计，支持大规模向量相似度搜索。

## 功能特性

- ✅ 数据库服务
- ✅ 数据库服务
- ✅ 健康检查支持
- ✅ 数据持久化存储
- ✅ 多服务架构

## 默认凭证

部署后，系统会自动生成以下凭证：

- **minio Root 密码**: 自动生成（18位随机密码）

## 连接信息

- **主机**: `milvus` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `19530`
- **主机**: `etcd` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `2379`

## 数据持久化

所有数据存储在 Docker volumes 中：

- `milvus_data`: milvus 数据存储
- `etcd_data`: etcd 数据存储
- `minio_data`: minio 数据文件

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
2. 更多信息请访问：https://milvus.io/


# MinIO 模板

MinIO 是一个高性能的对象存储服务，兼容 Amazon S3 API，适合存储图片、视频、文档等。

## 功能特性

- ✅ 健康检查支持
- ✅ 数据持久化存储

## 默认凭证

部署后，系统会自动生成以下凭证：

- **minio Root 密码**: 自动生成（24位随机密码）

## 数据持久化

所有数据存储在 Docker volumes 中：

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

1. 更多信息请访问：https://min.io/


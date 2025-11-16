# Paperless-ngx (无纸化办公) 模板

无纸化办公系统，自动 OCR 识别、分类和搜索文档，支持 PDF、图片等多种格式。

## 功能特性

- ✅ Web 应用服务
- ✅ 数据库服务
- ✅ 缓存服务
- ✅ 健康检查支持
- ✅ 数据持久化存储
- ✅ 多服务架构

## 默认凭证

部署后，系统会自动生成以下凭证：

- **postgres 用户名**: {app_name}_paperless
- **postgres 密码**: 自动生成（18位随机密码）
- **postgres 数据库名**: {app_name}_paperless
- **redis 密码**: 自动生成（16位随机密码）
- **paperless-ngx Secret Key**: 自动生成（32位随机密钥）

## 连接信息

- **主机**: `postgres` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `5432`

## 首次访问

1. 访问 `http://{{PRIMARY_DOMAIN}}`
2. 按照安装向导完成配置
3. 使用系统生成的凭证登录

## 数据持久化

所有数据存储在 Docker volumes 中：

- `paperless_ngx_data`: paperless-ngx 数据文件
- `paperless_ngx_media`: paperless-ngx 数据存储
- `paperless_ngx_export`: paperless-ngx 数据存储
- `postgres_data`: postgres 数据文件
- `redis_data`: redis 数据文件

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

1. 更多信息请访问：https://github.com/paperless-ngx/paperless-ngx


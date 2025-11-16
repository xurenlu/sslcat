# Tyk (API网关) 模板

开源 API 网关和 API 管理平台，支持限流、认证、监控等功能。

## 功能特性

- ✅ 缓存服务
- ✅ 数据库服务
- ✅ 健康检查支持
- ✅ 数据持久化存储
- ✅ 多服务架构

## 默认凭证

部署后，系统会自动生成以下凭证：

- **mongo 用户名**: {app_name}_tyk
- **mongo 密码**: 自动生成（18位随机密码）
- **mongo 数据库名**: {app_name}_tyk
- **redis 密码**: 自动生成（16位随机密码）

## 连接信息

- **主机**: `mongo` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `27017`

## 数据持久化

所有数据存储在 Docker volumes 中：

- `tyk_data`: tyk-gateway 数据存储
- `redis_data`: redis 数据文件
- `mongo_data`: mongo 数据文件

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

1. 更多信息请访问：https://tyk.io/


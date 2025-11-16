# Zipkin (分布式追踪) 模板

分布式追踪系统，用于监控和排查微服务架构中的请求流程，Twitter 开源。

## 功能特性

- ✅ Web 应用服务
- ✅ 数据库服务
- ✅ 健康检查支持
- ✅ 数据持久化存储
- ✅ 多服务架构

## 连接信息

- **主机**: `elasticsearch` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `9200`

## 首次访问

1. 访问 `http://{{PRIMARY_DOMAIN}}`
2. 按照安装向导完成配置

## 数据持久化

所有数据存储在 Docker volumes 中：

- `zipkin_data`: zipkin 数据存储
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

1. 更多信息请访问：https://zipkin.io/


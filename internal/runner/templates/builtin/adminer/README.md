# Adminer (数据库管理) 模板

轻量级数据库管理工具，支持 MySQL、PostgreSQL、SQLite、MongoDB 等多种数据库。

## 功能特性

- ✅ Web 应用服务
- ✅ 健康检查支持

## 首次访问

1. 访问 `http://{{PRIMARY_DOMAIN}}`
2. 按照安装向导完成配置

## 数据持久化

数据存储在 Docker volumes 中，即使容器重启，数据也会保留。

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

1. 更多信息请访问：https://www.adminer.org/


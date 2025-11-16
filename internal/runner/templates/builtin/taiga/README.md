# Taiga 模板

开源敏捷项目管理工具，支持 Scrum 和 Kanban，界面美观。

## 功能特性

- ✅ Web 应用服务
- ✅ 数据库服务
- ✅ 缓存服务
- ✅ 健康检查支持
- ✅ 数据持久化存储
- ✅ 多服务架构

## 默认凭证

部署后，系统会自动生成以下凭证：

- **postgres 用户名**: {app_name}_taiga
- **postgres 密码**: 自动生成（18位随机密码）
- **postgres 数据库名**: {app_name}_taiga
- **rabbitmq 用户名**: {app_name}_taiga
- **rabbitmq 密码**: 自动生成（16位随机密码）
- **taiga Secret Key**: 自动生成（64位随机密钥）

## 连接信息

- **主机**: `postgres` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `5432`

## 首次访问

1. 访问 `http://{{PRIMARY_DOMAIN}}`
2. 按照安装向导完成配置
3. 使用系统生成的凭证登录

## 数据持久化

所有数据存储在 Docker volumes 中：

- `taiga_back_data`: taiga-back 数据存储
- `taiga_back_static`: taiga-back 数据存储
- `postgres_data`: postgres 数据文件
- `rabbitmq_data`: rabbitmq 数据存储
- `redis_data`: redis 数据文件

**重要**: 即使容器重启，所有数据都会保留。

## 环境变量

重要的环境变量（系统自动设置）：

- `REDIS_URL / REDIS_HOST`: Redis 连接信息（自动生成）

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

1. 更多信息请访问：https://www.taiga.io/


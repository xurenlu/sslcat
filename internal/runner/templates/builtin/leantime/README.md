# Leantime 模板

开源项目管理和协作工具，支持看板、时间跟踪和报告。

## 功能特性

- ✅ Web 应用服务
- ✅ 数据库服务
- ✅ 健康检查支持
- ✅ 数据持久化存储
- ✅ 多服务架构

## 默认凭证

部署后，系统会自动生成以下凭证：

- **mysql 用户名**: {app_name}_leantime
- **mysql 密码**: 自动生成（18位随机密码）
- **mysql 数据库名**: {app_name}_leantime
- **mysql Root 密码**: 自动生成（20位随机密码）

## 连接信息

- **主机**: `mysql` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `3306`

## 首次访问

1. 访问 `http://{{PRIMARY_DOMAIN}}`
2. 按照安装向导完成配置
3. 使用系统生成的凭证登录

## 数据持久化

所有数据存储在 Docker volumes 中：

- `leantime_data`: leantime 数据存储
- `mysql_data`: mysql 数据存储

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

1. 更多信息请访问：https://leantime.io/


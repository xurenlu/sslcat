# SillyTavern (语音对话) 模板

角色扮演对话平台，支持自定义角色和语音对话，类似 Character.AI。

## 功能特性

- ✅ Web 应用服务
- ✅ 数据库服务
- ✅ 健康检查支持
- ✅ 数据持久化存储
- ✅ 多服务架构

## 默认凭证

部署后，系统会自动生成以下凭证：

- **postgres 用户名**: {app_name}_sillytavern
- **postgres 密码**: 自动生成（18位随机密码）
- **postgres 数据库名**: {app_name}_sillytavern

## 连接信息

- **主机**: `postgres` (容器内) 或 `127.0.0.1` (外部)
- **端口**: `5432`

## 首次访问

1. 访问 `http://{{PRIMARY_DOMAIN}}`
2. 按照安装向导完成配置
3. 使用系统生成的凭证登录

## 数据持久化

所有数据存储在 Docker volumes 中：

- `sillytavern_data`: sillytavern 数据文件
- `sillytavern_characters`: sillytavern 数据存储
- `postgres_data`: postgres 数据文件

**重要**: 即使容器重启，所有数据都会保留。

## 环境变量

重要的环境变量（系统自动设置）：

- `DATABASE_URL`: 数据库连接字符串（自动生成）

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

1. 部分 AI 应用需要 GPU 支持，请确保已安装 NVIDIA 驱动和 nvidia-container-toolkit
2. 更多信息请访问：https://github.com/SillyTavern/SillyTavern


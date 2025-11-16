# Jitsi Meet (视频会议) 模板

开源视频会议平台，支持多人视频通话、屏幕分享、录制等功能，无需注册即可使用。

## 功能特性

- ✅ Web 应用服务
- ✅ 健康检查支持
- ✅ 数据持久化存储
- ✅ 多服务架构

## 默认凭证

部署后，系统会自动生成以下凭证：


## 首次访问

1. 访问 `http://{{PRIMARY_DOMAIN}}`
2. 按照安装向导完成配置
3. 使用系统生成的凭证登录

## 数据持久化

所有数据存储在 Docker volumes 中：

- `jitsi_web`: web 配置文件
- `prosody_data`: prosody 配置文件
- `jvb_data`: jvb 配置文件

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

1. 更多信息请访问：https://jitsi.org/


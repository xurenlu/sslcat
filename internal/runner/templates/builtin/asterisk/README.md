# Asterisk (呼叫中心) 模板

开源的IP电话交换机（PBX）系统，支持VoIP通话、呼叫中心、语音信箱、IVR等功能。

## 功能特性

- ✅ 健康检查支持
- ✅ 数据持久化存储

## 数据持久化

所有数据存储在 Docker volumes 中：

- `asterisk_data`: asterisk 数据存储
- `asterisk_logs`: asterisk 数据存储

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

1. 更多信息请访问：https://www.asterisk.org/


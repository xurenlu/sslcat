# Regex Tester (正则表达式测试工具) 模板

在线正则表达式测试工具，支持实时匹配、高亮显示、多语言正则语法、常用正则模板。

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

1. 更多信息请访问：https://regex101.com/


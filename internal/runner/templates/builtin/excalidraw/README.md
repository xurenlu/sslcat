# Excalidraw (白板工具) 模板

开源的虚拟白板工具，支持手绘风格的图表绘制，适合团队协作、头脑风暴、流程图绘制等场景。

## 功能特性

- ✅ Web 应用服务
- ✅ 健康检查支持
- ✅ 数据持久化存储

## 首次访问

1. 访问 `http://{{PRIMARY_DOMAIN}}`
2. 按照安装向导完成配置

## 数据持久化

所有数据存储在 Docker volumes 中：

- `excalidraw_data`: excalidraw 数据文件

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

1. 更多信息请访问：https://excalidraw.com/


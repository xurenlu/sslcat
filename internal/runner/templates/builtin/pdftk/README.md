# PDFtk Server 模板

PDF 处理工具，支持合并、拆分、旋转、加密等操作。

## 功能特性

- ✅ Web 应用服务
- ✅ 健康检查支持
- ✅ 数据持久化存储

## 首次访问

1. 访问 `http://{{PRIMARY_DOMAIN}}`
2. 按照安装向导完成配置

## 数据持久化

所有数据存储在 Docker volumes 中：

- `pdftk_data`: pdftk 数据文件

**重要**: 即使容器重启，所有数据都会保留。

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

1. 更多信息请访问：https://www.pdflabs.com/tools/pdftk-server/


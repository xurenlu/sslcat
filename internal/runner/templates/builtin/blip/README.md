# BLIP (图片理解) 模板

Salesforce 开源的视觉语言模型，支持图片描述、问答和检索，需要 GPU。

## 功能特性

- ✅ 健康检查支持
- ✅ 数据持久化存储

## 数据持久化

所有数据存储在 Docker volumes 中：

- `blip_data`: blip 数据存储

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

1. 部分 AI 应用需要 GPU 支持，请确保已安装 NVIDIA 驱动和 nvidia-container-toolkit
2. 更多信息请访问：https://github.com/salesforce/BLIP


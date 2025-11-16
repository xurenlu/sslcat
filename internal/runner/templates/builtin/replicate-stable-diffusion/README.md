# Replicate Stable Diffusion 模板

Replicate 上的 Stable Diffusion 模型，高质量图片生成，需要 GPU。

## 功能特性

- ✅ 健康检查支持
- ✅ 数据持久化存储

## 默认凭证

部署后，系统会自动生成以下凭证：


## 数据持久化

所有数据存储在 Docker volumes 中：

- `replicate_sd_data`: replicate-sd 数据存储

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
2. 更多信息请访问：https://replicate.com/stability-ai/stable-diffusion


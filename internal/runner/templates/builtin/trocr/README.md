# TrOCR (图片文字识别翻译) 模板

Transformer OCR 服务，支持图片文字识别和多语言翻译。

## 功能特性

- ✅ API 服务
- ✅ GPU 加速支持（可选，推荐）
- ✅ 健康检查支持
- ✅ 数据持久化存储
- ✅ OCR 识别
- ✅ 多语言翻译
- ✅ Transformer 模型

## 默认配置

部署时可以选择：

- **TrOCR 模型**: `base`（基础模型）或 `large`（大型模型）
  - `base`: 速度较快，准确度较高
  - `large`: 准确度更高，但速度较慢

## API 使用

API 端点：`http://{{PRIMARY_DOMAIN}}/api/ocr`

支持的功能：
- 图片文字识别
- 多语言翻译
- 批量处理

## 数据持久化

所有数据存储在 Docker volumes 中：

- `trocr_data`: 模型文件和应用数据

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

1. **推荐使用 GPU** 以获得更好的性能，但 CPU 模式也可运行
2. 首次部署需要下载模型文件，可能需要较长时间（约 5-10 分钟）
3. `large` 模型需要更多内存和存储空间
4. 更多信息请访问：https://github.com/microsoft/unilm/tree/master/trocr


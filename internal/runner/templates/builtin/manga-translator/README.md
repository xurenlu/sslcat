# Manga Translator (图片翻译) 模板

漫画/图片翻译工具，支持 OCR 识别、文本翻译和图片修复，专为漫画优化。

## 功能特性

- ✅ Web 应用服务
- ✅ GPU 加速支持（必需）
- ✅ 健康检查支持
- ✅ 数据持久化存储
- ✅ OCR 识别
- ✅ 文本翻译
- ✅ 图片修复

## 首次访问

1. 访问 `http://{{PRIMARY_DOMAIN}}`
2. 上传需要翻译的图片或漫画
3. 选择源语言和目标语言
4. 等待翻译完成并下载结果

## 数据持久化

所有数据存储在 Docker volumes 中：

- `manga_translator_data`: 应用数据和配置
- `manga_translator_output`: 翻译输出文件

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

1. **此应用需要 GPU 支持**，请确保已安装 NVIDIA 驱动和 nvidia-container-toolkit
2. 首次部署需要下载模型文件，可能需要较长时间（约 5-10 分钟）
3. GPU 内存建议至少 4GB，处理大图片时可能需要更多内存
4. 更多信息请访问：https://github.com/zyddnys/manga-image-translator


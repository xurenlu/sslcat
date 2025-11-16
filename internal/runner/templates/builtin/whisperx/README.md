# WhisperX (视频翻译) 模板

强大的视频翻译工具，支持语音识别、时间戳对齐和翻译。

## 功能特性

- ✅ API 服务
- ✅ GPU 加速支持（可选，推荐）
- ✅ 健康检查支持
- ✅ 数据持久化存储
- ✅ 视频翻译
- ✅ 时间戳对齐
- ✅ 多语言支持

## 版本选择

部署时可以选择：

- **WhisperX 版本**: `cpu` 或 `cuda118`
  - `cpu`: 仅使用 CPU，无需 GPU
  - `cuda118`: 使用 GPU 加速（需要 CUDA 11.8+）

- **WhisperX 模型**: `tiny`、`base`、`small`、`medium`、`large-v2`、`large-v3`
  - 模型越大，准确度越高，但速度越慢
  - 推荐使用 `large-v2` 或 `large-v3` 获得最佳效果

## API 使用

API 端点：`http://{{PRIMARY_DOMAIN}}/api/translate`

支持的功能：
- 视频语音识别
- 时间戳对齐
- 多语言翻译
- 字幕生成

## 数据持久化

所有数据存储在 Docker volumes 中：

- `whisperx_data`: 应用数据和临时文件
- `whisperx_models`: 模型文件存储

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

1. **推荐使用 GPU 版本**（cuda118）以获得更好的性能
2. 首次部署需要下载模型文件，可能需要较长时间（约 10-20 分钟）
3. `large-v2` 和 `large-v3` 模型需要较多内存和存储空间
4. 处理长视频时可能需要较长时间
5. 更多信息请访问：https://github.com/m-bain/whisperX


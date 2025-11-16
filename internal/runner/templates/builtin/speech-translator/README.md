# Speech Translator (语音翻译) 模板

实时语音翻译服务，支持语音识别、翻译和语音合成。

## 功能特性

- ✅ API 服务
- ✅ GPU 加速支持（可选，推荐）
- ✅ 健康检查支持
- ✅ 数据持久化存储
- ✅ 实时翻译
- ✅ 语音识别
- ✅ 语音合成
- ✅ 多语言支持

## 默认配置

部署时可以通过环境变量配置：

- **默认源语言**: `zh`（中文）
- **默认目标语言**: `en`（英文）

## API 使用

API 端点：`http://{{PRIMARY_DOMAIN}}/api/translate`

支持的功能：
- 语音识别
- 文本翻译
- 语音合成
- 实时翻译

## 数据持久化

所有数据存储在 Docker volumes 中：

- `speech_translator_data`: 应用数据和模型文件

**重要**: 即使容器重启，所有数据都会保留。

## 环境变量

重要的环境变量（系统自动设置）：

- `DEFAULT_SRC_LANG`: 默认源语言代码
- `DEFAULT_TGT_LANG`: 默认目标语言代码

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
2. 首次部署需要下载模型文件，可能需要较长时间（约 3-5 分钟）
3. 实时翻译功能需要稳定的网络连接
4. 更多信息请访问：https://github.com/speech-translator


# WhisperX Web API 包装器开发 TODO

## 任务概述

为 WhisperX 模板添加 Web API 接口包装器，使其能够通过 HTTP API 提供服务，而不仅仅是命令行工具。

## 当前状态

- ✅ WhisperX 模板已更新使用 `thomasvvugt/whisperx` 镜像
- ✅ 容器可以正常启动和运行
- ❌ 当前镜像只提供命令行工具，没有 Web API 服务
- ❌ 需要通过 `docker exec` 进入容器执行命令才能使用

## 目标

创建一个 Web API 包装器，提供以下功能：
1. HTTP REST API 接口
2. 文件上传和处理
3. 异步任务处理（可选）
4. 结果返回（JSON/文本格式）

## 技术方案

### 方案 1: 创建独立的 API 服务镜像（推荐）

**优点：**
- 可以基于现有镜像添加 API 层
- 独立维护，不影响原镜像
- 可以添加更多功能（认证、限流等）

**实现步骤：**
1. 创建 Dockerfile，基于 `thomasvvugt/whisperx:cpu` 或 `thomasvvugt/whisperx:cuda118`
2. 安装 FastAPI/Flask 等 Web 框架
3. 创建 API 服务代码（见下方 API 设计）
4. 构建并推送到 Docker Hub/GHCR
5. 更新模板使用新镜像

### 方案 2: 在现有模板中添加启动脚本

**优点：**
- 不需要构建新镜像
- 快速实现

**缺点：**
- 需要在容器启动时安装依赖
- 启动时间较长
- 每次重启都需要重新安装

**实现步骤：**
1. 在 docker-compose.yml 中添加启动脚本
2. 脚本在容器启动时安装 FastAPI 等依赖
3. 启动 API 服务

## API 设计

### 基础端点

```
GET  /health          - 健康检查
GET  /api/v1/models   - 获取可用模型列表
POST /api/v1/transcribe - 转录音频/视频
POST /api/v1/translate   - 翻译文本
GET  /api/v1/tasks/{task_id} - 查询任务状态（如果支持异步）
```

### 请求示例

**转录请求：**
```json
POST /api/v1/transcribe
Content-Type: multipart/form-data

{
  "file": <audio/video file>,
  "model": "large-v2",
  "language": "zh",
  "output_format": "json"  // json, srt, vtt, txt
}
```

**响应示例：**
```json
{
  "status": "success",
  "task_id": "uuid",
  "result": {
    "text": "转录的文本内容",
    "segments": [
      {
        "start": 0.0,
        "end": 5.2,
        "text": "第一段文本"
      }
    ],
    "language": "zh"
  }
}
```

### 功能特性

- [ ] 文件上传（支持音频/视频格式）
- [ ] 多语言支持
- [ ] 多种输出格式（JSON, SRT, VTT, TXT）
- [ ] 时间戳对齐
- [ ] 说话人分离（diarization）
- [ ] 异步任务处理（大文件）
- [ ] 任务状态查询
- [ ] 错误处理和日志记录
- [ ] API 文档（Swagger/OpenAPI）

## 实现细节

### 技术栈建议

- **Web 框架**: FastAPI（推荐，自动生成 API 文档）
- **文件处理**: python-multipart
- **异步任务**: Celery + Redis（可选，用于大文件处理）
- **模型管理**: 缓存已加载的模型

### 代码结构

```
whisperx-api/
├── Dockerfile
├── requirements.txt
├── app/
│   ├── __init__.py
│   ├── main.py          # FastAPI 应用入口
│   ├── api/
│   │   ├── __init__.py
│   │   ├── routes.py    # API 路由
│   │   └── schemas.py   # Pydantic 模型
│   ├── services/
│   │   ├── __init__.py
│   │   ├── whisperx_service.py  # WhisperX 服务封装
│   │   └── file_handler.py      # 文件处理
│   └── utils/
│       ├── __init__.py
│       └── config.py    # 配置管理
└── README.md
```

### Dockerfile 示例

```dockerfile
FROM thomasvvugt/whisperx:cpu

# 安装 Web 框架和依赖
RUN pip install fastapi uvicorn python-multipart pydantic

# 复制应用代码
COPY app/ /app/
WORKDIR /app

# 暴露端口
EXPOSE 8000

# 启动命令
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

## 开发计划

### 阶段 1: 基础 API（MVP）
- [ ] 创建项目结构
- [ ] 实现基础健康检查端点
- [ ] 实现文件上传和转录端点
- [ ] 基础错误处理
- [ ] 本地测试

### 阶段 2: 功能完善
- [ ] 添加多语言支持
- [ ] 添加多种输出格式
- [ ] 添加时间戳对齐
- [ ] 添加说话人分离选项
- [ ] API 文档完善

### 阶段 3: 优化和部署
- [ ] 异步任务处理（大文件）
- [ ] 性能优化（模型缓存）
- [ ] 错误处理和日志完善
- [ ] 构建 Docker 镜像
- [ ] 推送到镜像仓库
- [ ] 更新模板配置

### 阶段 4: 高级功能（可选）
- [ ] 用户认证和授权
- [ ] 请求限流
- [ ] 任务队列管理
- [ ] WebSocket 支持（实时进度）
- [ ] 批量处理接口

## 测试计划

- [ ] 单元测试（服务层）
- [ ] API 集成测试
- [ ] 性能测试（并发请求）
- [ ] 大文件处理测试
- [ ] 错误场景测试

## 相关资源

- WhisperX GitHub: https://github.com/m-bain/whisperX
- FastAPI 文档: https://fastapi.tiangolo.com/
- Docker 镜像: thomasvvugt/whisperx

## 注意事项

1. **资源限制**: WhisperX 需要大量内存和计算资源，需要合理设置容器资源限制
2. **模型下载**: 首次使用需要下载模型，可能需要较长时间
3. **GPU 支持**: 如果使用 GPU 版本，需要确保 Docker 运行时支持 NVIDIA GPU
4. **文件大小限制**: 需要设置合理的文件大小限制，避免内存溢出
5. **并发处理**: 考虑实现任务队列，避免同时处理多个大文件导致资源耗尽

## 更新记录

- 2025-11-11: 创建初始 TODO 文档
- 2025-11-11: 更新 WhisperX 模板使用 thomasvvugt/whisperx 镜像


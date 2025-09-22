# SSLcat Runner 功能说明

## 概述

SSLcat 现在集成了三个强大的 Runner 功能，支持本地程序执行、Docker 容器化执行和 Git 服务器功能。

## 功能特性

### 1. Local Runner（本地运行器）

支持直接执行本地二进制程序，特别针对以下场景：

#### Golang 程序支持
- 直接执行 Golang 编译后的二进制文件
- 通过 `PORT` 环境变量传递端口号
- 支持自定义命令行参数和环境变量
- 自动进程管理和监控

#### Spring Boot 程序支持
- 执行 Spring Boot JAR 包
- 通过 `--spring.profiles.active` 参数设置 active profile
- 通过 `PORT` 环境变量传递端口号
- 支持自定义 JVM 参数和环境变量

#### 配置示例
```json
{
  "runners": {
    "local": {
      "enabled": true,
      "work_dir": "./data/runners/local",
      "max_concurrent": 10,
      "timeout": 300
    }
  }
}
```

### 2. Docker Runner（Docker 运行器）

从 Git 仓库拉取代码，自动检测项目类型，构建并运行 Docker 容器。

#### 支持的项目类型
- **Golang**: 检测 `go.mod` 文件
- **Node.js**: 检测 `package.json` 文件
- **Next.js**: 检测 Next.js 框架
- **Python**: 检测 `requirements.txt`、`setup.py`、`pyproject.toml`、`Pipfile`
- **PHP**: 检测 `composer.json` 文件
- **Ruby**: 检测 `Gemfile` 文件
- **Java**: 检测 `pom.xml`、`build.gradle` 文件
- **C#**: 检测 `*.csproj`、`*.sln` 文件
- **Rust**: 检测 `Cargo.toml` 文件
- **C/C++**: 检测 `Makefile`、`CMakeLists.txt` 文件

#### Docker 文件检测
- **Dockerfile**: 自动检测并使用 Dockerfile 构建
- **docker-compose**: 检测 `docker-compose.yml` 或 `docker-compose.yaml`

#### 框架检测
- **Node.js 框架**: Express、Koa、Fastify、React、Vue、Angular、Svelte
- **Python 框架**: Django、Flask、FastAPI、Tornado、aiohttp
- **PHP 框架**: Laravel、Symfony、CodeIgniter、CakePHP
- **Ruby 框架**: Rails、Sinatra、Hanami
- **Go 框架**: Gin、Gorilla、Echo

#### 配置示例
```json
{
  "runners": {
    "docker": {
      "enabled": true,
      "image_prefix": "sslcat-runner",
      "work_dir": "./data/runners/docker",
      "max_concurrent": 5,
      "timeout": 600,
      "auto_cleanup": true,
      "cleanup_interval": 3600
    }
  }
}
```

### 3. Git 服务器（Git 服务器）

集成 Git 操作和代码执行功能。

#### 功能特性
- 克隆和管理 Git 仓库
- 支持多分支管理
- 在仓库中执行命令
- 自动更新和同步
- 资源清理和管理

#### 配置示例
```json
{
  "runners": {
    "git": {
      "enabled": true,
      "repos_dir": "./data/runners/git",
      "max_concurrent": 3,
      "clone_timeout": 300,
      "auto_cleanup": true,
      "cleanup_interval": 7200
    }
  }
}
```

## API 接口

### Local Runner API

#### 列出任务
```
GET /sslcat-panel/api/local-runner/tasks
```

#### 获取任务详情
```
GET /sslcat-panel/api/local-runner/task?id={task_id}
```

#### 添加任务
```
POST /sslcat-panel/api/local-runner/task/add
Content-Type: application/json

{
  "name": "任务名称",
  "type": "golang|springboot",
  "binary_path": "/path/to/binary",
  "port": 8080,
  "args": ["arg1", "arg2"],
  "env": {
    "KEY": "value"
  },
  "active_profile": "prod"  // Spring Boot 专用
}
```

#### 启动任务
```
GET /sslcat-panel/api/local-runner/task/start?id={task_id}
```

#### 停止任务
```
GET /sslcat-panel/api/local-runner/task/stop?id={task_id}
```

#### 删除任务
```
GET /sslcat-panel/api/local-runner/task/remove?id={task_id}
```

### Docker Runner API

#### 列出任务
```
GET /sslcat-panel/api/docker-runner/tasks
```

#### 获取任务详情
```
GET /sslcat-panel/api/docker-runner/task?id={task_id}
```

#### 添加任务
```
POST /sslcat-panel/api/docker-runner/task/add
Content-Type: application/json

{
  "name": "任务名称",
  "git_url": "https://github.com/user/repo.git",
  "git_branch": "main",
  "port": 8080,
  "env": {
    "KEY": "value"
  }
}
```

#### 启动任务
```
GET /sslcat-panel/api/docker-runner/task/start?id={task_id}
```

#### 停止任务
```
GET /sslcat-panel/api/docker-runner/task/stop?id={task_id}
```

#### 删除任务
```
GET /sslcat-panel/api/docker-runner/task/remove?id={task_id}
```

### Git 服务器 API

#### 列出仓库
```
GET /sslcat-panel/api/git-server/repos
```

#### 获取仓库详情
```
GET /sslcat-panel/api/git-server/repo?id={repo_id}
```

#### 添加仓库
```
POST /sslcat-panel/api/git-server/repo/add
Content-Type: application/json

{
  "name": "仓库名称",
  "url": "https://github.com/user/repo.git",
  "branch": "main"
}
```

#### 更新仓库
```
GET /sslcat-panel/api/git-server/repo/update?id={repo_id}
```

#### 删除仓库
```
GET /sslcat-panel/api/git-server/repo/remove?id={repo_id}
```

#### 执行命令
```
POST /sslcat-panel/api/git-server/execute
Content-Type: application/json

{
  "repo_id": "仓库ID",
  "command": ["npm", "install"],
  "work_dir": "subdirectory"
}
```

### 运行时检测 API

#### 检测项目类型
```
GET /sslcat-panel/api/runtime-detector/detect?path={project_path}
```

## 使用示例

### 1. 运行 Golang 应用

```bash
# 添加 Golang 任务
curl -X POST "http://localhost:443/sslcat-panel/api/local-runner/task/add" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Golang Web 服务",
    "type": "golang",
    "binary_path": "/path/to/your-app",
    "port": 8080,
    "args": ["--config", "config.yaml"],
    "env": {
      "GIN_MODE": "release",
      "LOG_LEVEL": "info"
    }
  }'

# 启动任务
curl -X GET "http://localhost:443/sslcat-panel/api/local-runner/task/start?id=task_id"
```

### 2. 运行 Spring Boot 应用

```bash
# 添加 Spring Boot 任务
curl -X POST "http://localhost:443/sslcat-panel/api/local-runner/task/add" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Spring Boot 应用",
    "type": "springboot",
    "binary_path": "/path/to/app.jar",
    "port": 8080,
    "active_profile": "prod",
    "args": ["--server.port=8080"],
    "env": {
      "SPRING_PROFILES_ACTIVE": "prod",
      "JAVA_OPTS": "-Xmx512m"
    }
  }'
```

### 3. 从 Git 仓库运行 Docker 应用

```bash
# 添加 Docker 任务
curl -X POST "http://localhost:443/sslcat-panel/api/docker-runner/task/add" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Node.js 应用",
    "git_url": "https://github.com/user/node-app.git",
    "git_branch": "main",
    "port": 3000,
    "env": {
      "NODE_ENV": "production"
    }
  }'
```

### 4. 管理 Git 仓库

```bash
# 添加仓库
curl -X POST "http://localhost:443/sslcat-panel/api/git-server/repo/add" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "我的项目",
    "url": "https://github.com/user/project.git",
    "branch": "main"
  }'

# 在仓库中执行命令
curl -X POST "http://localhost:443/sslcat-panel/api/git-server/execute" \
  -H "Content-Type: application/json" \
  -d '{
    "repo_id": "repo_id",
    "command": ["npm", "install"],
    "work_dir": ""
  }'
```

## 配置说明

### 环境变量支持

所有 Runner 都支持通过环境变量传递配置：

- `PORT`: 服务端口号
- `GIN_MODE`: Gin 框架模式（Golang）
- `SPRING_PROFILES_ACTIVE`: Spring Boot 激活的配置文件
- `NODE_ENV`: Node.js 环境
- `PYTHONPATH`: Python 路径
- 其他自定义环境变量

### 端口管理

- Local Runner 和 Docker Runner 都支持端口映射
- 自动检测端口冲突
- 支持动态端口分配

### 资源管理

- 自动清理过期任务和容器
- 限制并发执行数量
- 超时保护机制
- 日志轮转和存储

## 安全考虑

1. **权限控制**: 所有 API 都需要管理员认证
2. **资源限制**: 限制并发执行数量和资源使用
3. **超时保护**: 防止长时间运行的进程
4. **隔离执行**: Docker 容器提供进程隔离
5. **日志审计**: 记录所有操作和执行结果

## 故障排除

### 常见问题

1. **任务启动失败**
   - 检查二进制文件路径是否正确
   - 确认端口是否被占用
   - 查看任务日志文件

2. **Docker 构建失败**
   - 检查 Git 仓库是否可访问
   - 确认 Docker 是否安装和运行
   - 查看构建日志

3. **Git 克隆失败**
   - 检查网络连接
   - 确认仓库 URL 是否正确
   - 检查权限设置

### 日志位置

- Local Runner: `./data/runners/local/{task_id}.log`
- Docker Runner: Docker 容器日志
- Git 服务器: `./data/runners/git/`

## 总结

SSLcat Runner 功能提供了完整的应用部署和执行解决方案，支持从简单的本地程序到复杂的容器化应用，大大增强了 SSLcat 的功能性和实用性。通过统一的 API 接口，可以轻松管理和监控各种类型的应用程序。

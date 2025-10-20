# Docker Compose 部署支持功能说明

## 📋 更新概述

SSLcat Git 部署功能现已支持 **Docker Compose** 多容器应用自动部署！

### 🎯 实现时间
- **日期**: 2025-10-06
- **版本**: v1.3.10 (待发布)

## ✨ 新增功能

### 1. DockerComposeBuilder 构建器

新增了完整的 Docker Compose 构建器，位于：
- 文件：`internal/runner/builder_docker_compose.go`
- 功能：自动检测、构建和部署 Docker Compose 应用

### 2. 自动检测

支持检测以下配置文件（按优先级）：
1. `docker-compose.yml`
2. `docker-compose.yaml`
3. `compose.yml`
4. `compose.yaml`

### 3. 完整的部署流程

#### 构建阶段
- ✅ 检测并验证 docker-compose 配置文件
- ✅ 自动拉取所需的 Docker 镜像
- ✅ 构建自定义镜像（如果有 `build` 指令）
- ✅ 实时输出构建日志

#### 部署阶段
- ✅ 自动生成唯一的项目名称（`sslcat-<appname>`）
- ✅ 蓝绿部署：停止旧容器，启动新容器
- ✅ 自动加载 `.env` 环境变量文件
- ✅ 支持自定义环境变量注入
- ✅ 自动添加 SSLcat 系统环境变量
- ✅ 显示容器状态和管理命令

### 4. 环境变量支持

#### 自动注入的系统变量
```bash
SSLCAT_APP_NAME=myapp       # 应用名称
SSLCAT_APP_PORT=8080        # 分配的端口
SSLCAT_APP_DOMAIN=myapp.com # 应用域名
```

#### 用户自定义变量
- 支持项目根目录的 `.env` 文件
- 支持通过 SSLcat Web 界面配置环境变量
- 自动生成 `.env.sslcat` 文件用于部署

### 5. 项目隔离

每个应用使用独立的 Docker Compose 项目名称，确保：
- 容器名称不冲突
- 网络隔离
- 卷数据隔离
- 可以同时运行多个应用

## 📂 新增文件

### 1. 核心实现
```
internal/runner/builder_docker_compose.go  (新增，275 行)
```

### 2. 文档
```
docs/docker-compose-deploy.md              (新增，完整使用指南)
DOCKER_COMPOSE_SUPPORT.md                  (本文件，功能说明)
```

### 3. 配置更新
```
internal/runner/builder.go                 (更新，注册新的构建器)
DOCS.md                                    (更新，添加文档索引)
```

## 🚀 使用示例

### 示例 1: Node.js + PostgreSQL + Redis

创建 `docker-compose.yml`：

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/myapp
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: myapp
      POSTGRES_PASSWORD: password
    volumes:
      - postgres-data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data

volumes:
  postgres-data:
  redis-data:
```

推送部署：

```bash
git remote add sslcat ssh://git@your-server:2222/myapp
git push sslcat main
```

SSLcat 会自动：
1. 检测到 `docker-compose.yml`
2. 拉取 PostgreSQL 和 Redis 镜像
3. 构建你的应用镜像
4. 启动所有服务
5. 配置域名和 SSL

### 示例 2: 微服务架构

```yaml
version: '3.8'

services:
  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    depends_on:
      - api

  api:
    build: ./api
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/api_db
    depends_on:
      - db

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: api_db
      POSTGRES_PASSWORD: password
    volumes:
      - db-data:/var/lib/postgresql/data

volumes:
  db-data:
```

## 🔧 技术实现细节

### 1. 构建器优先级

在 `BuilderRegistry` 中，Docker Compose 具有最高优先级：

```go
// 按优先级注册构建器
registry.Register(NewDockerComposeBuilder(gs)) // 最高优先级
registry.Register(NewDockerBuilder(gs))        // Dockerfile
registry.Register(NewNodeJSBuilder(gs))        // Node.js
// ... 其他构建器
```

这样设计是因为：
- Docker Compose 通常会引用 Dockerfile
- 如果同时存在两者，应该使用更完整的 Docker Compose 配置

### 2. 命令执行流程

#### 拉取镜像
```bash
docker-compose -f docker-compose.yml pull --ignore-pull-failures
```

#### 构建自定义镜像
```bash
docker-compose -f docker-compose.yml build --pull
```

#### 停止旧版本
```bash
docker-compose -f docker-compose.yml -p sslcat-myapp down --remove-orphans
```

#### 启动新版本
```bash
docker-compose -f docker-compose.yml -p sslcat-myapp up -d --remove-orphans
```

### 3. 日志记录

使用 `DeployLogger` 记录所有部署过程：
- 构建日志
- 镜像拉取进度
- 容器启动状态
- 错误信息
- 管理命令提示

### 4. 错误处理

- 配置文件验证失败 → 中止部署
- 镜像拉取失败 → 警告但继续（使用本地镜像）
- 镜像构建失败 → 警告但继续（可能没有需要构建的）
- 容器启动失败 → 报错并返回详细日志

## 📊 与其他部署方式的对比

| 特性 | Dockerfile | Docker Compose | Node.js/Python |
|------|-----------|----------------|---------------|
| 容器数量 | 1 | 多个 | 0（直接运行）|
| 数据库支持 | 需外部 | 内置 | 需外部 |
| 缓存服务 | 需外部 | 内置 | 需外部 |
| 网络配置 | 手动 | 自动 | 无 |
| 资源限制 | 手动 | 配置文件 | 无 |
| 适用场景 | 简单应用 | 复杂应用 | 简单应用 |

## 🎯 优势

### 1. 零配置部署
- 推送代码即可部署
- 自动检测应用类型
- 自动配置域名和 SSL

### 2. 完整的开发环境
- 数据库、缓存一起部署
- 开发环境与生产环境一致
- 团队协作更方便

### 3. 蓝绿部署
- 零停机更新
- 自动清理旧容器
- 失败可快速回滚

### 4. 项目隔离
- 每个应用独立的网络
- 独立的数据卷
- 不会相互影响

## 📝 最佳实践

### 1. 使用健康检查

```yaml
services:
  web:
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### 2. 设置资源限制

```yaml
services:
  web:
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 512M
```

### 3. 数据持久化

```yaml
volumes:
  postgres-data:
    name: myapp-postgres-data
  redis-data:
    name: myapp-redis-data
```

### 4. 使用 .env 文件

```env
DATABASE_URL=postgresql://user:password@db:5432/myapp
REDIS_URL=redis://redis:6379
API_KEY=your-secret-key
```

### 5. 配置重启策略

```yaml
services:
  web:
    restart: unless-stopped
```

## 🔍 故障排查

### 查看部署日志
通过 SSLcat Web 界面查看实时部署日志

### 查看容器日志
```bash
docker-compose -f docker-compose.yml -p sslcat-myapp logs -f
```

### 查看容器状态
```bash
docker-compose -f docker-compose.yml -p sslcat-myapp ps
```

### 重启服务
```bash
docker-compose -f docker-compose.yml -p sslcat-myapp restart
```

## 🚧 已知限制

1. **Docker 版本要求**: 需要 Docker Compose V2 或更高版本
2. **资源占用**: 多容器应用会占用更多资源
3. **启动时间**: 相比单容器应用，启动时间较长
4. **网络配置**: 默认使用 bridge 网络，暂不支持自定义网络驱动

## 🗓️ 未来规划

- [ ] 支持 Docker Swarm 模式
- [ ] 支持 Kubernetes 部署
- [ ] 支持自定义网络配置
- [ ] 支持 Docker secrets 管理
- [ ] 添加容器监控和告警
- [ ] 支持服务扩容和缩容

## 📖 相关文档

- [Docker Compose 部署指南](docs/docker-compose-deploy.md) - 详细使用说明
- [Git 部署实现文档](docs/git-deploy-ssh-implementation.md) - Git 部署技术细节
- [Git 部署计划](docs/git-deploy-ssh-plan.md) - 功能规划
- [DOKKU 风格部署](DOKKU_STYLE_GIT_DEPLOY.md) - Dokku 风格说明

## 🎉 总结

Docker Compose 支持为 SSLcat 带来了真正的 **PaaS 平台能力**：

- ✅ 支持复杂的多容器应用
- ✅ 数据库、缓存等依赖服务一起部署
- ✅ 与 Heroku、Dokku、Railway 等 PaaS 平台功能对齐
- ✅ 开发者体验极佳：`git push` 即部署
- ✅ 企业级功能：蓝绿部署、零停机更新

现在 SSLcat 不仅是一个反向代理，更是一个完整的应用部署平台！🚀

---

**开发者**: Rocky Xu  
**更新时间**: 2025-10-06  
**版本**: v1.3.10 (待发布)


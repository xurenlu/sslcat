# Docker Compose Deployment Guide

SSLcat Git deployment now supports Docker Compose, allowing you to easily deploy complex applications with multiple containers.

## Features

✅ **Auto Detection** - Automatically recognizes `docker-compose.yml` or `docker-compose.yaml`  
✅ **Complete Build** - Automatically pulls images and builds custom images  
✅ **Blue-Green Deployment** - Automatically stops old containers and starts new ones  
✅ **Environment Variables** - Supports `.env` files and custom environment variables  
✅ **Real-time Logs** - Complete deployment logs and container status  
✅ **Project Isolation** - Each application uses an independent project name  

## Quick Start

### 1. Prepare Your Project

Create `docker-compose.yml` in your project root directory:

```yaml
version: '3.8'

services:
  web:
    build: .
    ports:
      - "18080:18080"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=${DATABASE_URL}
    depends_on:
      - db
      - redis

  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=myapp
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=password
    volumes:
      - db-data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  db-data:
```

### 2. 推送到 SSLcat

```bash
# 添加 git remote
git remote add sslcat ssh://git@your-server:2222/myapp

# 推送代码
git push sslcat main
```

### 3. 自动部署

SSLcat 会自动：
1. 检测到 `docker-compose.yml` 文件
2. 验证配置文件
3. 拉取所需的 Docker 镜像
4. 构建自定义镜像（如果有 `build` 指令）
5. 停止旧版本容器
6. 启动新版本容器
7. 显示部署状态和管理命令

## 支持的配置文件

SSLcat 会按以下优先级查找配置文件：

1. `docker-compose.yml`
2. `docker-compose.yaml`
3. `compose.yml`
4. `compose.yaml`

## 环境变量

### 使用 .env 文件

在项目根目录创建 `.env` 文件：

```env
DATABASE_URL=postgresql://user:password@db:5432/myapp
REDIS_URL=redis://redis:6379
API_KEY=your-secret-key
```

SSLcat 会自动加载这个文件。

### 在 SSLcat 中设置环境变量

通过 SSLcat Web 管理面板为应用设置环境变量，这些变量会自动注入到容器中。

SSLcat 还会自动添加以下环境变量：

- `SSLCAT_APP_NAME` - 应用名称
- `SSLCAT_APP_PORT` - 应用端口
- `SSLCAT_APP_DOMAIN` - 应用域名

## 端口映射

### 自动端口分配

SSLcat 会为每个应用分配一个唯一的端口。你可以在 docker-compose.yml 中使用这个端口：

```yaml
services:
  web:
    ports:
      - "${SSLCAT_APP_PORT}:8080"
```

### 固定端口

你也可以使用固定端口，但要确保不会冲突：

```yaml
services:
  web:
    ports:
      - "18080:18080"  # 容器内部端口
```

SSLcat 会通过反向代理将外部请求转发到你的应用。

## 常见场景

### 场景 1: Node.js + PostgreSQL + Redis

```yaml
version: '3.8'

services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://postgres:password@db:5432/myapp
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
    restart: unless-stopped

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: myapp
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  postgres-data:
  redis-data:
```

### 场景 2: Python Django + PostgreSQL

```yaml
version: '3.8'

services:
  web:
    build: .
    command: gunicorn myproject.wsgi:application --bind 0.0.0.0:8000
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/django_db
      - SECRET_KEY=${SECRET_KEY}
      - DEBUG=False
    depends_on:
      - db
    restart: unless-stopped

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: django_db
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  postgres-data:
```

### 场景 3: Go API + MySQL + Redis

```yaml
version: '3.8'

services:
  api:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "18080:18080"
    environment:
      - MYSQL_DSN=user:password@tcp(mysql:3306)/myapp?parseTime=true
      - REDIS_ADDR=redis:6379
      - ENV=production
    depends_on:
      - mysql
      - redis
    restart: unless-stopped

  mysql:
    image: mysql:8
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: myapp
      MYSQL_USER: user
      MYSQL_PASSWORD: password
    volumes:
      - mysql-data:/var/lib/mysql
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    restart: unless-stopped

volumes:
  mysql-data:
```

### 场景 4: 微服务架构

```yaml
version: '3.8'

services:
  # 前端服务
  frontend:
    build: ./frontend
    ports:
      - "3000:3000"
    environment:
      - API_URL=http://api:8080
    depends_on:
      - api
    restart: unless-stopped

  # API 服务
  api:
    build: ./api
    ports:
      - "18080:18080"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/api_db
      - REDIS_URL=redis://redis:6379
      - AUTH_SERVICE_URL=http://auth:8081
    depends_on:
      - db
      - redis
      - auth
    restart: unless-stopped

  # 认证服务
  auth:
    build: ./auth-service
    ports:
      - "8081:8081"
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/auth_db
      - JWT_SECRET=${JWT_SECRET}
    depends_on:
      - db
    restart: unless-stopped

  # 共享数据库
  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: password
    volumes:
      - postgres-data:/var/lib/postgresql/data
    restart: unless-stopped

  # 共享缓存
  redis:
    image: redis:7-alpine
    restart: unless-stopped

volumes:
  postgres-data:
```

## 管理命令

部署成功后，SSLcat 会显示管理命令。你也可以手动执行：

### 查看日志
```bash
docker-compose -f docker-compose.yml -p sslcat-myapp logs -f
```

### 查看特定服务的日志
```bash
docker-compose -f docker-compose.yml -p sslcat-myapp logs -f web
```

### 停止服务
```bash
docker-compose -f docker-compose.yml -p sslcat-myapp stop
```

### 重启服务
```bash
docker-compose -f docker-compose.yml -p sslcat-myapp restart
```

### 停止并删除容器
```bash
docker-compose -f docker-compose.yml -p sslcat-myapp down
```

### 查看容器状态
```bash
docker-compose -f docker-compose.yml -p sslcat-myapp ps
```

## 最佳实践

### 1. 使用健康检查

```yaml
services:
  web:
    build: .
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:18080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

### 2. 设置资源限制

```yaml
services:
  web:
    build: .
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
```

### 3. 使用命名卷

```yaml
volumes:
  postgres-data:
    name: myapp-postgres-data
  redis-data:
    name: myapp-redis-data
```

### 4. 配置重启策略

```yaml
services:
  web:
    restart: unless-stopped  # 推荐
    # 或
    restart: always
    # 或
    restart: on-failure:3
```

### 5. 使用网络隔离

```yaml
services:
  web:
    networks:
      - frontend
      - backend
  
  db:
    networks:
      - backend

networks:
  frontend:
  backend:
```

### 6. 敏感信息使用 secrets

```yaml
services:
  web:
    secrets:
      - db_password
      - api_key

secrets:
  db_password:
    file: ./secrets/db_password.txt
  api_key:
    file: ./secrets/api_key.txt
```

### 7. 数据持久化

确保重要数据使用 volumes：

```yaml
services:
  db:
    volumes:
      - db-data:/var/lib/postgresql/data  # 数据持久化
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql  # 初始化脚本

volumes:
  db-data:
```

## 故障排查

### 1. 容器启动失败

查看完整日志：
```bash
docker-compose -f docker-compose.yml -p sslcat-myapp logs
```

### 2. 端口冲突

修改 docker-compose.yml 中的端口映射，避免与其他应用冲突。

### 3. 镜像拉取失败

检查网络连接，或使用国内镜像源：
```yaml
services:
  db:
    image: registry.cn-hangzhou.aliyuncs.com/library/postgres:15
```

### 4. 构建失败

检查 Dockerfile 和构建上下文：
```bash
docker-compose -f docker-compose.yml build --no-cache
```

### 5. 数据库连接失败

确保：
- 服务启动顺序正确（使用 `depends_on` 和 `healthcheck`）
- 数据库连接字符串正确
- 网络配置正确

### 6. 环境变量未生效

检查：
- `.env` 文件是否在正确位置
- 变量名是否正确
- 是否需要重启容器

## 注意事项

1. **项目名称**: SSLcat 会自动为每个应用生成唯一的项目名称 `sslcat-<appname>`
2. **端口映射**: 容器端口会映射到主机，确保不会冲突
3. **数据持久化**: 使用 volumes 确保数据不会在容器重启时丢失
4. **资源限制**: 建议设置资源限制，避免单个应用占用过多资源
5. **健康检查**: 添加健康检查可以确保容器正常运行
6. **日志管理**: 配置日志驱动和日志轮转，避免日志占用过多磁盘空间

## 与单纯 Dockerfile 部署的区别

| 特性 | Dockerfile | Docker Compose |
|------|-----------|----------------|
| 容器数量 | 单个容器 | 多个容器 |
| 依赖服务 | 需要外部配置 | 内置支持 |
| 网络配置 | 手动配置 | 自动配置 |
| 数据卷 | 手动管理 | 声明式管理 |
| 环境变量 | 启动时传入 | 配置文件管理 |
| 适用场景 | 简单应用 | 复杂应用 |

## 示例项目

你可以参考以下示例项目：

1. **Node.js + PostgreSQL**: [examples/nodejs-postgres](../examples/nodejs-postgres)
2. **Python Django**: [examples/django-app](../examples/django-app)
3. **Go + MySQL**: [examples/go-mysql](../examples/go-mysql)
4. **微服务**: [examples/microservices](../examples/microservices)

## 相关文档

- [Git 部署 SSH 实现](./git-deploy-ssh-implementation.md)
- [Git 部署计划](./git-deploy-ssh-plan.md)
- [Docker 部署指南](../DOCKER_CGO_BUILD.md)
- [部署指南](../DEPLOYMENT.md)

## 获取帮助

如果遇到问题，可以：

1. 查看部署日志
2. 检查容器状态
3. 查看 SSLcat 系统日志
4. 在 GitHub 提交 issue

---

现在你可以使用 Docker Compose 轻松部署复杂的多容器应用了！🚀

# 静态站点 Builder - 基于 Nginx

## 概述

SSLcat 现在支持自动检测和部署纯静态站点。当所有其他 builder（如 Node.js、Python、Docker 等）都无法识别项目时，如果项目根目录包含 `index.html` 或 `index.htm` 文件，系统会自动使用静态站点 Builder。

## 工作原理

静态站点 Builder 采用最低优先级检测策略，基于 **Nginx Alpine** 镜像进行容器化部署：

1. **检测阶段**：在所有其他 builder 检测失败后，检查根目录是否存在 `index.html` 或 `index.htm`
2. **构建阶段**：
   - 自动创建临时 Dockerfile（`Dockerfile.sslcat-static`）
   - 使用 `nginx:alpine` 作为基础镜像
   - 将所有静态文件复制到 `/usr/share/nginx/html`
   - 构建 Docker 镜像：`sslcat-{appname}:latest`
   - 构建完成后自动删除临时 Dockerfile
3. **部署阶段**：
   - 停止并删除旧容器（如果存在）
   - 启动新的 Nginx 容器
   - 映射端口到主机

## 自动生成的 Dockerfile

```dockerfile
FROM nginx:alpine
COPY . /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

## 检测优先级

静态站点 Builder 在 **最低优先级**，确保只有在所有特定框架/语言 builder 都无法识别时才会触发：

1. Docker Compose
2. Dockerfile
3. Node.js (package.json)
4. Deno (deno.json)
5. Bun (bun.lockb)
6. Python (requirements.txt)
7. Go (go.mod)
8. Rust (Cargo.toml)
9. Java (pom.xml, build.gradle)
10. Ruby (Gemfile)
11. PHP (composer.json)
12. .NET (*.csproj)
13. **Static (index.html/index.htm)** ← 最低优先级

## 使用场景

### 1. 纯 HTML/CSS/JS 静态站点

```
my-static-site/
├── index.html
├── style.css
├── script.js
└── images/
    └── logo.png
```

### 2. 编译后的前端应用（无构建配置）

如果你有一个编译好的 React/Vue/Angular 应用，但已经删除了 `package.json`：

```
dist/
├── index.html
├── assets/
│   ├── main-abc123.js
│   └── style-def456.css
└── favicon.ico
```

### 3. 文档站点

```
docs/
├── index.html
├── api/
│   └── reference.html
└── guides/
    └── getting-started.html
```

## 部署示例

### 通过 Git Push 部署

```bash
# 创建静态站点
mkdir my-static-site
cd my-static-site
echo '<h1>Hello World</h1>' > index.html

# 初始化 Git 仓库
git init
git add .
git commit -m "Initial commit"

# 添加远程仓库并推送
git remote add origin git@your-server:my-static-site.git
git push origin main
```

### 部署日志输出示例

```
[info] static: 检测到静态文件应用
[info] static: 准备使用 Nginx 镜像构建...
[info] static: 创建临时 Dockerfile...
[info] static: 构建 Docker 镜像: sslcat-my-static-site:latest
[info] static: 镜像构建成功
[info] static: 启动 Nginx 容器...
[info] static: 停止旧容器（如果存在）...
[info] static: 启动新的 Nginx 容器...
[info] static: 静态站点已成功部署到 http://localhost:8080
```

## 默认配置

- **默认端口**：80（容器内）
- **容器名称**：`sslcat-{appname}`
- **镜像名称**：`sslcat-{appname}:latest`
- **基础镜像**：`nginx:alpine`
- **文档根目录**：`/usr/share/nginx/html`

## 环境变量支持

虽然静态站点通常不需要环境变量，但 Builder 仍支持通过 `-e` 参数传递环境变量到容器：

```bash
# 在 sslcat.conf 中配置环境变量
PORT=8080
CUSTOM_VAR=value
```

## Nginx 配置自定义

如果需要自定义 Nginx 配置，可以在项目根目录添加 `nginx.conf` 文件：

```nginx
server {
    listen 80;
    server_name localhost;
    root /usr/share/nginx/html;
    index index.html index.htm;

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

然后修改临时 Dockerfile 以包含自定义配置（或者直接创建 `Dockerfile`，这样会使用 Docker Builder 而不是 Static Builder）。

## 与 Docker Builder 的区别

| 特性 | Static Builder | Docker Builder |
|------|---------------|----------------|
| 触发条件 | 根目录有 index.html/htm | 根目录有 Dockerfile |
| Dockerfile | 自动生成临时文件 | 使用项目中的 Dockerfile |
| 优先级 | 最低 | 第二高（仅次于 Docker Compose） |
| 适用场景 | 纯静态文件 | 任何需要自定义构建的应用 |
| Nginx 配置 | 默认配置 | 可完全自定义 |

## 故障排查

### 问题：应用被识别为其他类型

**原因**：项目中包含其他 builder 的标识文件（如 `package.json`）

**解决方案**：删除不需要的配置文件，或者手动创建 Dockerfile

### 问题：页面显示 404

**原因**：缺少 index.html 或路径配置问题

**解决方案**：
1. 确保根目录有 `index.html`
2. 检查文件名大小写（Linux 区分大小写）
3. 查看容器日志：`docker logs sslcat-{appname}`

### 问题：静态资源加载失败

**原因**：资源路径使用了绝对路径或不正确的相对路径

**解决方案**：使用相对路径或以 `/` 开头的绝对路径

## 性能优化

Nginx Alpine 镜像非常轻量（约 20MB），提供了出色的性能：

- **Gzip 压缩**：默认启用
- **静态文件缓存**：自动处理 ETag 和 Last-Modified
- **并发连接**：支持高并发
- **内存占用**：极低

## 总结

静态站点 Builder 提供了一种简单、轻量、高效的方式来部署纯静态内容，无需编写任何配置文件。它作为"兜底"方案，确保即使是最简单的 HTML 页面也能快速部署到生产环境。


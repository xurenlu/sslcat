# SSLcat Builder 架构文档

## 概述

SSLcat 采用插件化的 Builder 架构来支持多种编程语言和框架的自动构建和部署。每种语言都有对应的 Builder 实现，负责检测、构建和启动应用。

## 架构设计

### 核心组件

1. **AppBuilder 接口**: 定义了所有 Builder 必须实现的方法
2. **BaseBuilder**: 提供通用功能的基础实现
3. **BuilderRegistry**: 管理所有 Builder 的注册表
4. **语言特定 Builder**: 每种语言的具体实现

### 接口定义

```go
type AppBuilder interface {
    Detect(appPath string) (bool, error)          // 检测应用类型
    GetType() string                               // 获取类型标识
    GetDisplayName() string                        // 获取显示名称
    Build(app *GitApp) error                       // 构建应用
    BuildWithLogging(app *GitApp, logger *DeployLogger) error  // 带日志构建
    Start(app *GitApp) error                       // 启动应用
    StartWithLogging(app *GitApp, logger *DeployLogger) error  // 带日志启动
    GetDefaultPort() int                           // 获取默认端口
    GetHealthCheckPath() string                    // 获取健康检查路径
}
```

## 支持的语言和框架

### 1. Node.js (`nodejs`)
**检测文件**: `package.json`

**支持的包管理器**:
- npm (默认)
- yarn (`yarn.lock`)
- pnpm (`pnpm-lock.yaml`)

**支持的框架**:
- Express
- Koa
- Fastify
- Next.js
- Nest.js
- 任何 Node.js 应用

**默认端口**: 3000

**文件**: `builder_nodejs.go`

---

### 2. Deno (`deno`)
**检测文件**: `deno.json`, `deno.jsonc`

**特性**:
- 原生 TypeScript 支持
- 依赖缓存
- 任务执行（deno task）

**默认端口**: 8000

**文件**: `builder_deno.go`

---

### 3. Bun (`bun`)
**检测文件**: `bun.lockb`, `bunfig.toml`, `package.json` (packageManager: "bun")

**特性**:
- 极快的包管理器
- 原生 TypeScript 支持
- 兼容 Node.js API

**默认端口**: 3000

**文件**: `builder_bun.go`

---

### 4. Python (`python`)
**检测文件**: `requirements.txt`, `Pipfile`, `pyproject.toml`, `setup.py`

**支持的包管理器**:
- pip (默认)
- pipenv (`Pipfile`)
- poetry (`pyproject.toml`)

**支持的框架**:
- Django
- Flask
- FastAPI
- Tornado
- 任何 WSGI/ASGI 应用

**默认端口**: 8000

**文件**: `builder_python.go`

---

### 5. Go (`go`)
**检测文件**: `go.mod`

**特性**:
- 自动依赖下载
- 静态编译
- 小体积二进制文件

**支持的框架**:
- Gin
- Echo
- Fiber
- Gorilla
- 任何 Go HTTP 应用

**默认端口**: 8080

**文件**: `builder_go.go`

---

### 6. Rust (`rust`)
**检测文件**: `Cargo.toml`

**特性**:
- Release 模式构建
- 高性能原生应用
- 零成本抽象

**支持的框架**:
- Actix-web
- Rocket
- Axum
- Warp

**默认端口**: 8080

**文件**: `builder_rust.go`

---

### 7. Java (`java`)
**检测文件**: `pom.xml`, `build.gradle`, `build.gradle.kts`

**支持的构建工具**:
- Maven (pom.xml)
- Gradle (build.gradle)

**支持的框架**:
- Spring Boot
- Spring MVC
- Micronaut
- Quarkus
- 任何 Java 应用

**默认端口**: 8080

**文件**: `builder_java.go`

---

### 8. Ruby (`ruby`)
**检测文件**: `Gemfile`, `config.ru`

**支持的框架**:
- Ruby on Rails
- Sinatra
- Hanami
- Padrino
- 任何 Rack 应用

**特性**:
- Bundler 依赖管理
- Rails 资产预编译
- 数据库迁移

**默认端口**: 3000

**文件**: `builder_ruby.go`

---

### 9. PHP (`php`)
**检测文件**: `composer.json`, `index.php`

**支持的框架**:
- Laravel
- Symfony
- CodeIgniter
- Slim
- 任何 PHP 应用

**特性**:
- Composer 依赖管理
- Laravel 优化
- 内置 PHP 服务器

**默认端口**: 8000

**文件**: `builder_php.go`

---

### 10. .NET (`dotnet`)
**检测文件**: `*.csproj`, `*.fsproj`, `*.vbproj`, `*.sln`

**支持的语言**:
- C#
- F#
- VB.NET

**支持的框架**:
- ASP.NET Core
- Blazor
- Web API
- MVC

**默认端口**: 5000

**文件**: `builder_dotnet.go`

---

### 11. Docker (`docker`)
**检测文件**: `Dockerfile`

**特性**:
- 完全自定义构建
- 多阶段构建支持
- 镜像缓存
- 容器编排

**默认端口**: 8080 (可配置)

**文件**: `builder_docker.go`

---

### 12. Static Files (`static`)
**检测文件**: `index.html`, `index.htm`

**特性**:
- 纯静态文件服务
- 无需构建
- 使用 Python http.server 或 npx http-server

**默认端口**: 8080

**文件**: `builder_static.go`

---

## Builder 优先级

检测应用类型时，按以下优先级顺序：

1. **Docker** - 最高优先级，如果有 Dockerfile 就使用
2. **Deno** - deno.json/deno.jsonc
3. **Bun** - bun.lockb
4. **Node.js** - package.json
5. **Python** - requirements.txt 等
6. **Go** - go.mod
7. **Rust** - Cargo.toml
8. **Java** - pom.xml/build.gradle
9. **.NET** - *.csproj 等
10. **Ruby** - Gemfile
11. **PHP** - composer.json/index.php
12. **Static** - index.html (兜底，最低优先级)

## 使用方式

### 自动检测

系统会自动检测应用类型并选择合适的 Builder：

```go
// 检测应用类型
appType, err := gs.detectAppType(app)

// 获取对应的 Builder
builder, err := gs.builderRegistry.GetBuilder(appType)

// 构建和部署
err = builder.BuildWithLogging(app, logger)
err = builder.StartWithLogging(app, logger)
```

### 手动指定

也可以在应用配置中手动指定类型：

```json
{
  "name": "my-app",
  "app_type": "nodejs",
  "port": 3000
}
```

## 扩展新语言

要添加新语言支持，只需：

1. 创建新的 Builder 文件 `builder_xxx.go`
2. 实现 `AppBuilder` 接口
3. 在 `InitBuilders()` 中注册

示例：

```go
// builder_kotlin.go
type KotlinBuilder struct {
    *BaseBuilder
}

func NewKotlinBuilder(gs *GitServer) *KotlinBuilder {
    return &KotlinBuilder{
        BaseBuilder: NewBaseBuilder("kotlin", "Kotlin", 8080, gs),
    }
}

func (b *KotlinBuilder) Detect(appPath string) (bool, error) {
    return b.fileExists(appPath, "build.gradle.kts"), nil
}

// ... 实现其他方法
```

然后在 `builder.go` 的 `InitBuilders()` 中注册：

```go
func (gs *GitServer) InitBuilders() *BuilderRegistry {
    registry := NewBuilderRegistry()
    // ...
    registry.Register(NewKotlinBuilder(gs))
    // ...
    return registry
}
```

## 代码组织

```
internal/runner/
├── builder.go              # 核心接口和 Registry
├── builder_nodejs.go       # Node.js Builder
├── builder_deno.go         # Deno Builder
├── builder_bun.go          # Bun Builder
├── builder_python.go       # Python Builder
├── builder_go.go           # Go Builder
├── builder_rust.go         # Rust Builder
├── builder_java.go         # Java Builder
├── builder_ruby.go         # Ruby Builder
├── builder_php.go          # PHP Builder
├── builder_dotnet.go       # .NET Builder
├── builder_docker.go       # Docker Builder
├── builder_static.go       # Static Builder
└── git_server.go           # 主服务（已重构）
```

每个 Builder 文件约 150-300 行代码，保持了良好的可维护性。

## 优势

1. **模块化**: 每种语言独立实现，互不影响
2. **可扩展**: 轻松添加新语言支持
3. **可维护**: 单个文件代码量控制在 300 行以内
4. **可测试**: 每个 Builder 可独立测试
5. **类型安全**: 完全的 Go 类型检查
6. **统一接口**: 所有语言使用相同的构建和部署流程

## 迁移说明

从旧架构迁移到新架构：

- ✅ 完全向后兼容
- ✅ 现有应用无需修改
- ✅ 自动使用新的 Builder 系统
- ✅ 保留了旧的构建方法（标记为 deprecated）

## 性能对比

| 语言 | 旧实现代码行数 | 新实现代码行数 | 减少 |
|------|------------|------------|------|
| Node.js | ~100 行 | ~220 行 | - |
| Python | ~80 行 | ~200 行 | - |
| Go | ~70 行 | ~150 行 | - |
| **总计** | ~1200 行（git_server.go 中） | ~2000 行（独立文件） | git_server.go 减少 50% |

虽然总代码量略有增加，但：
- git_server.go 从 2637 行降至约 1800 行
- 每个 Builder 文件独立，易于维护
- 新增了 6 种语言支持
- 代码结构更清晰

## 下一步计划

未来可以考虑添加：

1. **Scala** (sbt)
2. **Elixir** (mix)
3. **Swift** (Package.swift)
4. **Kotlin** (独立 Kotlin 项目)
5. **Zig** (build.zig)

只需要创建对应的 `builder_xxx.go` 文件即可！


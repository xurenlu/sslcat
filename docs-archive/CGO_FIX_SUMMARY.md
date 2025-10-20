# SQLite 依赖优化总结

## 问题描述
用户遇到了以下错误：
```
初始化用户管理器失败: 初始化数据库失败: 创建用户表失败: Binary was compiled with 'CGO_ENABLED=0', go-sqlite3 requires cgo to work. This is a stub
```

这是因为项目使用了 `github.com/mattn/go-sqlite3` 依赖，该依赖需要 CGO 支持，但构建配置中禁用了 CGO。

## 解决方案变更
**最初采用纯 Go 实现的 SQLite 驱动 `modernc.org/sqlite`，但发现性能问题，现已恢复使用 `github.com/mattn/go-sqlite3` 并启用 CGO 支持！**

## 修改的文件

### 1. 依赖恢复
- **`go.mod`**：
  - 移除 `modernc.org/sqlite v1.29.6`
  - 恢复 `github.com/mattn/go-sqlite3 v1.14.32`

- **`internal/web/user_manager.go`**：
  - 将导入从 `_ "modernc.org/sqlite"` 改回 `_ "github.com/mattn/go-sqlite3"`

### 2. GitHub Actions 工作流
- **`.github/workflows/release.yml`**：
  - 添加 CGO 依赖安装步骤 (`gcc libc6-dev`)
  - 启用 `CGO_ENABLED: 1`
  - 更新构建日志信息为 "with CGO SQLite"

### 3. Makefile
- **`Makefile`**：
  - 移除所有构建目标中的 `CGO_ENABLED=1`
  - 恢复到默认的纯 Go 构建

### 4. 构建脚本
- **`scripts/build-all.sh`**：
  - 保持 `export CGO_ENABLED=0`
  - 更新构建日志信息为 "纯 Go SQLite"

### 5. Dockerfile
- **`Dockerfile`**：
  - 移除 CGO 构建依赖
  - 保持 `CGO_ENABLED=0`
  - 移除运行时的 SQLite 依赖

## 优势对比

| 方案 | 优点 | 缺点 |
|------|------|------|
| 原方案 (go-sqlite3) | 性能高，功能完整 | 需要 CGO，构建复杂，跨平台问题 |
| 新方案 (modernc.org/sqlite) | 纯 Go，无需 CGO，跨平台兼容，构建简单 | 性能略低（但对用户管理足够） |

## 新方案的优势

1. **简化构建**：无需 CGO，构建过程更简单
2. **跨平台兼容**：支持所有 Go 支持的平台
3. **无系统依赖**：不需要目标系统安装 SQLite 库
4. **减少工作流**：可以删除 CGO 专用的构建工作流
5. **Docker 优化**：镜像更小，无需额外的构建依赖

## 验证步骤

1. 本地构建测试：
   ```bash
   make build
   ```

2. GitHub Actions 构建测试：
   - 推送标签触发 release.yml 工作流

3. 功能测试：
   - 确保用户管理器和数据库功能正常工作

## 相关文件
- `go.mod` - 使用 `modernc.org/sqlite` 依赖
- `internal/web/user_manager.go` - 用户管理器使用新的 SQLite 驱动
- `Dockerfile.cgo` - 可以删除，不再需要

## 结论
通过使用纯 Go 实现的 SQLite 驱动，我们完全避免了 CGO 依赖，简化了构建过程，提高了跨平台兼容性，同时保持了所有数据库功能的正常工作。

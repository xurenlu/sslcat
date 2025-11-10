# 模板自动化测试工具

用于自动测试所有模板服务是否能成功部署运行的测试工具。

## 功能特性

- ✅ Docker 镜像可用性检查
- ✅ Docker Compose 配置验证
- ✅ 容器启动测试
- ✅ 端口可访问性检查
- ✅ 网页内容关键词验证
- ✅ 并发测试支持
- ✅ 详细的 JSON 报告和控制台输出

## 使用方法

### 基本用法

```bash
# 测试所有模板
cd tools/test-templates
go run .

# 测试指定分类
go run . --category tools

# 测试单个模板
go run . --template satis

# 并行测试（默认 3 个并发）
go run . --parallel 5

# 指定输出目录
go run . --output-dir /tmp/test-results

# 跳过镜像检查（加快测试速度）
go run . --skip-image-check

# 跳过内容验证
go run . --skip-content-check
```

### 命令行参数

- `--templates-dir`: 模板目录路径（默认：`internal/runner/templates/builtin`）
- `--category`: 按分类过滤（可选）
- `--template`: 测试单个模板（可选）
- `--parallel`: 并发数（默认：3）
- `--output-dir`: 输出目录（默认：`./test-results`）
- `--timeout`: 容器启动超时（默认：5m）
- `--base-port`: 测试端口起始值（默认：20000）
- `--skip-image-check`: 跳过镜像检查
- `--skip-content-check`: 跳过内容验证
- `--cleanup`: 测试后清理容器（默认：true）

### 环境变量

- `TEST_BASE_PORT`: 测试端口起始值（默认：20000）
- `TEST_DOMAIN_SUFFIX`: 测试域名后缀（默认：`.test.local`）
- `GITHUB_TOKEN` 或 `GITHUB_PAT`: GitHub Personal Access Token（用于访问 ghcr.io 私有镜像）
- `GITHUB_USERNAME`: GitHub 用户名（可选，如果未设置则使用 token 作为用户名）

## 测试流程

1. **扫描模板** - 扫描并解析所有模板文件
2. **镜像检查** - 检查 Docker 镜像是否存在
3. **生成 Compose** - 生成测试用的 docker-compose.yml
4. **启动容器** - 启动 Docker 容器并等待健康检查
5. **端口检查** - 验证端口是否可访问
6. **内容验证** - 检查网页是否包含产品关键词
7. **清理环境** - 停止并清理容器

## 测试报告

测试完成后会生成：

- `test-results.json` - 详细的 JSON 格式测试报告
- 控制台输出 - 实时测试进度和汇总统计

## GitHub Container Registry (ghcr.io) 认证

如果模板使用了 `ghcr.io` 的镜像，可能需要 GitHub Personal Access Token 才能访问：

### 创建 GitHub Personal Access Token

1. 访问 GitHub Settings → Developer settings → Personal access tokens → Tokens (classic)
2. 点击 "Generate new token (classic)"
3. 设置权限：
   - `read:packages` - 读取 GitHub Packages
4. 生成并复制 token

### 使用 Token

```bash
# 方式1: 使用 GITHUB_TOKEN 环境变量
export GITHUB_TOKEN=your_github_pat_token
go run .

# 方式2: 使用 GITHUB_PAT 环境变量
export GITHUB_PAT=your_github_pat_token
go run .

# 可选：设置 GitHub 用户名（如果不设置，会使用 token 作为用户名）
export GITHUB_USERNAME=your_github_username
```

测试工具会在检测到 `ghcr.io` 镜像时自动尝试登录，如果设置了 token，会自动处理认证。

## 注意事项

- 需要 Docker 和 docker-compose 已安装并运行
- 需要足够的磁盘空间和内存
- 建议在专用测试服务器上运行
- 测试会创建临时容器和网络，测试完成后会自动清理
- 对于 ghcr.io 私有镜像，需要设置 `GITHUB_TOKEN` 或 `GITHUB_PAT` 环境变量


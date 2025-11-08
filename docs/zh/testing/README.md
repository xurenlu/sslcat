# 模板自动化测试指南

本文档说明如何在 `sg2.shifen.de` 测试机上运行模板自动化测试。

## 快速开始

### 1. 设置测试服务器环境

```bash
cd docs/zh/testing
bash setup-test-server.sh
```

这个脚本会：
- 检查 SSH 连接
- 安装 Docker、Docker Compose、Go、Git、jq 等必要工具
- 创建测试目录

### 2. 编译 SSLcat

```bash
# 编译 CGO 版本（推荐，支持 SQLite）
bash compile-sslcat.sh cgo

# 或编译标准版本
bash compile-sslcat.sh standard
```

### 3. 运行测试

```bash
# 测试所有优先级的模板
bash run-template-tests.sh all

# 只测试高优先级模板
bash run-template-tests.sh high

# 只测试中优先级模板
bash run-template-tests.sh medium

# 只测试低优先级模板
bash run-template-tests.sh low
```

## 测试配置

测试配置在 `template-test-config.json` 中：

```json
{
  "test_config": {
    "test_params": {
      "parallel": 2,           // 并发数（2-3）
      "timeout": "10m",        // 超时时间
      "base_port": 20000,     // 起始端口
      "cleanup": true         // 测试后清理
    }
  }
}
```

## 测试优先级

模板按优先级分为三类：

1. **高优先级**：AI 相关、企业常用工具（GitLab、Jenkins、Grafana 等）
2. **中优先级**：开发工具、数据库、CMS 等
3. **低优先级**：小众工具、实验性模板

测试会按优先级顺序执行，高优先级模板优先测试。

## 测试结果

### JSON 结果文件

测试完成后会生成 `test-results.json`，包含：

- `summary`: 测试汇总统计
- `results`: 每个模板的详细测试结果

### 查看结果

```bash
# 查看汇总
cat test-results.json | jq '.summary'

# 查看失败的模板
cat test-results.json | jq '.results[] | select(.status == "failed")'

# 查看镜像不存在的模板
cat test-results.json | jq '.results[] | select(.status == "skipped") | select(.errors[] | contains("镜像不存在"))'

# 按优先级统计
cat test-results.json | jq '.results | group_by(.priority) | map({priority: .[0].priority, total: length, passed: [.[] | select(.status == "passed")] | length})'
```

### 生成 Markdown 报告

```bash
# 使用报告生成工具（需要实现）
go run tools/test-templates/generate-report.go test-results.json template-test-results.md
```

## 手动测试单个模板

```bash
# SSH 到测试服务器
ssh root@sg2.shifen.de

# 进入项目目录
cd /opt/sslcat

# 编译测试工具
cd tools/test-templates
go build -o test-templates .

# 测试单个模板
./test-templates --template gitlab

# 测试特定分类
./test-templates --category devops

# 自定义参数
./test-templates \
  --template gitlab \
  --parallel 1 \
  --timeout 15m \
  --skip-image-check \
  --output-dir /tmp/test-results
```

## 测试工具参数

```bash
./test-templates --help

参数说明：
  --templates-dir: 模板目录路径（默认：internal/runner/templates/builtin）
  --category: 按分类过滤（可选）
  --template: 测试单个模板（可选）
  --priority: 只测试指定优先级（high/medium/low）
  --parallel: 并发数（默认：2）
  --output-dir: 输出目录（默认：./test-results）
  --timeout: 容器启动超时（默认：10m）
  --base-port: 测试端口起始值（默认：20000）
  --skip-image-check: 跳过镜像检查
  --skip-content-check: 跳过内容验证
  --cleanup: 测试后清理容器（默认：true）
```

## 故障排查

### SSH 连接失败

```bash
# 检查 SSH 配置
ssh -v root@sg2.shifen.de

# 配置 SSH 密钥
ssh-copy-id root@sg2.shifen.de
```

### Docker 镜像拉取失败

```bash
# 配置 Docker 镜像加速
ssh root@sg2.shifen.de
cat > /etc/docker/daemon.json << EOF
{
  "registry-mirrors": [
    "https://docker.mirrors.ustc.edu.cn",
    "https://hub-mirror.c.163.com"
  ]
}
EOF
systemctl restart docker
```

### 端口冲突

```bash
# 检查端口占用
ssh root@sg2.shifen.de "netstat -tlnp | grep 20000"

# 修改 base-port
./test-templates --base-port 30000
```

### 资源不足

```bash
# 检查系统资源
ssh root@sg2.shifen.de "free -h && df -h"

# 减少并发数
./test-templates --parallel 1

# 清理 Docker 资源
ssh root@sg2.shifen.de "docker system prune -a -f"
```

## 持续集成

可以将测试集成到 CI/CD 流程中：

```yaml
# .github/workflows/test-templates.yml
name: Test Templates

on:
  schedule:
    - cron: '0 2 * * *'  # 每天凌晨 2 点
  workflow_dispatch:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Template Tests
        run: |
          bash docs/zh/testing/run-template-tests.sh high
```

## 注意事项

1. **资源消耗**：测试会消耗大量磁盘空间和内存，建议在专用测试服务器上运行
2. **网络要求**：需要能够拉取 Docker 镜像，可能需要配置代理
3. **时间成本**：365 个模板的完整测试可能需要数小时甚至数天
4. **错误处理**：单个模板失败不会影响其他模板测试
5. **清理策略**：默认测试后会自动清理容器，避免资源浪费

## 相关文档

- [测试结果报告](template-test-results.md)
- [测试配置](template-test-config.json)
- [测试工具源码](../../../tools/test-templates/)


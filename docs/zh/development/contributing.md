# 贡献指南

欢迎为 SSLcat 项目做出贡献！本指南将帮助你了解如何参与项目开发。

## 贡献方式

### 1. 报告问题
- **Bug 报告**: 在 GitHub Issues 中报告发现的 bug
- **功能请求**: 提出新功能建议
- **文档改进**: 报告文档问题或改进建议

### 2. 代码贡献
- **修复 Bug**: 修复已知问题
- **新功能**: 实现新功能
- **性能优化**: 改进性能
- **代码重构**: 改进代码质量

### 3. 文档贡献
- **翻译**: 帮助翻译文档
- **示例**: 提供使用示例
- **教程**: 编写教程和指南

## 开发环境设置

### 系统要求
- **Go**: 1.21+
- **Git**: 2.0+
- **Docker**: 20.10+ (可选)
- **Make**: 3.0+ (可选)

### 克隆项目
```bash
# 克隆仓库
git clone https://github.com/xurenlu/sslcat.git
cd sslcat

# 添加上游仓库
git remote add upstream https://github.com/xurenlu/sslcat.git
```

### 安装依赖
```bash
# 安装 Go 依赖
go mod download

# 安装开发工具
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/air-verse/air@latest
```

### 构建项目
```bash
# 构建二进制文件
make build

# 或者使用 Go 命令
go build -o sslcat .

# 运行测试
make test

# 或者使用 Go 命令
go test ./...
```

## 开发流程

### 1. 创建分支
```bash
# 从主分支创建功能分支
git checkout main
git pull upstream main
git checkout -b feature/your-feature-name

# 或者创建修复分支
git checkout -b fix/your-bug-fix
```

### 2. 开发代码
```bash
# 使用热重载开发
air

# 或者手动运行
go run main.go -config examples/sslcat.conf
```

### 3. 运行测试
```bash
# 运行所有测试
make test

# 运行特定测试
go test ./internal/proxy/...

# 运行基准测试
go test -bench=. ./...

# 运行测试覆盖率
go test -cover ./...
```

### 4. 代码检查
```bash
# 运行代码检查
make lint

# 或者使用 golangci-lint
golangci-lint run

# 格式化代码
make fmt

# 或者使用 gofmt
gofmt -w .
```

### 5. 提交代码
```bash
# 添加更改
git add .

# 提交更改
git commit -m "feat: 添加新功能描述"

# 推送到你的分支
git push origin feature/your-feature-name
```

### 6. 创建 Pull Request
1. 在 GitHub 上创建 Pull Request
2. 填写详细的描述
3. 等待代码审查
4. 根据反馈进行修改

## 代码规范

### Go 代码规范
- 遵循 Go 官方代码规范
- 使用 `gofmt` 格式化代码
- 使用 `golint` 检查代码质量
- 编写单元测试和集成测试

### 提交信息规范
使用 Conventional Commits 规范：

```
<type>(<scope>): <description>

<body>

<footer>
```

**类型 (type)**:
- `feat`: 新功能
- `fix`: 修复 bug
- `docs`: 文档更改
- `style`: 代码格式更改
- `refactor`: 代码重构
- `test`: 测试相关
- `chore`: 构建过程或辅助工具的变动

**示例**:
```
feat(proxy): 添加负载均衡算法支持

- 添加轮询算法
- 添加最少连接算法
- 添加 IP 哈希算法

Closes #123
```

### 代码结构
```
sslcat/
├── cmd/                 # 命令行工具
├── internal/            # 内部包
│   ├── config/         # 配置管理
│   ├── proxy/          # 代理功能
│   ├── ssl/            # SSL 处理
│   ├── cache/          # 缓存功能
│   ├── monitoring/     # 监控功能
│   └── web/            # Web 服务器
├── pkg/                # 公共包
├── examples/           # 示例配置
├── docs/              # 文档
└── tests/             # 测试文件
```

## 测试指南

### 单元测试
```bash
# 运行单元测试
go test ./internal/...

# 运行特定包的测试
go test ./internal/proxy/

# 运行测试并显示覆盖率
go test -cover ./internal/...
```

### 集成测试
```bash
# 运行集成测试
go test ./tests/integration/...

# 使用 Docker 运行测试
docker-compose -f tests/docker-compose.yml up --abort-on-container-exit
```

### 性能测试
```bash
# 运行基准测试
go test -bench=. ./...

# 运行性能分析
go test -bench=. -cpuprofile=cpu.prof ./...
go tool pprof cpu.prof
```

## 文档贡献

### 文档结构
- 使用 Markdown 格式
- 遵循现有的文档结构
- 提供清晰的示例
- 保持中英文同步

### 文档类型
- **用户指南**: 面向最终用户
- **开发者指南**: 面向开发者
- **API 文档**: 面向 API 用户
- **教程**: 面向学习者

### 文档规范
- 使用清晰的标题结构
- 提供代码示例
- 包含截图和图表
- 保持内容更新

## 代码审查流程

### 审查标准
- **功能正确性**: 代码是否实现了预期功能
- **代码质量**: 代码是否清晰、可维护
- **测试覆盖**: 是否有足够的测试
- **文档更新**: 是否更新了相关文档

### 审查要点
- 代码逻辑是否正确
- 错误处理是否完善
- 性能是否有问题
- 安全性是否有漏洞
- 测试是否充分

## 发布流程

### 版本号规范
使用语义化版本号 (SemVer):
- **主版本号**: 不兼容的 API 修改
- **次版本号**: 向下兼容的功能性新增
- **修订号**: 向下兼容的问题修正

### 发布步骤
1. 更新版本号
2. 更新 CHANGELOG.md
3. 创建发布标签
4. 构建发布包
5. 发布到 GitHub Releases

## 社区参与

### 讨论渠道
- **GitHub Issues**: 问题讨论
- **GitHub Discussions**: 功能讨论
- **Pull Requests**: 代码讨论

### 行为准则
- 保持友好和尊重
- 提供建设性反馈
- 帮助新贡献者
- 遵循项目规范

## 获取帮助

### 常见问题
- 查看 [FAQ](../troubleshooting/common-issues.md)
- 搜索现有的 Issues
- 查看文档

### 联系方式
- **GitHub Issues**: 报告问题
- **GitHub Discussions**: 讨论功能
- **Email**: 联系维护者

## 贡献奖励

### 贡献者认可
- 在 README 中列出贡献者
- 在发布说明中提及贡献
- 提供贡献者徽章

### 长期贡献者
- 成为项目维护者
- 参与项目决策
- 获得更多权限

## 相关文档

- [架构设计](architecture.md)
- [测试指南](testing.md)
- [API 文档](../api/rest-api.md)
- [配置指南](../configuration/basic.md)

---

*感谢你为 SSLcat 项目做出贡献！你的参与让项目变得更好。*

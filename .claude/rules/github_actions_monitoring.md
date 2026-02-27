# GitHub Actions 自动监控和修复规则

所有 AI 助手必须遵循以下规则来监控和修复 GitHub Actions 构建失败：

## 1. 主动监控

- 定期检查 GitHub Actions 构建状态
- 使用提供的 `GITHUB_TOKEN` 访问 GitHub API
- 检查最近的构建运行状态

## 2. 失败分析

当构建失败时：
1. 获取失败的构建日志
2. 分析错误原因
3. 确定是代码问题还是配置问题
4. 检查是否有依赖问题

## 3. 自动修复

根据错误类型自动修复：

### 构建错误
- 编译错误 → 修复代码
- 类型错误 → 修复类型
- 依赖错误 → 更新依赖

### 配置错误
- 工作流语法错误 → 修复 `.github/workflows/*.yml`
- 环境配置错误 → 更新配置

### 测试失败
- 测试用例失败 → 修复代码或测试
- 超时错误 → 优化代码或增加超时

## 4. 修复流程

1. **修复代码**
   ```bash
   # 编辑问题文件
   # 本地测试构建
   go build .
   ```

2. **提交修复**
   ```bash
   git add .
   git commit -m "fix: 修复 GitHub Actions 构建失败

   - 详细描述修复内容

   🤖 Generated with [Claude Code](https://claude.com/claude-code)

   Co-Authored-By: Claude <noreply@anthropic.com>"
   git push origin main
   ```

3. **创建新版本标签触发构建**
   ```bash
   # 获取最新版本号
   git tag -l "v*" | sort -V | tail -1

   # 创建新标签 (版本号 + 1)
   git tag v1.3.XX -a -m "Release v1.3.XX: 修复说明"
   git push origin v1.3.XX
   ```

## 5. API 端点

使用以下端点监控构建：

```bash
# 获取最近的构建运行
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/repos/xurenlu/sslcat/actions/runs?per_page=5"

# 获取特定运行的作业
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/repos/xurenlu/sslcat/actions/runs/{run_id}/jobs"

# 获取构建日志
curl -L -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/repos/xurenlu/sslcat/actions/runs/{run_id}/logs"
```

## 6. 常见问题修复

### Yarn/pnpm 问题
- 检查 `package.json` 中的包管理器配置
- 确保工作流使用正确的包管理器
- 添加 Corepack 支持如果使用 Yarn 4+

### Go 构建问题
- 检查 `go.mod` 版本
- 验证 CGO 设置
- 检查交叉编译配置

### 前端构建问题
- 确保依赖正确安装
- 检查构建输出目录
- 验证资源复制路径

## 7. 环境变量

- `GITHUB_TOKEN`: 从用户获取或使用环境变量
- `GITHUB_REPO`: `xurenlu/sslcat`

**重要**: 不要将 GitHub Token 写入版本控制的文件中。使用环境变量或从用户获取。

## 8. 注意事项

- 所有修复必须先在本地测试
- 提交信息应清晰描述问题
- 版本号应递增
- 修复后必须推送新标签触发构建
- 如果无法自动修复，向用户报告问题详情

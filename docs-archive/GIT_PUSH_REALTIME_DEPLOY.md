# Git Push 实时部署日志功能

## 功能概述

实现了类似 Heroku/Vercel 的 `git push` 体验：在推送代码时，实时显示完整的部署流程，包括：

1. ✅ 推送进度（Git 自带）
2. ✅ 提交信息展示（commit、author、branch）
3. ✅ 仓库更新状态
4. ✅ 实时部署日志流式输出
5. ✅ 彩色格式化输出
6. ✅ 部署完成后显示访问地址

## 效果预览

当你执行 `git push` 时，会看到类似这样的输出：

```bash
$ git push deploy main

Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 8 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 342 bytes | 342.00 KiB/s, done.
Total 3 (delta 2), reused 0 (delta 0), pack-reused 0
remote: 
remote: ╔═══════════════════════════════════════════════════════════════╗
remote: ║                    SSLcat Git Deploy                          ║
remote: ╚═══════════════════════════════════════════════════════════════╝
remote: 
remote: Application: myapp
remote: Commit:      a3f2c1b - Add new feature
remote: Author:      John Doe
remote: Branch:      main
remote: 
remote: -----> Updating repository
remote:        ✓ Repository updated
remote: 
remote: -----> Deploying application
remote:        Waiting for deployment to start...
remote:        Streaming deployment logs...
remote: 
remote:        [git] 开始检测应用类型
remote:        [git] 检测到应用类型: nodejs
remote:        [build] 执行命令: npm install
remote:        [build] npm install 输出...
remote:        [build] 执行命令: npm run build
remote:        [build] npm run build 输出...
remote:        [deploy] 启动应用...
remote:        [deploy] 应用启动成功，端口: 8001
remote:        [deploy] 部署成功
remote: 
remote: ╔═══════════════════════════════════════════════════════════════╗
remote: ║                    Deployment Complete                         ║
remote: ╚═══════════════════════════════════════════════════════════════╝
remote: 
remote: Application URL:
remote:   https://myapp.example.com
remote: 
remote: Admin Panel:
remote:   http://localhost:9942/sslcat-panel2
remote: 
remote: View Logs:
remote:   tail -f /path/to/logs/deploy-2024-10-04.log
remote: 
remote:        ✓ Push accepted and deployed to https://myapp.example.com
remote: 
To server.com:myapp.git
   d2e1f0c..a3f2c1b  main -> main
```

## 功能特性

### 1. 彩色输出

使用 ANSI 颜色码美化输出：
- 🔵 **蓝色**: 标题和重要信息
- 🟢 **绿色**: 成功状态和 info 级别日志
- 🟡 **黄色**: 警告信息
- 🔴 **红色**: 错误信息
- 🔵 **青色**: 元数据标签

### 2. 实时日志流

- 监控部署日志文件的变化
- 实时解析并格式化输出
- 支持 JSON 和纯文本格式
- 根据日志级别使用不同颜色

### 3. 智能日志解析

自动解析 JSON 格式的日志：
```json
{
  "timestamp": "2024-10-04T16:20:00Z",
  "level": "info",
  "source": "build",
  "message": "构建成功"
}
```

格式化输出为：
```
       [build] 构建成功
```

### 4. 智能超时机制

采用双重超时保护：
- **空闲超时**: 30 秒内没有新日志输出时退出（说明部署可能卡住或已完成）
- **最大总时间**: 最长等待 10 分钟（防止无限等待）
- **自动检测**: 识别"部署成功"、"部署完成"等关键词自动退出
- **持续监控**: 只要有新日志就持续等待，不受时间限制

这意味着：
✅ 部署 5 分钟、10 分钟都没问题，只要持续有日志输出
✅ 如果 30 秒没有任何日志，会提示可能完成或卡住
✅ 超过 10 分钟会强制退出，但部署仍在后台继续

### 5. 完整信息展示

**推送信息**：
- 应用名称
- Commit SHA（短格式）
- Commit 消息
- 作者
- 分支名称

**部署结果**：
- 应用访问地址（HTTP/HTTPS）
- 管理面板地址
- 日志文件路径

## 实现原理

### 1. Post-Receive Hook

Git 的 post-receive hook 会在推送完成后执行，hook 的标准输出会直接显示给执行 `git push` 的用户。

### 2. 日志监控

Hook 脚本通过以下方式实时获取部署日志：

```bash
# 记录当前日志文件大小
START_POS=$(wc -c < "$DEPLOY_LOG")

# 循环检查新增内容
while [ $ELAPSED -lt $TIMEOUT ]; do
    CURRENT_POS=$(wc -c < "$DEPLOY_LOG")
    
    if [ $CURRENT_POS -gt $START_POS ]; then
        # 读取新增的日志内容
        NEW_LOGS=$(tail -c +$((START_POS + 1)) "$DEPLOY_LOG")
        
        # 格式化并输出
        echo "$NEW_LOGS" | while read -r line; do
            # 解析和格式化...
        done
        
        START_POS=$CURRENT_POS
    fi
    
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done
```

### 3. 异步部署触发

Hook 通过创建触发文件来启动部署：

```bash
DEPLOY_TRIGGER="/tmp/sslcat-deploy-$APP_NAME-$(date +%s)"
echo "$newrev|$refname|$COMMIT_MSG" > "$DEPLOY_TRIGGER"
```

SSLcat 主进程会监控这些触发文件并执行部署。

## 配置说明

### 自动配置

功能完全自动化，无需任何配置：
- 创建应用时自动生成优化的 hook 脚本
- 颜色输出自动适配终端
- 日志路径自动配置

### 手动调整（可选）

如果需要调整超时时间，可以编辑 hook 脚本：

```bash
# Hook 脚本位置
/path/to/repos/{appname}/git/hooks/post-receive

# 可调整参数
MAX_TOTAL_TIME=600    # 最长总等待时间（秒），默认 10 分钟
IDLE_TIMEOUT=120      # 无新日志超时时间（秒），默认 120 秒 (2分钟)
```

**推荐配置**：
- 小型项目（Node.js 静态站）: `MAX_TOTAL_TIME=300` (5分钟), `IDLE_TIMEOUT=60` (1分钟)
- 中型项目（React/Vue SPA）: `MAX_TOTAL_TIME=600` (10分钟), `IDLE_TIMEOUT=120` (2分钟)
- 大型项目（Go/Java 后端）: `MAX_TOTAL_TIME=1200` (20分钟), `IDLE_TIMEOUT=180` (3分钟)
- Docker 构建项目: `MAX_TOTAL_TIME=1800` (30分钟), `IDLE_TIMEOUT=300` (5分钟)

## 兼容性

### 终端支持

- ✅ **Linux/macOS**: 完全支持 ANSI 颜色
- ✅ **Windows Git Bash**: 支持 ANSI 颜色
- ✅ **Windows CMD**: 部分支持（可能无颜色）
- ✅ **CI/CD 环境**: 自动降级为纯文本输出

### Git 版本

- 要求 Git 2.0+
- 推荐 Git 2.20+

## 使用示例

### 基本推送

```bash
git push deploy main
```

### 推送到其他分支

```bash
git push deploy feature-branch
```

### 强制推送

```bash
git push deploy main --force
```

## 故障排查

### 1. 看不到彩色输出

**原因**: 终端不支持 ANSI 颜色

**解决**: 使用支持颜色的终端，或检查 `TERM` 环境变量：
```bash
echo $TERM
# 应该返回类似 xterm-256color
```

### 2. 部署日志未显示

**原因**: 部署尚未开始或日志文件路径错误

**解决**: 
1. 检查 sslcat 服务是否运行
2. 查看部署触发文件是否创建：`ls /tmp/sslcat-deploy-*`
3. 手动查看日志：`tail -f /path/to/logs/deploy-*.log`

### 3. 日志监控提前退出

**现象**: 看到 "No new logs for 120s (2 min)" 提示

**原因**: 
1. 部署可能已完成但没有输出"部署成功"关键词
2. 部署进程卡住，120秒内没有任何日志输出
3. 日志写入延迟
4. 构建工具在编译或下载依赖时长时间静默

**解决**: 
1. 检查 Web 管理面板的应用状态
2. 手动查看完整日志：`tail -f /path/to/logs/deploy-*.log`
3. 如果经常出现，可以进一步增加 `IDLE_TIMEOUT` 值（如 180秒=3分钟）

### 4. 权限问题

**原因**: Hook 脚本没有执行权限

**解决**:
```bash
chmod +x /path/to/repos/{appname}/git/hooks/post-receive
```

## 与其他 PaaS 对比

| 功能 | SSLcat | Heroku | Vercel | Railway |
|------|---------|--------|--------|---------|
| 实时日志 | ✅ | ✅ | ✅ | ✅ |
| 彩色输出 | ✅ | ✅ | ✅ | ✅ |
| 提交信息 | ✅ | ✅ | ✅ | ✅ |
| 访问地址 | ✅ | ✅ | ✅ | ✅ |
| 自托管 | ✅ | ❌ | ❌ | ❌ |

## 技术细节

### Hook 脚本结构

1. **颜色定义**: ANSI escape codes
2. **辅助函数**: print_header, print_info, print_success, print_error
3. **推送信息获取**: git log, git rev-parse
4. **仓库更新**: git fetch, git reset
5. **部署触发**: 创建触发文件
6. **日志监控**: tail -c, wc -c
7. **JSON 解析**: grep -o, cut
8. **状态检测**: 关键词匹配

### 性能考虑

- **日志读取**: 增量读取，不重复处理
- **轮询间隔**: 1 秒一次，平衡实时性和性能
- **智能超时**: 
  - 空闲超时：120 秒（2分钟）无新日志则退出
  - 最大时间：10 分钟总时间限制
  - 持续监控：有日志就继续，无时间限制
- **内存占用**: 流式处理，不缓存全部日志

### 超时机制详解

为了平衡用户体验和资源消耗，我们实现了智能的双重超时机制：

#### 1. 空闲超时（Idle Timeout）

**默认值**: 120 秒（2 分钟）  
**触发条件**: 连续 120 秒没有任何新日志输出  
**行为**: 显示警告并退出，但部署继续在后台运行

```bash
⚠ No new logs for 120s (2 min), deployment may still be running in background
  Check admin panel or logs for details: tail -f /path/to/deploy.log
```

**适用场景**:
- 部署已完成但没有输出完成关键词
- 部署进程卡住或出错
- 构建工具在编译/下载时长时间无输出
- 需要用户介入检查

**为什么增加到2分钟？**
- 很多构建工具（npm、go build、docker build）在编译或下载依赖时可能1-2分钟无输出
- 30秒太短，容易在正常构建中触发"假警报"
- 2分钟能更好地平衡用户体验和异常检测

#### 2. 最大总时间（Max Total Time）

**默认值**: 600 秒（10 分钟）  
**触发条件**: 从开始监控到达 10 分钟  
**行为**: 显示超时警告并强制退出

```bash
⚠ Deployment timeout after 600s, but may still be running
  Check admin panel or logs for status
```

**适用场景**:
- 超长构建时间（如 Docker 镜像）
- 防止永久挂起占用连接

#### 3. 自动完成检测

**触发关键词**:
- "部署成功"
- "部署完成"  
- "deployment success"
- "deployment complete"
- "部署失败"
- "deployment failed"

**行为**: 立即退出，显示完成信息

#### 工作流程

```
开始监控
    ↓
每秒检查一次日志
    ↓
有新日志? → 是 → 输出日志 + 重置空闲计时 → 继续监控
    ↓
   否
    ↓
空闲时间 ≥ 30s? → 是 → 退出（提示可能完成）
    ↓
   否
    ↓
总时间 ≥ 10分钟? → 是 → 强制退出（提示超时）
    ↓
   否
    ↓
发现完成关键词? → 是 → 退出（显示成功）
    ↓
   否
    ↓
继续监控
```

#### 实际示例

**场景 1: 快速部署（30秒）**
```
实际部署时间: 28秒
监控时间: 28秒
结果: 检测到"部署成功"，立即退出 ✓
```

**场景 2: 中等部署（3分钟）**
```
实际部署时间: 3分15秒
监控时间: 3分15秒
结果: 持续有日志输出，正常完成 ✓
```

**场景 3: 大型部署（8分钟）**
```
实际部署时间: 8分钟
监控时间: 8分钟
结果: 持续有日志输出，正常完成 ✓
```

**场景 4: 超大部署（15分钟）**
```
实际部署时间: 15分钟
监控时间: 10分钟
结果: 达到最大时间，退出但部署继续 ⚠
提示: 用户可通过 Web 面板或日志查看最终结果
```

**场景 5: 部署卡住**
```
实际情况: 构建进程挂起
监控时间: 30秒
结果: 30秒无新日志，提示并退出 ⚠
```

## 未来改进

- [ ] 支持进度条显示
- [ ] 支持部署历史对比
- [ ] 支持 WebSocket 实时推送（无轮询）
- [ ] 支持彩色 emoji 图标
- [ ] 支持多阶段部署可视化
- [ ] 支持部署时长统计

## 相关文档

- [Git Deploy 快速入门](docs/git-deploy-quickstart.md)
- [Git SSH 符号链接修复](GIT_SSH_SYMLINK_FIX.md)
- [Git 用户自动创建](GIT_USER_AUTO_CREATE.md)

## 贡献

这个功能的实现参考了：
- [Heroku Git Push 体验](https://devcenter.heroku.com/articles/git)
- [Vercel Deploy 输出](https://vercel.com/docs/cli#commands/git)
- [Railway Deploy Logs](https://docs.railway.app/deploy/deployments)

欢迎提交 PR 改进这个功能！


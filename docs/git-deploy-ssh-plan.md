# Git 部署服务 SSH 收包计划

## 目标
- 支持开发者通过 `git push ssh://git@sslcat/...` 直接向 SSLcat 推送代码
- 自动创建或更新 Git 应用，并触发构建/部署
- 提供安全的 SSH 密钥授权机制和操作审计

## 阶段划分

### 阶段 1：SSH 基础设施搭建 ✅ 已完成
- [x] 确认/创建 `git` 用户（若缺失给出提示，而不是强依赖 root）
- [x] 自动创建 `~/.ssh`、`authorized_keys`，写入 `command="git-shell -c \"$SSH_ORIGINAL_COMMAND\""`
- [x] 生成 SSHD 限制配置（禁止端口转发/X11，仅允许 git-shell）
- [x] 初始化 `git-shell-commands` 目录，阻止交互式登录

### 阶段 2：仓库初始化与接收脚本 ✅ 已完成
- [x] `CreateApp` 初始化裸仓库 + 工作目录
- [x] `initGitRepo` 完成 `git init --bare` 并初始克隆到工作目录
- [x] `setupGitHooks` 写入 `pre-receive` / `update` / `post-receive` / `receive-pack` 包装脚本
- [x] 钩子中记录推送日志并调用 `processGitPush`
- [x] 如果推送的 app 不存在，自动调用 `CreateApp` ✅ **已实现**

### 阶段 3：构建与部署流水线 ✅ 已完成
- [x] `processGitPush` 整合部署日志（DeployLogger）与实时日志流
- [x] 检测应用类型并调用 `buildAndDeploy*WithLogging`
- [x] 成功/失败写回状态，触发 `handleDeploySuccess` / `handleDeployError`
- [x] 构建失败时向 `git push` 返回非零状态码 ✅ **已实现**

### 阶段 4：安全与审计 ✅ 已完成
- [x] 基本推送日志记录（时间、部署ID、状态）
- [x] 校验推送应用与 SSH 密钥绑定关系 ✅ **已实现**
- [x] 限制推送大小/并发/超时 ✅ **已实现**
- [x] Web UI 展示最近推送记录、失败原因 ✅ **API已实现**

## 已完成的关键事项
- GitApp 结构扩展（裸仓库、工作目录、日志路径、环境变量等字段）
- CreateApp / initGitRepo：裸仓库和工作目录完整初始化
- setupGitHooks：自动生成完整钩子和 receive-pack 包装脚本
- processGitPush：整合部署流水线、实时日志
- 环境变量 / 域名 / 端口管理与部署流程联动

## TODO 备忘
- [x] 推送权限模型：密钥绑定、App 名称空间管理 ✅ **已实现**
- [x] 针对 `git push` 的错误反馈（失败时返回非零 exit code） ✅ **已实现**
- [x] Web UI：展示最近 push / 构建历史 ✅ **API已实现**
- [ ] 自动化测试：模拟 `git push` 并验证部署结果（待实现）

## 新增功能
- [x] 推送记录管理（PushRecord 结构和历史记录）
- [x] SSH 密钥绑定管理（BindKeyToApp / UnbindKeyFromApp）
- [x] 推送权限验证（CheckPushPermission）
- [x] 部署触发监听（WatchDeployTriggers）
- [x] 完整的 Git 钩子脚本生成
- [x] 推送大小限制（默认100MB）
- [x] API 接口完善（推送历史、密钥绑定）

## 备注
- 参考 Dokku/Heroku：`receive` 脚本 + `gitreceive` 子系统
- 需要关注容器化部署的权限问题（如 Docker 环境）
- 后续可扩展：多分支部署、预览环境、Webhook 通知

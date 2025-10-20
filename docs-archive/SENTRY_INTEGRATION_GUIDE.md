# Sentry 错误监控集成指南

本项目已集成 Sentry 前端错误监控，用于收集和追踪生产环境中的错误。

## 📋 目录

1. [功能特性](#功能特性)
2. [快速开始](#快速开始)
3. [配置说明](#配置说明)
4. [Source Maps 上传](#source-maps-上传)
5. [测试验证](#测试验证)
6. [常见问题](#常见问题)

---

## ✨ 功能特性

本项目的 Sentry 集成包含以下功能：

✅ **自动错误捕获**
- React 组件错误（通过 ErrorBoundary）
- 未捕获的 JavaScript 错误
- 未处理的 Promise 拒绝
- API 请求错误（5xx、401、403）

✅ **用户追踪**
- 登录时自动设置用户信息
- 登出时自动清除用户信息
- 关联错误到具体用户

✅ **调试上下文**
- API 请求/响应面包屑
- 用户操作路径
- 自动过滤敏感信息（密码、token 等）

✅ **性能监控**
- 页面加载性能
- API 响应时间
- 用户交互性能

✅ **会话重放**（可选）
- 记录用户操作视频
- 错误发生时自动保存重放
- 隐私保护（自动遮蔽输入框）

✅ **用户反馈**
- 用户可主动提交问题反馈
- 关联到错误事件

---

## 🚀 快速开始

### 第 1 步：注册 Sentry 账号

1. 访问 [https://sentry.io](https://sentry.io)
2. 注册账号（可使用 GitHub/Google 登录）
3. 创建新组织（Organization）

### 第 2 步：创建项目

1. 点击 "Create Project"
2. 选择平台：**React**
3. 设置告警频率：推荐 "Alert me on every new issue"
4. 项目名称：`sslcat-frontend`
5. 点击 "Create Project"

### 第 3 步：获取 DSN

创建项目后，Sentry 会显示 DSN，格式类似：

```
https://abc123def456@o123456.ingest.sentry.io/789012
```

复制这个 DSN。

### 第 4 步：配置环境变量

在 `frontend` 目录创建 `.env.production.local` 文件：

```bash
cd frontend
cp .env.production.example .env.production.local
```

编辑 `.env.production.local`，填入你的 DSN：

```bash
# 替换为你的真实 DSN
VITE_SENTRY_DSN=https://abc123def456@o123456.ingest.sentry.io/789012

# 环境标识
VITE_SENTRY_ENVIRONMENT=production

# 启用 Sentry
VITE_SENTRY_ENABLED=true

# 采样率（可选，默认值）
VITE_SENTRY_TRACES_SAMPLE_RATE=0.1
VITE_SENTRY_REPLAYS_SESSION_SAMPLE_RATE=0.1
```

### 第 5 步：构建前端

```bash
cd frontend
yarn build
```

### 第 6 步：部署

将 `frontend/dist` 目录部署到你的服务器。Sentry 将在生产环境自动启用。

### 第 7 步：验证

部署后：
1. 访问你的网站
2. 打开浏览器控制台，应该看到：`[Sentry] Initialized successfully`
3. 在 Sentry 控制台查看是否有事件上报

---

## ⚙️ 配置说明

### 环境变量

| 变量名 | 说明 | 默认值 | 必填 |
|--------|------|--------|------|
| `VITE_SENTRY_DSN` | Sentry 项目 DSN | - | ✅ 生产环境必填 |
| `VITE_SENTRY_ENVIRONMENT` | 环境标识 | `production` | ❌ |
| `VITE_SENTRY_ENABLED` | 是否启用 | `false`（开发）<br>`true`（生产） | ❌ |
| `VITE_SENTRY_TRACES_SAMPLE_RATE` | 性能追踪采样率 | `0.1` (10%) | ❌ |
| `VITE_SENTRY_REPLAYS_SESSION_SAMPLE_RATE` | 会话重放采样率 | `0.1` (10%) | ❌ |
| `VITE_APP_VERSION` | 应用版本号 | 从 `package.json` 读取 | ❌ |

### 不同环境的配置

#### 开发环境（默认禁用）

开发环境默认不启用 Sentry。如需测试，创建 `.env.development.local`：

```bash
# 开发环境测试 Sentry
VITE_SENTRY_DSN=your-dsn-here
VITE_SENTRY_ENABLED=true
VITE_SENTRY_ENVIRONMENT=development
```

#### 预发布环境

创建 `.env.staging.local`：

```bash
VITE_SENTRY_DSN=your-dsn-here
VITE_SENTRY_ENABLED=true
VITE_SENTRY_ENVIRONMENT=staging
VITE_SENTRY_TRACES_SAMPLE_RATE=0.5  # 预发布可以提高采样率
```

#### 生产环境

创建 `.env.production.local`（见上文第 4 步）。

### 采样率建议

| 流量规模 | 性能追踪 | 会话重放 |
|---------|---------|---------|
| 小型（< 1000 DAU） | 0.5 (50%) | 0.2 (20%) |
| 中型（1000-10000 DAU） | 0.1 (10%) | 0.1 (10%) |
| 大型（> 10000 DAU） | 0.05 (5%) | 0.05 (5%) |

注意：
- Sentry 免费版限制：**5000 错误/月**
- 会话重放消耗较多配额，谨慎设置

---

## 📦 Source Maps 上传

为了在 Sentry 中看到原始的 TypeScript 代码行号（而不是编译后的代码），需要上传 Source Maps。

### 方案 1：手动上传（推荐开始）

#### 安装 Sentry CLI

```bash
# macOS
brew install getsentry/tools/sentry-cli

# 或通过 npm
npm install -g @sentry/cli
```

#### 配置认证

创建 `~/.sentryclirc`：

```ini
[auth]
token=your-auth-token-here

[defaults]
org=your-org-slug
project=sslcat-frontend
```

获取 Auth Token：
1. 访问 https://sentry.io/settings/account/api/auth-tokens/
2. 点击 "Create New Token"
3. 权限选择：`project:read`, `project:releases`, `org:read`
4. 复制 token

#### 上传 Source Maps

构建后上传：

```bash
cd frontend

# 构建
yarn build

# 上传 source maps
sentry-cli releases new "$(node -p "require('./package.json').version")"
sentry-cli releases files "$(node -p "require('./package.json').version")" upload-sourcemaps ./dist/assets --url-prefix '~/assets'
sentry-cli releases finalize "$(node -p "require('./package.json').version")"
```

### 方案 2：自动上传（推荐生产）

#### 安装 Vite 插件

```bash
cd frontend
yarn add --dev @sentry/vite-plugin
```

#### 配置 `vite.config.ts`

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { sentryVitePlugin } from '@sentry/vite-plugin'

export default defineConfig({
  plugins: [
    react(),
    // 只在生产构建时上传 source maps
    process.env.NODE_ENV === 'production' && sentryVitePlugin({
      org: 'your-org-slug',
      project: 'sslcat-frontend',
      authToken: process.env.SENTRY_AUTH_TOKEN,
      
      // 可选配置
      include: './dist/assets',
      ignore: ['node_modules'],
      cleanArtifacts: true, // 上传后删除本地 source maps
    }),
  ].filter(Boolean),
  
  // ... 其他配置
})
```

#### 设置环境变量

```bash
export SENTRY_AUTH_TOKEN=your-auth-token-here
```

#### 构建

```bash
yarn build
# Source maps 将自动上传到 Sentry
```

### 验证 Source Maps

1. 在你的应用中触发一个错误
2. 在 Sentry 控制台查看错误详情
3. 检查堆栈跟踪是否显示原始的 TypeScript 代码和行号

---

## 🧪 测试验证

### 在开发环境测试

1. 创建 `.env.development.local`：

```bash
VITE_SENTRY_DSN=your-dsn-here
VITE_SENTRY_ENABLED=true
VITE_SENTRY_ENVIRONMENT=development
```

2. 启动开发服务器：

```bash
yarn dev
```

3. 打开浏览器控制台，应该看到：

```
[Sentry] Initialized successfully
```

### 测试错误捕获

在浏览器控制台执行：

```javascript
// 测试未捕获错误
throw new Error('测试错误捕获')

// 测试 Promise 拒绝
Promise.reject('测试 Promise 错误')

// 测试手动上报
import { captureMessage } from './utils/sentry'
captureMessage('手动测试消息', 'info')
```

### 测试 React ErrorBoundary

在某个组件中故意抛出错误：

```tsx
function TestComponent() {
  throw new Error('测试 React 错误边界')
  return <div>不会渲染</div>
}
```

### 测试用户追踪

1. 登录系统
2. 触发一个错误
3. 在 Sentry 查看错误时，应该看到用户信息（username、role）

### 测试 API 错误

```javascript
// 在浏览器控制台
fetch('/api/nonexistent').catch(console.error)
```

---

## ❓ 常见问题

### Q1: 开发环境看不到 Sentry 日志

**A:** 开发环境默认禁用 Sentry。如需测试，设置环境变量：

```bash
VITE_SENTRY_ENABLED=true
```

### Q2: 生产环境仍然没有错误上报

**A:** 检查以下几点：
1. `.env.production.local` 是否正确配置了 DSN
2. 构建时是否读取到了环境变量（检查构建日志）
3. 浏览器控制台是否有 `[Sentry] Initialized successfully` 日志
4. 检查浏览器是否阻止了请求（查看 Network 面板）

### Q3: 超过免费额度怎么办

**A:** Sentry 免费版限制 5000 错误/月。超过后有两个选择：
1. 升级到付费版（最低 $26/月）
2. 降低采样率或关闭会话重放

### Q4: 能看到错误但行号不对

**A:** 需要上传 Source Maps。参见 [Source Maps 上传](#source-maps-上传)。

### Q5: 不想上传敏感信息怎么办

**A:** 已内置过滤器，自动移除：
- Cookies
- URL 中的 token、password、secret 等参数
- 额外数据中的敏感字段

可以在 `frontend/src/utils/sentry.ts` 的 `beforeSend` 函数中自定义过滤逻辑。

### Q6: 如何关闭会话重放

**A:** 在环境变量中设置：

```bash
VITE_SENTRY_REPLAYS_SESSION_SAMPLE_RATE=0
```

### Q7: 如何自托管 Sentry

**A:** 使用官方 Docker 部署：

```bash
git clone https://github.com/getsentry/self-hosted.git
cd self-hosted
./install.sh
```

然后将 DSN 指向你的自托管实例。

### Q8: 如何在特定页面禁用 Sentry

**A:** 在组件中动态控制：

```typescript
import { Sentry } from '@/utils/sentry'

// 禁用当前作用域
Sentry.getCurrentScope().setEnabled(false)

// 重新启用
Sentry.getCurrentScope().setEnabled(true)
```

---

## 📚 更多资源

- [Sentry 官方文档](https://docs.sentry.io/)
- [Sentry React 集成指南](https://docs.sentry.io/platforms/javascript/guides/react/)
- [Sentry 最佳实践](https://docs.sentry.io/product/best-practices/)
- [Source Maps 指南](https://docs.sentry.io/platforms/javascript/sourcemaps/)

---

## 🎯 总结

Sentry 集成已完成，现在你可以：

✅ 实时监控生产环境错误
✅ 追踪错误到具体用户
✅ 查看完整的调试上下文
✅ 接收错误告警通知
✅ 分析性能问题

只需配置 DSN，即可开始使用！

如有任何问题，欢迎提交 Issue。


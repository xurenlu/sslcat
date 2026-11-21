# 前端代理循环检测功能

## 概述

为了防止用户在配置代理时不小心将后端地址设置为 sslcat 自己的监听端口，导致无限循环和系统资源耗尽，我们在前端添加了实时的代理循环检测功能。

## 功能特性

### 1. 实时验证

在用户输入后端配置时，系统会实时检测：
- **本地地址检测**：识别 `localhost`、`127.0.0.1`、`::1`、`0.0.0.0` 等本地地址
- **端口冲突检测**：检查端口是否是 sslcat 监听的端口（80、443、8080、8443）
- **即时反馈**：一旦检测到循环配置，立即显示红色警告框

### 2. 多层防护

#### 2.1 输入时警告
在每个后端服务器配置卡片中，如果检测到循环配置，会显示：
```
⚠️ 检测到代理循环：后端地址 127.0.0.1:80 指向 sslcat 自己！这会导致无限循环和资源耗尽。
💡 建议：如果需要代理到本地服务，请使用其他端口（如 3000、8080 等）
```

#### 2.2 顶部总览警告
如果有多个后端配置了循环，在页面顶部会显示总览警告：
```
🚨 检测到 2 个代理循环配置
以下后端服务器配置会导致代理循环，请立即修改：
• 后端服务器 1
• 后端服务器 2
```

#### 2.3 提交时拦截
当用户尝试保存配置时，系统会再次验证：
- 如果存在循环配置，阻止提交
- 显示 Toast 提示，列出所有错误
- 用户必须修复所有循环配置才能保存

### 3. 智能识别

#### 3.1 本地地址识别
系统能识别以下本地地址格式：
- `localhost`
- `127.0.0.1`
- `127.x.x.x`（整个 127 网段）
- `::1`（IPv6 loopback）
- `0.0.0.0`
- `::`（IPv6 any）

#### 3.2 协议前缀处理
自动处理带协议前缀的地址：
- `http://localhost:80` → 识别为 `localhost:80`
- `https://127.0.0.1:443` → 识别为 `127.0.0.1:443`

#### 3.3 端口提取
从完整 URL 中提取端口：
- `http://localhost:3000/api` → 端口 3000
- `https://127.0.0.1` → 端口 443（默认）

## 技术实现

### 文件结构

```
frontend/src/
├── utils/
│   └── proxyLoopDetection.ts      # 循环检测核心逻辑
├── components/
│   └── BackendConfig.tsx          # 后端配置组件（添加了实时验证）
└── pages/
    ├── ProxyAdd.tsx               # 添加代理页面（添加了提交验证）
    └── ProxyEdit.tsx              # 编辑代理页面（添加了提交验证）
```

### 核心函数

#### `detectProxyLoop(host: string, port: number): string | null`
检测单个后端是否存在循环配置。

**参数：**
- `host`: 后端主机地址
- `port`: 后端端口

**返回：**
- 如果检测到循环，返回错误信息
- 如果没有问题，返回 `null`

**示例：**
```typescript
detectProxyLoop('127.0.0.1', 80)
// 返回: "⚠️ 检测到代理循环：后端地址 127.0.0.1:80 指向 sslcat 自己！..."

detectProxyLoop('127.0.0.1', 3000)
// 返回: null（安全）

detectProxyLoop('example.com', 80)
// 返回: null（不是本地地址）
```

#### `detectProxyLoopInBackends(backends: Array): string[]`
批量检测多个后端配置。

**参数：**
- `backends`: 后端配置数组

**返回：**
- 错误信息数组，每个元素对应一个有问题的后端

**示例：**
```typescript
detectProxyLoopInBackends([
  { host: '127.0.0.1', port: 80, enabled: true },
  { host: 'example.com', port: 80, enabled: true },
  { host: 'localhost', port: 443, enabled: true }
])
// 返回: [
//   "后端服务器 1: ⚠️ 检测到代理循环...",
//   "后端服务器 3: ⚠️ 检测到代理循环..."
// ]
```

#### `isLocalhost(host: string): boolean`
判断主机地址是否是本地地址。

#### `getSSLCatListeningPorts(): number[]`
获取 sslcat 监听的端口列表。

**当前实现：**
```typescript
return [80, 443, 8080, 8443]
```

**未来改进：**
可以从服务器 API 动态获取实际监听的端口。

## 用户体验

### 场景 1：用户输入循环配置

1. 用户在"服务器地址"输入 `127.0.0.1`
2. 用户在"端口"输入 `80`
3. **立即显示红色警告框**，提示循环配置
4. 用户看到建议，改为使用端口 `3000`
5. 警告消失，配置正常

### 场景 2：用户尝试保存循环配置

1. 用户配置了多个后端，其中一个是 `localhost:80`
2. 页面顶部显示总览警告
3. 用户点击"保存"按钮
4. **系统阻止提交**，显示 Toast 提示
5. Toast 中列出所有有问题的后端
6. 用户修复配置后才能成功保存

### 场景 3：编辑现有配置

1. 用户打开编辑页面
2. 如果现有配置有循环，**立即显示警告**
3. 用户可以看到哪些后端有问题
4. 修复后警告消失

## 配置示例

### ❌ 错误配置（会被拦截）

```json
{
  "domain": "example.com",
  "backends": [
    {
      "host": "127.0.0.1",
      "port": 80,
      "enabled": true
    }
  ]
}
```

**问题：** 代理到 sslcat 自己的 80 端口，形成循环。

### ❌ 错误配置（多种本地地址）

```json
{
  "domain": "example.com",
  "backends": [
    {
      "host": "localhost",
      "port": 443,
      "enabled": true
    },
    {
      "host": "127.0.0.1",
      "port": 80,
      "enabled": true
    }
  ]
}
```

**问题：** 两个后端都指向 sslcat 自己。

### ✅ 正确配置（本地服务，不同端口）

```json
{
  "domain": "example.com",
  "backends": [
    {
      "host": "127.0.0.1",
      "port": 3000,
      "enabled": true
    }
  ]
}
```

**说明：** 代理到本地的 3000 端口，这是一个独立的服务，不会形成循环。

### ✅ 正确配置（外部服务）

```json
{
  "domain": "example.com",
  "backends": [
    {
      "host": "backend.example.com",
      "port": 80,
      "enabled": true
    }
  ]
}
```

**说明：** 代理到外部服务器，不会形成循环。

### ✅ 正确配置（禁用的后端）

```json
{
  "domain": "example.com",
  "backends": [
    {
      "host": "127.0.0.1",
      "port": 80,
      "enabled": false
    },
    {
      "host": "backend.example.com",
      "port": 80,
      "enabled": true
    }
  ]
}
```

**说明：** 虽然第一个后端是循环配置，但它被禁用了，所以不会触发警告。

## 与后端验证的关系

### 双重保护

1. **前端验证（本功能）**
   - 优点：即时反馈，用户体验好
   - 缺点：可以被绕过（如果直接调用 API）

2. **后端验证**（已实现）
   - 优点：无法绕过，安全可靠
   - 缺点：只在提交时才能发现问题

### 配合使用

前端验证和后端验证配合使用，形成完整的防护体系：
- 前端：提供友好的用户体验，及时发现问题
- 后端：提供最终的安全保障，防止恶意绕过

## 未来改进

### 1. 动态获取监听端口

当前监听端口是硬编码的：
```typescript
return [80, 443, 8080, 8443]
```

**改进方案：**
从服务器 API 获取实际监听的端口：
```typescript
export async function getSSLCatListeningPorts(): Promise<number[]> {
  const response = await fetch('/api/system/listening-ports')
  const data = await response.json()
  return data.ports
}
```

### 2. 支持域名解析

当前只检测 IP 地址，不检测域名。

**改进方案：**
- 在后端添加域名解析功能
- 检测域名是否解析到本地 IP
- 例如：`localhost.example.com` 可能解析到 `127.0.0.1`

### 3. 检测间接循环

当前只检测直接循环（A → A），不检测间接循环（A → B → A）。

**改进方案：**
- 构建代理关系图
- 使用图算法检测环路
- 这需要后端支持，因为需要知道所有代理规则

### 4. 自定义端口配置

允许用户配置哪些端口被认为是"安全"的本地端口。

**改进方案：**
```typescript
interface LoopDetectionConfig {
  listeningPorts: number[]
  safePorts: number[]  // 即使是本地地址，这些端口也被认为是安全的
}
```

## 测试

### 手动测试步骤

1. **测试基本循环检测**
   - 添加代理规则
   - 后端地址：`127.0.0.1`，端口：`80`
   - 验证：应该显示红色警告

2. **测试不同本地地址**
   - 测试 `localhost:80`
   - 测试 `127.0.0.1:443`
   - 测试 `::1:80`
   - 验证：都应该显示警告

3. **测试安全配置**
   - 后端地址：`127.0.0.1`，端口：`3000`
   - 验证：不应该显示警告

4. **测试外部地址**
   - 后端地址：`example.com`，端口：`80`
   - 验证：不应该显示警告

5. **测试提交拦截**
   - 配置循环后端
   - 点击保存
   - 验证：应该显示 Toast 错误，阻止提交

6. **测试多后端**
   - 添加 3 个后端，其中 2 个是循环配置
   - 验证：顶部应该显示"检测到 2 个代理循环配置"

7. **测试禁用后端**
   - 添加循环配置的后端
   - 禁用该后端
   - 验证：不应该显示警告

### 自动化测试

可以为 `proxyLoopDetection.ts` 添加单元测试：

```typescript
import { detectProxyLoop, isLocalhost } from './proxyLoopDetection'

describe('proxyLoopDetection', () => {
  describe('isLocalhost', () => {
    it('should detect localhost', () => {
      expect(isLocalhost('localhost')).toBe(true)
      expect(isLocalhost('127.0.0.1')).toBe(true)
      expect(isLocalhost('::1')).toBe(true)
    })

    it('should not detect external hosts', () => {
      expect(isLocalhost('example.com')).toBe(false)
      expect(isLocalhost('192.168.1.1')).toBe(false)
    })
  })

  describe('detectProxyLoop', () => {
    it('should detect loop on port 80', () => {
      const error = detectProxyLoop('127.0.0.1', 80)
      expect(error).toContain('代理循环')
    })

    it('should not detect loop on safe port', () => {
      const error = detectProxyLoop('127.0.0.1', 3000)
      expect(error).toBeNull()
    })

    it('should not detect loop on external host', () => {
      const error = detectProxyLoop('example.com', 80)
      expect(error).toBeNull()
    })
  })
})
```

## 总结

前端代理循环检测功能为用户提供了友好的配置体验，能够：

1. ✅ **即时反馈**：输入时立即显示警告
2. ✅ **清晰提示**：明确说明问题和解决方案
3. ✅ **多层防护**：输入时警告 + 提交时拦截
4. ✅ **智能识别**：支持多种本地地址格式
5. ✅ **用户友好**：不影响正常配置流程

配合后端的循环检测，形成了完整的防护体系，有效防止了因配置错误导致的系统资源耗尽问题。


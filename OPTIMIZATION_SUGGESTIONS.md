# SSLcat 项目优化建议

## 📋 已完成的工作

✅ **多语言硬编码问题修复**
- useApi.ts、AuthGuard.tsx、useFormValidation.ts、api.ts 已修复
- 所有语言文件已添加缺失的翻译键

✅ **代码质量改进**
- 类型安全改进（使用 instanceof Error）
- 清理了调试用的 console.log

✅ **语言支持精简**
- 移除了韩语、俄语、繁体中文支持
- 现在支持 6 种语言：中文、英文、日语、西班牙语、法语、德语

---

## 🔧 建议的优化项

### 1. **提取魔法数字为常量** ⚠️ 中优先级

**问题**：
- Toast 持续时间硬编码：`duration: 5000`、`duration: 3000`
- API 超时固定：`API_TIMEOUT = 10000`

**建议**：
```typescript
// frontend/src/constants/index.ts
export const TOAST_DURATION = {
  SHORT: 3000,    // 3秒 - 成功消息
  MEDIUM: 5000,  // 5秒 - 错误/警告消息
  LONG: 8000,    // 8秒 - 重要通知
} as const

export const API_TIMEOUT = {
  DEFAULT: 10000,      // 10秒 - 默认请求
  QUICK: 5000,         // 5秒 - 快速操作
  UPLOAD: 60000,       // 60秒 - 文件上传
  CERTIFICATE: 120000, // 120秒 - 证书申请
} as const
```

**影响文件**：
- `frontend/src/hooks/useApi.ts`
- `frontend/src/pages/AISecurityAnalysis.tsx`
- `frontend/src/utils/api.ts`
- `frontend/src/pages/Settings.tsx`

---

### 2. **优化 API 超时配置** ⚠️ 中优先级

**问题**：
- 所有 API 请求使用固定 10 秒超时
- 证书申请、文件上传等操作可能需要更长时间

**建议**：
```typescript
// 为不同类型的请求设置不同的超时时间
export const apiService = {
  // 快速操作（5秒）
  getStats: () => api.get('/stats', { timeout: API_TIMEOUT.QUICK }),
  
  // 默认操作（10秒）
  getProxyRules: () => api.get('/proxy', { timeout: API_TIMEOUT.DEFAULT }),
  
  // 长时间操作（60秒）
  createCertificate: (cert) => api.post('/ssl', cert, { timeout: API_TIMEOUT.CERTIFICATE }),
  
  // 文件上传（60秒）
  uploadFile: (file) => {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/upload', formData, { 
      timeout: API_TIMEOUT.UPLOAD,
      headers: { 'Content-Type': 'multipart/form-data' }
    })
  },
}
```

---

### 3. **实现请求去重和取消机制** 💡 低优先级

**问题**：
- 相同请求可能在 pending 时重复发送
- 组件卸载时未完成的请求没有被取消

**建议**：
```typescript
// frontend/src/utils/api.ts
import axios, { CancelTokenSource } from 'axios'

const pendingRequests = new Map<string, CancelTokenSource>()

// 请求去重
const getRequestKey = (method: string, url: string, data?: any) => {
  return `${method}:${url}:${JSON.stringify(data)}`
}

// 取消重复请求
const cancelPendingRequest = (key: string) => {
  const pending = pendingRequests.get(key)
  if (pending) {
    pending.cancel('Request cancelled: duplicate request')
    pendingRequests.delete(key)
  }
}

// 在请求拦截器中添加
api.interceptors.request.use((config) => {
  const key = getRequestKey(config.method || 'get', config.url || '', config.data)
  cancelPendingRequest(key)
  
  const source = axios.CancelToken.source()
  config.cancelToken = source.token
  pendingRequests.set(key, source)
  
  return config
})

// 在响应拦截器中清理
api.interceptors.response.use(
  (response) => {
    const key = getRequestKey(
      response.config.method || 'get',
      response.config.url || '',
      response.config.data
    )
    pendingRequests.delete(key)
    return response
  },
  (error) => {
    if (error.config) {
      const key = getRequestKey(
        error.config.method || 'get',
        error.config.url || '',
        error.config.data
      )
      pendingRequests.delete(key)
    }
    return Promise.reject(error)
  }
)
```

---

### 4. **优化 useApi Hook** 💡 低优先级

**问题**：
- `useApi` 中的 `execute` 函数依赖项可能导致不必要的重新创建

**建议**：
```typescript
// 使用 useRef 存储稳定的函数引用
export function useApi<T = any>(
  apiFunction: () => Promise<T>,
  options: UseApiOptions = {}
) {
  const apiFunctionRef = useRef(apiFunction)
  const optionsRef = useRef(options)
  
  // 更新引用
  useEffect(() => {
    apiFunctionRef.current = apiFunction
    optionsRef.current = options
  })
  
  const execute = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const result = await apiFunctionRef.current()
      setData(result)
      optionsRef.current.onSuccess?.(result)
      return result
    } catch (err) {
      // ... error handling
    }
  }, [toast, t]) // 只依赖真正需要的值
}
```

---

### 5. **统一错误处理机制** ✅ 基本完成

**现状**：
- ✅ 已有 `useToastMessages` hook 提供统一的 toast 方法
- ✅ `useApi` 和 `useMutation` 已使用翻译系统
- ✅ API 拦截器已统一错误处理

**可进一步优化**：
- 检查是否所有页面都使用了统一的错误处理
- 考虑添加全局错误边界组件

---

### 6. **性能优化建议** 💡 低优先级

#### 6.1 请求缓存优化
```typescript
// 根据数据更新频率设置不同 TTL
export const apiService = {
  getStats: async () => {
    const cacheKey = 'stats'
    const cached = apiCache.get(cacheKey)
    if (cached) return cached
    
    const result = await api.get('/stats')
    apiCache.set(cacheKey, result, 60000) // 1分钟缓存
    return result
  },
  
  getProxyRules: async () => {
    const cacheKey = 'proxy-rules'
    const cached = apiCache.get(cacheKey)
    if (cached) return cached
    
    const result = await api.get('/proxy')
    apiCache.set(cacheKey, result, 300000) // 5分钟缓存
    return result
  },
}
```

#### 6.2 图片懒加载
- 检查是否有大量图片需要懒加载
- 考虑使用 `react-lazy-load-image-component`

---

## 📊 优先级总结

### 🔴 高优先级（影响用户体验）
无（已完成）

### 🟡 中优先级（提升体验）
1. **提取魔法数字为常量** - 提高代码可维护性
2. **优化 API 超时配置** - 改善长时间操作的体验

### 🟢 低优先级（优化）
3. **实现请求去重和取消机制** - 减少不必要的请求
4. **优化 useApi Hook** - 减少不必要的重新渲染
5. **性能优化** - 缓存策略、懒加载等

---

## 🎯 建议行动

**立即执行**（预计 1-2 小时）：
1. 提取魔法数字为常量
2. 优化 API 超时配置

**后续优化**（预计 2-4 小时）：
3. 实现请求去重和取消机制
4. 优化 useApi Hook

---

*最后更新: 2025-11-11*


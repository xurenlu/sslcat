import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios'
import { ApiResponse } from '../types'

// 常量定义
const FALLBACK_ADMIN_PREFIX = '/sslcat-panel2' // 仅作为最后的备用选项
const ADMIN_PREFIX_STORAGE_KEY = 'adminPrefix'
const API_TIMEOUT = 10000

// 动态获取 API baseURL
const getApiBaseURL = (): string => {
  // 优先级：URL检测 > localStorage > 备用值
  const pathSegments = window.location.pathname.split('/').filter(Boolean)
  let urlPrefix = null
  
  if (pathSegments.length > 0) {
    const detectedPrefix = `/${pathSegments[0]}`
    // 验证这看起来像一个admin prefix
    if (detectedPrefix.includes('panel') || detectedPrefix.includes('admin') || detectedPrefix.includes('sslcat')) {
      urlPrefix = detectedPrefix
    }
  }
  
  const storedPrefix = localStorage.getItem(ADMIN_PREFIX_STORAGE_KEY)
  const prefix = urlPrefix || storedPrefix || FALLBACK_ADMIN_PREFIX
  return `${prefix}/api`
}

// 创建 axios 实例
const createApiInstance = (): AxiosInstance => {
  return axios.create({
    baseURL: getApiBaseURL(),
    timeout: API_TIMEOUT,
    headers: {
      'Content-Type': 'application/json',
    },
  })
}

const api = createApiInstance()

// 动态更新API baseURL的函数
export const updateApiBaseURL = (newPrefix: string): void => {
  const newBaseURL = `${newPrefix}/api`
  api.defaults.baseURL = newBaseURL
  console.log('Updated API baseURL to:', newBaseURL)
}

// 请求拦截器
api.interceptors.request.use(
  (config) => {
    // 添加认证信息
    config.withCredentials = true // 包含 cookies
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// 响应拦截器 - 改进错误处理
api.interceptors.response.use(
  (response: AxiosResponse) => {
    return response.data
  },
  (error) => {
    console.error('API Error:', error)
    
    // 统一错误处理
    if (error.response) {
      // 服务器响应了错误状态码
      const { status, data } = error.response
      const errorMessage = data?.error || data?.message || `HTTP ${status} Error`
      
      return Promise.reject({
        status,
        message: errorMessage,
        data: data,
        isNetworkError: false
      })
    } else if (error.request) {
      // 请求已发出但没有收到响应
      return Promise.reject({
        status: 0,
        message: '网络连接失败，请检查网络设置',
        isNetworkError: true
      })
    } else {
      // 其他错误
      return Promise.reject({
        status: -1,
        message: error.message || '未知错误',
        isNetworkError: false
      })
    }
  }
)

// 统一类型定义
export interface ProxyRule {
  id: string
  domain: string
  target: string
  enabled: boolean
  sslOnly?: boolean
  port?: number
}

export interface SSLCertificate {
  id: string
  domain: string
  expiresAt: string
  autoRenew: boolean
  issuer?: string
  status?: string
}

export interface SecurityEvent {
  id: string
  type: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  timestamp: string
  source: string
  description?: string
}

export interface SystemStats {
  totalRequests: number
  activeConnections: number
  sslCertificates: number
  proxyRules: number
  blockedIPs: number
  uptime: string
}

export interface NotificationSettings {
  email: string
  webhook: string
  enabled: boolean
}

export interface SecuritySettings {
  enableCaptcha: boolean
  enableDDOS: boolean
  enableWAF: boolean
  enableUAFilter: boolean
  minFormMs: number
}

// 缓存管理
class APICache {
  private cache = new Map<string, { data: any; timestamp: number; ttl: number }>()
  
  set(key: string, data: any, ttl: number = 300000): void { // 默认5分钟TTL
    this.cache.set(key, {
      data,
      timestamp: Date.now(),
      ttl
    })
  }
  
  get(key: string): any | null {
    const item = this.cache.get(key)
    if (!item) return null
    
    if (Date.now() - item.timestamp > item.ttl) {
      this.cache.delete(key)
      return null
    }
    
    return item.data
  }
  
  clear(): void {
    this.cache.clear()
  }
  
  delete(key: string): void {
    this.cache.delete(key)
  }
}

export const apiCache = new APICache()

// 输入验证工具
export const validators = {
  // 验证域名格式
  validateDomain: (domain: string): boolean => {
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/
    return domainRegex.test(domain)
  },
  
  // 验证URL格式
  validateURL: (url: string): boolean => {
    try {
      new URL(url)
      return true
    } catch {
      return false
    }
  },
  
  // 验证IP地址格式
  validateIP: (ip: string): boolean => {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
    return ipRegex.test(ip)
  },
  
  // 验证端口号
  validatePort: (port: number): boolean => {
    return port > 0 && port <= 65535
  },
  
  // 验证邮箱格式
  validateEmail: (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    return emailRegex.test(email)
  },
  
  // 验证密码强度
  validatePassword: (password: string): { valid: boolean; message: string } => {
    if (password.length < 8) {
      return { valid: false, message: '密码长度至少8位' }
    }
    if (!/(?=.*[a-z])/.test(password)) {
      return { valid: false, message: '密码必须包含小写字母' }
    }
    if (!/(?=.*[A-Z])/.test(password)) {
      return { valid: false, message: '密码必须包含大写字母' }
    }
    if (!/(?=.*\d)/.test(password)) {
      return { valid: false, message: '密码必须包含数字' }
    }
    return { valid: true, message: '密码强度符合要求' }
  }
}

// API 方法 - 使用更严格的类型定义和缓存优化
export const apiService = {
  // 仪表板 - 带缓存
  getStats: async (): Promise<any> => {
    const cacheKey = 'stats'
    const cached = apiCache.get(cacheKey)
    if (cached) return cached
    
    const result = await api.get('/stats')
    apiCache.set(cacheKey, result, 60000) // 1分钟缓存
    return result
  },
  
  // 代理规则 - 带缓存
  getProxyRules: async (): Promise<any> => {
    const cacheKey = 'proxy-rules'
    const cached = apiCache.get(cacheKey)
    if (cached) return cached
    
    const result = await api.get('/proxy')
    apiCache.set(cacheKey, result, 300000) // 5分钟缓存
    return result
  },
  
  createProxyRule: async (rule: Omit<ProxyRule, 'id'>): Promise<any> => {
    const result = await api.post('/proxy', rule)
    apiCache.delete('proxy-rules') // 清除缓存
    return result
  },
  
  updateProxyRule: async (id: string, rule: Partial<ProxyRule>): Promise<any> => {
    const result = await api.put(`/proxy/${id}`, rule)
    apiCache.delete('proxy-rules') // 清除缓存
    return result
  },
  
  deleteProxyRule: async (id: string): Promise<any> => {
    const result = await api.delete(`/proxy/${id}`)
    apiCache.delete('proxy-rules') // 清除缓存
    return result
  },
  
  // SSL证书 - 带缓存
  getCertificates: async (): Promise<any> => {
    const cacheKey = 'ssl-certificates'
    const cached = apiCache.get(cacheKey)
    if (cached) return cached
    
    const result = await api.get('/ssl')
    apiCache.set(cacheKey, result, 600000) // 10分钟缓存
    return result
  },
  
  createCertificate: async (cert: Omit<SSLCertificate, 'id'>): Promise<any> => {
    const result = await api.post('/ssl', cert)
    apiCache.delete('ssl-certificates') // 清除缓存
    return result
  },
  
  renewCertificate: async (id: string): Promise<any> => {
    const result = await api.post(`/ssl/${id}/renew`)
    apiCache.delete('ssl-certificates') // 清除缓存
    return result
  },
  
  deleteCertificate: async (id: string): Promise<any> => {
    const result = await api.delete(`/ssl/${id}`)
    apiCache.delete('ssl-certificates') // 清除缓存
    return result
  },
  
  // 通知
  getNotifications: (): Promise<any> => 
    api.get('/notifications'),
  sendTestNotification: (data: Record<string, any>): Promise<any> => 
    api.post('/notifications/test', data),
  testNotificationChannels: (): Promise<any> => 
    api.post('/notifications/test-channels'),
  
  // 安全
  getSecurityEvents: (): Promise<any> => 
    api.get('/security/events'),
  getSecurityStats: (): Promise<any> => 
    api.get('/security/stats'),
  blockIP: (ip: string): Promise<any> => 
    api.post('/security/block-ip', { ip }),
  unblockIP: (ip: string): Promise<any> => 
    api.post('/security/unblock-ip', { ip }),
  updateSecuritySettings: (settings: SecuritySettings): Promise<any> => 
    api.post('/security/settings', settings),
  
  // 设置
  getSettings: (): Promise<any> => 
    api.get('/settings'),
  updateSettings: (settings: Record<string, any>): Promise<any> => 
    api.post('/settings', settings),
  updateBasicSettings: (settings: Record<string, any>): Promise<any> => 
    api.post('/settings/basic', settings),
  
  // 云存储检测
  detectCloudStorage: (target: string): Promise<any> => 
    api.get(`/cloud-storage/detect?target=${encodeURIComponent(target)}`),
}

// 缓存管理工具
export const cacheUtils = {
  // 清除所有缓存
  clearAll: () => {
    apiCache.clear()
  },
  
  // 清除特定类型的缓存
  clearByType: (type: 'stats' | 'proxy' | 'ssl' | 'security' | 'notifications') => {
    const keys = {
      stats: ['stats'],
      proxy: ['proxy-rules'],
      ssl: ['ssl-certificates'],
      security: ['security-events', 'security-stats'],
      notifications: ['notifications']
    }
    
    keys[type]?.forEach(key => apiCache.delete(key))
  },
  
  // 预加载数据
  preloadData: async () => {
    try {
      await Promise.all([
        apiService.getStats(),
        apiService.getProxyRules(),
        apiService.getCertificates()
      ])
    } catch (error) {
      console.warn('预加载数据失败:', error)
    }
  }
}

export default api

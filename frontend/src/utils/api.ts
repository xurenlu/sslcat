import axios from 'axios'
import { ApiResponse } from '../types'

// 动态获取 API baseURL
const getApiBaseURL = () => {
  // 从当前路径推断前缀
  const currentPath = window.location.pathname
  const pathSegments = currentPath.split('/').filter(Boolean)
  
  if (pathSegments.length > 0) {
    return `/${pathSegments[0]}/api`
  }
  
  // 如果无法从URL推断，尝试从localStorage获取
  const storedPrefix = localStorage.getItem('adminPrefix')
  if (storedPrefix) {
    return `${storedPrefix}/api`
  }
  
  // 最后回退到默认前缀
  return '/sslcat-panel/api'
}

// 创建 axios 实例
const api = axios.create({
  baseURL: getApiBaseURL(),
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// 动态更新API baseURL的函数
export const updateApiBaseURL = (newPrefix: string) => {
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

// 响应拦截器
api.interceptors.response.use(
  (response) => {
    return response.data
  },
  (error) => {
    console.error('API Error:', error)
    return Promise.reject(error)
  }
)

// API 方法
export const apiService = {
  // 仪表板
  getStats: () => api.get('/stats'),
  
  // 代理规则
  getProxyRules: () => api.get('/proxy'),
  createProxyRule: (rule: any) => api.post('/proxy', rule),
  updateProxyRule: (id: string, rule: any) => api.put(`/proxy/${id}`, rule),
  deleteProxyRule: (id: string) => api.delete(`/proxy/${id}`),
  
  // SSL证书
  getCertificates: () => api.get('/ssl'),
  createCertificate: (cert: any) => api.post('/ssl', cert),
  renewCertificate: (id: string) => api.post(`/ssl/${id}/renew`),
  deleteCertificate: (id: string) => api.delete(`/ssl/${id}`),
  
  // 通知
  getNotifications: () => api.get('/notifications'),
  sendTestNotification: (data: any) => api.post('/notifications/test', data),
  testNotificationChannels: () => api.post('/notifications/test-channels'),
  
  // 安全
  getSecurityEvents: () => api.get('/security/events'),
  getSecurityStats: () => api.get('/security/stats'),
  blockIP: (ip: string) => api.post('/security/block-ip', { ip }),
  updateSecuritySettings: (settings: any) => api.post('/security/settings', settings),
  
  // 设置
  getSettings: () => api.get('/settings'),
  updateSettings: (settings: any) => api.post('/settings', settings),
}

export default api

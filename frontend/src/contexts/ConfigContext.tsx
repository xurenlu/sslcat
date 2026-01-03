import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback, useMemo } from 'react'
import { updateApiBaseURL } from '../utils/api'

// 常量定义
const FALLBACK_ADMIN_PREFIX = '/sslcat-panel' // 仅作为最后的备用选项
const ADMIN_PREFIX_STORAGE_KEY = 'adminPrefix'

interface ConfigContextType {
  adminPrefix: string
  version: string
  isLoading: boolean
  error: string | null
  refreshConfig: () => Promise<void>
  updatePrefix: (newPrefix: string) => void
  changeAdminPrefix: (newPrefix: string, onSuccess?: (prefix: string) => void, onError?: (error: Error) => void) => Promise<void>
}

const ConfigContext = createContext<ConfigContextType | undefined>(undefined)

interface ConfigProviderProps {
  children: ReactNode
}

export const ConfigProvider: React.FC<ConfigProviderProps> = ({ children }) => {
  const [adminPrefix, setAdminPrefix] = useState('')
  const [version, setVersion] = useState('')
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // 从URL检测前缀 - 优先级最高
  const detectPrefixFromURL = useCallback((): string | null => {
    const currentPath = window.location.pathname
    const pathSegments = currentPath.split('/').filter(Boolean)
    
    if (pathSegments.length > 0) {
      const detectedPrefix = `/${pathSegments[0]}`
      // 验证这看起来像一个admin prefix（通常包含panel、admin等关键词）
      if (detectedPrefix.includes('panel') || detectedPrefix.includes('admin') || detectedPrefix.includes('sslcat')) {
        return detectedPrefix
      }
    }
    return null
  }, [])

  // 从localStorage获取前缀
  const getStoredPrefix = useCallback((): string | null => {
    return localStorage.getItem(ADMIN_PREFIX_STORAGE_KEY)
  }, [])

  // 更新前缀的内部函数
  const updatePrefix = useCallback((newPrefix: string) => {
    setAdminPrefix(newPrefix)
    localStorage.setItem(ADMIN_PREFIX_STORAGE_KEY, newPrefix)
    updateApiBaseURL(newPrefix)
  }, [])

  // 验证前缀是否有效
  const validatePrefix = useCallback(async (prefix: string): Promise<{ valid: boolean; serverPrefix?: string; version?: string }> => {
    try {
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), 5000) // 5秒超时
      
      const response = await fetch(`${prefix}/api/settings`, {
        credentials: 'include',
        signal: controller.signal
      })
      
      clearTimeout(timeoutId)
      
      if (response.ok) {
        const data = await response.json()
        const settings = data.data || {}
        return { 
          valid: true, 
          serverPrefix: settings.admin_prefix || prefix,
          version: settings.server_info?.version || ''
        }
      }
    } catch (error) {
      if (error instanceof Error && error.name !== 'AbortError') {
        console.warn('Failed to validate prefix:', error)
      }
    }
    return { valid: false }
  }, [])

  // 更改admin prefix并跳转到新地址
  const changeAdminPrefix = useCallback(async (newPrefix: string, onSuccess?: (prefix: string) => void, onError?: (error: Error) => void): Promise<void> => {
    try {
      // 确保前缀格式正确
      const normalizedPrefix = newPrefix.startsWith('/') ? newPrefix : `/${newPrefix}`
      
      // 验证新前缀是否有效
      const validation = await validatePrefix(normalizedPrefix)
      
      if (!validation.valid) {
        throw new Error('新的admin prefix无效或服务器无响应')
      }
      
      // 使用服务器返回的实际前缀
      const finalPrefix = validation.serverPrefix || normalizedPrefix
      
      // 发送admin prefix更改通知
      try {
        await sendAdminPrefixChangeNotification(adminPrefix, finalPrefix)
      } catch (notificationError) {
        console.warn('发送admin prefix更改通知失败:', notificationError)
        // 通知失败不应该阻止prefix更改，只记录警告
      }
      
      // 更新前缀
      updatePrefix(finalPrefix)
      
      // 调用成功回调
      if (onSuccess) {
        onSuccess(finalPrefix)
      }
      
      // 跳转到新的前缀地址
      const currentPath = window.location.pathname
      const currentPrefix = detectPrefixFromURL()
      
      if (currentPrefix && currentPath.startsWith(currentPrefix)) {
        // 替换当前路径中的前缀部分
        const newPath = currentPath.replace(currentPrefix, finalPrefix)
        window.location.href = newPath
      } else {
        // 直接跳转到新前缀的根路径
        window.location.href = finalPrefix
      }
      
    } catch (error) {
      console.error('更改admin prefix失败:', error)
      if (onError) {
        onError(error instanceof Error ? error : new Error('未知错误'))
      }
      throw error
    }
  }, [validatePrefix, updatePrefix, detectPrefixFromURL, adminPrefix])

  // 发送admin prefix更改通知
  const sendAdminPrefixChangeNotification = useCallback(async (oldPrefix: string, newPrefix: string): Promise<void> => {
    try {
      const notificationData = {
        type: 'admin_prefix_changed',
        message: `Admin panel access prefix changed from "${oldPrefix}" to "${newPrefix}"`,
        details: {
          old_prefix: oldPrefix,
          new_prefix: newPrefix,
          changed_at: new Date().toISOString(),
          changed_by: 'admin', // 这里可以获取当前用户信息
          server_info: {
            hostname: window.location.hostname,
            user_agent: navigator.userAgent,
          }
        },
        severity: 'high', // 高优先级通知
        category: 'security' // 安全类别
      }

      // 发送通知到服务器，服务器会处理邮件、webhook等通知
      const response = await fetch(`${oldPrefix}/api/notifications/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(notificationData),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.message || '发送通知失败')
      }

      console.log('Admin prefix更改通知已发送')
    } catch (error) {
      console.error('发送admin prefix更改通知失败:', error)
      throw error
    }
  }, [])

  // 初始化配置 - 按优先级检测admin prefix
  const fetchConfig = useCallback(async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      // 清理旧的备用值（如果存在）
      const storedValue = localStorage.getItem(ADMIN_PREFIX_STORAGE_KEY)
      if (storedValue === '/sslcat-panel2') {
        console.log('检测到旧的备用值 /sslcat-panel2，清理中...')
        localStorage.removeItem(ADMIN_PREFIX_STORAGE_KEY)
      }
      
      // 检测是否在开发模式（Vite dev server）
      const isDevelopment = window.location.port === '9980'
      
      // 1. 最高优先级：从当前URL检测前缀
      const urlPrefix = detectPrefixFromURL()
      
      // 如果从 URL 检测到了前缀，尝试使用它并验证版本
      if (urlPrefix) {
        console.log('从 URL 检测到 admin prefix:', urlPrefix, '尝试验证...')
        updatePrefix(urlPrefix)
        
        try {
          const validation = await validatePrefix(urlPrefix)
          if (validation.valid) {
            console.log('URL 前缀验证成功')
            if (validation.version) {
              setVersion(validation.version)
            }
          }
        } catch (error) {
          console.warn('URL 前缀验证失败:', error)
        }
        
        setIsLoading(false)
        return
      }
      
      // 2. 次优先级：从localStorage获取存储的前缀
      const storedPrefix = getStoredPrefix()
      
      // 3. 最低优先级：使用备用前缀
      const fallbackPrefix = FALLBACK_ADMIN_PREFIX
      
      // 在开发模式下且URL中没有前缀时，直接使用 localStorage 或 fallback
      if (isDevelopment) {
        const devPrefix = storedPrefix || fallbackPrefix
        console.log('开发模式：使用', storedPrefix ? 'localStorage' : 'fallback', 'prefix:', devPrefix)
        updatePrefix(devPrefix)
        setIsLoading(false)
        return
      }
      
      // 生产模式下，尝试验证 localStorage 中的前缀
      if (storedPrefix) {
        try {
          console.log('尝试验证 localStorage 中的前缀:', storedPrefix)
          const validation = await validatePrefix(storedPrefix)
          if (validation.valid) {
            const finalPrefix = validation.serverPrefix || storedPrefix
            console.log('localStorage 前缀验证成功，使用:', finalPrefix)
            updatePrefix(finalPrefix)
            if (validation.version) {
              setVersion(validation.version)
            }
            setIsLoading(false)
            return
          }
        } catch (error) {
          console.warn('localStorage 前缀验证失败:', error)
        }
      }
      
      // 最后使用备用前缀（不验证，直接使用）
      console.log('使用备用 admin prefix:', fallbackPrefix)
      updatePrefix(fallbackPrefix)
      
    } catch (err) {
      console.error('Failed to fetch config:', err)
      setError(err instanceof Error ? err.message : 'Unknown error')
      // 即使出错也要设置一个前缀
      const urlPrefix = detectPrefixFromURL()
      updatePrefix(urlPrefix || FALLBACK_ADMIN_PREFIX)
    } finally {
      setIsLoading(false)
    }
  }, [detectPrefixFromURL, getStoredPrefix, validatePrefix, updatePrefix])

  // 使用useCallback优化refreshConfig函数
  const refreshConfig = useCallback(async () => {
    await fetchConfig()
  }, [fetchConfig])

  useEffect(() => {
    fetchConfig()
  }, [fetchConfig])

  // 使用useMemo优化context value，避免不必要的重新渲染
  const value: ConfigContextType = useMemo(() => ({
    adminPrefix,
    version,
    isLoading,
    error,
    refreshConfig,
    updatePrefix,
    changeAdminPrefix,
  }), [adminPrefix, version, isLoading, error, refreshConfig, updatePrefix, changeAdminPrefix])

  return (
    <ConfigContext.Provider value={value}>
      {children}
    </ConfigContext.Provider>
  )
}

export const useConfig = (): ConfigContextType => {
  const context = useContext(ConfigContext)
  if (context === undefined) {
    throw new Error('useConfig must be used within a ConfigProvider')
  }
  return context
}

// 工具函数：构建带前缀的路径 - 使用useMemo优化
export const buildPath = (prefix: string, path: string): string => {
  // 确保前缀以 / 开头
  const normalizedPrefix = prefix.startsWith('/') ? prefix : `/${prefix}`
  // 确保路径以 / 开头
  const normalizedPath = path.startsWith('/') ? path : `/${path}`
  // 组合路径
  return `${normalizedPrefix}${normalizedPath}`
}

// 工具函数：构建API路径 - 使用useMemo优化
export const buildApiPath = (prefix: string, path: string): string => {
  // 如果path已经以/api开头，直接使用；否则添加/api前缀
  const apiPath = path.startsWith('/api') ? path : `/api${path}`
  return buildPath(prefix, apiPath)
}


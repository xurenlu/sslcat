import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback, useMemo } from 'react'
import { updateApiBaseURL } from '../utils/api'

// 常量定义
const DEFAULT_ADMIN_PREFIX = '/sslcat-panel2'
const ADMIN_PREFIX_STORAGE_KEY = 'adminPrefix'

interface ConfigContextType {
  adminPrefix: string
  isLoading: boolean
  error: string | null
  refreshConfig: () => Promise<void>
  updatePrefix: (newPrefix: string) => void
}

const ConfigContext = createContext<ConfigContextType | undefined>(undefined)

interface ConfigProviderProps {
  children: ReactNode
}

export const ConfigProvider: React.FC<ConfigProviderProps> = ({ children }) => {
  const [adminPrefix, setAdminPrefix] = useState(DEFAULT_ADMIN_PREFIX)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // 更新前缀的通用函数 - 使用useCallback优化性能
  const updatePrefix = useCallback((newPrefix: string) => {
    setAdminPrefix(newPrefix)
    localStorage.setItem(ADMIN_PREFIX_STORAGE_KEY, newPrefix)
    updateApiBaseURL(newPrefix)
  }, [])

  // 从URL检测前缀 - 使用useMemo缓存结果
  const detectPrefixFromURL = useCallback((): string => {
    const currentPath = window.location.pathname
    const pathSegments = currentPath.split('/').filter(Boolean)
    return pathSegments.length > 0 ? `/${pathSegments[0]}` : DEFAULT_ADMIN_PREFIX
  }, [])

  // 从localStorage获取前缀
  const getStoredPrefix = useCallback((): string => {
    return localStorage.getItem(ADMIN_PREFIX_STORAGE_KEY) || DEFAULT_ADMIN_PREFIX
  }, [])

  // 验证前缀是否有效 - 添加超时和错误处理
  const validatePrefix = useCallback(async (prefix: string): Promise<string> => {
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
        return data.admin_prefix || prefix
      }
    } catch (error) {
      if (error instanceof Error && error.name !== 'AbortError') {
        console.warn('Failed to validate prefix:', error)
      }
    }
    return prefix
  }, [])

  // 使用useCallback优化fetchConfig函数
  const fetchConfig = useCallback(async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      // 1. 优先从URL检测前缀
      const urlPrefix = detectPrefixFromURL()
      let finalPrefix = urlPrefix
      
      // 2. 如果URL检测失败，尝试从localStorage获取
      if (urlPrefix === DEFAULT_ADMIN_PREFIX) {
        finalPrefix = getStoredPrefix()
      }
      
      // 3. 更新前缀
      updatePrefix(finalPrefix)
      
      // 4. 验证前缀（异步，不阻塞UI）
      validatePrefix(finalPrefix).then(validatedPrefix => {
        if (validatedPrefix !== finalPrefix) {
          console.log('Server prefix differs from detected:', { 
            detected: finalPrefix, 
            server: validatedPrefix 
          })
          updatePrefix(validatedPrefix)
        }
      }).catch(error => {
        console.warn('Prefix validation failed:', error)
      })
      
    } catch (err) {
      console.error('Failed to fetch config:', err)
      setError(err instanceof Error ? err.message : 'Unknown error')
      updatePrefix(DEFAULT_ADMIN_PREFIX)
    } finally {
      setIsLoading(false)
    }
  }, [detectPrefixFromURL, getStoredPrefix, updatePrefix, validatePrefix])

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
    isLoading,
    error,
    refreshConfig,
    updatePrefix,
  }), [adminPrefix, isLoading, error, refreshConfig, updatePrefix])

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

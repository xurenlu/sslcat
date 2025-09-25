import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react'

interface ConfigContextType {
  adminPrefix: string
  isLoading: boolean
  error: string | null
  refreshConfig: () => Promise<void>
}

const ConfigContext = createContext<ConfigContextType | undefined>(undefined)

interface ConfigProviderProps {
  children: ReactNode
}

export const ConfigProvider: React.FC<ConfigProviderProps> = ({ children }) => {
  const [adminPrefix, setAdminPrefix] = useState('/sslcat-panel')
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchConfig = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      // 尝试从当前路径推断前缀
      const currentPath = window.location.pathname
      const pathSegments = currentPath.split('/').filter(Boolean)
      
      if (pathSegments.length > 0) {
        // 如果当前路径包含前缀，使用它
        const detectedPrefix = '/' + pathSegments[0]
        setAdminPrefix(detectedPrefix)
      } else {
        // 否则尝试从API获取配置
        try {
          const response = await fetch('/api/config/prefix')
          if (response.ok) {
            const data = await response.json()
            setAdminPrefix(data.adminPrefix || '/sslcat-panel')
          }
        } catch (apiError) {
          // API调用失败，使用默认值
          console.warn('Failed to fetch config from API, using default prefix')
          setAdminPrefix('/sslcat-panel')
        }
      }
    } catch (err) {
      console.error('Failed to fetch config:', err)
      setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setIsLoading(false)
    }
  }

  const refreshConfig = async () => {
    await fetchConfig()
  }

  useEffect(() => {
    fetchConfig()
  }, [])

  const value: ConfigContextType = {
    adminPrefix,
    isLoading,
    error,
    refreshConfig,
  }

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

// 工具函数：构建带前缀的路径
export const buildPath = (prefix: string, path: string): string => {
  // 确保前缀以 / 开头
  const normalizedPrefix = prefix.startsWith('/') ? prefix : `/${prefix}`
  // 确保路径以 / 开头
  const normalizedPath = path.startsWith('/') ? path : `/${path}`
  // 组合路径
  return `${normalizedPrefix}${normalizedPath}`
}

// 工具函数：构建API路径
export const buildApiPath = (prefix: string, path: string): string => {
  // 如果path已经以/api开头，直接使用；否则添加/api前缀
  const apiPath = path.startsWith('/api') ? path : `/api${path}`
  return buildPath(prefix, apiPath)
}

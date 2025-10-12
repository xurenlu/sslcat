import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { useConfig } from './ConfigContext'
import { setSentryUser, clearSentryUser } from '../utils/sentry'

interface User {
  username: string
  role: string
  is_active?: boolean
}

interface AuthContextType {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (username: string, password: string) => Promise<boolean>
  logout: () => void
  checkAuth: () => Promise<boolean>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

interface AuthProviderProps {
  children: ReactNode
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const { adminPrefix, isLoading: configLoading } = useConfig()
  const navigate = useNavigate()

  // 获取有效的 admin prefix，确保不为空
  const getEffectivePrefix = useCallback(() => {
    return adminPrefix || '/sslcat-panel'
  }, [adminPrefix])

  // 检查认证状态
  const checkAuth = useCallback(async (): Promise<boolean> => {
    let loadingSet = false
    try {
      const effectivePrefix = getEffectivePrefix()
      console.log('检查认证状态，adminPrefix:', adminPrefix, 'effectivePrefix:', effectivePrefix)
      const response = await fetch(`${effectivePrefix}/api/auth/me`, {
        credentials: 'include', // 包含 cookies
      })
      
      console.log('认证检查响应状态:', response.status)
      
      // 检查响应的 Content-Type
      const contentType = response.headers.get('content-type')
      console.log('响应 Content-Type:', contentType)
      
      // 如果返回的是 HTML，说明 API 路径有问题（可能 adminPrefix 错误）
      // 这种情况下不应该触发登出，而应该忽略这次检查
      if (contentType?.includes('text/html')) {
        console.warn('API 返回了 HTML 而不是 JSON，可能是路径配置问题，跳过本次认证检查')
        // 保持当前状态，不清除用户信息
        setIsLoading(false)
        loadingSet = true
        return false // 返回 false 但不清除用户状态
      }
      
      if (response.ok) {
        try {
          const userData = await response.json()
          console.log('认证成功，用户数据:', userData)
          setUser(userData)
          
          // 设置 Sentry 用户信息
          setSentryUser({
            id: userData.username, // 使用 username 作为 ID
            username: userData.username,
            role: userData.role,
          })
          
          setIsLoading(false)
          loadingSet = true
          return true
        } catch (jsonError) {
          console.error('解析用户数据失败:', jsonError)
          // JSON 解析失败，但状态码是 200，可能是路径问题
          console.warn('响应状态 200 但无法解析 JSON，跳过本次认证检查')
          setIsLoading(false)
          loadingSet = true
          return false
        }
      } else {
        // 真正的认证失败（401）
        console.warn('认证失败:', response.status)
        setUser(null)
        setIsLoading(false)
        loadingSet = true
        return false
      }
    } catch (error) {
      console.error('Auth check failed:', error)
      // 网络错误等情况，不清除用户信息，保持当前状态
      console.warn('认证检查出错，保持当前登录状态')
      if (!loadingSet) {
        setIsLoading(false)
      }
      return false
    } finally {
      if (!loadingSet) {
        setIsLoading(false)
      }
    }
  }, [adminPrefix, getEffectivePrefix])

  // 登录
  const login = useCallback(async (username: string, password: string): Promise<boolean> => {
    try {
      const effectivePrefix = getEffectivePrefix()
      const response = await fetch(`${effectivePrefix}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({ username, password }),
      })

      if (response.ok) {
        const userData = await response.json()
        setUser(userData)
        
        // 设置 Sentry 用户信息
        setSentryUser({
          id: userData.username,
          username: userData.username,
          role: userData.role,
        })
        
        // 登录成功后不要立即触发 checkAuth，避免重复检查
        console.log('登录成功，用户:', userData)
        return true
      } else {
        const errorData = await response.json()
        console.error('Login failed:', errorData.error)
        return false
      }
    } catch (error) {
      console.error('Login error:', error)
      return false
    }
  }, [getEffectivePrefix])

  // 登出
  const logout = useCallback(async () => {
    try {
      const effectivePrefix = getEffectivePrefix()
      await fetch(`${effectivePrefix}/api/auth/logout`, {
        method: 'POST',
        credentials: 'include',
      })
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      // 清除 Sentry 用户信息
      clearSentryUser()
      
      setUser(null)
      const effectivePrefix = getEffectivePrefix()
      navigate(`${effectivePrefix}/login`)
    }
  }, [getEffectivePrefix, navigate])

  // 初始化时检查认证状态
  useEffect(() => {
    // 等待 ConfigContext 加载完成
    if (configLoading) {
      console.log('等待 ConfigContext 加载完成...')
      return
    }
    
    // 只在有 adminPrefix 且不在登录页时检查认证
    if (adminPrefix && !window.location.pathname.includes('/login')) {
      console.log('Auth useEffect triggered, adminPrefix:', adminPrefix)
      // 直接调用，不依赖 checkAuth 函数引用
      const doCheck = async () => {
        await checkAuth()
      }
      doCheck()
    } else {
      // 在登录页面或没有 adminPrefix，直接设置加载完成
      console.log('跳过认证检查（登录页或无 adminPrefix）')
      setIsLoading(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [adminPrefix, configLoading]) // 依赖 adminPrefix 和 configLoading

  const value: AuthContextType = {
    user,
    isAuthenticated: !!user,
    isLoading,
    login,
    logout,
    checkAuth,
  }

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import { useConfig } from './ConfigContext'

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
  const { adminPrefix } = useConfig()
  const navigate = useNavigate()

  // 获取有效的 admin prefix，确保不为空
  const getEffectivePrefix = () => {
    return adminPrefix || '/sslcat-panel2'
  }

  // 检查认证状态
  const checkAuth = async (): Promise<boolean> => {
    try {
      const effectivePrefix = getEffectivePrefix()
      console.log('检查认证状态，adminPrefix:', adminPrefix, 'effectivePrefix:', effectivePrefix)
      const response = await fetch(`${effectivePrefix}/api/auth/me`, {
        credentials: 'include', // 包含 cookies
      })
      
      console.log('认证检查响应状态:', response.status)
      
      if (response.ok) {
        const userData = await response.json()
        console.log('认证成功，用户数据:', userData)
        setUser(userData)
        return true
      } else {
        const errorText = await response.text()
        console.warn('认证失败:', response.status, errorText)
        setUser(null)
        return false
      }
    } catch (error) {
      console.error('Auth check failed:', error)
      setUser(null)
      return false
    } finally {
      setIsLoading(false)
    }
  }

  // 登录
  const login = async (username: string, password: string): Promise<boolean> => {
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
  }

  // 登出
  const logout = async () => {
    try {
      const effectivePrefix = getEffectivePrefix()
      await fetch(`${effectivePrefix}/api/auth/logout`, {
        method: 'POST',
        credentials: 'include',
      })
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      setUser(null)
      const effectivePrefix = getEffectivePrefix()
      navigate(`${effectivePrefix}/login`)
    }
  }

  // 初始化时检查认证状态
  useEffect(() => {
    checkAuth()
  }, [adminPrefix])

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

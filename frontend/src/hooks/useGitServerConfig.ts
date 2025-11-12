import { useState, useCallback, useRef, useEffect } from 'react'
import { buildApiPath } from '../contexts/ConfigContext'
import { useErrorHandler } from './useErrorHandler'
import { useToast } from '@chakra-ui/react'
import { GitServerConfig } from '../pages/GitServerManagement/types'
import { TOAST_DURATION } from '../constants'
import { useTranslation } from './useLanguage'

interface UseGitServerConfigOptions {
  adminPrefix: string
}

// 缓存接口
interface CacheEntry<T> {
  data: T
  timestamp: number
  ttl: number
}

// 简单的内存缓存
const cache = new Map<string, CacheEntry<any>>()
const CACHE_TTL = 30000 // 30秒

// 请求去重：存储正在进行的请求
const pendingRequests = new Map<string, Promise<any>>()

const defaultConfig: GitServerConfig = {
  enabled: true,
  port: 22,
  webhook: '',
  defaultBranch: 'main',
  autoSSL: true,
  domainSuffix: 'localhost',
  portRange: [8000, 9000],
  welcomeMessage: '欢迎使用 SSLcat Git 部署平台！',
  sslEmail: '',
  defaultStrategy: 'auto',
  buildTimeout: 300,
  autoDomain: true,
}

export const useGitServerConfig = ({ adminPrefix }: UseGitServerConfigOptions) => {
  const [config, setConfig] = useState<GitServerConfig>(defaultConfig)
  const [loading, setLoading] = useState(false)
  const { handleError } = useErrorHandler()
  const toast = useToast()
  const t = useTranslation()
  const abortControllerRef = useRef<AbortController | null>(null)

  const loadConfig = useCallback(
    async (force = false) => {
      const cacheKey = `config-${adminPrefix}`
      const now = Date.now()

      // 检查缓存
      if (!force) {
        const cached = cache.get(cacheKey)
        if (cached && (now - cached.timestamp) < cached.ttl) {
          setConfig(cached.data)
          return cached.data
        }
      }

      // 检查是否有正在进行的请求
      if (pendingRequests.has(cacheKey)) {
        return pendingRequests.get(cacheKey)
      }

      // 取消之前的请求
      if (abortControllerRef.current) {
        abortControllerRef.current.abort()
      }

      // 创建新的 AbortController
      const controller = new AbortController()
      abortControllerRef.current = controller

      setLoading(true)

      const requestPromise = (async () => {
        try {
          const response = await fetch(buildApiPath(adminPrefix, '/git-server/config'), {
            signal: controller.signal,
          })

          if (!response.ok) {
            throw new Error(t.gitServer.pushHistoryFailed || 'Failed to get server config')
          }

          const configJson = await response.json()
          let frontendConfig: GitServerConfig = defaultConfig

          if (configJson?.data) {
            // 转换后端返回的字段命名（下划线）为前端使用的驼峰命名
            const backendConfig = configJson.data
            frontendConfig = {
              enabled: backendConfig.enabled,
              port: backendConfig.port,
              webhook: backendConfig.webhook,
              defaultBranch: backendConfig.defaultBranch || backendConfig.default_branch,
              autoSSL: backendConfig.autoSSL ?? backendConfig.auto_ssl,
              domainSuffix: backendConfig.domainSuffix || backendConfig.domain_suffix,
              portRange: backendConfig.portRange || backendConfig.port_range || [8000, 9000],
              welcomeMessage: backendConfig.welcomeMessage || backendConfig.welcome_message,
              sslEmail: backendConfig.sslEmail || backendConfig.ssl_email,
              defaultStrategy: backendConfig.defaultStrategy || backendConfig.default_strategy,
              buildTimeout: backendConfig.buildTimeout ?? backendConfig.build_timeout,
              autoDomain: backendConfig.autoDomain ?? backendConfig.auto_domain,
            }
          }

          // 更新缓存
          cache.set(cacheKey, {
            data: frontendConfig,
            timestamp: now,
            ttl: CACHE_TTL,
          })

          setConfig(frontendConfig)
          return frontendConfig
        } catch (error: any) {
          if (error.name === 'AbortError') {
            return // 请求被取消，不处理
          }
          handleError(error, { context: '获取服务器配置' })
          setConfig(defaultConfig)
          throw error
        } finally {
          setLoading(false)
          pendingRequests.delete(cacheKey)
        }
      })()

      pendingRequests.set(cacheKey, requestPromise)
      return requestPromise
    },
    [adminPrefix, handleError, t]
  )

  // 组件卸载时取消请求
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort()
      }
    }
  }, [])

  const updateConfig = useCallback(
    async (newConfig: GitServerConfig) => {
      try {
        // 转换前端的驼峰命名为后端需要的下划线命名
        const backendConfig = {
          enabled: newConfig.enabled,
          port: newConfig.port,
          webhook: newConfig.webhook,
          default_branch: newConfig.defaultBranch,
          auto_ssl: newConfig.autoSSL,
          domain_suffix: newConfig.domainSuffix,
          port_range: newConfig.portRange,
          welcome_message: newConfig.welcomeMessage,
          ssl_email: newConfig.sslEmail,
          default_strategy: newConfig.defaultStrategy,
          build_timeout: newConfig.buildTimeout,
          auto_domain: newConfig.autoDomain,
        }

        const response = await fetch(buildApiPath(adminPrefix, '/git-server/config'), {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(backendConfig),
        })

        if (!response.ok) {
          throw new Error(t.gitServer.deployFailed || 'Failed to update config')
        }

        toast({
          title: t.gitServer.configUpdatedSuccess,
          status: 'success',
          duration: TOAST_DURATION.MEDIUM,
          isClosable: true,
        })

        // 清除缓存，强制重新加载
        cache.delete(`config-${adminPrefix}`)
        await loadConfig(true)

        return newConfig
      } catch (error) {
        handleError(error, { context: '更新Git服务器配置' })
        throw error
      }
    },
    [adminPrefix, handleError, toast, loadConfig, t]
  )

  const restartSSHD = useCallback(async () => {
    setLoading(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/git-server/restart-sshd'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.message || '重启失败')
      }

      const data = await response.json()

      toast({
        title: t.gitServer.sshRestartSuccess,
        description: data.message || t.gitServer.sshRestartDescription,
        status: 'success',
        duration: TOAST_DURATION.MEDIUM,
        isClosable: true,
      })
    } catch (error) {
      handleError(error, { context: '重启SSH服务' })
      throw error
    } finally {
      setLoading(false)
    }
  }, [adminPrefix, handleError, toast])

  return {
    config,
    loading,
    loadConfig,
    updateConfig,
    restartSSHD,
  }
}


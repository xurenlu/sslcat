import { useState, useCallback, useRef, useEffect } from 'react'
import { buildApiPath } from '../contexts/ConfigContext'
import { useErrorHandler } from './useErrorHandler'
import { useTranslation } from './useLanguage'
import { useToast } from '@chakra-ui/react'
import { SSHKey } from '../pages/GitServerManagement/types'
import { TOAST_DURATION } from '../constants'

interface UseSSHKeysOptions {
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

export const useSSHKeys = ({ adminPrefix }: UseSSHKeysOptions) => {
  const [sshKeys, setSSHKeys] = useState<SSHKey[]>([])
  const [loading, setLoading] = useState(false)
  const { handleError } = useErrorHandler()
  const toast = useToast()
  const t = useTranslation()
  const abortControllerRef = useRef<AbortController | null>(null)

  const loadSSHKeys = useCallback(
    async (force = false) => {
      const cacheKey = `ssh-keys-${adminPrefix}`
      const now = Date.now()

      // 检查缓存
      if (!force) {
        const cached = cache.get(cacheKey)
        if (cached && (now - cached.timestamp) < cached.ttl) {
          setSSHKeys(cached.data)
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
          const response = await fetch(buildApiPath(adminPrefix, '/git-server/ssh-keys'), {
            signal: controller.signal,
          })

          if (!response.ok) {
            throw new Error(t.gitServer.pushHistoryFailed || 'Failed to get SSH keys')
          }

          const keysJson = await response.json()
          const keysData = Array.isArray(keysJson?.data) ? keysJson.data : []

          // 更新缓存
          cache.set(cacheKey, {
            data: keysData,
            timestamp: now,
            ttl: CACHE_TTL,
          })

          setSSHKeys(keysData)
          return keysData
        } catch (error: any) {
          if (error.name === 'AbortError') {
            return // 请求被取消，不处理
          }
          handleError(error, { context: '获取SSH密钥' })
          setSSHKeys([])
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

  const addSSHKey = useCallback(
    async (name: string, publicKey: string) => {
      try {
        const response = await fetch(buildApiPath(adminPrefix, '/git-server/ssh-keys'), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ name, publicKey }),
        })

        if (!response.ok) {
          throw new Error(t.gitServer.deployFailed || 'Failed to add SSH key')
        }

        toast({
          title: t.gitServer.sshKeyAdded,
          status: 'success',
          duration: TOAST_DURATION.MEDIUM,
          isClosable: true,
        })

        // 清除缓存，强制重新加载
        cache.delete(`ssh-keys-${adminPrefix}`)
        await loadSSHKeys(true)
      } catch (error) {
        handleError(error, { context: '添加SSH密钥' })
        throw error
      }
    },
    [adminPrefix, handleError, toast, loadSSHKeys, t]
  )

  const deleteSSHKey = useCallback(
    async (fingerprint: string) => {
      // 乐观更新：立即从 UI 中移除
      const previousKeys = sshKeys
      setSSHKeys((prev) => prev.filter((key) => key.fingerprint !== fingerprint))

      try {
        const response = await fetch(
          buildApiPath(
            adminPrefix,
            `/git-server/ssh-key/remove?fingerprint=${encodeURIComponent(fingerprint)}`
          ),
          {
            method: 'POST',
          }
        )

        if (!response.ok) {
          throw new Error(t.gitServer.deployFailed || 'Failed to delete SSH key')
        }

        // 清除缓存，强制重新加载
        cache.delete(`ssh-keys-${adminPrefix}`)
        await loadSSHKeys(true)

        toast({
          title: t.gitServer.sshKeyDeleted,
          status: 'success',
          duration: TOAST_DURATION.MEDIUM,
          isClosable: true,
        })
      } catch (error) {
        // 失败时回滚
        setSSHKeys(previousKeys)
        handleError(error, { context: '删除SSH密钥' })
        throw error
      }
    },
    [adminPrefix, handleError, toast, loadSSHKeys, t, sshKeys]
  )

  return {
    sshKeys,
    loading,
    loadSSHKeys,
    addSSHKey,
    deleteSSHKey,
  }
}


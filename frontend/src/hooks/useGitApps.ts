import { useState, useCallback, useRef, useEffect } from 'react'
import React from 'react'
import { useToast } from '@chakra-ui/react'
import { buildApiPath } from '../contexts/ConfigContext'
import { useErrorHandler } from './useErrorHandler'
import { useTranslation } from './useLanguage'
import { CreateAppRuntimeOptions, GitApp, RunnerSpec, transformBackendAppToGitApp } from '../pages/GitServerManagement/types'
import { TOAST_DURATION } from '../constants'
import { GitCommandToast } from '../components/GitCommandToast'

interface UseGitAppsOptions {
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

export const useGitApps = ({ adminPrefix }: UseGitAppsOptions) => {
  const [apps, setApps] = useState<GitApp[]>([])
  const [loading, setLoading] = useState(false)
  const { handleError } = useErrorHandler()
  const toast = useToast()
  const t = useTranslation()
  const abortControllerRef = useRef<AbortController | null>(null)

  const loadApps = useCallback(
    async (force = false) => {
      const cacheKey = `apps-${adminPrefix}`
      const now = Date.now()

      // 检查缓存
      if (!force) {
        const cached = cache.get(cacheKey)
        if (cached && (now - cached.timestamp) < cached.ttl) {
          setApps(cached.data)
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
          const response = await fetch(buildApiPath(adminPrefix, '/git-server/apps'), {
            signal: controller.signal,
          })

          if (!response.ok) {
            throw new Error(t.gitServer.pushHistoryFailed || 'Failed to get Git apps list')
          }

          const appsJson = await response.json()
          const appsDataRaw = Array.isArray(appsJson?.data) ? appsJson.data : []

          // 转换后端状态为前端状态
          const appsData = appsDataRaw.map(transformBackendAppToGitApp)

          // 更新缓存
          cache.set(cacheKey, {
            data: appsData,
            timestamp: now,
            ttl: CACHE_TTL,
          })

          setApps(appsData)
          return appsData
        } catch (error: any) {
          if (error.name === 'AbortError') {
            return // 请求被取消，不处理
          }
          handleError(error, { context: '获取Git应用列表' })
          setApps([])
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

  const updateAppRuntime = useCallback(
    async (appName: string, runtime: RunnerSpec) => {
      const response = await fetch(
        buildApiPath(adminPrefix, `/git-server/apps/${encodeURIComponent(appName)}/runtime`),
        {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(runtime),
        }
      )

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.error || t.gitServer.runtimeUpdateFailed)
      }
    },
    [adminPrefix, t]
  )

  const uploadAppArtifact = useCallback(
    async (appName: string, options: NonNullable<CreateAppRuntimeOptions['artifact']>, sourceType: CreateAppRuntimeOptions['sourceType']) => {
      const formData = new FormData()
      formData.append('source_type', sourceType)
      formData.append('start_command', options.startCommand || '')
      formData.append('work_dir', options.workDir || '')
      formData.append('internal_port', options.internalPort ? String(options.internalPort) : '')
      formData.append('env_vars', JSON.stringify(options.envVars || {}))
      options.files.forEach((file, index) => {
        formData.append('files', file)
        formData.append('paths', options.paths[index] || file.name)
      })

      const response = await fetch(
        buildApiPath(adminPrefix, `/git-server/apps/${encodeURIComponent(appName)}/artifact`),
        {
          method: 'POST',
          body: formData,
        }
      )

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.error || t.gitServer.artifactUploadFailed)
      }
    },
    [adminPrefix, t]
  )

  const createApp = useCallback(
    async (name: string, autoSSL: boolean, options?: CreateAppRuntimeOptions) => {
      try {
        const response = await fetch(buildApiPath(adminPrefix, '/git-server/apps'), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            name,
            auto_ssl: autoSSL,
          }),
        })

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}))
          throw new Error(errorData.error || t.gitServer.deployFailed || 'Failed to create Git app')
        }

        const result = await response.json()
        const appData = result.data

        if (options?.sourceType === 'docker_image' && options.runtime) {
          await updateAppRuntime(name, options.runtime)
        }
        if ((options?.sourceType === 'directory' || options?.sourceType === 'binary') && options.artifact) {
          await uploadAppArtifact(name, options.artifact, options.sourceType)
        }

        toast({
          title: t.gitServer.appCreatedSuccess,
          description: options?.sourceType && options.sourceType !== 'git'
            ? t.gitServer.runnerConfigSaved
            : t.gitServer.gitAddressFormat.replace('{hostname}', window.location.hostname).replace('{name}', name),
          status: 'success',
          duration: TOAST_DURATION.LONG,
          isClosable: true,
        })

        // 清除缓存，强制重新加载
        cache.delete(`apps-${adminPrefix}`)
        await loadApps(true)

        if (!options?.sourceType || options.sourceType === 'git') {
          setTimeout(() => {
            const gitCommands = `git remote add sslcat git@${window.location.hostname}:${name}.git
git push sslcat main`

            toast({
              title: t.gitServer.pushCodeToApp,
              description: React.createElement(GitCommandToast, { gitCommands }),
              status: 'info',
              duration: TOAST_DURATION.LONG * 2,
              isClosable: true,
            })
          }, 1000)
        }

        return appData
      } catch (error) {
        handleError(error, { context: '创建Git应用' })
        throw error
      }
    },
    [adminPrefix, handleError, toast, loadApps, t, updateAppRuntime, uploadAppArtifact]
  )

  const deleteApp = useCallback(
    async (appName: string) => {
      // 乐观更新：立即从 UI 中移除
      const previousApps = apps
      setApps((prev) => prev.filter((app) => app.name !== appName))

      try {
        const response = await fetch(
          buildApiPath(adminPrefix, `/git-server/app/delete?name=${encodeURIComponent(appName)}`),
          {
            method: 'DELETE',
          }
        )

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}))
          throw new Error(errorData.error || t.gitServer.deployFailed || 'Failed to delete Git app')
        }

        // 清除缓存，强制重新加载
        cache.delete(`apps-${adminPrefix}`)
        await loadApps(true)

        toast({
          title: t.gitServer.appDeletedSuccess,
          status: 'success',
          duration: TOAST_DURATION.MEDIUM,
          isClosable: true,
        })
      } catch (error) {
        // 失败时回滚
        setApps(previousApps)
        handleError(error, { context: '删除Git应用' })
        throw error
      }
    },
    [adminPrefix, handleError, toast, loadApps, t, apps]
  )

  const deployApp = useCallback(
    async (appName: string) => {
      try {
        const response = await fetch(
          buildApiPath(adminPrefix, `/git-server/app/redeploy?name=${encodeURIComponent(appName)}`),
          {
            method: 'POST',
          }
        )

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}))
          throw new Error(errorData.error || t.gitServer.deployFailed || 'Failed to trigger deploy')
        }

        toast({
          title: t.gitServer.redeployStarted,
          description: t.gitServer.redeployDescription,
          status: 'info',
          duration: TOAST_DURATION.MEDIUM,
          isClosable: true,
        })

        // 清除缓存，强制重新加载
        cache.delete(`apps-${adminPrefix}`)
        await loadApps(true)
      } catch (error) {
        handleError(error, { context: '部署应用' })
        throw error
      }
    },
    [adminPrefix, handleError, toast, loadApps, t]
  )

  const updateEnvVars = useCallback(
    async (appName: string, envVars: Record<string, string>) => {
      try {
        const response = await fetch(
          buildApiPath(adminPrefix, `/git-server/app/env?name=${encodeURIComponent(appName)}`),
          {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ env_vars: envVars }),
          }
        )

        if (!response.ok) {
          throw new Error(t.gitServer.deployFailed || 'Failed to update environment variables')
        }

        const responseData = await response.json().catch(() => ({}))

        toast({
          title: t.gitServer.envVarsUpdated,
          description: responseData.message || t.gitServer.needRedeployForEnvVars,
          status: 'success',
          duration: TOAST_DURATION.MEDIUM,
          isClosable: true,
        })

        // 清除缓存，强制重新加载
        cache.delete(`apps-${adminPrefix}`)
        await loadApps(true)
      } catch (error) {
        handleError(error, { context: '更新环境变量' })
        throw error
      }
    },
    [adminPrefix, handleError, toast, loadApps, t]
  )

  const updateRouting = useCallback(
    async (appName: string, domain: string, port: number) => {
      try {
        const response = await fetch(
          buildApiPath(adminPrefix, `/git-server/app/routing?name=${encodeURIComponent(appName)}`),
          {
            method: 'PUT',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ domain, port }),
          }
        )

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}))
          throw new Error(errorData.error || t.gitServer.deployFailed || 'Failed to update domain and port')
        }

        toast({
          title: t.gitServer.routingUpdated,
          status: 'success',
          duration: TOAST_DURATION.MEDIUM,
          isClosable: true,
        })

        // 清除缓存，强制重新加载
        cache.delete(`apps-${adminPrefix}`)
        await loadApps(true)
      } catch (error) {
        handleError(error, { context: '更新域名和端口' })
        throw error
      }
    },
    [adminPrefix, handleError, toast, loadApps, t]
  )

  return {
    apps,
    loading,
    loadApps,
    createApp,
    deleteApp,
    deployApp,
    updateEnvVars,
    updateRouting,
    updateAppRuntime,
    uploadAppArtifact,
  }
}

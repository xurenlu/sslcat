import React, { createContext, useContext, useState, useCallback, ReactNode } from 'react'
import { GitApp } from '../pages/GitServerManagement/types'
import { SSHKey } from '../pages/GitServerManagement/types'
import { GitServerConfig } from '../pages/GitServerManagement/types'
import { useGitApps } from '../hooks/useGitApps'
import { useSSHKeys } from '../hooks/useSSHKeys'
import { useGitServerConfig } from '../hooks/useGitServerConfig'
import { useConfig } from './ConfigContext'

interface GitServerContextValue {
  apps: GitApp[]
  sshKeys: SSHKey[]
  config: GitServerConfig | null
  loading: boolean
  refreshAll: () => Promise<void>
  // Git Apps methods
  createApp: (name: string, autoSSL: boolean) => Promise<any>
  deleteApp: (appName: string) => Promise<void>
  deployApp: (appName: string) => Promise<void>
  updateEnvVars: (appName: string, envVars: Record<string, string>) => Promise<void>
  updateRouting: (appName: string, domain: string, port: number) => Promise<void>
  // SSH Keys methods
  addSSHKey: (name: string, publicKey: string) => Promise<void>
  deleteSSHKey: (fingerprint: string) => Promise<void>
  // Config methods
  updateConfig: (config: GitServerConfig) => Promise<GitServerConfig>
  restartSSHD: () => Promise<void>
}

const GitServerContext = createContext<GitServerContextValue | undefined>(undefined)

interface GitServerProviderProps {
  children: ReactNode
}

export const GitServerProvider: React.FC<GitServerProviderProps> = ({ children }) => {
  const { adminPrefix } = useConfig()

  // 使用自定义 Hooks
  const {
    apps,
    loading: appsLoading,
    loadApps,
    createApp,
    deleteApp,
    deployApp,
    updateEnvVars,
    updateRouting,
  } = useGitApps({ adminPrefix })

  const {
    sshKeys,
    loading: keysLoading,
    loadSSHKeys,
    addSSHKey,
    deleteSSHKey,
  } = useSSHKeys({ adminPrefix })

  const {
    config,
    loading: configLoading,
    loadConfig,
    updateConfig,
    restartSSHD,
  } = useGitServerConfig({ adminPrefix })

  const loading = appsLoading || keysLoading || configLoading

  // 统一刷新所有数据
  const refreshAll = useCallback(async () => {
    await Promise.all([loadApps(), loadSSHKeys(), loadConfig()])
  }, [loadApps, loadSSHKeys, loadConfig])

  const value: GitServerContextValue = {
    apps,
    sshKeys,
    config,
    loading,
    refreshAll,
    createApp,
    deleteApp,
    deployApp,
    updateEnvVars,
    updateRouting,
    addSSHKey,
    deleteSSHKey,
    updateConfig,
    restartSSHD,
  }

  return <GitServerContext.Provider value={value}>{children}</GitServerContext.Provider>
}

export const useGitServerContext = () => {
  const context = useContext(GitServerContext)
  if (context === undefined) {
    throw new Error('useGitServerContext must be used within a GitServerProvider')
  }
  return context
}


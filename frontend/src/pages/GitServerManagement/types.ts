/**
 * Git Deploy 相关类型定义
 */

export interface GitApp {
  id: string
  name: string
  git_url?: string
  status: 'active' | 'inactive' | 'deploying' | 'error'
  lastDeploy: string
  commits: number
  autoSSL: boolean
  domain?: string
  port?: number
  envVars?: Record<string, string>
  allowed_keys?: string[]
  push_history?: any[]
  pending_restart?: boolean
}

export interface SSHKey {
  id: string
  name: string
  fingerprint: string
  type: string
  created: string
  lastUsed?: string
}

export interface GitServerConfig {
  enabled: boolean
  port: number
  webhook: string
  defaultBranch: string
  autoSSL: boolean
  domainSuffix: string
  portRange: [number, number]
  welcomeMessage: string
  sslEmail: string
  defaultStrategy: string
  buildTimeout: number
  autoDomain: boolean
}


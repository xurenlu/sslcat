/**
 * Git Deploy 相关类型定义
 */

/**
 * Git Deploy 后端返回的原始状态值
 */
export type GitAppBackendStatus = 'idle' | 'building' | 'deploying' | 'running' | 'failed'
export type RunnerSourceType = 'git' | 'directory' | 'binary' | 'docker_image'
export type RunnerRuntimeType = 'auto' | 'docker_image'

/**
 * Git Deploy 前端显示的映射状态值
 */
export type GitAppDisplayStatus = 'active' | 'inactive' | 'deploying' | 'error'

/**
 * 后端原始状态接口（用于 API 响应）
 */
export interface GitAppBackendResponse {
  id: string
  name: string
  git_url?: string
  status: GitAppBackendStatus
  last_deploy?: string
  docker_image?: string
  domain?: string
  port?: number
  env_vars?: Record<string, string>
  allowed_keys?: string[]
  push_history?: any[]
  pending_restart?: boolean
  autoSSL?: boolean
  deploy_history?: any[]
  source_type?: RunnerSourceType
  runtime?: RunnerSpec
}

/**
 * 将后端状态映射为前端显示状态
 */
export function mapBackendStatusToDisplayStatus(backendStatus: GitAppBackendStatus): GitAppDisplayStatus {
  switch (backendStatus) {
    case 'running':
      return 'active'
    case 'idle':
      return 'inactive'
    case 'building':
    case 'deploying':
      return 'deploying'
    case 'failed':
      return 'error'
    default:
      return 'inactive'
  }
}

/**
 * 转换后端应用数据为前端格式
 */
export function transformBackendAppToGitApp(backendApp: GitAppBackendResponse): GitApp {
  return {
    id: backendApp.id || backendApp.name,
    name: backendApp.name,
    git_url: backendApp.git_url,
    status: mapBackendStatusToDisplayStatus(backendApp.status),
    lastDeploy: backendApp.last_deploy || '',
    commits: 0, // 后端暂未提供此字段
    autoSSL: backendApp.autoSSL || false,
    domain: backendApp.domain,
    port: backendApp.port,
    envVars: backendApp.env_vars,
    allowed_keys: backendApp.allowed_keys,
    push_history: backendApp.push_history,
    pending_restart: backendApp.pending_restart,
    sourceType: backendApp.source_type,
    runtime: backendApp.runtime,
  }
}

export interface GitApp {
  id: string
  name: string
  git_url?: string
  status: GitAppDisplayStatus
  lastDeploy: string
  commits: number
  autoSSL: boolean
  domain?: string
  port?: number
  envVars?: Record<string, string>
  allowed_keys?: string[]
  push_history?: any[]
  pending_restart?: boolean
  sourceType?: RunnerSourceType
  runtime?: RunnerSpec
}

export interface DockerVolumeMount {
  source: string
  target: string
  read_only?: boolean
}

export interface DockerImageRunConfig {
  image?: string
  pull_policy?: string
  entrypoint?: string
  command?: string[]
  env_vars?: Record<string, string>
  volumes?: DockerVolumeMount[]
  internal_port?: number
  restart_policy?: string
}

export interface ArtifactRunConfig {
  kind?: RunnerSourceType
  path?: string
  work_dir?: string
  start_command?: string
  internal_port?: number
  env_vars?: Record<string, string>
}

export interface RunnerSpec {
  source_type?: RunnerSourceType
  runtime_type?: RunnerRuntimeType
  artifact?: ArtifactRunConfig
  docker_image?: DockerImageRunConfig
  env_vars?: Record<string, string>
  start_command?: string
  work_dir?: string
  internal_port?: number
  health_check_path?: string
}

export interface CreateAppRuntimeOptions {
  sourceType: RunnerSourceType
  autoDeploy?: boolean
  runtime?: RunnerSpec
  artifact?: {
    files: File[]
    paths: string[]
    startCommand?: string
    workDir?: string
    internalPort?: number
    envVars?: Record<string, string>
  }
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

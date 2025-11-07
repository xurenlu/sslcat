export type TunnelStatus = 'unknown' | 'disconnected' | 'connecting' | 'connected' | 'error'

export interface TunnelCredentialSummary {
  key: string
  has_value: boolean
}

export interface TunnelWithStatus {
  provider_id: string
  id: string
  name: string
  protocol: string
  local_address: string
  local_port: number
  public_hostname?: string
  public_port?: number
  edge_region?: string
  auto_start: boolean
  metadata?: Record<string, string>
  parameters?: Record<string, string>
  notes?: string
  status: TunnelStatus
  last_error?: string
  updated_at?: string
  log_path?: string
  process_id?: string
  pid?: number
  restart_count: number
  last_started_at?: string
  last_stopped_at?: string
}

export interface TunnelProviderSummary {
  id: string
  name: string
  type: string
  enabled: boolean
  description?: string
  auto_start: boolean
  options?: Record<string, string>
  credentials: TunnelCredentialSummary[]
  tunnels: TunnelWithStatus[]
}

export interface TunnelDefinitionPayload {
  id?: string
  name: string
  protocol: string
  local_address: string
  local_port: number
  public_hostname?: string
  public_port?: number
  edge_region?: string
  auto_start: boolean
  metadata?: Record<string, string>
  parameters?: Record<string, string>
  notes?: string
}

export interface TunnelProviderPayload {
  id?: string
  name: string
  type: string
  enabled: boolean
  description?: string
  auto_start: boolean
  credentials?: Record<string, string>
  options?: Record<string, string>
  tunnels: TunnelDefinitionPayload[]
}


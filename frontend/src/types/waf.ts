// WAF 相关类型定义

export interface WAFStats {
  enabled: boolean
  total_rules: number
  total_events: number
  blocked_events: number
  detection_rate: number
  rules_by_type: Record<string, number>
  events_by_type: Record<string, number>
}

export interface WAFRule {
  id: string
  name: string
  type: string
  pattern: string
  action: string
  enabled: boolean
  description: string
  created_at: string
}

export interface WAFEvent {
  id: string
  client_ip: string
  user_agent: string
  url: string
  method: string
  rule_id: string
  rule_name: string
  rule_type: string
  action: string
  payload: string
  timestamp: string
  blocked: boolean
}

export interface WAFStatsResponse {
  success: boolean
  message?: string
  data?: WAFStats
}

export interface WAFRulesResponse {
  success: boolean
  message?: string
  rules?: WAFRule[]
}

export interface WAFEventsResponse {
  success: boolean
  message?: string
  events?: WAFEvent[]
  total?: number
}

export interface WAFConfigRequest {
  enabled?: boolean
}

// 规则类型枚举
export enum RuleType {
  SQLInjection = 'sql_injection',
  XSS = 'xss',
  PathTraversal = 'path_traversal',
  CommandInjection = 'command_injection',
  FileUpload = 'file_upload',
  SensitiveFile = 'sensitive_file',
  ScannerDetection = 'scanner_detection',
  Custom = 'custom',
}

// 动作类型枚举
export enum ActionType {
  Block = 'block',
  Log = 'log',
  Warn = 'warn',
}


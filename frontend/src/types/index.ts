export interface ApiResponse<T = any> {
  success: boolean
  data?: T
  message?: string
  error?: string
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  total: number
  page: number
  limit: number
}

export interface ProxyRule {
  id: string
  domain: string
  target: string
  enabled: boolean
  ssl: boolean
  created: string
  updated?: string
}

export interface SSLCertificate {
  id: string
  domain: string
  issuer: string
  expires: string
  status: 'valid' | 'expiring' | 'expired'
  autoRenew: boolean
  created: string
}

export interface NotificationItem {
  id: string
  level: 'info' | 'warning' | 'error' | 'critical'
  type: string
  title: string
  message: string
  timestamp: string
  source: string
  details?: Record<string, string>
}

export interface SecurityEvent {
  id: string
  type: 'ddos_attack' | 'bruteforce' | 'suspicious_ip' | 'malware'
  severity: 'low' | 'medium' | 'high' | 'critical'
  source: string
  description: string
  timestamp: string
  blocked: boolean
}

export interface DashboardStats {
  activeRules: number
  cachedProxies: number
  publicIP: string
  goVersion: string
}

export interface SystemSettings {
  adminPrefix: string
  // 新的端口配置
  portMode: 'standard' | 'custom'
  customPort: number
  enableHttps: boolean
  autoSSL: boolean
  letsEncryptEmail: string
  sslProvider: string
  enableDDoSProtection: boolean
  maxRequestsPerMinute: string
  enableRateLimit: boolean
  enableAccessLog: boolean
  enableErrorLog: boolean
  logLevel: string
  enableNotifications: boolean
  notificationChannels: string
}

// 配置相关的类型定义

// 代理后端服务器配置
export interface ProxyBackend {
  id: string
  host: string
  port: number
  weight: number
  priority: number
  enabled: boolean
  health_check_enabled: boolean
  health_check_path: string
  health_check_interval: number
  health_check_timeout: number
  health_check_method: string
  expected_status_code: number
  max_connections: number
  connect_timeout: number
  read_timeout: number
  write_timeout: number
  keep_alive_timeout: number
  tls_enabled: boolean
  tls_insecure: boolean
  max_retries: number
  retry_interval: number
  failure_threshold: number
  recovery_threshold: number
}

// 路径前缀规则配置
export interface PathPrefixRule {
  // 规则名称和描述
  name: string // 规则名称
  description: string // 规则描述
  enabled: boolean // 是否启用该规则

  // 路径前缀配置
  prefixes: string[] // 路径前缀列表，如 ["/api/v1/", "/api/v2/"]
  exact: boolean // 是否精确匹配路径前缀

  // 后端服务器配置
  backends: ProxyBackend[] // 该规则对应的后端服务器列表

  // 负载均衡配置
  load_balancer_algorithm: string // 负载均衡算法

  // 会话保持配置
  session_affinity_enabled: boolean // 是否启用会话保持
  session_affinity_method: string // 会话保持方法
  session_affinity_cookie: string // Cookie名称
  session_affinity_header: string // Header名称
  session_affinity_ttl: number // 会话保持时间（秒）

  // 健康检查配置
  health_check_enabled: boolean // 是否启用健康检查
  health_check_path: string // 健康检查路径
  health_check_interval: number // 健康检查间隔（秒）
  health_check_timeout: number // 健康检查超时（秒）
  health_check_method: string // 健康检查HTTP方法
  expected_status_code: number // 期望的状态码

  // 故障转移配置
  failover_enabled: boolean // 是否启用故障转移
  max_retries: number // 最大重试次数
  retry_interval: number // 重试间隔（秒）
  failure_threshold: number // 故障阈值
  recovery_threshold: number // 恢复阈值
}

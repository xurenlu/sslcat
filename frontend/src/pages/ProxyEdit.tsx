import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  Button,
  Card,
  CardBody,
  FormControl,
  FormLabel,
  Input,
  Switch,
  HStack,
  VStack,
  Icon,
  useToast,
  Text,
  Divider,
  Alert,
  AlertIcon,
  Flex,
  SimpleGrid,
} from '@chakra-ui/react'
import { FiArrowLeft, FiZap, FiGlobe, FiShield, FiSave, FiPlus, FiClock, FiSettings } from 'react-icons/fi'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useConfig, buildPath, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'
import HeaderEditor from '../components/HeaderEditor'
import { CORS_PRESET } from '../constants/cors'
import BackendConfig from '../components/BackendConfig'
import WebSocketConfig from '../components/WebSocketConfig'
import PathPrefixRulesConfig from '../components/PathPrefixRulesConfig'
import { detectProxyLoopInBackends } from '../utils/proxyLoopDetection'

interface ProxyAuthUser {
  username: string
  password: string
}

interface ProxyBackend {
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
  max_retries: number
  retry_interval: number
  failure_threshold: number
  recovery_threshold: number
  connect_timeout: number
  read_timeout: number
  write_timeout: number
  keep_alive_timeout: number
  max_connections: number
  tls_enabled: boolean
  tls_insecure: boolean
}

interface ProxyRuleForm {
  domain: string
  enabled: boolean
  ssl_only: boolean
  
  // 路径前缀匹配配置
  path_prefixes: string[]
  path_exact: boolean
  
  // 路径前缀规则配置（支持多组配置）
  path_prefix_rules: Array<{
    name: string
    description: string
    enabled: boolean
    prefixes: string[]
    exact: boolean
    backends: ProxyBackend[]
    load_balancer_algorithm: string
    session_affinity_enabled: boolean
    session_affinity_method: string
    session_affinity_cookie: string
    session_affinity_header: string
    session_affinity_ttl: number
    health_check_enabled: boolean
    health_check_path: string
    health_check_interval: number
    health_check_timeout: number
    health_check_method: string
    expected_status_code: number
    failover_enabled: boolean
    max_retries: number
    retry_interval: number
    failure_threshold: number
    recovery_threshold: number
  }>
  
  // 统一后端配置
  backends: ProxyBackend[]
  
  // 负载均衡配置（自动启用）
  load_balancer_algorithm: string
  
  // 会话保持配置
  session_affinity_enabled: boolean
  session_affinity_method: string
  session_affinity_cookie: string
  session_affinity_header: string
  session_affinity_ttl: number
  
  // 健康检查配置
  health_check_enabled: boolean
  health_check_path: string
  health_check_interval: number
  health_check_timeout: number
  health_check_method: string
  expected_status_code: number
  
  // 故障转移配置
  failover_enabled: boolean
  max_retries: number
  retry_interval: number
  failure_threshold: number
  recovery_threshold: number
  
  // 类CDN设置
  cdn_mode_enabled: boolean
  cdn_enabled: boolean
  cdn_preset: string
  cdn_ttl_seconds: number
  // HTTP Host头部优化
  optimize_host_header: boolean
  // 访问控制字段
  auth_enabled: boolean
  auth_users: ProxyAuthUser[]
  auth_session_timeout: number
  auth_cookie_domain: string
  // 代理超时配置
  connect_timeout_sec: number
  keep_alive_timeout_sec: number
  idle_timeout_sec: number
  
  // WAF 配置
  waf_enabled?: boolean | null
  
  // 性能监控配置
  enable_tracing: boolean
  enable_metrics: boolean
  tls_handshake_timeout_sec: number
  expect_continue_timeout_sec: number
  health_check_timeout_sec: number
  // WebSocket优化配置
  websocket_optimized: boolean
  websocket_buffer_size: number
  websocket_read_timeout: number
  websocket_write_timeout: number
  websocket_ping_interval: number
  upstream_request_headers: Record<string, string>
  response_headers: Record<string, string>
}

const ProxyEdit: React.FC = () => {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const toast = useToast()
  const [loading, setLoading] = useState(false)
  const [initialLoading, setInitialLoading] = useState(true)
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  
  const domain = searchParams.get('domain') || ''
  
  const [formData, setFormData] = useState<ProxyRuleForm>({
    domain: '',
    enabled: true,
    ssl_only: true,
    
    // 路径前缀匹配配置
    path_prefixes: [],
    path_exact: false,
    
    // 路径前缀规则配置
    path_prefix_rules: [],
    
    // 统一后端配置（至少一个后端）
    backends: [
      {
        id: '',
        host: '',
        port: 80,
        weight: 1,
        priority: 0,
        enabled: true,
        health_check_enabled: false,
        health_check_path: '/health',
        health_check_interval: 30,
        health_check_timeout: 5,
        health_check_method: 'GET',
        expected_status_code: 200,
        max_retries: 3,
        retry_interval: 1,
        failure_threshold: 3,
        recovery_threshold: 2,
        connect_timeout: 30,
        read_timeout: 30,
        write_timeout: 30,
        keep_alive_timeout: 30,
        max_connections: 100,
        tls_enabled: false,
        tls_insecure: false
      }
    ],
    
    // 负载均衡配置（自动启用）
    load_balancer_algorithm: 'round_robin',
    
    // 会话保持配置
    session_affinity_enabled: false,
    session_affinity_method: 'ip',
    session_affinity_cookie: '',
    session_affinity_header: '',
    session_affinity_ttl: 3600,
    
    // 健康检查配置
    health_check_enabled: false,
    health_check_path: '/health',
    health_check_interval: 30,
    health_check_timeout: 5,
    health_check_method: 'GET',
    expected_status_code: 200,
    
    // 故障转移配置
    failover_enabled: true,
    max_retries: 3,
    retry_interval: 1,
    failure_threshold: 3,
    recovery_threshold: 2,
    
    // 类CDN设置
    cdn_mode_enabled: false,
    cdn_enabled: false,
    cdn_preset: '',
    cdn_ttl_seconds: 259200, // 默认72小时
    // HTTP Host头部优化
    optimize_host_header: false,
    // 访问控制字段
    auth_enabled: false,
    auth_users: [{ username: '', password: '' }],
    auth_session_timeout: 3600,
    auth_cookie_domain: '',
    // 代理超时配置
    connect_timeout_sec: 30,
    keep_alive_timeout_sec: 30,
    idle_timeout_sec: 90,
    tls_handshake_timeout_sec: 10,
    expect_continue_timeout_sec: 1,
    health_check_timeout_sec: 5,
    // WebSocket优化配置
    websocket_optimized: true,
    websocket_buffer_size: 100,
    websocket_read_timeout: 30,
    // WAF 配置 (null 表示使用全局配置)
    waf_enabled: null,
    websocket_write_timeout: 10,
    websocket_ping_interval: 30,
    upstream_request_headers: {},
    response_headers: {},
    
    // 性能监控配置
    enable_tracing: false,
    enable_metrics: false,
  })

  // 加载现有规则数据
  useEffect(() => {
    const loadRuleData = async () => {
      if (!domain) {
        toast({
          title: '参数错误',
          description: '缺少域名参数',
          status: 'error',
          duration: 3000,
          isClosable: true,
        })
        navigate(buildPath(adminPrefix, '/proxy'))
        return
      }

      try {
        const response = await fetch(buildApiPath(adminPrefix, `/proxy/rule?domain=${encodeURIComponent(domain)}`), {
          method: 'GET',
          credentials: 'include',
        })

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`)
        }

        const data = await response.json()
        if (data && data.success && data.data) {
          const rule = data.data
          
          // 迁移逻辑：从旧格式到新格式
          let backends = rule.backends || []
          if (backends.length === 0) {
            // 从旧字段迁移
            if (rule.load_balancer_enabled && rule.load_balancer_backends && rule.load_balancer_backends.length > 0) {
              // 从负载均衡配置迁移
              backends = rule.load_balancer_backends
            } else if (rule.target) {
              // 从单后端配置迁移
              backends = [{
                id: `${rule.domain}_backend_1`,
                host: rule.target,
                port: rule.port || 80,
                weight: 1,
                priority: 0,
                enabled: true,
                health_check_enabled: false,
                health_check_path: '/health',
                health_check_interval: 30,
                health_check_timeout: 5,
                health_check_method: 'GET',
                expected_status_code: 200,
                max_retries: 3,
                retry_interval: 1,
                failure_threshold: 3,
                recovery_threshold: 2,
                connect_timeout: 30,
                read_timeout: 30,
                write_timeout: 30,
                keep_alive_timeout: 30,
                max_connections: 100,
                tls_enabled: false,
                tls_insecure: false
              }]
            }
          }
          
          setFormData({
            domain: rule.domain || '',
            enabled: rule.enabled ?? true,
            ssl_only: rule.ssl_only ?? true,
            
            // 路径前缀匹配配置
            path_prefixes: rule.path_prefixes || [],
            path_exact: rule.path_exact ?? false,
            
            // 路径前缀规则配置
            path_prefix_rules: rule.path_prefix_rules || [],
            
            // 统一后端配置
            backends: backends,
            
            // WAF 配置
            waf_enabled: rule.waf_enabled ?? null,
            
            // 负载均衡配置（自动启用）
            load_balancer_algorithm: rule.load_balancer_algorithm || 'round_robin',
            
            // 会话保持配置
            session_affinity_enabled: rule.session_affinity_enabled ?? false,
            session_affinity_method: rule.session_affinity_method || 'ip',
            session_affinity_cookie: rule.session_affinity_cookie || '',
            session_affinity_header: rule.session_affinity_header || '',
            session_affinity_ttl: rule.session_affinity_ttl || 3600,
            
            // 健康检查配置
            health_check_enabled: rule.health_check_enabled ?? false,
            health_check_path: rule.health_check_path || '/health',
            health_check_interval: rule.health_check_interval || 30,
            health_check_timeout: rule.health_check_timeout || 5,
            health_check_method: rule.health_check_method || 'GET',
            expected_status_code: rule.expected_status_code || 200,
            
            // 故障转移配置
            failover_enabled: rule.failover_enabled ?? true,
            max_retries: rule.max_retries || 3,
            retry_interval: rule.retry_interval || 1,
            failure_threshold: rule.failure_threshold || 3,
            recovery_threshold: rule.recovery_threshold || 2,
            
            // 类CDN设置 - 如果CDN缓存或Host头部优化任一启用，则认为类CDN模式启用
            cdn_mode_enabled: (rule.cdn_enabled ?? false) || (rule.optimize_host_header ?? false),
            cdn_enabled: rule.cdn_enabled ?? false,
            cdn_preset: rule.cdn_preset || '',
            cdn_ttl_seconds: rule.cdn_ttl_seconds || 259200,
            // HTTP Host头部优化
            optimize_host_header: rule.optimize_host_header ?? false,
            // 访问控制字段
            auth_enabled: rule.auth_enabled ?? false,
            auth_users: rule.auth_users || [{ username: '', password: '' }],
            auth_session_timeout: rule.auth_session_timeout || 3600,
            auth_cookie_domain: rule.auth_cookie_domain || '',
            // 代理超时配置
            connect_timeout_sec: rule.connect_timeout_sec || 30,
            keep_alive_timeout_sec: rule.keep_alive_timeout_sec || 30,
            idle_timeout_sec: rule.idle_timeout_sec || 90,
            tls_handshake_timeout_sec: rule.tls_handshake_timeout_sec || 10,
            expect_continue_timeout_sec: rule.expect_continue_timeout_sec || 1,
            health_check_timeout_sec: rule.health_check_timeout_sec || 5,
            // WebSocket优化配置
            websocket_optimized: rule.websocket_optimized ?? true,
            websocket_buffer_size: rule.websocket_buffer_size || 100,
            websocket_read_timeout: rule.websocket_read_timeout || 30,
            websocket_write_timeout: rule.websocket_write_timeout || 10,
            websocket_ping_interval: rule.websocket_ping_interval || 30,
            upstream_request_headers: rule.upstream_request_headers || {},
            response_headers: rule.response_headers || {},
            
            // 性能监控配置
            enable_tracing: rule.enable_tracing || false,
            enable_metrics: rule.enable_metrics || false,
          })
        }
      } catch (error) {
        console.error('加载代理规则失败:', error)
        toast({
          title: '加载失败',
          description: error instanceof Error ? error.message : '未知错误',
          status: 'error',
          duration: 3000,
          isClosable: true,
        })
        navigate(buildPath(adminPrefix, '/proxy'))
      } finally {
        setInitialLoading(false)
      }
    }

    loadRuleData()
  }, [domain, adminPrefix, navigate, toast])

  const handleInputChange = (field: string, value: any) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }))
  }

  const handleAuthUserChange = (index: number, field: keyof ProxyAuthUser, value: string) => {
    setFormData(prev => ({
      ...prev,
      auth_users: prev.auth_users.map((user, i) => 
        i === index ? { ...user, [field]: value } : user
      )
    }))
  }

  const addAuthUser = () => {
    setFormData(prev => ({
      ...prev,
      auth_users: [...prev.auth_users, { username: '', password: '' }]
    }))
  }

  const removeAuthUser = (index: number) => {
    if (formData.auth_users.length > 1) {
      setFormData(prev => ({
        ...prev,
        auth_users: prev.auth_users.filter((_, i) => i !== index)
      }))
    }
  }

  // 后端服务器管理函数
  const handleBackendChange = (index: number, field: string, value: any) => {
    setFormData(prev => ({
      ...prev,
      backends: prev.backends.map((backend, i) => 
        i === index ? { ...backend, [field]: value } : backend
      )
    }))
  }

  const addBackend = () => {
    const newBackend: ProxyBackend = {
      id: `backend_${Date.now()}`,
      host: '',
      port: 8080,
      weight: 1,
      priority: 0,
      enabled: true,
      health_check_enabled: false,
      health_check_path: '/health',
      health_check_interval: 30,
      health_check_timeout: 5,
      health_check_method: 'GET',
      expected_status_code: 200,
      max_retries: 3,
      retry_interval: 1,
      failure_threshold: 3,
      recovery_threshold: 2,
      connect_timeout: 30,
      read_timeout: 30,
      write_timeout: 30,
      keep_alive_timeout: 30,
      max_connections: 100,
      tls_enabled: false,
      tls_insecure: false
    }
    setFormData(prev => ({
      ...prev,
      backends: [...prev.backends, newBackend]
    }))
  }

  const removeBackend = (index: number) => {
    if (formData.backends.length > 1) {
      setFormData(prev => ({
        ...prev,
        backends: prev.backends.filter((_, i) => i !== index)
      }))
    }
  }

  const applyCorsPreset = () => {
    setFormData(prev => ({
      ...prev,
      response_headers: {
        ...prev.response_headers,
        ...CORS_PRESET.response,
      },
    }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    // 检测代理循环
    const loopErrors = detectProxyLoopInBackends(formData.backends)
    if (loopErrors.length > 0) {
      toast({
        title: '配置错误',
        description: (
          <Box>
            <Text mb={2}>检测到代理循环配置，无法保存：</Text>
            {loopErrors.map((error, index) => (
              <Text key={index} fontSize="sm">• {error}</Text>
            ))}
          </Box>
        ),
        status: 'error',
        duration: 8000,
        isClosable: true,
      })
      return
    }
    
    setLoading(true)

    try {
      const response = await fetch(buildApiPath(adminPrefix, `/proxy/rule?domain=${encodeURIComponent(domain)}`), {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          domain: formData.domain,
          backends: formData.backends,
          enabled: formData.enabled,
          ssl_only: formData.ssl_only,
          // WAF 配置
          waf_enabled: formData.waf_enabled,
          // 类CDN设置
          cdn_mode_enabled: formData.cdn_mode_enabled,
          cdn_enabled: formData.cdn_enabled,
          cdn_preset: formData.cdn_preset,
          cdn_ttl_seconds: formData.cdn_ttl_seconds,
          // HTTP Host头部优化
          optimize_host_header: formData.optimize_host_header,
          // 访问控制字段
          auth_enabled: formData.auth_enabled,
          auth_users: formData.auth_users.filter(user => user.username.trim() && user.password.trim()),
          auth_session_timeout: formData.auth_session_timeout,
          auth_cookie_domain: formData.auth_cookie_domain || formData.domain,
          upstream_request_headers: formData.upstream_request_headers,
          response_headers: formData.response_headers,
        }),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const data = await response.json()
      if (data.success) {
        toast({
          title: '更新成功',
          description: '代理规则已更新',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        navigate(buildPath(adminPrefix, '/proxy'))
      } else {
        throw new Error(data.message || '更新失败')
      }
    } catch (error) {
      console.error('更新代理规则失败:', error)
      toast({
        title: '更新失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  if (initialLoading) {
    return (
      <Box p={6}>
        <Flex align="center" justify="center" h="200px">
          <Text>加载中...</Text>
        </Flex>
      </Box>
    )
  }

  return (
    <Box p={6}>
      <VStack spacing={6} align="stretch">
        {/* 页面头部 */}
        <Flex align="center" justify="space-between">
          <HStack spacing={4}>
            <Button
              leftIcon={<Icon as={FiArrowLeft} />}
              variant="ghost"
              onClick={() => navigate(buildPath(adminPrefix, '/proxy'))}
            >
{t.common.back}
            </Button>
            <Heading size="lg">{t.proxy.editRule}</Heading>
          </HStack>
        </Flex>

        {/* 编辑表单 */}
        <Card>
          <CardBody>
            <form onSubmit={handleSubmit}>
              <VStack spacing={6} align="stretch">
                {/* 基本配置 */}
                <Box>
                  <Heading size="md" mb={4} display="flex" alignItems="center">
                    <Icon as={FiGlobe} mr={2} />
                    基本配置
                  </Heading>
                  <VStack spacing={4} align="stretch">
                    <FormControl isRequired>
                      <FormLabel>域名</FormLabel>
                      <Input
                        value={formData.domain}
                        onChange={(e) => handleInputChange('domain', e.target.value)}
                        placeholder={domain || "example.com"}
                        isDisabled
                      />
                      <Text fontSize="sm" color="gray.500" mt={1}>
                        域名不可修改
                      </Text>
                    </FormControl>

                  </VStack>
                </Box>

                <Divider />

                <Box>
                  <Heading size="md" mb={4} display="flex" alignItems="center">
                    <Icon as={FiSettings} mr={2} />
                    自定义头部
                  </Heading>
                  <VStack align="stretch" spacing={6}>
                    <Box>
                      <Text fontWeight="medium" mb={2}>上游请求头</Text>
                      <HeaderEditor
                        value={formData.upstream_request_headers}
                        onChange={(headers) => handleInputChange('upstream_request_headers', headers)}
                        placeholderKey="X-Forwarded-For"
                        placeholderValue="client-ip"
                      />
                    </Box>
                    <Box>
                      <Flex justify="space-between" align="center" mb={2}>
                        <Text fontWeight="medium">响应头</Text>
                        <Button size="sm" variant="outline" onClick={applyCorsPreset}>一键填充 CORS 预设</Button>
                      </Flex>
                      <HeaderEditor
                        value={formData.response_headers}
                        onChange={(headers) => handleInputChange('response_headers', headers)}
                        placeholderKey="Access-Control-Allow-Origin"
                        placeholderValue="*"
                      />
                    </Box>
                  </VStack>
                </Box>

                {/* 路径前缀规则配置 */}
                <PathPrefixRulesConfig
                  pathPrefixRules={formData.path_prefix_rules}
                  onChange={(rules) => handleInputChange('path_prefix_rules', rules)}
                />

                <Divider />

                {/* 后端服务器配置 */}
                <BackendConfig
                  backends={formData.backends}
                  load_balancer_algorithm={formData.load_balancer_algorithm}
                  session_affinity_enabled={formData.session_affinity_enabled}
                  session_affinity_method={formData.session_affinity_method}
                  session_affinity_cookie={formData.session_affinity_cookie}
                  session_affinity_header={formData.session_affinity_header}
                  session_affinity_ttl={formData.session_affinity_ttl}
                  health_check_enabled={formData.health_check_enabled}
                  health_check_path={formData.health_check_path}
                  health_check_interval={formData.health_check_interval}
                  health_check_timeout={formData.health_check_timeout}
                  health_check_method={formData.health_check_method}
                  expected_status_code={formData.expected_status_code}
                  failover_enabled={formData.failover_enabled}
                  max_retries={formData.max_retries}
                  retry_interval={formData.retry_interval}
                  failure_threshold={formData.failure_threshold}
                  recovery_threshold={formData.recovery_threshold}
                  onFieldChange={handleInputChange}
                  onBackendChange={handleBackendChange}
                  onAddBackend={addBackend}
                  onRemoveBackend={removeBackend}
                />

                <Divider />

                {/* 安全配置 */}
                <Box>
                  <Heading size="md" mb={4} display="flex" alignItems="center">
                    <Icon as={FiShield} mr={2} />
                    安全配置
                  </Heading>
                  
                  <Alert status="info" mb={4}>
                    <AlertIcon />
                    <Box>
                      <Text fontWeight="bold" mb={1}>配置说明：</Text>
                      <Text fontSize="sm">
                        • <strong>启用规则</strong>：控制代理规则是否生效<br/>
                        • <strong>仅HTTPS</strong>：只允许HTTPS请求通过<br/>
                        • <strong>启用CDN缓存</strong>：开启缓存加速功能<br/>
                        • <strong>优化HTTP Host头部</strong>：使用目标地址域名作为Host头部，避免防盗链问题
                      </Text>
                    </Box>
                  </Alert>
                  <VStack spacing={4} align="stretch">
                    <HStack justify="space-between">
                      <FormLabel mb={0}>启用规则</FormLabel>
                      <Switch
                        isChecked={formData.enabled}
                        onChange={(e) => handleInputChange('enabled', e.target.checked)}
                      />
                    </HStack>

                    <HStack justify="space-between">
                      <FormLabel mb={0}>仅HTTPS</FormLabel>
                      <Switch
                        isChecked={formData.ssl_only}
                        onChange={(e) => handleInputChange('ssl_only', e.target.checked)}
                      />
                    </HStack>

                    <HStack justify="space-between">
                      <Box>
                        <FormLabel mb={1}>
                          <HStack>
                            <Icon as={FiShield} />
                            <Text>WAF 防护</Text>
                          </HStack>
                        </FormLabel>
                        <Text fontSize="sm" color="gray.500">
                          {formData.waf_enabled === null 
                            ? '使用全局 WAF 配置（默认）' 
                            : formData.waf_enabled 
                              ? '已为此域名启用 WAF' 
                              : '已为此域名禁用 WAF'}
                        </Text>
                      </Box>
                      <HStack>
                        <Button
                          size="sm"
                          variant={formData.waf_enabled === null ? 'solid' : 'outline'}
                          colorScheme={formData.waf_enabled === null ? 'blue' : 'gray'}
                          onClick={() => handleInputChange('waf_enabled', null)}
                        >
                          全局
                        </Button>
                        <Button
                          size="sm"
                          variant={formData.waf_enabled === true ? 'solid' : 'outline'}
                          colorScheme={formData.waf_enabled === true ? 'green' : 'gray'}
                          onClick={() => handleInputChange('waf_enabled', true)}
                        >
                          启用
                        </Button>
                        <Button
                          size="sm"
                          variant={formData.waf_enabled === false ? 'solid' : 'outline'}
                          colorScheme={formData.waf_enabled === false ? 'red' : 'gray'}
                          onClick={() => handleInputChange('waf_enabled', false)}
                        >
                          禁用
                        </Button>
                      </HStack>
                    </HStack>

                    <HStack justify="space-between">
                      <Box>
                        <FormLabel mb={1}>启用类CDN功能</FormLabel>
                        <Text fontSize="sm" color="gray.500">
                          启用CDN缓存和Host头部优化功能
                        </Text>
                      </Box>
                      <Switch
                        isChecked={formData.cdn_mode_enabled}
                        onChange={(e) => handleInputChange('cdn_mode_enabled', e.target.checked)}
                      />
                    </HStack>

                    {formData.cdn_mode_enabled && (
                      <VStack spacing={4} align="stretch">
                        <HStack justify="space-between">
                          <FormLabel mb={0}>启用CDN缓存</FormLabel>
                          <Switch
                            isChecked={formData.cdn_enabled}
                            onChange={(e) => handleInputChange('cdn_enabled', e.target.checked)}
                          />
                        </HStack>

                        {formData.cdn_enabled && (
                          <VStack spacing={4} align="stretch">
                            <Alert status="success" variant="subtle">
                              <AlertIcon />
                              <Box>
                                <Text fontWeight="bold" mb={1}>CDN缓存已启用</Text>
                                <Text fontSize="sm">
                                  系统将缓存静态资源，提升访问速度。建议配置合适的TTL时间。
                                </Text>
                              </Box>
                            </Alert>
                            
                            <FormControl>
                              <FormLabel>CDN预设</FormLabel>
                              <Input
                                value={formData.cdn_preset}
                                onChange={(e) => handleInputChange('cdn_preset', e.target.value)}
                                placeholder="default"
                              />
                              <Text fontSize="sm" color="gray.500" mt={1}>
                                缓存策略预设，可选：default, static, images
                              </Text>
                            </FormControl>
                            
                            <FormControl>
                              <FormLabel>CDN TTL (秒)</FormLabel>
                              <Input
                                type="number"
                                value={formData.cdn_ttl_seconds}
                                onChange={(e) => handleInputChange('cdn_ttl_seconds', parseInt(e.target.value))}
                                min="0"
                              />
                              <Text fontSize="sm" color="gray.500" mt={1}>
                                缓存时间，0表示使用全局设置
                              </Text>
                            </FormControl>
                          </VStack>
                        )}

                        <HStack justify="space-between">
                          <Box>
                            <FormLabel mb={0}>优化HTTP Host头部</FormLabel>
                            <Text fontSize="sm" color="gray.600">
                              解决防盗链问题
                            </Text>
                          </Box>
                          <Switch
                            isChecked={formData.optimize_host_header}
                            onChange={(e) => handleInputChange('optimize_host_header', e.target.checked)}
                          />
                        </HStack>
                        
                        {formData.optimize_host_header && (
                          <Alert status="warning">
                            <AlertIcon />
                            <Box>
                              <Text fontWeight="bold" mb={1}>Host头部优化已启用</Text>
                              <Text fontSize="sm">
                                系统将使用目标地址的域名作为HTTP Host头部，而不是浏览器发送的域名。
                                这有助于绕过某些防盗链检查，但可能影响某些依赖原始Host头部的应用。
                              </Text>
                            </Box>
                          </Alert>
                        )}
                      </VStack>
                    )}
                  </VStack>
                </Box>

                <Divider />

                {/* 访问控制 */}
                <Box>
                  <Heading size="md" mb={4}>访问控制</Heading>
                  <VStack spacing={4} align="stretch">
                    <HStack justify="space-between">
                      <FormLabel mb={0}>启用访问控制</FormLabel>
                      <Switch
                        isChecked={formData.auth_enabled}
                        onChange={(e) => handleInputChange('auth_enabled', e.target.checked)}
                      />
                    </HStack>

                    {formData.auth_enabled && (
                      <VStack spacing={4} align="stretch">
                        <Alert status="info">
                          <AlertIcon />
                          配置访问控制用户
                        </Alert>

                        {formData.auth_users.map((user, index) => (
                          <HStack key={index} spacing={4}>
                            <FormControl>
                              <FormLabel>用户名</FormLabel>
                              <Input
                                value={user.username}
                                onChange={(e) => handleAuthUserChange(index, 'username', e.target.value)}
                                placeholder={t.proxy.username}
                              />
                            </FormControl>
                            <FormControl>
                              <FormLabel>密码</FormLabel>
                              <Input
                                type="password"
                                value={user.password}
                                onChange={(e) => handleAuthUserChange(index, 'password', e.target.value)}
                                placeholder={t.proxy.password}
                              />
                            </FormControl>
                            <Button
                              colorScheme="red"
                              variant="outline"
                              onClick={() => removeAuthUser(index)}
                              isDisabled={formData.auth_users.length <= 1}
                            >
                              删除
                            </Button>
                          </HStack>
                        ))}

                        <Button
                          leftIcon={<Icon as={FiPlus} />}
                          variant="outline"
                          onClick={addAuthUser}
                        >
                          添加用户
                        </Button>

                        <HStack spacing={4}>
                          <FormControl>
                            <FormLabel>会话超时 (秒)</FormLabel>
                            <Input
                              type="number"
                              value={formData.auth_session_timeout}
                              onChange={(e) => handleInputChange('auth_session_timeout', parseInt(e.target.value))}
                              min="60"
                            />
                          </FormControl>
                          <FormControl>
                            <FormLabel>Cookie域名</FormLabel>
                            <Input
                              value={formData.auth_cookie_domain}
                              onChange={(e) => handleInputChange('auth_cookie_domain', e.target.value)}
                              placeholder=".example.com"
                            />
                          </FormControl>
                        </HStack>
                      </VStack>
                    )}
                  </VStack>
                </Box>

                <Divider />

                {/* 代理超时配置 */}
                <Box>
                  <Heading size="md" mb={4}>
                    <Icon as={FiClock} mr={2} />
                    代理超时配置
                  </Heading>
                  <VStack spacing={4}>
                    <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4} w="full">
                      <FormControl>
                        <FormLabel>连接超时（秒）</FormLabel>
                        <Input
                          type="number"
                          value={formData.connect_timeout_sec}
                          onChange={(e) => handleInputChange('connect_timeout_sec', parseInt(e.target.value) || 30)}
                          placeholder="30"
                        />
                        <Text fontSize="sm" color="gray.500" mt={1}>
                          建立连接到上游服务器的超时时间
                        </Text>
                      </FormControl>

                      <FormControl>
                        <FormLabel>连接保持超时（秒）</FormLabel>
                        <Input
                          type="number"
                          value={formData.keep_alive_timeout_sec}
                          onChange={(e) => handleInputChange('keep_alive_timeout_sec', parseInt(e.target.value) || 30)}
                          placeholder="30"
                        />
                        <Text fontSize="sm" color="gray.500" mt={1}>
                          TCP连接保持活跃的超时时间
                        </Text>
                      </FormControl>

                      <FormControl>
                        <FormLabel>空闲连接超时（秒）</FormLabel>
                        <Input
                          type="number"
                          value={formData.idle_timeout_sec}
                          onChange={(e) => handleInputChange('idle_timeout_sec', parseInt(e.target.value) || 90)}
                          placeholder="90"
                        />
                        <Text fontSize="sm" color="gray.500" mt={1}>
                          空闲连接在连接池中的超时时间
                        </Text>
                      </FormControl>

                      <FormControl>
                        <FormLabel>TLS握手超时（秒）</FormLabel>
                        <Input
                          type="number"
                          value={formData.tls_handshake_timeout_sec}
                          onChange={(e) => handleInputChange('tls_handshake_timeout_sec', parseInt(e.target.value) || 10)}
                          placeholder="10"
                        />
                        <Text fontSize="sm" color="gray.500" mt={1}>
                          TLS/SSL握手过程的超时时间
                        </Text>
                      </FormControl>

                      <FormControl>
                        <FormLabel>Expect-Continue超时（秒）</FormLabel>
                        <Input
                          type="number"
                          value={formData.expect_continue_timeout_sec}
                          onChange={(e) => handleInputChange('expect_continue_timeout_sec', parseInt(e.target.value) || 1)}
                          placeholder="1"
                        />
                        <Text fontSize="sm" color="gray.500" mt={1}>
                          等待100-Continue响应的超时时间
                        </Text>
                      </FormControl>

                      <FormControl>
                        <FormLabel>健康检查超时（秒）</FormLabel>
                        <Input
                          type="number"
                          value={formData.health_check_timeout_sec}
                          onChange={(e) => handleInputChange('health_check_timeout_sec', parseInt(e.target.value) || 5)}
                          placeholder="5"
                        />
                        <Text fontSize="sm" color="gray.500" mt={1}>
                          测试上游服务器连接的超时时间
                        </Text>
                      </FormControl>
                    </SimpleGrid>
                  </VStack>
                </Box>

                {/* WebSocket优化配置 */}
                <Card>
                  <CardBody>
                    <WebSocketConfig
                      websocket_optimized={formData.websocket_optimized}
                      websocket_buffer_size={formData.websocket_buffer_size}
                      websocket_read_timeout={formData.websocket_read_timeout}
                      websocket_write_timeout={formData.websocket_write_timeout}
                      websocket_ping_interval={formData.websocket_ping_interval}
                      onFieldChange={handleInputChange}
                    />
                  </CardBody>
                </Card>

                {/* 性能监控配置 */}
                <Box>
                  <Heading size="md" mb={4} color="gray.700">
                    <Icon as={FiZap} mr={2} />
                    {t.proxy.performance_monitoring}
                  </Heading>
                  
                  <VStack spacing={4}>
                    <FormControl>
                      <HStack justify="space-between">
                        <Box>
                          <FormLabel mb={1}>{t.proxy.enable_tracing}</FormLabel>
                          <Text fontSize="sm" color="red.500">
                            {t.proxy.tracing_warning}
                          </Text>
                        </Box>
                        <Switch
                          isChecked={formData.enable_tracing}
                          onChange={(e) => handleInputChange('enable_tracing', e.target.checked)}
                          size="lg"
                          colorScheme="red"
                        />
                      </HStack>
                    </FormControl>

                    <FormControl>
                      <HStack justify="space-between">
                        <Box>
                          <FormLabel mb={1}>{t.proxy.enable_metrics}</FormLabel>
                          <Text fontSize="sm" color="orange.500">
                            {t.proxy.metrics_warning}
                          </Text>
                        </Box>
                        <Switch
                          isChecked={formData.enable_metrics}
                          onChange={(e) => handleInputChange('enable_metrics', e.target.checked)}
                          size="lg"
                          colorScheme="orange"
                        />
                      </HStack>
                    </FormControl>
                  </VStack>
                </Box>

                {/* 提交按钮 */}
                <HStack spacing={4} justify="flex-end">
                  <Button
                    variant="outline"
                    onClick={() => navigate(buildPath(adminPrefix, '/proxy'))}
                  >
                    取消
                  </Button>
                  <Button
                    type="submit"
                    colorScheme="blue"
                    leftIcon={<Icon as={FiSave} />}
                    isLoading={loading}
                    loadingText={t.common.saving}
                  >
                    保存更改
                  </Button>
                </HStack>
              </VStack>
            </form>
          </CardBody>
        </Card>
      </VStack>
    </Box>
  )
}

export default ProxyEdit

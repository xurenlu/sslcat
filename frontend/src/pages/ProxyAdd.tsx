import React, { useState } from 'react'
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
  SimpleGrid,
  Text,
  Divider,
  Alert,
  AlertIcon,
  Flex,
} from '@chakra-ui/react'
import { FiArrowLeft, FiZap, FiGlobe, FiShield, FiPlus, FiClock, FiSettings } from 'react-icons/fi'
import { useNavigate } from 'react-router-dom'
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
  
  // 性能监控配置
  enable_tracing: boolean
  
  // WAF 配置
  waf_enabled?: boolean | null
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

const ProxyAdd: React.FC = () => {
  const navigate = useNavigate()
  const toast = useToast()
  const [loading, setLoading] = useState(false)
  const { adminPrefix } = useConfig()
  const t = useTranslation()
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
    
    // 性能监控配置
    enable_tracing: false,
    enable_metrics: false,
    // 访问控制字段
    auth_enabled: false,
    // WAF 配置 (null 表示使用全局配置)
    waf_enabled: null,
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
    websocket_write_timeout: 10,
    websocket_ping_interval: 30,
    upstream_request_headers: {},
    response_headers: {},
  })

  const applyCorsPreset = () => {
    setFormData(prev => ({
      ...prev,
      response_headers: {
        ...prev.response_headers,
        ...CORS_PRESET.response,
      },
    }))
  }

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
      const response = await fetch(buildApiPath(adminPrefix, '/proxy/rule'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include', // 包含认证 cookies
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
        const errorData = await response.json()
        throw new Error(errorData.error || '创建失败')
      }

      const result = await response.json()
      
      toast({
        title: '代理规则创建成功',
        description: '新的代理规则已添加到系统中',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      
      navigate(buildPath(adminPrefix, '/proxy'))
    } catch (error) {
      toast({
        title: '创建失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  const handleCancel = () => {
    navigate(buildPath(adminPrefix, '/proxy'))
  }

  return (
    <Box>
      {/* 页面头部 */}
      <Flex justify="space-between" align="center" mb={6}>
        <HStack>
          <Button
            leftIcon={<Icon as={FiArrowLeft} />}
            variant="ghost"
            onClick={handleCancel}
          >
            返回
          </Button>
          <Divider orientation="vertical" height="24px" />
          <Icon as={FiZap} boxSize={6} />
          <Heading size="lg">添加代理规则</Heading>
        </HStack>
      </Flex>

      {/* 表单内容 */}
      <Card>
        <CardBody>
          <form onSubmit={handleSubmit}>
            <VStack spacing={6} align="stretch">
              {/* 基本信息 */}
              <Box>
                <Heading size="md" mb={4} color="gray.700">
                  <Icon as={FiGlobe} mr={2} />
                  基本信息
                </Heading>
                
                <VStack spacing={4}>
                  <FormControl isRequired>
                    <FormLabel>域名</FormLabel>
                    <Input
                      value={formData.domain}
                      onChange={(e) => handleInputChange('domain', e.target.value)}
                      placeholder="example.com"
                      size="lg"
                    />
                    <Text fontSize="sm" color="gray.500" mt={1}>
                      输入要代理的域名，支持通配符如 *.example.com
                    </Text>
                  </FormControl>

                  <FormControl>
                    <FormLabel>路径前缀匹配（可选）</FormLabel>
                    <VStack spacing={3} align="stretch">
                      <Text fontSize="sm" color="gray.500">
                        指定哪些路径前缀需要走负载均衡转发，如 /api/v1/、/api/v2/ 等
                      </Text>
                      <Input
                        value={formData.path_prefixes.join(', ')}
                        onChange={(e) => {
                          const prefixes = e.target.value.split(',').map(p => p.trim()).filter(p => p)
                          handleInputChange('path_prefixes', prefixes)
                        }}
                        placeholder="/api/v1/, /api/v2/, /admin/"
                        size="lg"
                      />
                      <HStack>
                        <Switch
                          isChecked={formData.path_exact}
                          onChange={(e) => handleInputChange('path_exact', e.target.checked)}
                        />
                        <Text fontSize="sm">精确匹配路径前缀</Text>
                      </HStack>
                      <Text fontSize="xs" color="gray.400">
                        精确匹配：路径必须完全等于前缀；前缀匹配：路径必须以指定前缀开头
                      </Text>
                    </VStack>
                  </FormControl>

                </VStack>
              </Box>

              <Divider />

              <Box>
                <Heading size="md" mb={4} color="gray.700">
                  <Icon as={FiSettings} mr={2} />
                  自定义头部
                </Heading>
                <VStack align="stretch" spacing={6}>
                  <Box>
                    <Flex justify="space-between" align="center" mb={2}>
                      <Text fontWeight="medium">上游请求头</Text>
                      <Button size="sm" variant="outline" onClick={applyCorsPreset}>一键填充 CORS 预设</Button>
                    </Flex>
                    <HeaderEditor
                      value={formData.upstream_request_headers}
                      onChange={headers => handleInputChange('upstream_request_headers', headers)}
                      placeholderKey="X-Forwarded-For"
                      placeholderValue="client-ip"
                    />
                  </Box>
                  <Box>
                    <Text fontWeight="medium" mb={2}>响应头</Text>
                    <HeaderEditor
                      value={formData.response_headers}
                      onChange={headers => handleInputChange('response_headers', headers)}
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

              {/* 安全设置 */}
              <Box>
                <Heading size="md" mb={4} color="gray.700">
                  <Icon as={FiShield} mr={2} />
                  安全设置
                </Heading>
                
                <VStack spacing={4}>
                  <FormControl>
                    <HStack justify="space-between">
                      <Box>
                        <FormLabel mb={1}>启用规则</FormLabel>
                        <Text fontSize="sm" color="gray.500">
                          规则创建后是否立即启用
                        </Text>
                      </Box>
                      <Switch
                        isChecked={formData.enabled}
                        onChange={(e) => handleInputChange('enabled', e.target.checked)}
                        size="lg"
                      />
                    </HStack>
                  </FormControl>

                  <FormControl>
                    <HStack justify="space-between">
                      <Box>
                        <FormLabel mb={1}>仅 HTTPS</FormLabel>
                        <Text fontSize="sm" color="gray.500">
                          只允许 HTTPS 连接，自动重定向 HTTP 到 HTTPS
                        </Text>
                      </Box>
                      <Switch
                        isChecked={formData.ssl_only}
                        onChange={(e) => handleInputChange('ssl_only', e.target.checked)}
                        size="lg"
                      />
                    </HStack>
                  </FormControl>
                </VStack>
              </Box>

              <Divider />

              {/* 类CDN设置 */}
              <Box>
                <Heading size="md" mb={4} color="gray.700">
                  类CDN设置
                </Heading>
                
                <VStack spacing={4}>
                  <FormControl>
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
                        size="lg"
                      />
                    </HStack>
                  </FormControl>

                  {formData.cdn_mode_enabled && (
                    <>
                      <FormControl>
                        <HStack justify="space-between">
                          <Box>
                            <FormLabel mb={1}>启用 CDN 缓存</FormLabel>
                            <Text fontSize="sm" color="gray.500">
                              启用静态资源缓存以提升性能
                            </Text>
                          </Box>
                          <Switch
                            isChecked={formData.cdn_enabled}
                            onChange={(e) => handleInputChange('cdn_enabled', e.target.checked)}
                            size="lg"
                          />
                        </HStack>
                      </FormControl>

                      {formData.cdn_enabled && (
                        <>
                          <FormControl>
                            <FormLabel>缓存预设</FormLabel>
                            <Input
                              value={formData.cdn_preset}
                              onChange={(e) => handleInputChange('cdn_preset', e.target.value)}
                              placeholder="default"
                              size="lg"
                            />
                            <Text fontSize="sm" color="gray.500" mt={1}>
                              缓存策略预设名称
                            </Text>
                          </FormControl>

                          <FormControl>
                            <FormLabel>缓存时间（秒）</FormLabel>
                            <Input
                              type="number"
                              value={formData.cdn_ttl_seconds}
                              onChange={(e) => handleInputChange('cdn_ttl_seconds', parseInt(e.target.value) || 259200)}
                              placeholder="259200"
                              size="lg"
                            />
                            <Text fontSize="sm" color="gray.500" mt={1}>
                              静态资源缓存时间，默认 72 小时
                            </Text>
                          </FormControl>
                        </>
                      )}

                      <FormControl>
                        <HStack justify="space-between">
                          <Box>
                            <FormLabel mb={1}>优化HTTP Host头部</FormLabel>
                            <Text fontSize="sm" color="gray.500">
                              使用目标地址域名作为Host头部，解决防盗链问题
                            </Text>
                          </Box>
                          <Switch
                            isChecked={formData.optimize_host_header}
                            onChange={(e) => handleInputChange('optimize_host_header', e.target.checked)}
                            size="lg"
                          />
                        </HStack>
                      </FormControl>
                    </>
                  )}
                </VStack>
              </Box>

              <Divider />

              {/* 访问控制设置 */}
              <Box>
                <Heading size="md" mb={4} color="gray.700">
                  <Icon as={FiShield} mr={2} />
                  访问控制设置
                </Heading>
                
                <VStack spacing={4}>
                  <FormControl>
                    <HStack justify="space-between">
                      <Box>
                        <FormLabel mb={1}>启用访问控制</FormLabel>
                        <Text fontSize="sm" color="gray.500">
                          为代理域名设置用户名和密码认证
                        </Text>
                      </Box>
                      <Switch
                        isChecked={formData.auth_enabled}
                        onChange={(e) => handleInputChange('auth_enabled', e.target.checked)}
                        size="lg"
                      />
                    </HStack>
                  </FormControl>

                  {formData.auth_enabled && (
                    <>
                      <FormControl>
                        <FormLabel>认证用户</FormLabel>
                        <VStack spacing={3} align="stretch">
                          {formData.auth_users.map((user, index) => (
                            <HStack key={index} spacing={3}>
                              <Input
                                placeholder={t.proxy.username}
                                value={user.username}
                                onChange={(e) => handleAuthUserChange(index, 'username', e.target.value)}
                                size="md"
                              />
                              <Input
                                type="password"
                                placeholder={t.proxy.password}
                                value={user.password}
                                onChange={(e) => handleAuthUserChange(index, 'password', e.target.value)}
                                size="md"
                              />
                              {formData.auth_users.length > 1 && (
                                <Button
                                  size="sm"
                                  colorScheme="red"
                                  variant="outline"
                                  onClick={() => removeAuthUser(index)}
                                >
                                  删除
                                </Button>
                              )}
                            </HStack>
                          ))}
                          <Button
                            leftIcon={<Icon as={FiPlus} />}
                            variant="outline"
                            onClick={addAuthUser}
                            size="sm"
                          >
                            添加用户
                          </Button>
                        </VStack>
                        <Text fontSize="sm" color="gray.500" mt={1}>
                          访问代理域名时需要输入用户名和密码
                        </Text>
                      </FormControl>

                      <FormControl>
                        <FormLabel>会话超时时间（秒）</FormLabel>
                        <Input
                          type="number"
                          value={formData.auth_session_timeout}
                          onChange={(e) => handleInputChange('auth_session_timeout', parseInt(e.target.value) || 3600)}
                          placeholder="3600"
                          size="lg"
                        />
                        <Text fontSize="sm" color="gray.500" mt={1}>
                          用户登录后的有效时间，默认1小时
                        </Text>
                      </FormControl>

                      <FormControl>
                        <FormLabel>Cookie域名（可选）</FormLabel>
                        <Input
                          value={formData.auth_cookie_domain}
                          onChange={(e) => handleInputChange('auth_cookie_domain', e.target.value)}
                          placeholder={formData.domain || "example.com"}
                          size="lg"
                        />
                        <Text fontSize="sm" color="gray.500" mt={1}>
                          认证Cookie的作用域，默认为代理域名
                        </Text>
                      </FormControl>
                    </>
                  )}
                </VStack>
              </Box>

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
                        size="lg"
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
                        size="lg"
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
                        size="lg"
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
                        size="lg"
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
                        size="lg"
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
                        size="lg"
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

              {/* 提示信息 */}
              <Alert status="info">
                <AlertIcon />
                <Box>
                  <Text fontWeight="bold">提示：</Text>
                  <Text fontSize="sm">
                    创建代理规则后，系统会自动为域名申请 SSL 证书（如果启用 HTTPS）。
                    请确保域名已正确解析到当前服务器。
                  </Text>
                </Box>
              </Alert>

              {/* 操作按钮 */}
              <HStack justify="flex-end" spacing={4} pt={4}>
                <Button
                  onClick={handleCancel}
                  variant="outline"
                  size="lg"
                >
                  取消
                </Button>
                <Button
                  type="submit"
                  colorScheme="blue"
                  size="lg"
                  isLoading={loading}
                  loadingText={t.common.creating}
                >
                  创建规则
                </Button>
              </HStack>
            </VStack>
          </form>
        </CardBody>
      </Card>
    </Box>
  )
}

export default ProxyAdd

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
} from '@chakra-ui/react'
import { FiArrowLeft, FiZap, FiGlobe, FiShield, FiSave, FiPlus } from 'react-icons/fi'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useConfig, buildPath, buildApiPath } from '../contexts/ConfigContext'

interface ProxyAuthUser {
  username: string
  password: string
}

interface ProxyRuleForm {
  domain: string
  target: string
  enabled: boolean
  ssl_only: boolean
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
}

const ProxyEdit: React.FC = () => {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const toast = useToast()
  const [loading, setLoading] = useState(false)
  const [initialLoading, setInitialLoading] = useState(true)
  const { adminPrefix } = useConfig()
  
  const domain = searchParams.get('domain') || ''
  
  const [formData, setFormData] = useState<ProxyRuleForm>({
    domain: '',
    target: '',
    enabled: true,
    ssl_only: true,
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
          setFormData({
            domain: rule.domain || '',
            target: rule.target || '',
            enabled: rule.enabled ?? true,
            ssl_only: rule.ssl_only ?? true,
            // 类CDN设置 - 如果CDN缓存或Host头部优化任一启用，则认为类CDN模式启用
            cdn_mode_enabled: (rule.cdn_enabled ?? false) || (rule.optimize_host_header ?? false),
            cdn_enabled: rule.cdn_enabled ?? false,
            cdn_preset: rule.cdn_preset || '',
            cdn_ttl_seconds: rule.cdn_ttl_seconds || 259200,
            // HTTP Host头部优化
            optimize_host_header: rule.optimize_host_header ?? false,
            auth_enabled: rule.auth_enabled ?? false,
            auth_users: rule.auth_users || [{ username: '', password: '' }],
            auth_session_timeout: rule.auth_session_timeout || 3600,
            auth_cookie_domain: rule.auth_cookie_domain || '',
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

  const handleInputChange = (field: keyof ProxyRuleForm, value: string | boolean | number) => {
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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
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
          target: formData.target,
          enabled: formData.enabled,
          ssl_only: formData.ssl_only,
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
              返回
            </Button>
            <Heading size="lg">编辑代理规则</Heading>
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

                    <FormControl isRequired>
                      <FormLabel>目标地址</FormLabel>
                      <Input
                        value={formData.target}
                        onChange={(e) => handleInputChange('target', e.target.value)}
                        placeholder="http://127.0.0.1:8080"
                      />
                      <Text fontSize="sm" color="gray.500" mt={1}>
                        完整的代理目标地址，包含协议、主机和端口
                      </Text>
                    </FormControl>
                  </VStack>
                </Box>

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
                                placeholder="用户名"
                              />
                            </FormControl>
                            <FormControl>
                              <FormLabel>密码</FormLabel>
                              <Input
                                type="password"
                                value={user.password}
                                onChange={(e) => handleAuthUserChange(index, 'password', e.target.value)}
                                placeholder="密码"
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
                    loadingText="保存中..."
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

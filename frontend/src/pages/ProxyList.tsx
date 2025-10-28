import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  Button,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Card,
  CardBody,
  HStack,
  VStack,
  Badge,
  Icon,
  Flex,
  Text,
  IconButton,
  useToast,
  Switch,
  Tooltip,
} from '@chakra-ui/react'
import {
  FiPlus,
  FiRefreshCw,
  FiEdit,
  FiTrash2,
  FiZap,
  FiGlobe,
} from 'react-icons/fi'
import { useNavigate } from 'react-router-dom'
import { useConfig, buildPath, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

interface ProxyRule {
  domain: string
  target: string
  port: number
  enabled: boolean
  ssl_only: boolean
  cdn_enabled: boolean
  cdn_preset: string
  cdn_ttl_seconds: number
  // 访问控制字段
  auth_enabled: boolean
  auth_users: Array<{username: string, password: string}>
  auth_session_timeout: number
  auth_cookie_domain: string
  // Git部署服务标记
  managed_by_git_deploy?: boolean
  git_deploy_app_name?: string
  git_deploy_app_id?: string
}

const ProxyList: React.FC = () => {
  const navigate = useNavigate()
  const [rules, setRules] = useState<ProxyRule[]>([])
  const [loading, setLoading] = useState(false)
  const toast = useToast()
  const { adminPrefix } = useConfig()
  const t = useTranslation()

  // 格式化目标地址和端口显示
  const formatTargetWithPort = (target: string, port: number): string => {
    // 如果端口为0或未设置，直接返回target
    if (!port || port === 0) {
      return target
    }
    
    // 首先检查target是否已经包含端口号（使用正则表达式）
    const hasPortPattern = /^https?:\/\/[^:]+:\d+(\/.*)?$/
    if (hasPortPattern.test(target)) {
      return target
    }
    
    // 如果target不包含端口号，添加端口号
    return `${target}:${port}`
  }

  const refreshRules = async () => {
    setLoading(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/proxy/rules'), {
        method: 'GET',
        credentials: 'include', // 包含认证 cookies
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const data = await response.json()
      setRules(data || [])
    } catch (error) {
      console.error('获取代理规则失败:', error)
      toast({
        title: '获取失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  const deleteRule = async (domain: string) => {
    // 添加确认对话框
    if (!window.confirm(`确定要删除代理规则 "${domain}" 吗？此操作不可撤销。`)) {
      return
    }

    try {
      const response = await fetch(buildApiPath(adminPrefix, `/proxy/rule?domain=${encodeURIComponent(domain)}`), {
        method: 'DELETE',
        credentials: 'include',
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const data = await response.json()
      if (data.success) {
        setRules(rules.filter(rule => rule.domain !== domain))
        toast({
          title: '删除成功',
          description: '代理规则已成功删除',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
      } else {
        throw new Error(data.error || '删除失败')
      }
    } catch (error) {
      toast({
        title: '删除失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 4000,
        isClosable: true,
      })
    }
  }

  const toggleRule = async (domain: string, enabled: boolean) => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, `/proxy/rule?domain=${encodeURIComponent(domain)}`), {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          domain,
          enabled,
        }),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const data = await response.json()
      if (data.success) {
        setRules(rules.map(rule => 
          rule.domain === domain ? { ...rule, enabled } : rule
        ))
        toast({
          title: enabled ? '代理规则已启用' : '代理规则已禁用',
          description: '规则状态更新成功',
          status: 'success',
          duration: 2000,
          isClosable: true,
        })
      } else {
        throw new Error(data.error || '状态更新失败')
      }
    } catch (error) {
      toast({
        title: '状态更新失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  useEffect(() => {
    refreshRules()
  }, [])

  return (
    <Box>
      <Flex justify="space-between" align="center" mb={6}>
        <HStack>
          <Icon as={FiZap} boxSize={6} />
          <Heading size="lg">{t.proxy.title}</Heading>
        </HStack>
        <HStack>
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            onClick={refreshRules}
            isLoading={loading}
            variant="outline"
          >
{t.common.refresh}
          </Button>
          <Button
            leftIcon={<Icon as={FiPlus} />}
            colorScheme="blue"
            onClick={() => navigate(buildPath(adminPrefix, '/proxy/add'))}
          >
{t.proxy.addRule}
          </Button>
        </HStack>
      </Flex>

      <Card>
        <CardBody>
          {rules.length > 0 ? (
            <Table variant="simple">
              <Thead>
                <Tr>
                  <Th>{t.ssl.domain}</Th>
                  <Th>目标地址</Th>
                  <Th>{t.ssl.status}</Th>
                  <Th>SSL</Th>
                  <Th>功能</Th>
                  <Th>{t.ssl.actions}</Th>
                </Tr>
              </Thead>
              <Tbody>
                {rules.map((rule) => (
                  <Tr key={rule.domain}>
                    <Td>
                      <VStack align="start" spacing={1}>
                        <HStack>
                          <Icon as={FiGlobe} />
                          <Text fontFamily="mono">{rule.domain}</Text>
                        </HStack>
                        {rule.managed_by_git_deploy && (
                          <Badge colorScheme="teal" size="sm">
                            🚀 Git部署: {rule.git_deploy_app_name}
                          </Badge>
                        )}
                      </VStack>
                    </Td>
                    <Td>
                      <Text fontFamily="mono" fontSize="sm">
                        {formatTargetWithPort(rule.target, rule.port)}
                      </Text>
                    </Td>
                    <Td>
                      <Tooltip label={rule.enabled ? '点击禁用' : '点击启用'}>
                        <Switch
                          isChecked={rule.enabled}
                          onChange={(e) => toggleRule(rule.domain, e.target.checked)}
                          colorScheme="green"
                        />
                      </Tooltip>
                    </Td>
                    <Td>
                      <Badge colorScheme={rule.ssl_only ? 'blue' : 'orange'}>
                        {rule.ssl_only ? 'HTTPS' : 'HTTP'}
                      </Badge>
                    </Td>
                    <Td>
                      <HStack spacing={1}>
                        {rule.cdn_enabled && (
                          <Badge colorScheme="purple" size="sm">CDN</Badge>
                        )}
                        {rule.auth_enabled && (
                          <Badge colorScheme="red" size="sm">认证</Badge>
                        )}
                      </HStack>
                    </Td>
                    <Td>
                      <HStack spacing={2}>
                        <IconButton
                          aria-label={t.proxyList.edit}
                          icon={<FiEdit />}
                          size="sm"
                          variant="ghost"
                          onClick={() => navigate(buildPath(adminPrefix, `/proxy/edit?domain=${encodeURIComponent(rule.domain)}`))}
                        />
                        <IconButton
                          aria-label={t.proxyList.delete}
                          icon={<FiTrash2 />}
                          size="sm"
                          variant="ghost"
                          colorScheme="red"
                          onClick={() => deleteRule(rule.domain)}
                        />
                      </HStack>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          ) : (
            <Box textAlign="center" py={8}>
              <Icon as={FiZap} boxSize={12} color="gray.300" mb={4} />
              <Text color="gray.500" mb={4}>暂无代理规则</Text>
              <Button 
                leftIcon={<Icon as={FiPlus} />} 
                colorScheme="blue"
                onClick={() => navigate(buildPath(adminPrefix, '/proxy/add'))}
              >
                创建第一个规则
              </Button>
            </Box>
          )}
        </CardBody>
      </Card>
    </Box>
  )
}

export default ProxyList

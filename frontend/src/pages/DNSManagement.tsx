import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  SimpleGrid,
  Card,
  CardBody,
  CardHeader,
  VStack,
  HStack,
  Button,
  Icon,
  Text,
  Flex,
  Badge,
  IconButton,
  useToast,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  FormControl,
  FormLabel,
  Input,
  Select,
  useDisclosure,
  Stat,
  StatLabel,
  StatNumber,
  Switch,
} from '@chakra-ui/react'
import {
  FiGlobe,
  FiRefreshCw,
  FiTrash2,
  FiSettings,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'


interface DNSProvider {
  id: string
  name: string
  type: 'cloudflare' | 'aliyun' | 'tencent' | 'aws' | 'godaddy' | 'custom'
  status: 'connected' | 'error' | 'disabled'
  domains: number
  lastSync: string
}

const DNSManagement: React.FC = () => {
  const [providers, setProviders] = useState<DNSProvider[]>([])
  const [loading, setLoading] = useState(false)
  const [editingProvider, setEditingProvider] = useState<DNSProvider | null>(null)
  const {
    isOpen: isProviderOpen,
    onOpen: onProviderOpen,
    onClose: onProviderClose,
  } = useDisclosure()
  const {
    isOpen: isEditOpen,
    onOpen: onEditOpen,
    onClose: onEditClose,
  } = useDisclosure()
  const toast = useToast()
  const { adminPrefix } = useConfig()

  const [newProvider, setNewProvider] = useState({
    name: '',
    type: 'cloudflare' as DNSProvider['type'],
    apiKey: '',
    apiSecret: '',
    email: '',
    zoneId: '',
    endpoint: '',
  })

  const refreshData = async (showToast: boolean = false) => {
    setLoading(true)
    try {
      // 首先触发缓存刷新
      const refreshResponse = await fetch(buildApiPath(adminPrefix, '/api/dns/refresh'), {
        method: 'POST',
        credentials: 'include',
      })

      if (!refreshResponse.ok) {
        console.warn('缓存刷新失败，继续使用现有缓存数据')
      }

      // 然后获取DNS提供商数据（从缓存读取）
      const providersResponse = await fetch(buildApiPath(adminPrefix, '/api/dns/providers'), {
        method: 'GET',
        credentials: 'include',
      })

      if (providersResponse.ok) {
        const providersData = await providersResponse.json()
        // 处理后端返回的数据格式：{available: [], configured: [], default: "", methods: []}
        const configuredProviders = providersData.configured || []
        
        // 转换为前端期望的格式
        const formattedProviders = configuredProviders.map((provider: any, index: number) => ({
          id: index.toString(),
          name: provider.name,
          type: provider.type,
          status: provider.enabled ? 'connected' : 'disabled',
          domains: provider.domains || 0, // 使用后端提供的域名数量
          lastSync: new Date().toLocaleDateString('zh-CN')
        }))
        
        setProviders(formattedProviders)
        
        // 只在手动刷新时显示提示
        if (showToast) {
          toast({
            title: '刷新成功',
            description: 'DNS 提供商数据已更新',
            status: 'success',
            duration: 2000,
            isClosable: true,
          })
        }
        
      } else {
        throw new Error('获取DNS数据失败')
      }
    } catch (error) {
      console.error('获取DNS数据失败:', error)
      // 错误时总是显示提示
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


  const handleConnectProvider = async () => {
    try {
      setLoading(true)
      
      const response = await fetch(buildApiPath(adminPrefix, '/api/dns/provider'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          name: newProvider.name,
          type: newProvider.type,
          api_key: newProvider.apiKey,
          api_secret: newProvider.apiSecret,
          zone_id: newProvider.zoneId,
          endpoint: newProvider.endpoint,
          priority: 1, // 默认优先级
          enabled: true, // 默认启用
        }),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || '添加DNS提供商失败')
      }

      const result = await response.json()
      
      toast({
        title: 'DNS提供商添加成功',
        description: '新的DNS提供商已成功添加到系统中',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      
      onProviderClose()
      refreshData()
      resetProviderForm()
    } catch (error) {
      toast({
        title: '添加失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }


  const resetProviderForm = () => {
    setNewProvider({
      name: '',
      type: 'cloudflare',
      apiKey: '',
      apiSecret: '',
      email: '',
      zoneId: '',
      endpoint: '',
    })
  }

  const handleEditProvider = (provider: DNSProvider) => {
    setEditingProvider(provider)
    setNewProvider({
      name: provider.name,
      type: provider.type,
      apiKey: '', // 不显示敏感信息
      apiSecret: '',
      email: '',
      zoneId: '',
      endpoint: '',
    })
    onEditOpen()
  }

  const handleUpdateProvider = async () => {
    if (!editingProvider) return

    try {
      setLoading(true)
      
      const response = await fetch(buildApiPath(adminPrefix, '/api/dns/provider'), {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          name: newProvider.name,
          type: newProvider.type,
          api_key: newProvider.apiKey,
          api_secret: newProvider.apiSecret,
          zone_id: newProvider.zoneId,
          endpoint: newProvider.endpoint,
          priority: 1,
          enabled: true,
        }),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || '更新DNS提供商失败')
      }

      toast({
        title: 'DNS提供商更新成功',
        description: 'DNS提供商信息已成功更新',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      
      onEditClose()
      refreshData()
      resetProviderForm()
      setEditingProvider(null)
    } catch (error) {
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

  const handleDeleteProvider = async (provider: DNSProvider) => {
    if (!confirm(`确定要删除DNS提供商 "${provider.name}" 吗？此操作不可撤销。`)) {
      return
    }

    try {
      setLoading(true)
      
      const response = await fetch(buildApiPath(adminPrefix, `/api/dns/provider?name=${encodeURIComponent(provider.name)}`), {
        method: 'DELETE',
        credentials: 'include',
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || '删除DNS提供商失败')
      }

      toast({
        title: 'DNS提供商删除成功',
        description: `DNS提供商 "${provider.name}" 已成功删除`,
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      
      refreshData()
    } catch (error) {
      toast({
        title: '删除失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }


  const getProviderStatusColor = (status: string) => {
    switch (status) {
      case 'connected': return 'green'
      case 'error': return 'red'
      case 'disabled': return 'gray'
      default: return 'gray'
    }
  }

  const getProviderStatusText = (status: string) => {
    switch (status) {
      case 'connected': return '已连接'
      case 'error': return '错误'
      case 'disabled': return '已禁用'
      default: return status
    }
  }

  useEffect(() => {
    refreshData()
  }, [])

  return (
    <Box>
      <Flex justify="space-between" align="center" mb={6}>
        <HStack>
          <Icon as={FiGlobe} boxSize={6} />
          <Heading size="lg">DNS 配置</Heading>
        </HStack>
        <HStack>
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            onClick={() => refreshData(true)}
            isLoading={loading}
            variant="outline"
          >
            刷新
          </Button>
        </HStack>
      </Flex>

      {/* DNS 提供商状态 */}
      <SimpleGrid columns={{ base: 1, lg: 2 }} spacing={6} mb={8}>
        <Card>
          <CardHeader>
            <HStack justify="space-between">
              <Heading size="md">DNS 提供商</Heading>
              <Button size="sm" variant="outline" onClick={onProviderOpen}>
                添加提供商
              </Button>
            </HStack>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              {providers.map((provider) => (
                <Box
                  key={provider.id}
                  p={4}
                  border="1px solid"
                  borderColor="gray.200"
                  borderRadius="md"
                >
                  <Flex justify="space-between" align="center">
                    <VStack align="start" spacing={1}>
                      <HStack>
                        <Text fontWeight="medium">{provider.name}</Text>
                        <Badge colorScheme={getProviderStatusColor(provider.status)}>
                          {getProviderStatusText(provider.status)}
                        </Badge>
                      </HStack>
                      <Text fontSize="sm" color="gray.600">
                        {provider.domains} 个域名 · 最后同步: {provider.lastSync}
                      </Text>
                    </VStack>
                    <HStack>
                      <IconButton
                        aria-label="设置"
                        icon={<FiSettings />}
                        size="sm"
                        variant="ghost"
                        onClick={() => handleEditProvider(provider)}
                      />
                      <IconButton
                        aria-label="删除"
                        icon={<FiTrash2 />}
                        size="sm"
                        variant="ghost"
                        colorScheme="red"
                        onClick={() => handleDeleteProvider(provider)}
                      />
                    </HStack>
                  </Flex>
                </Box>
              ))}
            </VStack>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <Heading size="md">DNS 统计</Heading>
          </CardHeader>
          <CardBody>
            <SimpleGrid columns={2} spacing={4}>
              <Stat>
                <StatLabel>总记录数</StatLabel>
                <StatNumber>0</StatNumber>
              </Stat>
              <Stat>
                <StatLabel>活跃记录</StatLabel>
                <StatNumber>0</StatNumber>
              </Stat>
              <Stat>
                <StatLabel>提供商数</StatLabel>
                <StatNumber>{providers.length}</StatNumber>
              </Stat>
              <Stat>
                <StatLabel>域名数</StatLabel>
                <StatNumber>{providers.reduce((sum, p) => sum + p.domains, 0)}</StatNumber>
              </Stat>
            </SimpleGrid>
          </CardBody>
        </Card>
      </SimpleGrid>



      {/* 添加 DNS 提供商模态框 */}
      <Modal isOpen={isProviderOpen} onClose={onProviderClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>添加 DNS 提供商</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>提供商名称</FormLabel>
                <Input
                  value={newProvider.name}
                  onChange={(e) => setNewProvider({ ...newProvider, name: e.target.value })}
                  placeholder="我的 Cloudflare"
                />
              </FormControl>

              <FormControl>
                <FormLabel>提供商类型</FormLabel>
                <Select
                  value={newProvider.type}
                  onChange={(e) => setNewProvider({ ...newProvider, type: e.target.value as DNSProvider['type'] })}
                >
                  <option value="cloudflare">Cloudflare</option>
                  <option value="aliyun">阿里云 DNS</option>
                  <option value="tencent">腾讯云 DNS</option>
                  <option value="aws">AWS Route53</option>
                  <option value="godaddy">GoDaddy</option>
                  <option value="custom">自定义 API</option>
                </Select>
              </FormControl>

              <FormControl>
                <FormLabel>API Key</FormLabel>
                <Input
                  type="password"
                  value={newProvider.apiKey}
                  onChange={(e) => setNewProvider({ ...newProvider, apiKey: e.target.value })}
                  placeholder="API 密钥"
                />
              </FormControl>

              {newProvider.type === 'cloudflare' && (
                <FormControl>
                  <FormLabel>邮箱地址</FormLabel>
                  <Input
                    type="email"
                    value={newProvider.email}
                    onChange={(e) => setNewProvider({ ...newProvider, email: e.target.value })}
                    placeholder="user@example.com"
                  />
                </FormControl>
              )}

              {newProvider.type !== 'cloudflare' && (
                <FormControl>
                  <FormLabel>API Secret</FormLabel>
                  <Input
                    type="password"
                    value={newProvider.apiSecret}
                    onChange={(e) => setNewProvider({ ...newProvider, apiSecret: e.target.value })}
                    placeholder="API 密钥"
                  />
                </FormControl>
              )}

              {(newProvider.type === 'cloudflare' || newProvider.type === 'aliyun') && (
                <FormControl>
                  <FormLabel>Zone ID</FormLabel>
                  <Input
                    value={newProvider.zoneId}
                    onChange={(e) => setNewProvider({ ...newProvider, zoneId: e.target.value })}
                    placeholder="Zone ID (Cloudflare等需要)"
                  />
                </FormControl>
              )}

              {newProvider.type === 'custom' && (
                <FormControl>
                  <FormLabel>API 端点</FormLabel>
                  <Input
                    value={newProvider.endpoint}
                    onChange={(e) => setNewProvider({ ...newProvider, endpoint: e.target.value })}
                    placeholder="https://api.example.com"
                  />
                </FormControl>
              )}
            </VStack>
          </ModalBody>

          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onProviderClose}>
              取消
            </Button>
            <Button colorScheme="blue" onClick={handleConnectProvider}>
              连接提供商
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* 编辑 DNS 提供商模态框 */}
      <Modal isOpen={isEditOpen} onClose={onEditClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>编辑 DNS 提供商</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>提供商名称</FormLabel>
                <Input
                  value={newProvider.name}
                  onChange={(e) => setNewProvider({ ...newProvider, name: e.target.value })}
                  placeholder="我的 Cloudflare"
                />
              </FormControl>

              <FormControl>
                <FormLabel>提供商类型</FormLabel>
                <Select
                  value={newProvider.type}
                  onChange={(e) => setNewProvider({ ...newProvider, type: e.target.value as DNSProvider['type'] })}
                >
                  <option value="cloudflare">Cloudflare</option>
                  <option value="aliyun">阿里云 DNS</option>
                  <option value="tencent">腾讯云 DNS</option>
                  <option value="aws">AWS Route53</option>
                  <option value="godaddy">GoDaddy</option>
                  <option value="custom">自定义 API</option>
                </Select>
              </FormControl>

              <FormControl>
                <FormLabel>API Key</FormLabel>
                <Input
                  type="password"
                  value={newProvider.apiKey}
                  onChange={(e) => setNewProvider({ ...newProvider, apiKey: e.target.value })}
                  placeholder="API 密钥（留空则不更新）"
                />
              </FormControl>

              {newProvider.type === 'cloudflare' && (
                <FormControl>
                  <FormLabel>邮箱地址</FormLabel>
                  <Input
                    type="email"
                    value={newProvider.email}
                    onChange={(e) => setNewProvider({ ...newProvider, email: e.target.value })}
                    placeholder="user@example.com"
                  />
                </FormControl>
              )}

              {newProvider.type !== 'cloudflare' && (
                <FormControl>
                  <FormLabel>API Secret</FormLabel>
                  <Input
                    type="password"
                    value={newProvider.apiSecret}
                    onChange={(e) => setNewProvider({ ...newProvider, apiSecret: e.target.value })}
                    placeholder="API 密钥（留空则不更新）"
                  />
                </FormControl>
              )}

              {(newProvider.type === 'cloudflare' || newProvider.type === 'aliyun') && (
                <FormControl>
                  <FormLabel>Zone ID</FormLabel>
                  <Input
                    value={newProvider.zoneId}
                    onChange={(e) => setNewProvider({ ...newProvider, zoneId: e.target.value })}
                    placeholder="Zone ID (Cloudflare等需要)"
                  />
                </FormControl>
              )}

              {newProvider.type === 'custom' && (
                <FormControl>
                  <FormLabel>API 端点</FormLabel>
                  <Input
                    value={newProvider.endpoint}
                    onChange={(e) => setNewProvider({ ...newProvider, endpoint: e.target.value })}
                    placeholder="https://api.example.com"
                  />
                </FormControl>
              )}
            </VStack>
          </ModalBody>

          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onEditClose}>
              取消
            </Button>
            <Button colorScheme="blue" onClick={handleUpdateProvider}>
              保存更改
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default DNSManagement

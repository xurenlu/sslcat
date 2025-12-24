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
import { useTranslation } from '../hooks/useLanguage'


interface DNSProvider {
  id: string
  name: string
  type: 'cloudflare' | 'aliyun' | 'tencent' | 'aws' | 'godaddy' | 'custom'
  status: 'connected' | 'error' | 'disabled' | 'updating'
  domains: number
  lastSync: string
  error?: string
  updating?: boolean
}

const DNSManagement: React.FC = () => {
  const [providers, setProviders] = useState<DNSProvider[]>([])
  const [loading, setLoading] = useState(false)
  const [selectedProviderDomains, setSelectedProviderDomains] = useState<string[]>([])
  const [selectedProviderName, setSelectedProviderName] = useState<string>('')
  const {
    isOpen: isDomainsOpen,
    onOpen: onDomainsOpen,
    onClose: onDomainsClose,
  } = useDisclosure()
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
  const t = useTranslation()

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
      } else {
        // 等待缓存更新完成（异步更新需要时间）
        await new Promise(resolve => setTimeout(resolve, 3000))
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
          status: provider.enabled ? (provider.error ? 'error' : provider.updating ? 'updating' : 'connected') : 'disabled',
          domains: provider.domains || 0, // 使用后端提供的域名数量
          lastSync: provider.last_update || new Date().toLocaleDateString('zh-CN'),
          error: provider.error || '',
          updating: provider.updating || false
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


  const handleTestProvider = async () => {
    // 验证必填字段
    if (!newProvider.type) {
      toast({
        title: '测试失败',
        description: '请选择提供商类型',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    if (newProvider.type !== 'cloudflare' && (!newProvider.apiKey || !newProvider.apiSecret)) {
      toast({
        title: '测试失败',
        description: '请填写 API Key 和 API Secret',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    if (newProvider.type === 'cloudflare' && !newProvider.apiKey) {
      toast({
        title: '测试失败',
        description: '请填写 API Key',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    try {
      setLoading(true)
      
      const response = await fetch(buildApiPath(adminPrefix, '/api/dns/test-config'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          type: newProvider.type,
          api_key: newProvider.apiKey,
          api_secret: newProvider.apiSecret,
          zone_id: newProvider.zoneId,
          endpoint: newProvider.endpoint,
        }),
      })

      const result = await response.json()

      if (!response.ok || !result.success) {
        throw new Error(result.error || '测试失败')
      }

      toast({
        title: '测试成功',
        description: result.message || `成功连接到 ${newProvider.type}，找到 ${result.domain_count || 0} 个域名`,
        status: 'success',
        duration: 5000,
        isClosable: true,
      })
    } catch (error) {
      toast({
        title: '测试失败',
        description: error instanceof Error ? error.message : '无法连接到 DNS 提供商 API，请检查配置',
        status: 'error',
        duration: 5000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  const handleConnectProvider = async () => {
    // 验证必填字段
    if (!newProvider.name) {
      toast({
        title: '保存失败',
        description: '请填写提供商名称',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    if (!newProvider.type) {
      toast({
        title: '保存失败',
        description: '请选择提供商类型',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    if (newProvider.type !== 'cloudflare' && (!newProvider.apiKey || !newProvider.apiSecret)) {
      toast({
        title: '保存失败',
        description: '请填写 API Key 和 API Secret',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    if (newProvider.type === 'cloudflare' && !newProvider.apiKey) {
      toast({
        title: '保存失败',
        description: '请填写 API Key',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    try {
      setLoading(true)
      
      // 先测试连接
      const testResponse = await fetch(buildApiPath(adminPrefix, '/api/dns/test-config'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          type: newProvider.type,
          api_key: newProvider.apiKey,
          api_secret: newProvider.apiSecret,
          zone_id: newProvider.zoneId,
          endpoint: newProvider.endpoint,
        }),
      })

      const testResult = await testResponse.json()

      if (!testResponse.ok || !testResult.success) {
        throw new Error(testResult.error || '配置测试失败，请检查 API Key 和 Secret 是否正确')
      }

      // 测试通过后，保存配置
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
        description: `配置已保存，找到 ${testResult.domain_count || 0} 个域名`,
        status: 'success',
        duration: 5000,
        isClosable: true,
      })
      
      onProviderClose()
      resetProviderForm()
      
      // 等待缓存更新完成（异步更新需要时间）
      setTimeout(() => {
        refreshData()
      }, 2000)
    } catch (error) {
      toast({
        title: '添加失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 5000,
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

    // 验证必填字段
    if (!newProvider.type) {
      toast({
        title: '更新失败',
        description: '请选择提供商类型',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    // 修改时，如果提供了新的 key/secret 才需要验证
    // 如果不提供，后端会保留原有值
    const hasNewKey = newProvider.apiKey && newProvider.apiKey.trim() !== ''
    const hasNewSecret = newProvider.apiSecret && newProvider.apiSecret.trim() !== ''
    
    if (hasNewKey || hasNewSecret) {
      // 如果提供了新的 key 或 secret，需要验证完整性
      if (newProvider.type !== 'cloudflare' && hasNewKey && !hasNewSecret) {
        toast({
          title: '更新失败',
          description: '请同时填写 API Key 和 API Secret',
          status: 'error',
          duration: 3000,
          isClosable: true,
        })
        return
      }
      
      if (newProvider.type !== 'cloudflare' && !hasNewKey && hasNewSecret) {
        toast({
          title: '更新失败',
          description: '请同时填写 API Key 和 API Secret',
          status: 'error',
          duration: 3000,
          isClosable: true,
        })
        return
      }
    }

    try {
      setLoading(true)
      
      // 先测试连接（如果提供了新的 API Key 或 Secret）
      if (newProvider.apiKey || newProvider.apiSecret) {
        const testResponse = await fetch(buildApiPath(adminPrefix, '/api/dns/test-config'), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify({
            type: newProvider.type,
            api_key: newProvider.apiKey,
            api_secret: newProvider.apiSecret,
            zone_id: newProvider.zoneId,
            endpoint: newProvider.endpoint,
          }),
        })

        const testResult = await testResponse.json()

        if (!testResponse.ok || !testResult.success) {
          throw new Error(testResult.error || '配置测试失败，请检查 API Key 和 Secret 是否正确')
        }
      }
      
      // 使用编辑时的原始名称，确保更新而不是新增
      const response = await fetch(buildApiPath(adminPrefix, '/api/dns/provider'), {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          name: editingProvider.name, // 使用原始名称，确保是更新而不是新增
          type: newProvider.type,
          api_key: newProvider.apiKey || '', // 如果为空，后端会保留原有值
          api_secret: newProvider.apiSecret || '', // 如果为空，后端会保留原有值
          zone_id: newProvider.zoneId || '',
          endpoint: newProvider.endpoint || '',
          priority: 1,
          enabled: true,
        }),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || t.dns.updateFailed)
      }

      toast({
        title: t.dns.updateSuccess,
        description: 'DNS提供商配置已更新',
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
        title: t.dns.updateFailed,
        description: error instanceof Error ? error.message : t.dns.unknownError,
        status: 'error',
        duration: 5000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  const handleDeleteProvider = async (provider: DNSProvider) => {
    if (!confirm(t.dns.confirmDeleteMessage.replace('{name}', provider.name))) {
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
        throw new Error(errorData.error || t.dns.deleteFailed)
      }

      toast({
        title: t.dns.deleteSuccess,
        description: `DNS提供商 "${provider.name}" 已成功删除`,
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      
      refreshData()
    } catch (error) {
      toast({
        title: t.dns.deleteFailed,
        description: error instanceof Error ? error.message : t.dns.unknownError,
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
      case 'connected': return t.dns.connected
      case 'error': return t.dns.error
      case 'disabled': return t.dns.disabled
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
          <Heading size="lg">{t.dns.title}</Heading>
        </HStack>
        <HStack>
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            onClick={() => refreshData(true)}
            isLoading={loading}
            variant="outline"
          >
            {t.dns.refresh}
          </Button>
        </HStack>
      </Flex>

      {/* DNS 提供商状态 */}
      <SimpleGrid columns={{ base: 1, lg: 2 }} spacing={6} mb={8}>
        <Card>
          <CardHeader>
            <HStack justify="space-between">
              <Heading size="md">{t.dns.providers}</Heading>
              <Button size="sm" variant="outline" onClick={onProviderOpen}>
                {t.dns.addProvider}
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
                        <Text 
                          as="span" 
                          cursor="pointer" 
                          color="blue.500"
                          fontWeight="medium"
                          onClick={async () => {
                            try {
                              const response = await fetch(buildApiPath(adminPrefix, `/api/dns/provider/domains?provider=${provider.name}`), {
                                method: 'GET',
                                credentials: 'include',
                              })
                              if (response.ok) {
                                const data = await response.json()
                                if (data.success && data.domains) {
                                  setSelectedProviderDomains(data.domains.map((d: any) => d.name))
                                  setSelectedProviderName(provider.name)
                                  onDomainsOpen()
                                }
                              }
                            } catch (error) {
                              console.error('Failed to fetch domains:', error)
                            }
                          }}
                          _hover={{ textDecoration: 'underline' }}
                        >
                          {provider.domains} {t.dns.domainsCount}
                        </Text>
                        {' · '}
                        {t.dns.lastSync}: {provider.lastSync}
                      </Text>
                      {provider.error && (
                        <Text fontSize="xs" color="red.500">
                          错误: {provider.error}
                        </Text>
                      )}
                      {provider.updating && (
                        <Text fontSize="xs" color="blue.500">
                          正在更新...
                        </Text>
                      )}
                    </VStack>
                    <HStack>
                      <IconButton
                        aria-label={t.dns.settings}
                        icon={<FiSettings />}
                        size="sm"
                        variant="ghost"
                        onClick={() => handleEditProvider(provider)}
                      />
                      <IconButton
                        aria-label={t.dns.delete}
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
            <Heading size="md">{t.dns.dnsStats}</Heading>
          </CardHeader>
          <CardBody>
            <SimpleGrid columns={2} spacing={4}>
              <Stat>
                <StatLabel>{t.dns.totalRecords}</StatLabel>
                <StatNumber>0</StatNumber>
              </Stat>
              <Stat>
                <StatLabel>{t.dns.activeRecords}</StatLabel>
                <StatNumber>0</StatNumber>
              </Stat>
              <Stat>
                <StatLabel>{t.dns.providerCount}</StatLabel>
                <StatNumber>{providers.length}</StatNumber>
              </Stat>
              <Stat>
                <StatLabel>{t.dns.domainCount}</StatLabel>
                <StatNumber 
                  cursor="pointer" 
                  onClick={async () => {
                    // 获取所有提供商的域名
                    const allDomains: string[] = []
                    for (const provider of providers) {
                      if (provider.domains > 0) {
                        try {
                          const response = await fetch(buildApiPath(adminPrefix, `/api/dns/provider/domains?provider=${provider.name}`), {
                            method: 'GET',
                            credentials: 'include',
                          })
                          if (response.ok) {
                            const data = await response.json()
                            if (data.success && data.domains) {
                              data.domains.forEach((d: any) => {
                                if (!allDomains.includes(d.name)) {
                                  allDomains.push(d.name)
                                }
                              })
                            }
                          }
                        } catch (error) {
                          console.error('Failed to fetch domains:', error)
                        }
                      }
                    }
                    setSelectedProviderDomains(allDomains)
                    setSelectedProviderName('所有提供商')
                    onDomainsOpen()
                  }}
                  _hover={{ color: 'blue.500' }}
                >
                  {providers.reduce((sum, p) => sum + p.domains, 0)}
                </StatNumber>
              </Stat>
            </SimpleGrid>
          </CardBody>
        </Card>
      </SimpleGrid>

      {/* 域名列表模态框 */}
      <Modal isOpen={isDomainsOpen} onClose={onDomainsClose} size="xl">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>域名列表 - {selectedProviderName}</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            {selectedProviderDomains.length === 0 ? (
              <Text>暂无域名</Text>
            ) : (
              <VStack spacing={2} align="stretch" maxH="400px" overflowY="auto">
                {selectedProviderDomains.map((domain, index) => (
                  <Box
                    key={index}
                    p={3}
                    border="1px solid"
                    borderColor="gray.200"
                    borderRadius="md"
                  >
                    <Text>{domain}</Text>
                  </Box>
                ))}
              </VStack>
            )}
          </ModalBody>
          <ModalFooter>
            <Button onClick={onDomainsClose}>关闭</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* 添加 DNS 提供商模态框 */}
      <Modal isOpen={isProviderOpen} onClose={onProviderClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>{t.dns.addProviderModal}</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>提供商名称</FormLabel>
                <Input
                  value={newProvider.name}
                  onChange={(e) => setNewProvider({ ...newProvider, name: e.target.value })}
                  placeholder={t.dns.cloudflare_name_placeholder}
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
                  placeholder={t.dns.api_key_placeholder}
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
                    placeholder={t.dns.api_key_placeholder}
                  />
                </FormControl>
              )}

              {newProvider.type === 'cloudflare' && (
                <FormControl>
                  <FormLabel>Zone ID</FormLabel>
                  <Input
                    value={newProvider.zoneId}
                    onChange={(e) => setNewProvider({ ...newProvider, zoneId: e.target.value })}
                    placeholder={t.dns.zone_id_placeholder}
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
              {t.dns.cancel}
            </Button>
            <Button 
              variant="outline" 
              colorScheme="green" 
              mr={3} 
              onClick={handleTestProvider}
              isLoading={loading}
              loadingText="测试中..."
            >
              测试连接
            </Button>
            <Button 
              colorScheme="blue" 
              onClick={handleConnectProvider}
              isLoading={loading}
              loadingText="保存中..."
            >
              {t.dns.connectProvider}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* 编辑 DNS 提供商模态框 */}
      <Modal isOpen={isEditOpen} onClose={onEditClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>{t.dns.editProviderModal}</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>提供商名称</FormLabel>
                <Input
                  value={newProvider.name}
                  onChange={(e) => setNewProvider({ ...newProvider, name: e.target.value })}
                  placeholder={t.dns.cloudflare_name_placeholder}
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
                  placeholder={t.dns.api_key_update_placeholder}
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
                    placeholder={t.dns.api_key_update_placeholder}
                  />
                </FormControl>
              )}

              {(newProvider.type === 'cloudflare' || newProvider.type === 'aliyun') && (
                <FormControl>
                  <FormLabel>Zone ID</FormLabel>
                  <Input
                    value={newProvider.zoneId}
                    onChange={(e) => setNewProvider({ ...newProvider, zoneId: e.target.value })}
                    placeholder={t.dns.zone_id_placeholder}
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

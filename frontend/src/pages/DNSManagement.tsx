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
  type: 'cloudflare' | 'aliyun' | 'dnspod' | 'godaddy'
  status: 'connected' | 'error' | 'disabled'
  domains: number
  lastSync: string
}

const DNSManagement: React.FC = () => {
  const [providers, setProviders] = useState<DNSProvider[]>([])
  const [loading, setLoading] = useState(false)
  const {
    isOpen: isProviderOpen,
    onOpen: onProviderOpen,
    onClose: onProviderClose,
  } = useDisclosure()
  const toast = useToast()
  const { adminPrefix } = useConfig()

  const [newProvider, setNewProvider] = useState({
    name: '',
    type: 'cloudflare' as DNSProvider['type'],
    apiKey: '',
    apiSecret: '',
    email: '',
  })

  const refreshData = async () => {
    setLoading(true)
    try {
      // 获取DNS提供商（DNS记录API暂时不存在，使用提供商API）
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
          domains: 0, // 暂时设为0，因为后端没有提供这个信息
          lastSync: new Date().toLocaleDateString('zh-CN')
        }))
        
        setProviders(formattedProviders)
        
      } else {
        throw new Error('获取DNS数据失败')
      }
    } catch (error) {
      console.error('获取DNS数据失败:', error)
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
      // TODO: 实际的 API 调用
      toast({
        title: 'DNS提供商连接成功',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      
      onProviderClose()
      refreshData()
      resetProviderForm()
    } catch (error) {
      toast({
        title: '连接失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }


  const resetProviderForm = () => {
    setNewProvider({
      name: '',
      type: 'cloudflare',
      apiKey: '',
      apiSecret: '',
      email: '',
    })
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
            onClick={refreshData}
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
                      />
                      <IconButton
                        aria-label="删除"
                        icon={<FiTrash2 />}
                        size="sm"
                        variant="ghost"
                        colorScheme="red"
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
                  <option value="dnspod">DNSPod</option>
                  <option value="godaddy">GoDaddy</option>
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
    </Box>
  )
}

export default DNSManagement

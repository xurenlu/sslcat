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
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
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
  FiPlus,
  FiEdit,
  FiTrash2,
  FiSettings,
} from 'react-icons/fi'

interface DNSRecord {
  id: string
  name: string
  type: 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'SRV'
  value: string
  ttl: number
  priority?: number
  enabled: boolean
  created: string
}

interface DNSProvider {
  id: string
  name: string
  type: 'cloudflare' | 'aliyun' | 'dnspod' | 'godaddy'
  status: 'connected' | 'error' | 'disabled'
  domains: number
  lastSync: string
}

const DNSManagement: React.FC = () => {
  const [records, setRecords] = useState<DNSRecord[]>([])
  const [providers, setProviders] = useState<DNSProvider[]>([])
  const [loading, setLoading] = useState(false)
  const { isOpen, onOpen, onClose } = useDisclosure()
  const {
    isOpen: isProviderOpen,
    onOpen: onProviderOpen,
    onClose: onProviderClose,
  } = useDisclosure()
  const [editingRecord, setEditingRecord] = useState<DNSRecord | null>(null)
  const toast = useToast()

  const [newRecord, setNewRecord] = useState({
    name: '',
    type: 'A' as DNSRecord['type'],
    value: '',
    ttl: 3600,
    priority: 10,
    enabled: true,
  })

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
      // TODO: 实际的 API 调用
      setTimeout(() => {
        setRecords([
          {
            id: '1',
            name: 'www',
            type: 'A',
            value: '192.168.1.100',
            ttl: 3600,
            enabled: true,
            created: '2024-01-15',
          },
          {
            id: '2',
            name: 'mail',
            type: 'A',
            value: '192.168.1.101',
            ttl: 3600,
            enabled: true,
            created: '2024-01-14',
          },
          {
            id: '3',
            name: '@',
            type: 'MX',
            value: 'mail.example.com',
            ttl: 3600,
            priority: 10,
            enabled: true,
            created: '2024-01-13',
          },
        ])

        setProviders([
          {
            id: '1',
            name: 'Cloudflare',
            type: 'cloudflare',
            status: 'connected',
            domains: 5,
            lastSync: '2024-01-15 10:30:00',
          },
          {
            id: '2',
            name: '阿里云DNS',
            type: 'aliyun',
            status: 'error',
            domains: 2,
            lastSync: '2024-01-14 15:20:00',
          },
        ])
        setLoading(false)
      }, 1000)
    } catch (error) {
      console.error('获取DNS数据失败:', error)
      setLoading(false)
    }
  }

  const handleCreateRecord = async () => {
    try {
      // TODO: 实际的 API 调用
      toast({
        title: 'DNS记录创建成功',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      
      onClose()
      refreshData()
      resetRecordForm()
    } catch (error) {
      toast({
        title: '创建失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const handleDeleteRecord = async (id: string) => {
    try {
      setRecords(records.filter(record => record.id !== id))
      toast({
        title: 'DNS记录删除成功',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
    } catch (error) {
      toast({
        title: '删除失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
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

  const resetRecordForm = () => {
    setNewRecord({
      name: '',
      type: 'A',
      value: '',
      ttl: 3600,
      priority: 10,
      enabled: true,
    })
    setEditingRecord(null)
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

  const getRecordTypeColor = (type: string) => {
    switch (type) {
      case 'A': return 'blue'
      case 'AAAA': return 'purple'
      case 'CNAME': return 'green'
      case 'MX': return 'orange'
      case 'TXT': return 'yellow'
      case 'SRV': return 'red'
      default: return 'gray'
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
            onClick={refreshData}
            isLoading={loading}
            variant="outline"
          >
            刷新
          </Button>
          <Button
            leftIcon={<Icon as={FiPlus} />}
            colorScheme="blue"
            onClick={onOpen}
          >
            添加记录
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
                <StatNumber>{records.length}</StatNumber>
              </Stat>
              <Stat>
                <StatLabel>活跃记录</StatLabel>
                <StatNumber>{records.filter(r => r.enabled).length}</StatNumber>
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

      {/* DNS 记录列表 */}
      <Card>
        <CardHeader>
          <Heading size="md">DNS 记录</Heading>
        </CardHeader>
        <CardBody>
          {records.length > 0 ? (
            <Table variant="simple">
              <Thead>
                <Tr>
                  <Th>名称</Th>
                  <Th>类型</Th>
                  <Th>值</Th>
                  <Th>TTL</Th>
                  <Th>优先级</Th>
                  <Th>状态</Th>
                  <Th>创建时间</Th>
                  <Th>操作</Th>
                </Tr>
              </Thead>
              <Tbody>
                {records.map((record) => (
                  <Tr key={record.id}>
                    <Td>
                      <Text fontFamily="mono">{record.name}</Text>
                    </Td>
                    <Td>
                      <Badge colorScheme={getRecordTypeColor(record.type)}>
                        {record.type}
                      </Badge>
                    </Td>
                    <Td>
                      <Text fontSize="sm" fontFamily="mono">
                        {record.value}
                      </Text>
                    </Td>
                    <Td>{record.ttl}</Td>
                    <Td>{record.priority || '-'}</Td>
                    <Td>
                      <Badge colorScheme={record.enabled ? 'green' : 'gray'}>
                        {record.enabled ? '启用' : '禁用'}
                      </Badge>
                    </Td>
                    <Td>{record.created}</Td>
                    <Td>
                      <HStack spacing={2}>
                        <IconButton
                          aria-label="编辑"
                          icon={<FiEdit />}
                          size="sm"
                          variant="ghost"
                        />
                        <IconButton
                          aria-label="删除"
                          icon={<FiTrash2 />}
                          size="sm"
                          variant="ghost"
                          colorScheme="red"
                          onClick={() => handleDeleteRecord(record.id)}
                        />
                      </HStack>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          ) : (
            <Box textAlign="center" py={8}>
              <Icon as={FiGlobe} boxSize={12} color="gray.300" mb={4} />
              <Text color="gray.500" mb={4}>暂无 DNS 记录</Text>
              <Button leftIcon={<Icon as={FiPlus} />} colorScheme="blue" onClick={onOpen}>
                添加第一个记录
              </Button>
            </Box>
          )}
        </CardBody>
      </Card>

      {/* 添加 DNS 记录模态框 */}
      <Modal isOpen={isOpen} onClose={onClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>添加 DNS 记录</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>名称</FormLabel>
                <Input
                  value={newRecord.name}
                  onChange={(e) => setNewRecord({ ...newRecord, name: e.target.value })}
                  placeholder="www 或 @ 或子域名"
                />
              </FormControl>

              <FormControl>
                <FormLabel>记录类型</FormLabel>
                <Select
                  value={newRecord.type}
                  onChange={(e) => setNewRecord({ ...newRecord, type: e.target.value as DNSRecord['type'] })}
                >
                  <option value="A">A 记录 (IPv4 地址)</option>
                  <option value="AAAA">AAAA 记录 (IPv6 地址)</option>
                  <option value="CNAME">CNAME 记录 (别名)</option>
                  <option value="MX">MX 记录 (邮件交换)</option>
                  <option value="TXT">TXT 记录 (文本)</option>
                  <option value="SRV">SRV 记录 (服务)</option>
                </Select>
              </FormControl>

              <FormControl>
                <FormLabel>值</FormLabel>
                <Input
                  value={newRecord.value}
                  onChange={(e) => setNewRecord({ ...newRecord, value: e.target.value })}
                  placeholder={
                    newRecord.type === 'A' ? '192.168.1.100' :
                    newRecord.type === 'CNAME' ? 'example.com' :
                    newRecord.type === 'MX' ? 'mail.example.com' :
                    '记录值'
                  }
                />
              </FormControl>

              <FormControl>
                <FormLabel>TTL (秒)</FormLabel>
                <Select
                  value={newRecord.ttl.toString()}
                  onChange={(e) => setNewRecord({ ...newRecord, ttl: parseInt(e.target.value) })}
                >
                  <option value="300">5 分钟 (300)</option>
                  <option value="1800">30 分钟 (1800)</option>
                  <option value="3600">1 小时 (3600)</option>
                  <option value="14400">4 小时 (14400)</option>
                  <option value="86400">1 天 (86400)</option>
                </Select>
              </FormControl>

              {newRecord.type === 'MX' && (
                <FormControl>
                  <FormLabel>优先级</FormLabel>
                  <Input
                    type="number"
                    value={newRecord.priority}
                    onChange={(e) => setNewRecord({ ...newRecord, priority: parseInt(e.target.value) })}
                  />
                </FormControl>
              )}

              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">启用记录</FormLabel>
                <Switch
                  isChecked={newRecord.enabled}
                  onChange={(e) => setNewRecord({ ...newRecord, enabled: e.target.checked })}
                />
              </FormControl>
            </VStack>
          </ModalBody>

          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onClose}>
              取消
            </Button>
            <Button colorScheme="blue" onClick={handleCreateRecord}>
              创建记录
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

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

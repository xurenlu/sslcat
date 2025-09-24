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
  StatHelpText,
  Switch,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Progress,
} from '@chakra-ui/react'
import {
  FiUsers,
  FiRefreshCw,
  FiPlus,
  FiEdit,
  FiTrash2,
  FiServer,
  FiSettings,
  FiPlay,
} from 'react-icons/fi'

interface ClusterNode {
  id: string
  name: string
  ip: string
  port: number
  role: 'master' | 'slave' | 'standalone'
  status: 'online' | 'offline' | 'syncing' | 'error'
  version: string
  lastSeen: string
  load: {
    cpu: number
    memory: number
    connections: number
  }
  uptime: string
}

interface ClusterConfig {
  mode: 'standalone' | 'master' | 'slave'
  masterNode: string
  syncInterval: number
  autoFailover: boolean
  healthCheckInterval: number
}

const ClusterManagement: React.FC = () => {
  const [nodes, setNodes] = useState<ClusterNode[]>([])
  const [config, setConfig] = useState<ClusterConfig>({
    mode: 'standalone',
    masterNode: '',
    syncInterval: 30,
    autoFailover: true,
    healthCheckInterval: 10,
  })
  const [loading, setLoading] = useState(false)
  const { isOpen, onOpen, onClose } = useDisclosure()
  const {
    isOpen: isConfigOpen,
    onOpen: onConfigOpen,
    onClose: onConfigClose,
  } = useDisclosure()
  const toast = useToast()

  const [newNode, setNewNode] = useState({
    name: '',
    ip: '',
    port: 8443,
    apiKey: '',
  })

  const refreshData = async () => {
    setLoading(true)
    try {
      // TODO: 实际的 API 调用
      setTimeout(() => {
        setNodes([
          {
            id: '1',
            name: 'master-node-01',
            ip: '192.168.1.100',
            port: 8443,
            role: 'master',
            status: 'online',
            version: 'v1.2.2',
            lastSeen: '2024-01-15 14:30:00',
            load: {
              cpu: 45,
              memory: 67,
              connections: 150,
            },
            uptime: '15 天 8 小时',
          },
          {
            id: '2',
            name: 'slave-node-01',
            ip: '192.168.1.101',
            port: 8443,
            role: 'slave',
            status: 'syncing',
            version: 'v1.2.2',
            lastSeen: '2024-01-15 14:29:45',
            load: {
              cpu: 32,
              memory: 54,
              connections: 89,
            },
            uptime: '10 天 3 小时',
          },
          {
            id: '3',
            name: 'slave-node-02',
            ip: '192.168.1.102',
            port: 8443,
            role: 'slave',
            status: 'offline',
            version: 'v1.2.1',
            lastSeen: '2024-01-15 12:15:30',
            load: {
              cpu: 0,
              memory: 0,
              connections: 0,
            },
            uptime: '-',
          },
        ])
        setLoading(false)
      }, 1000)
    } catch (error) {
      console.error('获取集群数据失败:', error)
      setLoading(false)
    }
  }

  const handleAddNode = async () => {
    try {
      // TODO: 实际的 API 调用
      toast({
        title: '节点添加成功',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      
      onClose()
      refreshData()
      resetForm()
    } catch (error) {
      toast({
        title: '添加失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const handleRemoveNode = async (id: string) => {
    try {
      setNodes(nodes.filter(node => node.id !== id))
      toast({
        title: '节点移除成功',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
    } catch (error) {
      toast({
        title: '移除失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const handlePromoteToMaster = async (id: string) => {
    try {
      // TODO: 实际的 API 调用
      toast({
        title: '节点已提升为主节点',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      refreshData()
    } catch (error) {
      toast({
        title: '提升失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const handleSyncCluster = async () => {
    try {
      // TODO: 实际的 API 调用
      toast({
        title: '集群同步已启动',
        status: 'info',
        duration: 3000,
        isClosable: true,
      })
    } catch (error) {
      toast({
        title: '同步失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const handleUpdateConfig = async () => {
    try {
      // TODO: 实际的 API 调用
      toast({
        title: '集群配置更新成功',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      onConfigClose()
    } catch (error) {
      toast({
        title: '更新失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const resetForm = () => {
    setNewNode({
      name: '',
      ip: '',
      port: 8443,
      apiKey: '',
    })
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online': return 'green'
      case 'syncing': return 'blue'
      case 'offline': return 'red'
      case 'error': return 'orange'
      default: return 'gray'
    }
  }

  const getStatusText = (status: string) => {
    switch (status) {
      case 'online': return '在线'
      case 'syncing': return '同步中'
      case 'offline': return '离线'
      case 'error': return '错误'
      default: return status
    }
  }

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'master': return 'purple'
      case 'slave': return 'blue'
      case 'standalone': return 'gray'
      default: return 'gray'
    }
  }

  const getRoleText = (role: string) => {
    switch (role) {
      case 'master': return '主节点'
      case 'slave': return '从节点'
      case 'standalone': return '独立节点'
      default: return role
    }
  }

  const getLoadColor = (load: number) => {
    if (load < 50) return 'green'
    if (load < 80) return 'yellow'
    return 'red'
  }

  useEffect(() => {
    refreshData()
  }, [])

  const masterNode = nodes.find(node => node.role === 'master')
  const slaveNodes = nodes.filter(node => node.role === 'slave')
  const onlineNodes = nodes.filter(node => node.status === 'online').length

  return (
    <Box>
      <Flex justify="space-between" align="center" mb={6}>
        <HStack>
          <Icon as={FiUsers} boxSize={6} />
          <Heading size="lg">集群管理</Heading>
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
            leftIcon={<Icon as={FiSettings} />}
            onClick={onConfigOpen}
            variant="outline"
          >
            集群配置
          </Button>
          <Button
            leftIcon={<Icon as={FiPlay} />}
            onClick={handleSyncCluster}
            colorScheme="green"
          >
            同步集群
          </Button>
        </HStack>
      </Flex>

      {/* 集群状态概览 */}
      <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={6} mb={8}>
        <Card>
          <CardBody>
            <Stat>
              <StatLabel>集群模式</StatLabel>
              <StatNumber fontSize="lg">
                <Badge colorScheme="purple" fontSize="md">
                  {config.mode === 'standalone' ? '独立模式' : config.mode === 'master' ? '主节点模式' : '从节点模式'}
                </Badge>
              </StatNumber>
              <StatHelpText>当前运行模式</StatHelpText>
            </Stat>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <Stat>
              <StatLabel>节点总数</StatLabel>
              <StatNumber>{nodes.length}</StatNumber>
              <StatHelpText>在线: {onlineNodes} / {nodes.length}</StatHelpText>
            </Stat>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <Stat>
              <StatLabel>主节点</StatLabel>
              <StatNumber fontSize="sm">
                {masterNode ? masterNode.name : '未设置'}
              </StatNumber>
              <StatHelpText>
                {masterNode ? (
                  <Badge colorScheme={getStatusColor(masterNode.status)}>
                    {getStatusText(masterNode.status)}
                  </Badge>
                ) : (
                  '无主节点'
                )}
              </StatHelpText>
            </Stat>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <Stat>
              <StatLabel>从节点</StatLabel>
              <StatNumber>{slaveNodes.length}</StatNumber>
              <StatHelpText>
                在线: {slaveNodes.filter(n => n.status === 'online').length}
              </StatHelpText>
            </Stat>
          </CardBody>
        </Card>
      </SimpleGrid>

      {/* 集群状态警告 */}
      {config.mode !== 'standalone' && !masterNode && (
        <Alert status="warning" mb={6}>
          <AlertIcon />
          <AlertTitle>集群配置警告</AlertTitle>
          <AlertDescription>
            集群模式已启用但未发现主节点，请检查网络连接或手动指定主节点。
          </AlertDescription>
        </Alert>
      )}

      {/* 节点列表 */}
      <Card>
        <CardHeader>
          <HStack justify="space-between">
            <Heading size="md">集群节点</Heading>
            <Button leftIcon={<Icon as={FiPlus} />} colorScheme="blue" onClick={onOpen}>
              添加节点
            </Button>
          </HStack>
        </CardHeader>
        <CardBody>
          {nodes.length > 0 ? (
            <Table variant="simple">
              <Thead>
                <Tr>
                  <Th>节点信息</Th>
                  <Th>角色</Th>
                  <Th>状态</Th>
                  <Th>负载</Th>
                  <Th>连接数</Th>
                  <Th>运行时间</Th>
                  <Th>最后连接</Th>
                  <Th>操作</Th>
                </Tr>
              </Thead>
              <Tbody>
                {nodes.map((node) => (
                  <Tr key={node.id}>
                    <Td>
                      <VStack align="start" spacing={1}>
                        <HStack>
                          <Icon as={FiServer} />
                          <Text fontWeight="medium">{node.name}</Text>
                        </HStack>
                        <Text fontSize="sm" color="gray.600" fontFamily="mono">
                          {node.ip}:{node.port}
                        </Text>
                        <Badge variant="outline" size="sm">
                          {node.version}
                        </Badge>
                      </VStack>
                    </Td>
                    <Td>
                      <Badge colorScheme={getRoleColor(node.role)}>
                        {getRoleText(node.role)}
                      </Badge>
                    </Td>
                    <Td>
                      <Badge colorScheme={getStatusColor(node.status)}>
                        {getStatusText(node.status)}
                      </Badge>
                    </Td>
                    <Td>
                      <VStack align="start" spacing={1}>
                        <HStack w="full">
                          <Text fontSize="xs" minW="30px">CPU:</Text>
                          <Progress
                            value={node.load.cpu}
                            colorScheme={getLoadColor(node.load.cpu)}
                            size="sm"
                            flex={1}
                          />
                          <Text fontSize="xs" minW="35px">{node.load.cpu}%</Text>
                        </HStack>
                        <HStack w="full">
                          <Text fontSize="xs" minW="30px">MEM:</Text>
                          <Progress
                            value={node.load.memory}
                            colorScheme={getLoadColor(node.load.memory)}
                            size="sm"
                            flex={1}
                          />
                          <Text fontSize="xs" minW="35px">{node.load.memory}%</Text>
                        </HStack>
                      </VStack>
                    </Td>
                    <Td>{node.load.connections}</Td>
                    <Td>{node.uptime}</Td>
                    <Td>{node.lastSeen}</Td>
                    <Td>
                      <HStack spacing={2}>
                        {node.role === 'slave' && (
                          <IconButton
                            aria-label="提升为主节点"
                            icon={<FiPlay />}
                            size="sm"
                            variant="ghost"
                            colorScheme="green"
                            onClick={() => handlePromoteToMaster(node.id)}
                          />
                        )}
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
                          onClick={() => handleRemoveNode(node.id)}
                        />
                      </HStack>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          ) : (
            <Box textAlign="center" py={8}>
              <Icon as={FiUsers} boxSize={12} color="gray.300" mb={4} />
              <Text color="gray.500" mb={4}>暂无集群节点</Text>
              <Button leftIcon={<Icon as={FiPlus} />} colorScheme="blue" onClick={onOpen}>
                添加第一个节点
              </Button>
            </Box>
          )}
        </CardBody>
      </Card>

      {/* 添加节点模态框 */}
      <Modal isOpen={isOpen} onClose={onClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>添加集群节点</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>节点名称</FormLabel>
                <Input
                  value={newNode.name}
                  onChange={(e) => setNewNode({ ...newNode, name: e.target.value })}
                  placeholder="slave-node-01"
                />
              </FormControl>

              <FormControl>
                <FormLabel>IP 地址</FormLabel>
                <Input
                  value={newNode.ip}
                  onChange={(e) => setNewNode({ ...newNode, ip: e.target.value })}
                  placeholder="192.168.1.101"
                />
              </FormControl>

              <FormControl>
                <FormLabel>端口</FormLabel>
                <Input
                  type="number"
                  value={newNode.port}
                  onChange={(e) => setNewNode({ ...newNode, port: parseInt(e.target.value) })}
                />
              </FormControl>

              <FormControl>
                <FormLabel>API 密钥</FormLabel>
                <Input
                  type="password"
                  value={newNode.apiKey}
                  onChange={(e) => setNewNode({ ...newNode, apiKey: e.target.value })}
                  placeholder="节点的 API 访问密钥"
                />
              </FormControl>
            </VStack>
          </ModalBody>

          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onClose}>
              取消
            </Button>
            <Button colorScheme="blue" onClick={handleAddNode}>
              添加节点
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* 集群配置模态框 */}
      <Modal isOpen={isConfigOpen} onClose={onConfigClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>集群配置</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>集群模式</FormLabel>
                <Select
                  value={config.mode}
                  onChange={(e) => setConfig({ ...config, mode: e.target.value as ClusterConfig['mode'] })}
                >
                  <option value="standalone">独立模式</option>
                  <option value="master">主节点模式</option>
                  <option value="slave">从节点模式</option>
                </Select>
              </FormControl>

              {config.mode === 'slave' && (
                <FormControl>
                  <FormLabel>主节点地址</FormLabel>
                  <Input
                    value={config.masterNode}
                    onChange={(e) => setConfig({ ...config, masterNode: e.target.value })}
                    placeholder="192.168.1.100:8443"
                  />
                </FormControl>
              )}

              <FormControl>
                <FormLabel>同步间隔（秒）</FormLabel>
                <Input
                  type="number"
                  value={config.syncInterval}
                  onChange={(e) => setConfig({ ...config, syncInterval: parseInt(e.target.value) })}
                />
              </FormControl>

              <FormControl>
                <FormLabel>健康检查间隔（秒）</FormLabel>
                <Input
                  type="number"
                  value={config.healthCheckInterval}
                  onChange={(e) => setConfig({ ...config, healthCheckInterval: parseInt(e.target.value) })}
                />
              </FormControl>

              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">自动故障转移</FormLabel>
                <Switch
                  isChecked={config.autoFailover}
                  onChange={(e) => setConfig({ ...config, autoFailover: e.target.checked })}
                />
              </FormControl>
            </VStack>
          </ModalBody>

          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onConfigClose}>
              取消
            </Button>
            <Button colorScheme="blue" onClick={handleUpdateConfig}>
              保存配置
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default ClusterManagement

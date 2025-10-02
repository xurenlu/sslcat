import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  SimpleGrid,
  Card,
  CardBody,
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
  Textarea,
  useDisclosure,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Code,
  Switch,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
} from '@chakra-ui/react'
import {
  FiGitBranch,
  FiRefreshCw,
  FiPlus,
  FiEdit,
  FiTrash2,
  FiGithub,
  FiUpload,
  FiSettings,
  FiKey,
  FiFolder,
  FiCopy,
  FiTerminal,
  FiPackage,
  FiClock,
} from 'react-icons/fi'
import { useConfig, buildPath, buildApiPath } from '../contexts/ConfigContext'
import RealtimeLogs from '../components/RealtimeLogs'
import DockerImageManager from '../components/DockerImageManager'
import DeployHistory from '../components/DeployHistory'

interface GitApp {
  id: string
  name: string
  repository: string
  branch: string
  deployPath: string
  status: 'active' | 'inactive' | 'deploying' | 'error'
  lastDeploy: string
  commits: number
  webhook: string
  autoSSL: boolean
  domain?: string
}

interface SSHKey {
  id: string
  name: string
  fingerprint: string
  type: string
  created: string
  lastUsed?: string
}

interface GitServerConfig {
  enabled: boolean
  port: number
  webhook: string
  autoSSL: boolean
  defaultBranch: string
  domainSuffix: string
  portRange: [number, number]
  welcomeMessage: string
  sslEmail: string
  defaultStrategy: string
  buildTimeout: number
  autoDomain: boolean
}

const GitServerManagement: React.FC = () => {
  const { adminPrefix } = useConfig()
  const [apps, setApps] = useState<GitApp[]>([])
  const [sshKeys, setSSHKeys] = useState<SSHKey[]>([])
  const [config, setConfig] = useState<GitServerConfig>({
    enabled: true,
    port: 22,
    webhook: '',
    autoSSL: true,
    defaultBranch: 'main',
    domainSuffix: 'localhost',
    portRange: [8000, 9000],
    welcomeMessage: '欢迎使用 SSLcat Git 部署平台！',
    sslEmail: '',
    defaultStrategy: 'auto',
    buildTimeout: 300,
    autoDomain: true,
  })
  const [loading, setLoading] = useState(false)
  const { isOpen, onOpen, onClose } = useDisclosure()
  const {
    isOpen: isKeyOpen,
    onOpen: onKeyOpen,
    onClose: onKeyClose,
  } = useDisclosure()
  const {
    isOpen: isConfigOpen,
    onOpen: onConfigOpen,
    onClose: onConfigClose,
  } = useDisclosure()
  const toast = useToast()

  const [newApp, setNewApp] = useState({
    name: '',
    repository: '',
    branch: 'main',
    deployPath: '/var/www',
    autoSSL: true,
    domain: '',
  })

  const [newKey, setNewKey] = useState({
    name: '',
    publicKey: '',
  })
  
  const [selectedApp, setSelectedApp] = useState<string>('')

  const refreshData = async () => {
    setLoading(true)
    try {
      // 获取Git应用列表
      const appsResponse = await fetch(buildApiPath(adminPrefix, '/git-server/apps'))
      const appsData = appsResponse.ok ? await appsResponse.json() : []
      // 确保apps是数组
      const apps = Array.isArray(appsData) ? appsData : []
      setApps(apps)
      
      // 获取SSH密钥列表
      const keysResponse = await fetch(buildApiPath(adminPrefix, '/git-server/ssh-keys'))
      const keysData = keysResponse.ok ? await keysResponse.json() : []
      // 确保sshKeys是数组
      const sshKeys = Array.isArray(keysData) ? keysData : []
      setSSHKeys(sshKeys)
      
      // 获取服务器配置
      const configResponse = await fetch(buildApiPath(adminPrefix, '/git-server/config'))
      if (configResponse.ok) {
        const serverConfig = await configResponse.json()
        setConfig(serverConfig)
      }
      
      setLoading(false)
    } catch (error) {
      console.error('获取Git服务器数据失败:', error)
      // 确保在错误情况下也设置空数组
      setApps([])
      setSSHKeys([])
      setLoading(false)
    }
  }

  const handleCreateApp = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/git-server/apps'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(newApp),
      })
      
      if (response.ok) {
        toast({
          title: 'Git应用创建成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        
        onClose()
        refreshData()
        resetAppForm()
      } else {
        throw new Error('创建Git应用失败')
      }
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

  const handleDeleteApp = async (id: string) => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, `/git-server/apps/${id}`), {
        method: 'DELETE',
      })
      
      if (response.ok) {
        toast({
          title: 'Git应用删除成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        refreshData()
      } else {
        throw new Error('删除Git应用失败')
      }
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

  const handleDeployApp = async (id: string) => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, `/git-server/apps/${id}/deploy`), {
        method: 'POST',
      })
      
      if (response.ok) {
        toast({
          title: '部署已启动',
          status: 'info',
          duration: 3000,
          isClosable: true,
        })
        refreshData()
      } else {
        throw new Error('部署应用失败')
      }
    } catch (error) {
      toast({
        title: '部署失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const handleAddSSHKey = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/git-server/ssh-keys'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(newKey),
      })
      
      if (response.ok) {
        toast({
          title: 'SSH密钥添加成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        
        onKeyClose()
        refreshData()
        resetKeyForm()
      } else {
        throw new Error('添加SSH密钥失败')
      }
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

  const handleDeleteSSHKey = async (id: string) => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, `/git-server/ssh-keys/${id}`), {
        method: 'DELETE',
      })
      
      if (response.ok) {
        toast({
          title: 'SSH密钥删除成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        refreshData()
      } else {
        throw new Error('删除SSH密钥失败')
      }
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

  const handleUpdateConfig = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/git-server/config'), {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(config),
      })
      
      if (response.ok) {
        toast({
          title: 'Git服务器配置更新成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        onConfigClose()
        refreshData()
      } else {
        throw new Error('更新配置失败')
      }
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

  const resetAppForm = () => {
    setNewApp({
      name: '',
      repository: '',
      branch: 'main',
      deployPath: '/var/www',
      autoSSL: true,
      domain: '',
    })
  }

  const resetKeyForm = () => {
    setNewKey({
      name: '',
      publicKey: '',
    })
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'green'
      case 'deploying': return 'blue'
      case 'inactive': return 'gray'
      case 'error': return 'red'
      default: return 'gray'
    }
  }

  const getStatusText = (status: string) => {
    switch (status) {
      case 'active': return '运行中'
      case 'deploying': return '部署中'
      case 'inactive': return '未激活'
      case 'error': return '错误'
      default: return status
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast({
      title: '已复制到剪贴板',
      status: 'success',
      duration: 2000,
      isClosable: true,
    })
  }

  useEffect(() => {
    refreshData()
  }, [])

  return (
    <Box>
      <Flex justify="space-between" align="center" mb={6}>
        <HStack>
          <Icon as={FiGitBranch} boxSize={6} />
          <Heading size="lg">Git部署服务器</Heading>
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
            服务器配置
          </Button>
          <Button
            leftIcon={<Icon as={FiPlus} />}
            colorScheme="blue"
            onClick={onOpen}
          >
            创建应用
          </Button>
        </HStack>
      </Flex>

      {/* 服务器状态 */}
      <Alert status={config.enabled ? 'success' : 'warning'} mb={6}>
        <AlertIcon />
        <AlertTitle>Git服务器状态:</AlertTitle>
        <AlertDescription>
          {config.enabled ? `服务器正在运行，端口 ${config.port}` : '服务器已禁用'}
        </AlertDescription>
      </Alert>

      {/* 统计信息 */}
      <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={6} mb={8}>
        <Card>
          <CardBody>
            <Stat>
              <StatLabel>Git应用</StatLabel>
              <StatNumber>{apps.length}</StatNumber>
              <StatHelpText>
                运行中: {Array.isArray(apps) ? apps.filter(app => app.status === 'active').length : 0}
              </StatHelpText>
            </Stat>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <Stat>
              <StatLabel>SSH密钥</StatLabel>
              <StatNumber>{sshKeys.length}</StatNumber>
              <StatHelpText>已配置的部署密钥</StatHelpText>
            </Stat>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <Stat>
              <StatLabel>总提交数</StatLabel>
              <StatNumber>{Array.isArray(apps) ? apps.reduce((sum, app) => sum + (app.commits || 0), 0) : 0}</StatNumber>
              <StatHelpText>所有应用的提交总数</StatHelpText>
            </Stat>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <Stat>
              <StatLabel>自动SSL</StatLabel>
              <StatNumber>{Array.isArray(apps) ? apps.filter(app => app.autoSSL).length : 0}</StatNumber>
              <StatHelpText>启用自动SSL的应用</StatHelpText>
            </Stat>
          </CardBody>
        </Card>
      </SimpleGrid>

      <Tabs variant="enclosed">
        <TabList>
          <Tab>
            <HStack>
              <Icon as={FiFolder} />
              <Text>Git应用</Text>
              <Badge colorScheme="blue">{apps.length}</Badge>
            </HStack>
          </Tab>
          <Tab>
            <HStack>
              <Icon as={FiKey} />
              <Text>SSH密钥</Text>
              <Badge colorScheme="green">{sshKeys.length}</Badge>
            </HStack>
          </Tab>
          
          <Tab>
            <HStack>
              <Icon as={FiTerminal} />
              <Text>实时日志</Text>
            </HStack>
          </Tab>
          
          <Tab>
            <HStack>
              <Icon as={FiPackage} />
              <Text>Docker镜像</Text>
            </HStack>
          </Tab>
          
          <Tab>
            <HStack>
              <Icon as={FiClock} />
              <Text>部署历史</Text>
            </HStack>
          </Tab>
        </TabList>

        <TabPanels>
          {/* Git应用 */}
          <TabPanel>
            <Card>
              <CardBody>
                {Array.isArray(apps) && apps.length > 0 ? (
                  <Table variant="simple">
                    <Thead>
                      <Tr>
                        <Th>选择</Th>
                        <Th>应用信息</Th>
                        <Th>仓库</Th>
                        <Th>状态</Th>
                        <Th>部署路径</Th>
                        <Th>最后部署</Th>
                        <Th>操作</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {apps.map((app) => (
                        <Tr 
                          key={app.id}
                          bg={selectedApp === app.name ? 'blue.50' : 'transparent'}
                          _hover={{ bg: 'gray.50' }}
                        >
                          <Td>
                            <Button
                              size="sm"
                              variant={selectedApp === app.name ? 'solid' : 'outline'}
                              colorScheme="blue"
                              onClick={() => setSelectedApp(selectedApp === app.name ? '' : app.name)}
                            >
                              {selectedApp === app.name ? '已选中' : '选择'}
                            </Button>
                          </Td>
                          <Td>
                            <VStack align="start" spacing={1}>
                              <HStack>
                                <Icon as={FiGithub} />
                                <Text fontWeight="medium">{app.name}</Text>
                              </HStack>
                              <HStack spacing={2}>
                                <Badge variant="outline">{app.branch}</Badge>
                                <Badge colorScheme="gray">{app.commits} commits</Badge>
                                {app.autoSSL && (
                                  <Badge colorScheme="green">SSL</Badge>
                                )}
                              </HStack>
                              {app.domain && (
                                <Text fontSize="sm" color="gray.600">
                                  域名: {app.domain}
                                </Text>
                              )}
                            </VStack>
                          </Td>
                          <Td>
                            <Code fontSize="xs" maxW="200px" isTruncated>
                              {app.repository}
                            </Code>
                          </Td>
                          <Td>
                            <Badge colorScheme={getStatusColor(app.status)}>
                              {getStatusText(app.status)}
                            </Badge>
                          </Td>
                          <Td>
                            <Code fontSize="xs">{app.deployPath}</Code>
                          </Td>
                          <Td>{app.lastDeploy}</Td>
                          <Td>
                            <HStack spacing={1}>
                              <IconButton
                                aria-label="部署"
                                icon={<FiUpload />}
                                size="sm"
                                variant="ghost"
                                colorScheme="green"
                                onClick={() => handleDeployApp(app.id)}
                              />
                              <IconButton
                                aria-label="复制Webhook"
                                icon={<FiCopy />}
                                size="sm"
                                variant="ghost"
                                onClick={() => copyToClipboard(app.webhook)}
                              />
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
                                onClick={() => handleDeleteApp(app.id)}
                              />
                            </HStack>
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                ) : (
                  <Box textAlign="center" py={8}>
                    <Icon as={FiGitBranch} boxSize={12} color="gray.300" mb={4} />
                    <Text color="gray.500" mb={4}>暂无Git应用</Text>
                    <Button leftIcon={<Icon as={FiPlus} />} colorScheme="blue" onClick={onOpen}>
                      创建第一个应用
                    </Button>
                  </Box>
                )}
              </CardBody>
            </Card>
          </TabPanel>

          {/* SSH密钥 */}
          <TabPanel>
            <VStack spacing={4} align="stretch">
              <Flex justify="space-between" align="center">
                <Text fontSize="lg" fontWeight="medium">SSH部署密钥</Text>
                <Button leftIcon={<Icon as={FiPlus} />} colorScheme="green" onClick={onKeyOpen}>
                  添加SSH密钥
                </Button>
              </Flex>

              <Card>
                <CardBody>
                  {Array.isArray(sshKeys) && sshKeys.length > 0 ? (
                    <Table variant="simple">
                      <Thead>
                        <Tr>
                          <Th>密钥名称</Th>
                          <Th>指纹</Th>
                          <Th>类型</Th>
                          <Th>创建时间</Th>
                          <Th>最后使用</Th>
                          <Th>操作</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {sshKeys.map((key) => (
                          <Tr key={key.id}>
                            <Td>
                              <HStack>
                                <Icon as={FiKey} />
                                <Text fontWeight="medium">{key.name}</Text>
                              </HStack>
                            </Td>
                            <Td>
                              <Code fontSize="xs" maxW="200px" isTruncated>
                                {key.fingerprint}
                              </Code>
                            </Td>
                            <Td>
                              <Badge variant="outline">{key.type}</Badge>
                            </Td>
                            <Td>{key.created}</Td>
                            <Td>{key.lastUsed || '从未使用'}</Td>
                            <Td>
                              <HStack spacing={2}>
                                <IconButton
                                  aria-label="复制指纹"
                                  icon={<FiCopy />}
                                  size="sm"
                                  variant="ghost"
                                  onClick={() => copyToClipboard(key.fingerprint)}
                                />
                                <IconButton
                                  aria-label="删除"
                                  icon={<FiTrash2 />}
                                  size="sm"
                                  variant="ghost"
                                  colorScheme="red"
                                  onClick={() => handleDeleteSSHKey(key.id)}
                                />
                              </HStack>
                            </Td>
                          </Tr>
                        ))}
                      </Tbody>
                    </Table>
                  ) : (
                    <Box textAlign="center" py={8}>
                      <Icon as={FiKey} boxSize={12} color="gray.300" mb={4} />
                      <Text color="gray.500" mb={4}>暂无SSH密钥</Text>
                      <Button leftIcon={<Icon as={FiPlus} />} colorScheme="green" onClick={onKeyOpen}>
                        添加第一个SSH密钥
                      </Button>
                    </Box>
                  )}
                </CardBody>
              </Card>
            </VStack>
          </TabPanel>
          
          {/* 实时日志 */}
          <TabPanel>
            <VStack spacing={4} align="stretch">
              {selectedApp ? (
                <RealtimeLogs 
                  appName={selectedApp} 
                  autoScroll={true}
                  maxLines={500}
                  showControls={true}
                />
              ) : (
                <Alert status="info">
                  <AlertIcon />
                  请先选择一个应用来查看实时日志
                </Alert>
              )}
            </VStack>
          </TabPanel>
          
          {/* Docker镜像 */}
          <TabPanel>
            <VStack spacing={4} align="stretch">
              {selectedApp ? (
                <DockerImageManager appName={selectedApp} />
              ) : (
                <Alert status="info">
                  <AlertIcon />
                  请先选择一个应用来管理Docker镜像
                </Alert>
              )}
            </VStack>
          </TabPanel>
          
          {/* 部署历史 */}
          <TabPanel>
            <VStack spacing={4} align="stretch">
              {selectedApp ? (
                <DeployHistory appName={selectedApp} />
              ) : (
                <Alert status="info">
                  <AlertIcon />
                  请先选择一个应用来查看部署历史
                </Alert>
              )}
            </VStack>
          </TabPanel>
        </TabPanels>
      </Tabs>

      {/* 创建应用模态框 */}
      <Modal isOpen={isOpen} onClose={onClose} size="lg">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>创建Git应用</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>应用名称</FormLabel>
                <Input
                  value={newApp.name}
                  onChange={(e) => setNewApp({ ...newApp, name: e.target.value })}
                  placeholder="frontend-app"
                />
              </FormControl>

              <FormControl>
                <FormLabel>Git仓库地址</FormLabel>
                <Input
                  value={newApp.repository}
                  onChange={(e) => setNewApp({ ...newApp, repository: e.target.value })}
                  placeholder="https://github.com/user/repo.git"
                />
              </FormControl>

              <FormControl>
                <FormLabel>分支</FormLabel>
                <Input
                  value={newApp.branch}
                  onChange={(e) => setNewApp({ ...newApp, branch: e.target.value })}
                  placeholder="main"
                />
              </FormControl>

              <FormControl>
                <FormLabel>部署路径</FormLabel>
                <Input
                  value={newApp.deployPath}
                  onChange={(e) => setNewApp({ ...newApp, deployPath: e.target.value })}
                  placeholder="/var/www/app"
                />
              </FormControl>

              <FormControl>
                <FormLabel>域名（可选）</FormLabel>
                <Input
                  value={newApp.domain}
                  onChange={(e) => setNewApp({ ...newApp, domain: e.target.value })}
                  placeholder="app.example.com"
                />
              </FormControl>

              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">自动SSL证书</FormLabel>
                <Switch
                  isChecked={newApp.autoSSL}
                  onChange={(e) => setNewApp({ ...newApp, autoSSL: e.target.checked })}
                />
              </FormControl>
            </VStack>
          </ModalBody>

          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onClose}>
              取消
            </Button>
            <Button colorScheme="blue" onClick={handleCreateApp}>
              创建应用
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* 添加SSH密钥模态框 */}
      <Modal isOpen={isKeyOpen} onClose={onKeyClose} size="lg">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>添加SSH密钥</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>密钥名称</FormLabel>
                <Input
                  value={newKey.name}
                  onChange={(e) => setNewKey({ ...newKey, name: e.target.value })}
                  placeholder="deploy-key-1"
                />
              </FormControl>

              <FormControl>
                <FormLabel>公钥内容</FormLabel>
                <Textarea
                  value={newKey.publicKey}
                  onChange={(e) => setNewKey({ ...newKey, publicKey: e.target.value })}
                  placeholder="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..."
                  rows={6}
                />
              </FormControl>
            </VStack>
          </ModalBody>

          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onKeyClose}>
              取消
            </Button>
            <Button colorScheme="green" onClick={handleAddSSHKey}>
              添加密钥
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* 服务器配置模态框 */}
      <Modal isOpen={isConfigOpen} onClose={onConfigClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>Git服务器配置</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">启用Git服务器</FormLabel>
                <Switch
                  isChecked={config.enabled}
                  onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
                />
              </FormControl>

              <FormControl>
                <FormLabel>SSH端口</FormLabel>
                <Input
                  type="number"
                  value={config.port}
                  onChange={(e) => setConfig({ ...config, port: parseInt(e.target.value) })}
                />
              </FormControl>

              <FormControl>
                <FormLabel>Webhook基础URL</FormLabel>
                <Input
                  value={config.webhook}
                  onChange={(e) => setConfig({ ...config, webhook: e.target.value })}
                  placeholder="https://your-domain.com/webhook"
                />
                <Text fontSize="sm" color="gray.500" mt={1}>
                  部署完成后的回调通知URL，支持企业微信、飞书、钉钉、Slack等平台
                </Text>
              </FormControl>

              <FormControl>
                <FormLabel>默认分支</FormLabel>
                <Input
                  value={config.defaultBranch}
                  onChange={(e) => setConfig({ ...config, defaultBranch: e.target.value })}
                  placeholder="main"
                />
                <Text fontSize="sm" color="gray.500" mt={1}>
                  新Git应用创建时的默认分支名称
                </Text>
              </FormControl>

              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">默认启用自动SSL</FormLabel>
                <Switch
                  isChecked={config.autoSSL}
                  onChange={(e) => setConfig({ ...config, autoSSL: e.target.checked })}
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

export default GitServerManagement

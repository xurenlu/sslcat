import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
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
  Select,
  useDisclosure,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
} from '@chakra-ui/react'
import {
  FiGlobe,
  FiRefreshCw,
  FiPlus,
  FiEdit,
  FiTrash2,
  FiFolder,
  FiCode,
} from 'react-icons/fi'

interface StaticSite {
  id: string
  domain: string
  rootPath: string
  enabled: boolean
  indexFile: string
  created: string
  size: string
}

interface PHPSite {
  id: string
  domain: string
  rootPath: string
  phpVersion: string
  enabled: boolean
  memoryLimit: string
  maxExecutionTime: string
  created: string
}

const SitesManagement: React.FC = () => {
  const [staticSites, setStaticSites] = useState<StaticSite[]>([])
  const [phpSites, setPHPSites] = useState<PHPSite[]>([])
  const [loading, setLoading] = useState(false)
  const { isOpen, onOpen, onClose } = useDisclosure()
  const [modalType, setModalType] = useState<'static' | 'php'>('static')
  const [editingSite, setEditingSite] = useState<StaticSite | PHPSite | null>(null)
  const toast = useToast()

  const [newSite, setNewSite] = useState({
    domain: '',
    rootPath: '',
    enabled: true,
    indexFile: 'index.html',
    phpVersion: '8.1',
    memoryLimit: '128M',
    maxExecutionTime: '30',
  })

  const refreshData = async () => {
    setLoading(true)
    try {
      // TODO: 实际的 API 调用
      setTimeout(() => {
        setStaticSites([
          {
            id: '1',
            domain: 'example.com',
            rootPath: '/var/www/example.com',
            enabled: true,
            indexFile: 'index.html',
            created: '2024-01-15',
            size: '12.5 MB',
          },
          {
            id: '2',
            domain: 'blog.example.com',
            rootPath: '/var/www/blog',
            enabled: true,
            indexFile: 'index.html',
            created: '2024-01-10',
            size: '8.3 MB',
          },
        ])

        setPHPSites([
          {
            id: '1',
            domain: 'app.example.com',
            rootPath: '/var/www/app',
            phpVersion: '8.1',
            enabled: true,
            memoryLimit: '256M',
            maxExecutionTime: '60',
            created: '2024-01-12',
          },
        ])
        setLoading(false)
      }, 1000)
    } catch (error) {
      console.error('获取站点数据失败:', error)
      setLoading(false)
    }
  }

  const handleCreateSite = async () => {
    try {
      // TODO: 实际的 API 调用
      toast({
        title: '站点创建成功',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      
      onClose()
      refreshData()
      resetForm()
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

  const handleDeleteSite = async (id: string, type: 'static' | 'php') => {
    try {
      // TODO: 实际的 API 调用
      if (type === 'static') {
        setStaticSites(staticSites.filter(site => site.id !== id))
      } else {
        setPHPSites(phpSites.filter(site => site.id !== id))
      }
      
      toast({
        title: '站点删除成功',
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

  const resetForm = () => {
    setNewSite({
      domain: '',
      rootPath: '',
      enabled: true,
      indexFile: 'index.html',
      phpVersion: '8.1',
      memoryLimit: '128M',
      maxExecutionTime: '30',
    })
    setEditingSite(null)
  }

  const openCreateModal = (type: 'static' | 'php') => {
    setModalType(type)
    resetForm()
    onOpen()
  }

  useEffect(() => {
    refreshData()
  }, [])

  return (
    <Box>
      <Flex justify="space-between" align="center" mb={6}>
        <HStack>
          <Icon as={FiGlobe} boxSize={6} />
          <Heading size="lg">站点管理</Heading>
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

      <Tabs variant="enclosed">
        <TabList>
          <Tab>
            <HStack>
              <Icon as={FiFolder} />
              <Text>静态站点</Text>
              <Badge colorScheme="blue">{staticSites.length}</Badge>
            </HStack>
          </Tab>
          <Tab>
            <HStack>
              <Icon as={FiCode} />
              <Text>PHP 站点</Text>
              <Badge colorScheme="green">{phpSites.length}</Badge>
            </HStack>
          </Tab>
        </TabList>

        <TabPanels>
          {/* 静态站点面板 */}
          <TabPanel>
            <VStack spacing={6} align="stretch">
              <Flex justify="space-between" align="center">
                <Text fontSize="lg" fontWeight="medium">静态站点列表</Text>
                <Button
                  leftIcon={<Icon as={FiPlus} />}
                  colorScheme="blue"
                  onClick={() => openCreateModal('static')}
                >
                  添加静态站点
                </Button>
              </Flex>

              <Card>
                <CardBody>
                  {staticSites.length > 0 ? (
                    <Table variant="simple">
                      <Thead>
                        <Tr>
                          <Th>域名</Th>
                          <Th>根目录</Th>
                          <Th>状态</Th>
                          <Th>入口文件</Th>
                          <Th>大小</Th>
                          <Th>创建时间</Th>
                          <Th>操作</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {staticSites.map((site) => (
                          <Tr key={site.id}>
                            <Td>
                              <HStack>
                                <Icon as={FiGlobe} />
                                <Text fontFamily="mono">{site.domain}</Text>
                              </HStack>
                            </Td>
                            <Td>
                              <Text fontSize="sm" fontFamily="mono">
                                {site.rootPath}
                              </Text>
                            </Td>
                            <Td>
                              <Badge colorScheme={site.enabled ? 'green' : 'gray'}>
                                {site.enabled ? '启用' : '禁用'}
                              </Badge>
                            </Td>
                            <Td>{site.indexFile}</Td>
                            <Td>{site.size}</Td>
                            <Td>{site.created}</Td>
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
                                  onClick={() => handleDeleteSite(site.id, 'static')}
                                />
                              </HStack>
                            </Td>
                          </Tr>
                        ))}
                      </Tbody>
                    </Table>
                  ) : (
                    <Box textAlign="center" py={8}>
                      <Icon as={FiFolder} boxSize={12} color="gray.300" mb={4} />
                      <Text color="gray.500" mb={4}>暂无静态站点</Text>
                      <Button
                        leftIcon={<Icon as={FiPlus} />}
                        colorScheme="blue"
                        onClick={() => openCreateModal('static')}
                      >
                        添加第一个静态站点
                      </Button>
                    </Box>
                  )}
                </CardBody>
              </Card>
            </VStack>
          </TabPanel>

          {/* PHP 站点面板 */}
          <TabPanel>
            <VStack spacing={6} align="stretch">
              <Flex justify="space-between" align="center">
                <Text fontSize="lg" fontWeight="medium">PHP 站点列表</Text>
                <Button
                  leftIcon={<Icon as={FiPlus} />}
                  colorScheme="green"
                  onClick={() => openCreateModal('php')}
                >
                  添加 PHP 站点
                </Button>
              </Flex>

              <Card>
                <CardBody>
                  {phpSites.length > 0 ? (
                    <Table variant="simple">
                      <Thead>
                        <Tr>
                          <Th>域名</Th>
                          <Th>根目录</Th>
                          <Th>PHP版本</Th>
                          <Th>状态</Th>
                          <Th>内存限制</Th>
                          <Th>执行时间</Th>
                          <Th>创建时间</Th>
                          <Th>操作</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {phpSites.map((site) => (
                          <Tr key={site.id}>
                            <Td>
                              <HStack>
                                <Icon as={FiCode} />
                                <Text fontFamily="mono">{site.domain}</Text>
                              </HStack>
                            </Td>
                            <Td>
                              <Text fontSize="sm" fontFamily="mono">
                                {site.rootPath}
                              </Text>
                            </Td>
                            <Td>
                              <Badge colorScheme="purple">PHP {site.phpVersion}</Badge>
                            </Td>
                            <Td>
                              <Badge colorScheme={site.enabled ? 'green' : 'gray'}>
                                {site.enabled ? '启用' : '禁用'}
                              </Badge>
                            </Td>
                            <Td>{site.memoryLimit}</Td>
                            <Td>{site.maxExecutionTime}s</Td>
                            <Td>{site.created}</Td>
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
                                  onClick={() => handleDeleteSite(site.id, 'php')}
                                />
                              </HStack>
                            </Td>
                          </Tr>
                        ))}
                      </Tbody>
                    </Table>
                  ) : (
                    <Box textAlign="center" py={8}>
                      <Icon as={FiCode} boxSize={12} color="gray.300" mb={4} />
                      <Text color="gray.500" mb={4}>暂无 PHP 站点</Text>
                      <Button
                        leftIcon={<Icon as={FiPlus} />}
                        colorScheme="green"
                        onClick={() => openCreateModal('php')}
                      >
                        添加第一个 PHP 站点
                      </Button>
                    </Box>
                  )}
                </CardBody>
              </Card>
            </VStack>
          </TabPanel>
        </TabPanels>
      </Tabs>

      {/* 添加站点模态框 */}
      <Modal isOpen={isOpen} onClose={onClose} size="lg">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>
            {modalType === 'static' ? '添加静态站点' : '添加 PHP 站点'}
          </ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>域名</FormLabel>
                <Input
                  value={newSite.domain}
                  onChange={(e) => setNewSite({ ...newSite, domain: e.target.value })}
                  placeholder="example.com"
                />
              </FormControl>

              <FormControl>
                <FormLabel>根目录路径</FormLabel>
                <Input
                  value={newSite.rootPath}
                  onChange={(e) => setNewSite({ ...newSite, rootPath: e.target.value })}
                  placeholder="/var/www/example.com"
                />
              </FormControl>

              {modalType === 'static' ? (
                <FormControl>
                  <FormLabel>入口文件</FormLabel>
                  <Input
                    value={newSite.indexFile}
                    onChange={(e) => setNewSite({ ...newSite, indexFile: e.target.value })}
                    placeholder="index.html"
                  />
                </FormControl>
              ) : (
                <>
                  <FormControl>
                    <FormLabel>PHP 版本</FormLabel>
                    <Select
                      value={newSite.phpVersion}
                      onChange={(e) => setNewSite({ ...newSite, phpVersion: e.target.value })}
                    >
                      <option value="7.4">PHP 7.4</option>
                      <option value="8.0">PHP 8.0</option>
                      <option value="8.1">PHP 8.1</option>
                      <option value="8.2">PHP 8.2</option>
                    </Select>
                  </FormControl>

                  <FormControl>
                    <FormLabel>内存限制</FormLabel>
                    <Select
                      value={newSite.memoryLimit}
                      onChange={(e) => setNewSite({ ...newSite, memoryLimit: e.target.value })}
                    >
                      <option value="128M">128M</option>
                      <option value="256M">256M</option>
                      <option value="512M">512M</option>
                      <option value="1G">1G</option>
                    </Select>
                  </FormControl>

                  <FormControl>
                    <FormLabel>最大执行时间（秒）</FormLabel>
                    <Input
                      type="number"
                      value={newSite.maxExecutionTime}
                      onChange={(e) => setNewSite({ ...newSite, maxExecutionTime: e.target.value })}
                    />
                  </FormControl>
                </>
              )}
            </VStack>
          </ModalBody>

          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onClose}>
              取消
            </Button>
            <Button colorScheme="blue" onClick={handleCreateSite}>
              创建站点
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default SitesManagement

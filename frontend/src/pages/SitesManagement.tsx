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
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

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
  fcgiAddr: string
  created: string
}

const SitesManagement: React.FC = () => {
  const [staticSites, setStaticSites] = useState<StaticSite[]>([])
  const [phpSites, setPHPSites] = useState<PHPSite[]>([])
  const [loading, setLoading] = useState(false)
  const t = useTranslation()
  const { isOpen, onOpen, onClose } = useDisclosure()
  const [modalType, setModalType] = useState<'static' | 'php'>('static')
  const [editingSite, setEditingSite] = useState<StaticSite | PHPSite | null>(null)
  const toast = useToast()
  const { adminPrefix } = useConfig()

  const [newSite, setNewSite] = useState({
    domain: '',
    rootPath: '',
    enabled: true,
    indexFile: 'index.html',
    phpVersion: '8.1',
    memoryLimit: '128M',
    maxExecutionTime: '30',
    fcgiAddr: 'unix:/var/run/php-fpm.sock',
    headers: {} as Record<string, string>,
  })

  const refreshData = async () => {
    setLoading(true)
    try {
      let hasError = false
      
      // 获取静态站点
      try {
        const staticResponse = await fetch(buildApiPath(adminPrefix, '/api/static-sites'), {
          method: 'GET',
          credentials: 'include',
        })

        if (staticResponse.ok) {
          const staticData = await staticResponse.json()
          setStaticSites(staticData.sites || [])
        } else {
          console.warn('获取静态站点失败:', staticResponse.status)
          hasError = true
        }
      } catch (error) {
        console.warn('获取静态站点失败:', error)
        hasError = true
      }

      // 获取PHP站点
      try {
        const phpResponse = await fetch(buildApiPath(adminPrefix, '/api/php-sites'), {
          method: 'GET',
          credentials: 'include',
        })

        if (phpResponse.ok) {
          const phpData = await phpResponse.json()
          setPHPSites(phpData.sites || [])
        } else {
          console.warn('获取PHP站点失败:', phpResponse.status)
          hasError = true
        }
      } catch (error) {
        console.warn('获取PHP站点失败:', error)
        hasError = true
      }

      // 如果两个API都失败，才显示错误
      if (hasError) {
        toast({
          title: '部分数据获取失败',
          description: '某些站点数据可能无法加载，请检查网络连接',
          status: 'warning',
          duration: 3000,
          isClosable: true,
        })
      }
    } catch (error) {
      console.error('获取站点数据失败:', error)
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

  const validateFCGIAddress = (addr: string): boolean => {
    if (!addr.trim()) return false
    
    // 检查 Unix Socket 格式: unix:/path/to/sock
    if (addr.startsWith('unix:')) {
      const path = addr.substring(5)
      return path.length > 0 && path.startsWith('/')
    }
    
    // 检查 TCP 格式: host:port
    const tcpPattern = /^[a-zA-Z0-9.-]+:\d+$/
    return tcpPattern.test(addr)
  }

  const handleSaveSite = async () => {
    try {
      setLoading(true)
      
      // 验证 PHP 站点的 FCGI 地址
      if (modalType === 'php' && !validateFCGIAddress(newSite.fcgiAddr)) {
        toast({
          title: '连接地址格式错误',
          description: '请输入有效的连接地址，如 unix:/var/run/php-fpm.sock 或 127.0.0.1:9000',
          status: 'error',
          duration: 5000,
          isClosable: true,
        })
        return
      }
      
      const isEditing = editingSite !== null
      const method = isEditing ? 'PUT' : 'POST'
      const endpoint = isEditing 
        ? (modalType === 'static' 
            ? `/api/static-sites/${editingSite.id}` 
            : `/api/php-sites/${editingSite.id}`)
        : (modalType === 'static' 
            ? '/api/static-sites' 
            : '/api/php-sites')
      
      if (modalType === 'static') {
        // 创建或更新静态站点
        const response = await fetch(buildApiPath(adminPrefix, endpoint), {
          method,
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify({
            domain: newSite.domain,
            root: newSite.rootPath,
            index: newSite.indexFile,
            enabled: newSite.enabled,
            headers: newSite.headers,
          }),
        })

        if (!response.ok) {
          const errorData = await response.json()
          throw new Error(errorData.error || `${isEditing ? '更新' : '创建'}静态站点失败`)
        }
      } else {
        // 创建或更新 PHP 站点
        const response = await fetch(buildApiPath(adminPrefix, endpoint), {
          method,
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify({
            domain: newSite.domain,
            root: newSite.rootPath,
            index: 'index.php',
            enabled: newSite.enabled,
            fcgi_addr: newSite.fcgiAddr,
            vars: {
              PHP_VERSION: newSite.phpVersion,
              MEMORY_LIMIT: newSite.memoryLimit,
              MAX_EXECUTION_TIME: newSite.maxExecutionTime,
            },
            headers: newSite.headers,
          }),
        })

        if (!response.ok) {
          const errorData = await response.json()
          throw new Error(errorData.error || `${isEditing ? '更新' : '创建'} PHP 站点失败`)
        }
      }

      toast({
        title: `站点${isEditing ? '更新' : '创建'}成功`,
        description: `${modalType === 'static' ? '静态' : 'PHP'} 站点已成功${isEditing ? '更新' : '创建'}`,
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      
      onClose()
      refreshData()
      resetForm()
      setEditingSite(null)
    } catch (error) {
      toast({
        title: `${editingSite ? '更新' : '创建'}失败`,
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
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

  const handleEditSite = (site: StaticSite | PHPSite, type: 'static' | 'php') => {
    setEditingSite(site)
    setModalType(type)
    
    // 填充表单数据
    if (type === 'static') {
      const staticSite = site as StaticSite
      setNewSite({
        domain: staticSite.domain,
        rootPath: staticSite.rootPath,
        enabled: staticSite.enabled,
        indexFile: staticSite.indexFile,
        phpVersion: '8.1',
        memoryLimit: '128M',
        maxExecutionTime: '30',
        fcgiAddr: 'unix:/var/run/php-fpm.sock',
        headers: {},
      })
    } else {
      const phpSite = site as PHPSite
      setNewSite({
        domain: phpSite.domain,
        rootPath: phpSite.rootPath,
        enabled: phpSite.enabled,
        indexFile: 'index.php',
        phpVersion: phpSite.phpVersion,
        memoryLimit: phpSite.memoryLimit,
        maxExecutionTime: phpSite.maxExecutionTime,
        fcgiAddr: phpSite.fcgiAddr,
        headers: {},
      })
    }
    
    onOpen()
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
      fcgiAddr: 'unix:/var/run/php-fpm.sock',
      headers: {} as Record<string, string>,
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
          <Heading size="lg">{t.sites.title}</Heading>
        </HStack>
        <HStack>
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            onClick={refreshData}
            isLoading={loading}
            variant="outline"
          >
{t.sites.refresh}
          </Button>
        </HStack>
      </Flex>

      <Tabs variant="enclosed">
        <TabList>
          <Tab>
            <HStack>
              <Icon as={FiFolder} />
              <Text>{t.sites.staticSites}</Text>
              <Badge colorScheme="blue">{staticSites.length}</Badge>
            </HStack>
          </Tab>
          <Tab>
            <HStack>
              <Icon as={FiCode} />
              <Text>{t.sites.phpSites}</Text>
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
                                  onClick={() => handleEditSite(site, 'static')}
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
                          <Th>连接地址</Th>
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
                              <Text fontSize="sm" fontFamily="mono" color="blue.600">
                                {site.fcgiAddr}
                              </Text>
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
                                  onClick={() => handleEditSite(site, 'php')}
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
            {editingSite 
              ? (modalType === 'static' ? '编辑静态站点' : '编辑 PHP 站点')
              : (modalType === 'static' ? '添加静态站点' : '添加 PHP 站点')
            }
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

                  <FormControl>
                    <FormLabel>PHP-FPM 连接地址</FormLabel>
                    <Input
                      value={newSite.fcgiAddr}
                      onChange={(e) => setNewSite({ ...newSite, fcgiAddr: e.target.value })}
                      placeholder="unix:/var/run/php-fpm.sock 或 127.0.0.1:9000"
                    />
                    <Text fontSize="sm" color="gray.500" mt={1}>
                      支持 Unix Socket (unix:/path/to/sock) 或 TCP 连接 (host:port)
                    </Text>
                  </FormControl>
                </>
              )}
            </VStack>
          </ModalBody>

          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onClose}>
{t.common.cancel}
            </Button>
            <Button colorScheme="blue" onClick={handleSaveSite}>
              {editingSite ? t.sites.updateSite : t.sites.createSite}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default SitesManagement

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
import { useConfig, buildApiPath, buildPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'
import { useNavigate } from 'react-router-dom'
import { PathPrefixRule } from '../types/config'

interface StaticSite {
  id?: string
  domain: string
  root: string
  rootPath?: string  // 兼容旧字段名
  index: string
  indexFile?: string  // 兼容旧字段名
  enabled: boolean
  created?: string
  size?: string
  path_prefix_rules?: PathPrefixRule[]
}

interface PHPSite {
  id?: string
  domain: string
  root: string
  rootPath?: string  // 兼容旧字段名
  index: string
  indexFile?: string  // 兼容旧字段名
  enabled: boolean
  fcgi_addr: string
  fcgiAddr?: string  // 兼容旧字段名
  vars: Record<string, string>
  phpVersion?: string  // 兼容旧字段名
  memoryLimit?: string  // 兼容旧字段名
  maxExecutionTime?: string  // 兼容旧字段名
  created?: string
  path_prefix_rules?: PathPrefixRule[]
}

const SitesManagement: React.FC = () => {
  const [staticSites, setStaticSites] = useState<StaticSite[]>([])
  const [phpSites, setPHPSites] = useState<PHPSite[]>([])
  const [loading, setLoading] = useState(false)
  const t = useTranslation()
  const toast = useToast()
  const { adminPrefix } = useConfig()
  const navigate = useNavigate()


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
    if (type === 'static') {
      navigate(buildPath(adminPrefix, `/static-site-edit?domain=${encodeURIComponent(site.domain)}`))
    } else {
      navigate(buildPath(adminPrefix, `/php-site-edit?domain=${encodeURIComponent(site.domain)}`))
    }
  }

  const openCreateModal = (type: 'static' | 'php') => {
    if (type === 'static') {
      navigate(buildPath(adminPrefix, '/static-site-add'))
    } else {
      navigate(buildPath(adminPrefix, '/php-site-add'))
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
                                  onClick={() => handleDeleteSite(site.id || site.domain, 'static')}
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
                                  onClick={() => handleDeleteSite(site.id || site.domain, 'php')}
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

    </Box>
  )
}

export default SitesManagement

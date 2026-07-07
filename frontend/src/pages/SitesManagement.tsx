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
import { useToastMessages } from '../hooks/useToastMessages'
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
  path_prefix_rules?: PathPrefixRule[]
}

const SitesManagement: React.FC = () => {
  const [staticSites, setStaticSites] = useState<StaticSite[]>([])
  const [phpSites, setPHPSites] = useState<PHPSite[]>([])
  const [loading, setLoading] = useState(false)
  const t = useTranslation()
  const toastMessages = useToastMessages()
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
        toastMessages.siteDataLoadPartialFailed()
      }
    } catch (error) {
      console.error('获取站点数据失败:', error)
      toastMessages.siteDataLoadFailed(error instanceof Error ? error.message : undefined)
    } finally {
      setLoading(false)
    }
  }

  const getResponseError = async (response: Response): Promise<string> => {
    try {
      const data = await response.json()
      return data.error || data.message || response.statusText
    } catch {
      return response.statusText
    }
  }

  const handleDeleteSite = async (domain: string, type: 'static' | 'php') => {
    try {
      const endpoint = type === 'static' ? '/api/static-sites/delete' : '/api/php-sites/delete'
      const response = await fetch(
        buildApiPath(adminPrefix, `${endpoint}?domain=${encodeURIComponent(domain)}`),
        {
          method: 'DELETE',
          credentials: 'include',
        }
      )

      if (!response.ok) {
        throw new Error(await getResponseError(response))
      }

      if (type === 'static') {
        setStaticSites((sites) => sites.filter((site) => site.domain !== domain))
      } else {
        setPHPSites((sites) => sites.filter((site) => site.domain !== domain))
      }

      await refreshData()
      toastMessages.siteDeleteSuccess()
    } catch (error) {
      toastMessages.siteDeleteFailed(error instanceof Error ? error.message : undefined)
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
                <Text fontSize="lg" fontWeight="medium">{t.sites.staticSiteList}</Text>
                <Button
                  leftIcon={<Icon as={FiPlus} />}
                  colorScheme="blue"
                  onClick={() => openCreateModal('static')}
                >
                  {t.sites.addStaticSite}
                </Button>
              </Flex>

              <Card>
                <CardBody>
                  {staticSites.length > 0 ? (
                    <Table variant="simple">
                      <Thead>
                        <Tr>
                          <Th>{t.sites.domain}</Th>
                          <Th>{t.sites.rootDirectory}</Th>
                          <Th>{t.sites.status}</Th>
                          <Th>{t.sites.indexFile}</Th>
                          <Th>{t.sites.pathPrefixRules}</Th>
                          <Th>{t.sites.actions}</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {staticSites.map((site) => (
                          <Tr key={site.domain}>
                            <Td>
                              <HStack>
                                <Icon as={FiGlobe} />
                                <Text fontFamily="mono">{site.domain}</Text>
                              </HStack>
                            </Td>
                            <Td>
                              <Text fontSize="sm" fontFamily="mono">
                                {site.rootPath || site.root}
                              </Text>
                            </Td>
                            <Td>
                              <Badge colorScheme={site.enabled ? 'green' : 'gray'}>
                                {site.enabled ? t.common.enable : t.common.disable}
                              </Badge>
                            </Td>
                            <Td>{site.indexFile || site.index}</Td>
                            <Td>
                              <Badge colorScheme="blue">
                                {site.path_prefix_rules?.length || 0} {t.sites.rules}
                              </Badge>
                            </Td>
                            <Td>
                              <HStack spacing={2}>
                                <IconButton
                                  aria-label={t.sites.edit}
                                  icon={<FiEdit />}
                                  size="sm"
                                  variant="ghost"
                                  onClick={() => handleEditSite(site, 'static')}
                                />
                                <IconButton
                                  aria-label={t.sites.delete}
                                  icon={<FiTrash2 />}
                                  size="sm"
                                  variant="ghost"
                                  colorScheme="red"
                                  onClick={() => handleDeleteSite(site.domain, 'static')}
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
                      <Text color="gray.500" mb={4}>{t.sites.noStaticSites}</Text>
                      <Button
                        leftIcon={<Icon as={FiPlus} />}
                        colorScheme="blue"
                        onClick={() => openCreateModal('static')}
                      >
                        {t.sites.addFirstStaticSite}
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
                <Text fontSize="lg" fontWeight="medium">{t.sites.phpSites}</Text>
                <Button
                  leftIcon={<Icon as={FiPlus} />}
                  colorScheme="green"
                  onClick={() => openCreateModal('php')}
                >
                  {t.sites.createSite}
                </Button>
              </Flex>

              <Card>
                <CardBody>
                  {phpSites.length > 0 ? (
                    <Table variant="simple">
                      <Thead>
                        <Tr>
                          <Th>{t.sites.domain}</Th>
                          <Th>{t.sites.rootDirectory}</Th>
                          <Th>{t.sites.phpVersion}</Th>
                          <Th>{t.sites.connectionAddress}</Th>
                          <Th>{t.sites.status}</Th>
                          <Th>{t.sites.memoryLimit}</Th>
                          <Th>{t.sites.executionTime}</Th>
                          <Th>{t.sites.pathPrefixRules}</Th>
                          <Th>{t.sites.actions}</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {phpSites.map((site) => (
                          <Tr key={site.domain}>
                            <Td>
                              <HStack>
                                <Icon as={FiCode} />
                                <Text fontFamily="mono">{site.domain}</Text>
                              </HStack>
                            </Td>
                            <Td>
                              <Text fontSize="sm" fontFamily="mono">
                                {site.rootPath || site.root}
                              </Text>
                            </Td>
                            <Td>
                              <Badge colorScheme="purple">PHP {site.phpVersion || t.sites.defaultPhpVersion}</Badge>
                            </Td>
                            <Td>
                              <Text fontSize="sm" fontFamily="mono" color="blue.600">
                                {site.fcgiAddr || site.fcgi_addr}
                              </Text>
                            </Td>
                            <Td>
                              <Badge colorScheme={site.enabled ? 'green' : 'gray'}>
                                {site.enabled ? t.common.enable : t.common.disable}
                              </Badge>
                            </Td>
                            <Td>{site.memoryLimit || t.sites.defaultMemoryLimit}</Td>
                            <Td>{site.maxExecutionTime ? `${site.maxExecutionTime}s` : t.sites.defaultExecutionTime}</Td>
                            <Td>
                              <Badge colorScheme="green">
                                {site.path_prefix_rules?.length || 0} {t.sites.rules}
                              </Badge>
                            </Td>
                            <Td>
                              <HStack spacing={2}>
                                <IconButton
                                  aria-label={t.sites.edit}
                                  icon={<FiEdit />}
                                  size="sm"
                                  variant="ghost"
                                  onClick={() => handleEditSite(site, 'php')}
                                />
                                <IconButton
                                  aria-label={t.sites.delete}
                                  icon={<FiTrash2 />}
                                  size="sm"
                                  variant="ghost"
                                  colorScheme="red"
                                  onClick={() => handleDeleteSite(site.domain, 'php')}
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
                      <Text color="gray.500" mb={4}>{t.sites.noPHPSites}</Text>
                      <Button
                        leftIcon={<Icon as={FiPlus} />}
                        colorScheme="green"
                        onClick={() => openCreateModal('php')}
                      >
                        {t.sites.addFirstPHPSite}
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

import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Box,
  Heading,
  Card,
  CardBody,
  CardHeader,
  VStack,
  HStack,
  Button,
  Text,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  FormControl,
  FormLabel,
  Input,
  useToast,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Spinner,
  Center,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  useDisclosure,
  Select,
  Badge,
  IconButton,
  AlertDialog,
  AlertDialogBody,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogContent,
  AlertDialogOverlay,
  Alert,
  AlertIcon,
} from '@chakra-ui/react'
import {
  FiRefreshCw,
  FiX,
  FiPlus,
  FiTrash2,
  FiEdit2,
  FiAlertTriangle,
  FiClock,
} from 'react-icons/fi'
import { apiService } from '../utils/api'
import { useConfig, buildPath } from '../contexts/ConfigContext'
import { getCIDRTypeDescription, getCIDRTypeColor } from '../utils/cidr'
import { useTranslation } from '../hooks/useLanguage'

interface BlockedIP {
  source?: string
  ip: string
  reason: string
  block_time: string
  expire_time: string
}

interface BlockedTLS {
  fingerprint: string
  reason: string
  block_time: string
  expire_time: string
}

interface BlockedUserAgent {
  user_agent: string
  reason: string
  block_time: string
  expire_time: string
}

interface BlockedListData {
  ips: BlockedIP[]
  tls_fingerprints: BlockedTLS[]
  user_agents: BlockedUserAgent[]
}

interface WhitelistEntry {
  value: string
  description: string
  created_at: string
  updated_at: string
}

const BlockManagement: React.FC = () => {
  const [loading, setLoading] = useState(false)
  const [blockedData, setBlockedData] = useState<BlockedListData>({
    ips: [],
    tls_fingerprints: [],
    user_agents: [],
  })
  const { isOpen, onOpen, onClose } = useDisclosure()
  const { isOpen: isUnblockOpen, onOpen: onUnblockOpen, onClose: onUnblockClose } = useDisclosure()
  const { isOpen: isWhitelistOpen, onOpen: onWhitelistOpen, onClose: onWhitelistClose } = useDisclosure()
  const { isOpen: isWhitelistDeleteOpen, onOpen: onWhitelistDeleteOpen, onClose: onWhitelistDeleteClose } = useDisclosure()
  const [activeTab, setActiveTab] = useState(0)
  const [whitelistEntries, setWhitelistEntries] = useState<WhitelistEntry[]>([])
  const [whitelistValue, setWhitelistValue] = useState('')
  const [whitelistDescription, setWhitelistDescription] = useState('')
  const [editingWhitelist, setEditingWhitelist] = useState<WhitelistEntry | null>(null)
  const [deletingWhitelistValue, setDeletingWhitelistValue] = useState('')
  const [blockType, setBlockType] = useState<'ip' | 'tls_fingerprint' | 'user_agent'>('ip')
  const [blockValue, setBlockValue] = useState('')
  const [blockDuration, setBlockDuration] = useState('24')
  const [blockReason, setBlockReason] = useState('')
  const [unblockType, setUnblockType] = useState<'ip' | 'tls_fingerprint' | 'user_agent'>('ip')
  const [unblockValue, setUnblockValue] = useState('')
  const cancelRef = React.useRef<HTMLButtonElement>(null)
  const toast = useToast()
  const t = useTranslation()
  const navigate = useNavigate()
  const { adminPrefix } = useConfig()

  const fetchBlockedList = async () => {
    setLoading(true)
    try {
      const response = await apiService.getBlockedList()
      if (response.success && response.data) {
        setBlockedData({
          ips: response.data.ips || [],
          tls_fingerprints: response.data.tls_fingerprints || [],
          user_agents: response.data.user_agents || [],
        })
      }
    } catch (error) {
      console.error('获取封禁列表失败:', error)
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

  const fetchWhitelist = async () => {
    try {
      const response = await apiService.getWhitelist()
      if (response.success && response.data) {
        setWhitelistEntries(response.data || [])
      }
    } catch (error) {
      console.error('获取白名单失败:', error)
      toast({
        title: '获取失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  useEffect(() => {
    fetchBlockedList()
    fetchWhitelist()
  }, [])

  const handleBlock = async () => {
    if (!blockValue.trim()) {
      toast({
        title: '请输入要封禁的值',
        status: 'warning',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    try {
      const duration = parseFloat(blockDuration)
      const durationSeconds = duration === 0 ? 0 : Math.floor(duration * 3600) // 转换为秒，0表示永久
      
      await apiService.blockItem(blockType, blockValue.trim(), durationSeconds, blockReason.trim() || undefined)
      
      toast({
        title: '封禁成功',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      
      onClose()
      setBlockValue('')
      setBlockReason('')
      setBlockDuration('24')
      fetchBlockedList()
    } catch (error) {
      console.error('封禁失败:', error)
      toast({
        title: '封禁失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const handleUnblock = async () => {
    try {
      await apiService.unblockItem(unblockType, unblockValue)
      
      toast({
        title: '解封成功',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      
      onUnblockClose()
      setUnblockValue('')
      fetchBlockedList()
    } catch (error) {
      console.error('解封失败:', error)
      toast({
        title: '解封失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const formatTime = (timeStr: string) => {
    try {
      const date = new Date(timeStr)
      return date.toLocaleString('zh-CN')
    } catch {
      return timeStr
    }
  }

  const isExpired = (expireTimeStr: string) => {
    try {
      return new Date(expireTimeStr) < new Date()
    } catch {
      return false
    }
  }

  const openBlockModal = (type: 'ip' | 'tls_fingerprint' | 'user_agent') => {
    setBlockType(type)
    setActiveTab(type === 'ip' ? 0 : type === 'tls_fingerprint' ? 1 : 2)
    onOpen()
  }

  const openUnblockModal = (type: 'ip' | 'tls_fingerprint' | 'user_agent', value: string) => {
    setUnblockType(type)
    setUnblockValue(value)
    onUnblockOpen()
  }

  const openAddWhitelistModal = () => {
    setEditingWhitelist(null)
    setWhitelistValue('')
    setWhitelistDescription('')
    onWhitelistOpen()
  }

  const openEditWhitelistModal = (entry: WhitelistEntry) => {
    setEditingWhitelist(entry)
    setWhitelistValue(entry.value)
    setWhitelistDescription(entry.description)
    onWhitelistOpen()
  }

  const openDeleteWhitelistModal = (value: string) => {
    setDeletingWhitelistValue(value)
    onWhitelistDeleteOpen()
  }

  const handleGeoAddRule = () => {
    toast({
      title: t.blockManagement?.geoRuleAddHint || '地理位置规则配置',
      description: t.blockManagement?.geoRuleGoToSecurity || '请前往「安全中心」→「地理位置过滤」进行配置',
      status: 'info',
      duration: 6000,
      isClosable: true,
      position: 'top',
      render: ({ onClose }) => (
        <Box p={3} bg="white" borderRadius="md" boxShadow="lg">
          <Text fontWeight="medium" mb={2}>
            {t.blockManagement?.geoRuleAddHint || '地理位置规则配置'}
          </Text>
          <Text fontSize="sm" color="gray.600" mb={3}>
            {t.blockManagement?.geoRuleGoToSecurity || '请前往「安全中心」→「地理位置过滤」进行配置'}
          </Text>
          <HStack>
            <Button size="sm" colorScheme="blue" onClick={() => { navigate(buildPath(adminPrefix || '/sslcat-panel', '/security')); onClose() }}>
              {t.blockManagement?.geoRuleGoToBtn || '前往安全中心'}
            </Button>
            <Button size="sm" variant="ghost" onClick={onClose}>
              {t.common.cancel}
            </Button>
          </HStack>
        </Box>
      ),
    })
  }

  const handleTimeWindowAddRule = () => {
    toast({
      title: t.blockManagement?.timeWindowComingSoon || '功能开发中',
      description: t.blockManagement?.timeWindowComingSoonDesc || '时间窗口控制功能开发中，敬请期待',
      status: 'info',
      duration: 4000,
      isClosable: true,
      position: 'top',
    })
  }

  const handleWhitelistSubmit = async () => {
    if (!whitelistValue.trim()) {
      toast({
        title: '请输入IP地址或CIDR网段',
        status: 'warning',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    try {
      if (editingWhitelist) {
        // 更新
        await apiService.updateWhitelistEntry(editingWhitelist.value, whitelistValue.trim(), whitelistDescription.trim())
        toast({
          title: '更新成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
      } else {
        // 添加
        await apiService.addWhitelistEntry(whitelistValue.trim(), whitelistDescription.trim())
        toast({
          title: '添加成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
      }
      
      onWhitelistClose()
      setWhitelistValue('')
      setWhitelistDescription('')
      setEditingWhitelist(null)
      fetchWhitelist()
    } catch (error) {
      console.error('操作失败:', error)
      toast({
        title: editingWhitelist ? '更新失败' : '添加失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const handleWhitelistDelete = async () => {
    try {
      await apiService.removeWhitelistEntry(deletingWhitelistValue)
      toast({
        title: '删除成功',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      onWhitelistDeleteClose()
      setDeletingWhitelistValue('')
      fetchWhitelist()
    } catch (error) {
      console.error('删除失败:', error)
      toast({
        title: '删除失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  return (
    <Box p={6}>
      <HStack justify="space-between" mb={6}>
        <Heading size="lg">{t.blockManagement?.title || t.sidebar.blockManagement || 'Block Management'}</Heading>
        <HStack>
          <Button
            leftIcon={<FiRefreshCw />}
            onClick={() => {
              fetchBlockedList()
              if (activeTab === 3) {
                fetchWhitelist()
              }
            }}
            isLoading={loading}
            loadingText={t.common.loading}
          >
            {t.blockManagement?.refresh || t.common.refresh}
          </Button>
          {activeTab !== 3 && (
            <Button
              leftIcon={<FiPlus />}
              colorScheme="blue"
              onClick={() => {
                const type = activeTab === 0 ? 'ip' : activeTab === 1 ? 'tls_fingerprint' : 'user_agent'
                openBlockModal(type)
              }}
            >
              {t.blockManagement?.manualBlock || '+ Manual Block'}
            </Button>
          )}
          {activeTab === 3 && (
            <Button
              leftIcon={<FiPlus />}
              colorScheme="green"
              onClick={openAddWhitelistModal}
            >
              {t.blockManagement?.addWhitelist || 'Add Whitelist'}
            </Button>
          )}
        </HStack>
      </HStack>

      <Card>
        <CardBody>
          <Tabs index={activeTab} onChange={setActiveTab}>
            <TabList>
              <Tab>{t.blockManagement?.ipBlock || 'IP Block'} ({blockedData.ips.length})</Tab>
              <Tab>{t.blockManagement?.tlsFingerprintBlock || 'TLS Fingerprint Block'} ({blockedData.tls_fingerprints.length})</Tab>
              <Tab>{t.blockManagement?.userAgentBlock || 'User-Agent Block'} ({blockedData.user_agents.length})</Tab>
              <Tab>{t.blockManagement?.ipWhitelist || 'IP Whitelist'} ({whitelistEntries.length})</Tab>
              <Tab>{t.blockManagement?.geoControl || '地理位置控制'}</Tab>
              <Tab>{t.blockManagement?.timeWindowControl || '时间窗口控制'}</Tab>
            </TabList>

            <TabPanels>
              {/* IP封禁列表 */}
              <TabPanel>
                {loading ? (
                  <Center py={8}>
                    <Spinner size="xl" />
                  </Center>
                ) : blockedData.ips.length === 0 ? (
                  <Center py={8}>
                    <Text color="gray.500">{t.blockManagement?.noBlockedIPs || 'No blocked IPs for now'}</Text>
                  </Center>
                ) : (
                  <Table variant="simple">
                    <Thead>
                      <Tr>
                        <Th>{t.blockManagement?.ipAddress || 'IP Address'}</Th>
                        <Th>{t.blockManagement?.source || 'Source'}</Th>
                        <Th>{t.blockManagement?.blockReason || 'Block Reason'}</Th>
                        <Th>{t.blockManagement?.blockTime || 'Block Time'}</Th>
                        <Th>{t.blockManagement?.expireTime || 'Expire Time'}</Th>
                        <Th>{t.blockManagement?.actions || t.common.actions || 'Actions'}</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {blockedData.ips.map((item, index) => (
                        <Tr key={index}>
                          <Td>{item.ip}</Td>
                          <Td>
                            {item.source && (
                              <Badge colorScheme={item.source === 'security' ? 'blue' : 'purple'}>
                                {item.source === 'security' ? 'Security' : 'WAF'}
                              </Badge>
                            )}
                          </Td>
                          <Td>{item.reason}</Td>
                          <Td>{formatTime(item.block_time)}</Td>
                          <Td>
                            <Text color={isExpired(item.expire_time) ? 'red.500' : 'inherit'}>
                              {formatTime(item.expire_time)}
                            </Text>
                          </Td>
                          <Td>
                            <IconButton
                              aria-label={t.common.delete || 'Unblock'}
                              icon={<FiTrash2 />}
                              size="sm"
                              colorScheme="red"
                              variant="ghost"
                              onClick={() => openUnblockModal('ip', item.ip)}
                            />
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                )}
              </TabPanel>

              {/* TLS指纹封禁列表 */}
              <TabPanel>
                {loading ? (
                  <Center py={8}>
                    <Spinner size="xl" />
                  </Center>
                ) : blockedData.tls_fingerprints.length === 0 ? (
                  <Center py={8}>
                    <Text color="gray.500">{t.blockManagement?.noTlsFingerprints || 'No blocked TLS fingerprints'}</Text>
                  </Center>
                ) : (
                  <Table variant="simple">
                    <Thead>
                      <Tr>
                        <Th>TLS Fingerprint</Th>
                        <Th>{t.blockManagement?.blockReason || 'Block Reason'}</Th>
                        <Th>{t.blockManagement?.blockTime || 'Block Time'}</Th>
                        <Th>{t.blockManagement?.expireTime || 'Expire Time'}</Th>
                        <Th>{t.blockManagement?.actions || t.common.actions || 'Actions'}</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {blockedData.tls_fingerprints.map((item, index) => (
                        <Tr key={index}>
                          <Td>
                            <Text fontFamily="mono" fontSize="sm">
                              {item.fingerprint.length > 32 
                                ? `${item.fingerprint.substring(0, 32)}...` 
                                : item.fingerprint}
                            </Text>
                          </Td>
                          <Td>{item.reason}</Td>
                          <Td>{formatTime(item.block_time)}</Td>
                          <Td>
                            <Text color={isExpired(item.expire_time) ? 'red.500' : 'inherit'}>
                              {formatTime(item.expire_time)}
                            </Text>
                          </Td>
                          <Td>
                            <IconButton
                              aria-label={t.common.delete || 'Unblock'}
                              icon={<FiTrash2 />}
                              size="sm"
                              colorScheme="red"
                              variant="ghost"
                              onClick={() => openUnblockModal('tls_fingerprint', item.fingerprint)}
                            />
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                )}
              </TabPanel>

              {/* User-Agent封禁列表 */}
              <TabPanel>
                {loading ? (
                  <Center py={8}>
                    <Spinner size="xl" />
                  </Center>
                ) : blockedData.user_agents.length === 0 ? (
                  <Center py={8}>
                    <Text color="gray.500">{t.blockManagement?.noUserAgents || 'No blocked User-Agents'}</Text>
                  </Center>
                ) : (
                  <Table variant="simple">
                    <Thead>
                      <Tr>
                        <Th>User-Agent</Th>
                        <Th>{t.blockManagement?.blockReason || 'Block Reason'}</Th>
                        <Th>{t.blockManagement?.blockTime || 'Block Time'}</Th>
                        <Th>{t.blockManagement?.expireTime || 'Expire Time'}</Th>
                        <Th>{t.blockManagement?.actions || t.common.actions || 'Actions'}</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {blockedData.user_agents.map((item, index) => (
                        <Tr key={index}>
                          <Td>
                            <Text fontSize="sm" noOfLines={1} maxW="400px">
                              {item.user_agent}
                            </Text>
                          </Td>
                          <Td>{item.reason}</Td>
                          <Td>{formatTime(item.block_time)}</Td>
                          <Td>
                            <Text color={isExpired(item.expire_time) ? 'red.500' : 'inherit'}>
                              {formatTime(item.expire_time)}
                            </Text>
                          </Td>
                          <Td>
                            <IconButton
                              aria-label={t.common.delete || 'Unblock'}
                              icon={<FiTrash2 />}
                              size="sm"
                              colorScheme="red"
                              variant="ghost"
                              onClick={() => openUnblockModal('user_agent', item.user_agent)}
                            />
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                )}
              </TabPanel>

              {/* IP白名单列表 */}
              <TabPanel>
                {loading ? (
                  <Center py={8}>
                    <Spinner size="xl" />
                  </Center>
                ) : whitelistEntries.length === 0 ? (
                  <Center py={8}>
                    <Text color="gray.500">{t.blockManagement?.noWhitelistEntries || 'No whitelist entries'}</Text>
                  </Center>
                ) : (
                  <Table variant="simple">
                    <Thead>
                      <Tr>
                        <Th>{t.blockManagement?.ipCidr || 'IP/CIDR'}</Th>
                        <Th>{t.blockManagement?.type || 'Type'}</Th>
                        <Th>{t.blockManagement?.description || 'Description'}</Th>
                        <Th>{t.blockManagement?.createdAt || 'Created At'}</Th>
                        <Th>{t.blockManagement?.updatedAt || 'Updated At'}</Th>
                        <Th>{t.blockManagement?.actions || t.common.actions || 'Actions'}</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {whitelistEntries.map((entry, index) => (
                        <Tr key={index}>
                          <Td>
                            <Text fontFamily="mono" fontSize="sm">
                              {entry.value}
                            </Text>
                          </Td>
                          <Td>
                            <Badge colorScheme={getCIDRTypeColor(entry.value)}>
                              {getCIDRTypeDescription(entry.value)}
                            </Badge>
                          </Td>
                          <Td>{entry.description || '-'}</Td>
                          <Td>{formatTime(entry.created_at)}</Td>
                          <Td>{formatTime(entry.updated_at)}</Td>
                          <Td>
                            <HStack spacing={2}>
                              <IconButton
                                aria-label={t.common.edit || 'Edit'}
                                icon={<FiEdit2 />}
                                size="sm"
                                colorScheme="blue"
                                variant="ghost"
                                onClick={() => openEditWhitelistModal(entry)}
                              />
                              <IconButton
                                aria-label={t.common.delete || 'Delete'}
                                icon={<FiTrash2 />}
                                size="sm"
                                colorScheme="red"
                                variant="ghost"
                                onClick={() => openDeleteWhitelistModal(entry.value)}
                              />
                            </HStack>
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                )}
              </TabPanel>

              {/* 地理位置控制 */}
              <TabPanel>
                <VStack spacing={4} align="stretch">
                  <Alert status="info">
                    <FiAlertTriangle />
                    {t.blockManagement?.geoControlDesc || '基于客户端 IP 的地理位置进行访问控制'}
                  </Alert>

                  <HStack justify="space-between">
                    <Text fontSize="sm" color="gray.500">
                      {t.blockManagement?.geoAddRuleHint || '添加国家/地区规则来允许或拒绝访问'}
                    </Text>
                    <Button leftIcon={<FiPlus />} size="sm" colorScheme="blue" onClick={handleGeoAddRule}>
                      {t.blockManagement?.addRule || '添加规则'}
                    </Button>
                  </HStack>

                  <Box p={4} bg="gray.50" borderRadius="md" textAlign="center">
                    <Text color="gray.500">{t.blockManagement?.geoNoRules || '暂无地理位置规则'}</Text>
                    <Text fontSize="sm" color="gray.400" mt={2}>
                      {t.blockManagement?.geoClickToAdd || '点击上方按钮添加第一条规则'}
                    </Text>
                  </Box>
                </VStack>
              </TabPanel>

              {/* 时间窗口控制 */}
              <TabPanel>
                <VStack spacing={4} align="stretch">
                  <Alert status="info">
                    <FiClock />
                    {t.blockManagement?.timeWindowControlDesc || '基于时间窗口的访问控制规则'}
                  </Alert>

                  <HStack justify="space-between">
                    <Text fontSize="sm" color="gray.500">
                      {t.blockManagement?.timeWindowAddRuleHint || '设置特定时间段内的访问控制规则'}
                    </Text>
                    <Button leftIcon={<FiPlus />} size="sm" colorScheme="orange" onClick={handleTimeWindowAddRule}>
                      {t.blockManagement?.addRule || '添加规则'}
                    </Button>
                  </HStack>

                  <Box p={4} bg="gray.50" borderRadius="md" textAlign="center">
                    <Text color="gray.500">{t.blockManagement?.timeWindowNoRules || '暂无时间窗口规则'}</Text>
                    <Text fontSize="sm" color="gray.400" mt={2}>
                      {t.blockManagement?.timeWindowClickToAdd || '点击上方按钮添加第一条规则'}
                    </Text>
                  </Box>
                </VStack>
              </TabPanel>
            </TabPanels>
          </Tabs>
        </CardBody>
      </Card>

      {/* 添加/编辑白名单模态框 */}
      <Modal isOpen={isWhitelistOpen} onClose={onWhitelistClose} size="lg">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>{editingWhitelist ? (t.blockManagement?.editWhitelist || 'Edit Whitelist') : (t.blockManagement?.addWhitelistTitle || t.blockManagement?.addWhitelist || 'Add Whitelist')}</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl isRequired>
                <FormLabel>{t.blockManagement?.ipOrCidr || 'IP Address or CIDR'}</FormLabel>
                <Input
                  value={whitelistValue}
                  onChange={(e) => setWhitelistValue(e.target.value)}
                  placeholder={t.blockManagement?.ipOrCidrPlaceholder || 'e.g.: 192.168.1.1 or 192.168.1.0/24'}
                />
                <Text fontSize="sm" color="gray.500" mt={1}>
                  {t.blockManagement?.ipOrCidrDesc || 'Supports single IP (e.g. 192.168.1.1) or CIDR range (e.g. 192.168.1.0/24, 10.0.0.0/8, 172.16.0.0/16)'}
                </Text>
              </FormControl>

              <FormControl>
                <FormLabel>{t.blockManagement?.description || 'Description (Optional)'}</FormLabel>
                <Input
                  value={whitelistDescription}
                  onChange={(e) => setWhitelistDescription(e.target.value)}
                  placeholder={t.blockManagement?.descriptionPlaceholder || 'Enter description, e.g.: Office IP'}
                />
              </FormControl>
            </VStack>
          </ModalBody>

          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onWhitelistClose}>
              {t.common.cancel}
            </Button>
            <Button colorScheme="blue" onClick={handleWhitelistSubmit}>
              {editingWhitelist ? (t.blockManagement?.confirmEdit || 'Confirm Edit') : (t.blockManagement?.confirmAdd || 'Confirm Add')}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* 删除白名单确认对话框 */}
      <AlertDialog
        isOpen={isWhitelistDeleteOpen}
        leastDestructiveRef={cancelRef}
        onClose={onWhitelistDeleteClose}
      >
        <AlertDialogOverlay>
          <AlertDialogContent>
            <AlertDialogHeader fontSize="lg" fontWeight="bold">
              {t.blockManagement?.confirmDeleteWhitelist || 'Confirm Delete Whitelist'}
            </AlertDialogHeader>

            <AlertDialogBody>
              {t.blockManagement?.confirmDeleteWhitelistDesc || 'Are you sure you want to delete the following whitelist entry?'}
              <Box mt={2} p={2} bg="gray.100" borderRadius="md">
                <Text fontWeight="bold" fontFamily="mono" fontSize="sm">
                  {deletingWhitelistValue}
                </Text>
                <Badge colorScheme={getCIDRTypeColor(deletingWhitelistValue)} mt={2}>
                  {getCIDRTypeDescription(deletingWhitelistValue)}
                </Badge>
              </Box>
            </AlertDialogBody>

            <AlertDialogFooter>
              <Button ref={cancelRef} onClick={onWhitelistDeleteClose}>
                {t.common.cancel}
              </Button>
              <Button colorScheme="red" onClick={handleWhitelistDelete} ml={3}>
                {t.common.delete}
              </Button>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialogOverlay>
      </AlertDialog>

      {/* 手动封禁模态框 */}
      <Modal isOpen={isOpen} onClose={onClose} size="lg">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>{t.blockManagement?.manualBlock || '+ Manual Block'}</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>{t.blockManagement?.blockType || 'Block Type'}</FormLabel>
                <Select
                  value={blockType}
                  onChange={(e) => setBlockType(e.target.value as 'ip' | 'tls_fingerprint' | 'user_agent')}
                >
                  <option value="ip">{t.blockManagement?.ipAddress || 'IP Address'}</option>
                  <option value="tls_fingerprint">{t.blockManagement?.tlsFingerprint || 'TLS Fingerprint'}</option>
                  <option value="user_agent">User-Agent</option>
                </Select>
              </FormControl>

              <FormControl isRequired>
                <FormLabel>
                  {blockType === 'ip' ? (t.blockManagement?.ipAddress || 'IP Address') : blockType === 'tls_fingerprint' ? (t.blockManagement?.tlsFingerprint || 'TLS Fingerprint') : 'User-Agent'}
                </FormLabel>
                <Input
                  value={blockValue}
                  onChange={(e) => setBlockValue(e.target.value)}
                  placeholder={
                    blockType === 'ip' 
                      ? (t.blockManagement?.ipOrCidrPlaceholder || 'e.g.: 192.168.1.100')
                      : blockType === 'tls_fingerprint'
                      ? (t.blockManagement?.tlsFingerprintPlaceholder || 'Enter TLS fingerprint')
                      : (t.blockManagement?.userAgentPlaceholder || 'Enter User-Agent string')
                  }
                />
              </FormControl>

              <FormControl>
                <FormLabel>{t.blockManagement?.blockDuration || 'Block Duration (hours, 0 for permanent)'}</FormLabel>
                <Input
                  type="number"
                  value={blockDuration}
                  onChange={(e) => setBlockDuration(e.target.value)}
                  min="0"
                  step="0.5"
                  placeholder="24"
                />
              </FormControl>

              <FormControl>
                <FormLabel>{t.blockManagement?.blockReason || 'Block Reason'} ({t.common.optional || 'Optional'})</FormLabel>
                <Input
                  value={blockReason}
                  onChange={(e) => setBlockReason(e.target.value)}
                  placeholder={t.blockManagement?.blockReasonPlaceholder || 'Enter block reason'}
                />
              </FormControl>
            </VStack>
          </ModalBody>

          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onClose}>
              {t.common.cancel}
            </Button>
            <Button colorScheme="blue" onClick={handleBlock}>
              {t.blockManagement?.confirmBlock || 'Confirm Block'}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* 解封确认对话框 */}
      <AlertDialog
        isOpen={isUnblockOpen}
        leastDestructiveRef={cancelRef}
        onClose={onUnblockClose}
      >
        <AlertDialogOverlay>
          <AlertDialogContent>
            <AlertDialogHeader fontSize="lg" fontWeight="bold">
              {t.blockManagement?.confirmUnblock || 'Confirm Unblock'}
            </AlertDialogHeader>

            <AlertDialogBody>
              {t.blockManagement?.confirmUnblockDesc || 'Are you sure you want to unblock the following item?'}
              <Box mt={2} p={2} bg="gray.100" borderRadius="md">
                <Text fontWeight="bold">
                  {unblockType === 'ip' ? (t.blockManagement?.ipAddress || 'IP Address') : unblockType === 'tls_fingerprint' ? (t.blockManagement?.tlsFingerprint || 'TLS Fingerprint') : 'User-Agent'}
                </Text>
                <Text fontFamily={unblockType === 'tls_fingerprint' ? 'mono' : 'inherit'} fontSize="sm">
                  {unblockValue.length > 50 ? `${unblockValue.substring(0, 50)}...` : unblockValue}
                </Text>
              </Box>
            </AlertDialogBody>

            <AlertDialogFooter>
              <Button ref={cancelRef} onClick={onUnblockClose}>
                {t.common.cancel}
              </Button>
              <Button colorScheme="red" onClick={handleUnblock} ml={3}>
                {t.blockManagement?.confirmUnblock || 'Confirm Unblock'}
              </Button>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialogOverlay>
      </AlertDialog>
    </Box>
  )
}

export default BlockManagement


import React, { useState, useEffect } from 'react'
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
} from '@chakra-ui/react'
import {
  FiRefreshCw,
  FiX,
  FiPlus,
  FiTrash2,
} from 'react-icons/fi'
import { apiService } from '../utils/api'
import { useConfig } from '../contexts/ConfigContext'

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

const BlockManagement: React.FC = () => {
  const [loading, setLoading] = useState(false)
  const [blockedData, setBlockedData] = useState<BlockedListData>({
    ips: [],
    tls_fingerprints: [],
    user_agents: [],
  })
  const { isOpen, onOpen, onClose } = useDisclosure()
  const { isOpen: isUnblockOpen, onOpen: onUnblockOpen, onClose: onUnblockClose } = useDisclosure()
  const [activeTab, setActiveTab] = useState(0)
  const [blockType, setBlockType] = useState<'ip' | 'tls_fingerprint' | 'user_agent'>('ip')
  const [blockValue, setBlockValue] = useState('')
  const [blockDuration, setBlockDuration] = useState('24')
  const [blockReason, setBlockReason] = useState('')
  const [unblockType, setUnblockType] = useState<'ip' | 'tls_fingerprint' | 'user_agent'>('ip')
  const [unblockValue, setUnblockValue] = useState('')
  const cancelRef = React.useRef<HTMLButtonElement>(null)
  const toast = useToast()

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

  useEffect(() => {
    fetchBlockedList()
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

  return (
    <Box p={6}>
      <HStack justify="space-between" mb={6}>
        <Heading size="lg">封禁管理</Heading>
        <HStack>
          <Button
            leftIcon={<FiRefreshCw />}
            onClick={fetchBlockedList}
            isLoading={loading}
            loadingText="刷新中"
          >
            刷新
          </Button>
          <Button
            leftIcon={<FiPlus />}
            colorScheme="blue"
            onClick={() => {
              const type = activeTab === 0 ? 'ip' : activeTab === 1 ? 'tls_fingerprint' : 'user_agent'
              openBlockModal(type)
            }}
          >
            手动封禁
          </Button>
        </HStack>
      </HStack>

      <Card>
        <CardBody>
          <Tabs index={activeTab} onChange={setActiveTab}>
            <TabList>
              <Tab>IP封禁 ({blockedData.ips.length})</Tab>
              <Tab>TLS指纹封禁 ({blockedData.tls_fingerprints.length})</Tab>
              <Tab>User-Agent封禁 ({blockedData.user_agents.length})</Tab>
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
                    <Text color="gray.500">暂无封禁的IP</Text>
                  </Center>
                ) : (
                  <Table variant="simple">
                    <Thead>
                      <Tr>
                        <Th>IP地址</Th>
                        <Th>来源</Th>
                        <Th>封禁原因</Th>
                        <Th>封禁时间</Th>
                        <Th>过期时间</Th>
                        <Th>操作</Th>
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
                              aria-label="解封"
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
                    <Text color="gray.500">暂无封禁的TLS指纹</Text>
                  </Center>
                ) : (
                  <Table variant="simple">
                    <Thead>
                      <Tr>
                        <Th>TLS指纹</Th>
                        <Th>封禁原因</Th>
                        <Th>封禁时间</Th>
                        <Th>过期时间</Th>
                        <Th>操作</Th>
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
                              aria-label="解封"
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
                    <Text color="gray.500">暂无封禁的User-Agent</Text>
                  </Center>
                ) : (
                  <Table variant="simple">
                    <Thead>
                      <Tr>
                        <Th>User-Agent</Th>
                        <Th>封禁原因</Th>
                        <Th>封禁时间</Th>
                        <Th>过期时间</Th>
                        <Th>操作</Th>
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
                              aria-label="解封"
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
            </TabPanels>
          </Tabs>
        </CardBody>
      </Card>

      {/* 手动封禁模态框 */}
      <Modal isOpen={isOpen} onClose={onClose} size="lg">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>手动封禁</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>封禁类型</FormLabel>
                <Select
                  value={blockType}
                  onChange={(e) => setBlockType(e.target.value as 'ip' | 'tls_fingerprint' | 'user_agent')}
                >
                  <option value="ip">IP地址</option>
                  <option value="tls_fingerprint">TLS指纹</option>
                  <option value="user_agent">User-Agent</option>
                </Select>
              </FormControl>

              <FormControl isRequired>
                <FormLabel>
                  {blockType === 'ip' ? 'IP地址' : blockType === 'tls_fingerprint' ? 'TLS指纹' : 'User-Agent'}
                </FormLabel>
                <Input
                  value={blockValue}
                  onChange={(e) => setBlockValue(e.target.value)}
                  placeholder={
                    blockType === 'ip' 
                      ? '例如: 192.168.1.100' 
                      : blockType === 'tls_fingerprint'
                      ? '输入TLS指纹'
                      : '输入User-Agent字符串'
                  }
                />
              </FormControl>

              <FormControl>
                <FormLabel>封禁时长（小时，0表示永久）</FormLabel>
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
                <FormLabel>封禁原因（可选）</FormLabel>
                <Input
                  value={blockReason}
                  onChange={(e) => setBlockReason(e.target.value)}
                  placeholder="输入封禁原因"
                />
              </FormControl>
            </VStack>
          </ModalBody>

          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onClose}>
              取消
            </Button>
            <Button colorScheme="blue" onClick={handleBlock}>
              确认封禁
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
              确认解封
            </AlertDialogHeader>

            <AlertDialogBody>
              确定要解封以下项吗？
              <Box mt={2} p={2} bg="gray.100" borderRadius="md">
                <Text fontWeight="bold">
                  {unblockType === 'ip' ? 'IP地址' : unblockType === 'tls_fingerprint' ? 'TLS指纹' : 'User-Agent'}
                </Text>
                <Text fontFamily={unblockType === 'tls_fingerprint' ? 'mono' : 'inherit'} fontSize="sm">
                  {unblockValue.length > 50 ? `${unblockValue.substring(0, 50)}...` : unblockValue}
                </Text>
              </Box>
            </AlertDialogBody>

            <AlertDialogFooter>
              <Button ref={cancelRef} onClick={onUnblockClose}>
                取消
              </Button>
              <Button colorScheme="red" onClick={handleUnblock} ml={3}>
                确认解封
              </Button>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialogOverlay>
      </AlertDialog>
    </Box>
  )
}

export default BlockManagement


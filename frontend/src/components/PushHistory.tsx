import React, { useState, useEffect } from 'react'
import {
  Box,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  IconButton,
  Tooltip,
  Text,
  HStack,
  VStack,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  Button,
  Code,
  Divider,
  useDisclosure,
  useToast,
  Spinner,
  Icon,
  Flex,
} from '@chakra-ui/react'
import {
  FiClock,
  FiGitCommit,
  FiUser,
  FiInfo,
  FiCheckCircle,
  FiXCircle,
  FiAlertCircle,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'

interface PushRecord {
  id: string
  app_name: string
  pusher_key: string
  pusher_name: string
  commit_hash: string
  commit_message: string
  ref_name: string
  status: 'pending' | 'success' | 'failed'
  start_time: string
  end_time: string
  duration: number
  error_message: string
  log_file: string
  push_size: number
  client_ip: string
}

interface PushHistoryProps {
  appName: string
  limit?: number
}

const PushHistory: React.FC<PushHistoryProps> = ({ appName, limit = 50 }) => {
  const { adminPrefix } = useConfig()
  const [pushHistory, setPushHistory] = useState<PushRecord[]>([])
  const [loading, setLoading] = useState(false)
  const [selectedPush, setSelectedPush] = useState<PushRecord | null>(null)
  const { isOpen, onOpen, onClose } = useDisclosure()
  const toast = useToast()

  const fetchPushHistory = async () => {
    setLoading(true)
    try {
      const response = await fetch(
        buildApiPath(adminPrefix, `/git-server/push-history?app=${appName}&limit=${limit}`)
      )
      const data = await response.json()
      if (data.success) {
        setPushHistory(data.data || [])
      } else {
        toast({
          title: '获取推送历史失败',
          description: data.error || '未知错误',
          status: 'error',
          duration: 3000,
        })
      }
    } catch (error) {
      toast({
        title: '网络错误',
        description: '无法获取推送历史',
        status: 'error',
        duration: 3000,
      })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (appName) {
      fetchPushHistory()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [appName, limit])

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'success':
        return <Badge colorScheme="green">成功</Badge>
      case 'failed':
        return <Badge colorScheme="red">失败</Badge>
      case 'pending':
        return <Badge colorScheme="yellow">进行中</Badge>
      default:
        return <Badge>{status}</Badge>
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'success':
        return FiCheckCircle
      case 'failed':
        return FiXCircle
      case 'pending':
        return FiAlertCircle
      default:
        return FiInfo
    }
  }

  const formatDate = (dateStr: string) => {
    if (!dateStr) return '-'
    const date = new Date(dateStr)
    return date.toLocaleString('zh-CN')
  }

  const formatDuration = (ms: number) => {
    if (!ms || ms === 0) return '-'
    const seconds = Math.floor(ms / 1000)
    const minutes = Math.floor(seconds / 60)
    if (minutes > 0) {
      return `${minutes}分${seconds % 60}秒`
    }
    return `${seconds}秒`
  }

  const formatSize = (bytes: number) => {
    if (!bytes || bytes === 0) return '-'
    const kb = bytes / 1024
    const mb = kb / 1024
    if (mb >= 1) {
      return `${mb.toFixed(2)} MB`
    }
    return `${kb.toFixed(2)} KB`
  }

  const handleViewDetails = (push: PushRecord) => {
    setSelectedPush(push)
    onOpen()
  }

  if (loading && pushHistory.length === 0) {
    return (
      <Flex justify="center" align="center" py={8}>
        <Spinner size="lg" />
      </Flex>
    )
  }

  if (pushHistory.length === 0) {
    return (
      <Box textAlign="center" py={8}>
        <Icon as={FiGitCommit} boxSize={12} color="gray.400" mb={4} />
        <Text color="gray.500">暂无推送记录</Text>
      </Box>
    )
  }

  return (
    <>
      <Box overflowX="auto">
        <Table variant="simple">
          <Thead>
            <Tr>
              <Th>时间</Th>
              <Th>提交</Th>
              <Th>分支</Th>
              <Th>状态</Th>
              <Th>耗时</Th>
              <Th>推送者</Th>
              <Th>操作</Th>
            </Tr>
          </Thead>
          <Tbody>
            {pushHistory.map((push) => (
              <Tr key={push.id}>
                <Td>
                  <HStack spacing={2}>
                    <Icon as={FiClock} color="gray.500" />
                    <Text fontSize="sm">{formatDate(push.start_time)}</Text>
                  </HStack>
                </Td>
                <Td>
                  <VStack align="start" spacing={1}>
                    <Code fontSize="xs">{push.commit_hash?.substring(0, 7) || '-'}</Code>
                    <Text fontSize="sm" noOfLines={1} maxW="200px">
                      {push.commit_message || '无提交消息'}
                    </Text>
                  </VStack>
                </Td>
                <Td>
                  <Badge colorScheme="blue">
                    {push.ref_name?.replace('refs/heads/', '') || 'main'}
                  </Badge>
                </Td>
                <Td>{getStatusBadge(push.status)}</Td>
                <Td>
                  <Text fontSize="sm">{formatDuration(push.duration)}</Text>
                </Td>
                <Td>
                  <Tooltip label={push.pusher_key}>
                    <HStack spacing={2}>
                      <Icon as={FiUser} color="gray.500" />
                      <Text fontSize="sm">{push.pusher_name || push.client_ip || '-'}</Text>
                    </HStack>
                  </Tooltip>
                </Td>
                <Td>
                  <IconButton
                    aria-label={t.pushHistory.view_details}
                    icon={<FiInfo />}
                    size="sm"
                    onClick={() => handleViewDetails(push)}
                  />
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      </Box>

      {/* 推送详情模态框 */}
      <Modal isOpen={isOpen} onClose={onClose} size="xl">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>
            <HStack>
              <Icon as={getStatusIcon(selectedPush?.status || '')} />
              <Text>推送详情</Text>
            </HStack>
          </ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            {selectedPush && (
              <VStack align="stretch" spacing={4}>
                <Box>
                  <Text fontWeight="bold" mb={2}>基本信息</Text>
                  <VStack align="stretch" spacing={2} fontSize="sm">
                    <HStack justify="space-between">
                      <Text color="gray.600">推送ID:</Text>
                      <Code>{selectedPush.id}</Code>
                    </HStack>
                    <HStack justify="space-between">
                      <Text color="gray.600">应用名称:</Text>
                      <Text>{selectedPush.app_name}</Text>
                    </HStack>
                    <HStack justify="space-between">
                      <Text color="gray.600">状态:</Text>
                      {getStatusBadge(selectedPush.status)}
                    </HStack>
                    <HStack justify="space-between">
                      <Text color="gray.600">开始时间:</Text>
                      <Text>{formatDate(selectedPush.start_time)}</Text>
                    </HStack>
                    {selectedPush.end_time && (
                      <HStack justify="space-between">
                        <Text color="gray.600">结束时间:</Text>
                        <Text>{formatDate(selectedPush.end_time)}</Text>
                      </HStack>
                    )}
                    <HStack justify="space-between">
                      <Text color="gray.600">耗时:</Text>
                      <Text>{formatDuration(selectedPush.duration)}</Text>
                    </HStack>
                  </VStack>
                </Box>

                <Divider />

                <Box>
                  <Text fontWeight="bold" mb={2}>Git 信息</Text>
                  <VStack align="stretch" spacing={2} fontSize="sm">
                    <HStack justify="space-between">
                      <Text color="gray.600">提交哈希:</Text>
                      <Code>{selectedPush.commit_hash || '-'}</Code>
                    </HStack>
                    <Box>
                      <Text color="gray.600" mb={1}>提交消息:</Text>
                      <Code p={2} borderRadius="md" display="block" whiteSpace="pre-wrap">
                        {selectedPush.commit_message || '无提交消息'}
                      </Code>
                    </Box>
                    <HStack justify="space-between">
                      <Text color="gray.600">分支:</Text>
                      <Badge colorScheme="blue">
                        {selectedPush.ref_name?.replace('refs/heads/', '') || '-'}
                      </Badge>
                    </HStack>
                  </VStack>
                </Box>

                <Divider />

                <Box>
                  <Text fontWeight="bold" mb={2}>推送者信息</Text>
                  <VStack align="stretch" spacing={2} fontSize="sm">
                    <HStack justify="space-between">
                      <Text color="gray.600">客户端IP:</Text>
                      <Text>{selectedPush.client_ip || '-'}</Text>
                    </HStack>
                    <Box>
                      <Text color="gray.600" mb={1}>SSH密钥指纹:</Text>
                      <Code fontSize="xs" display="block" p={2} borderRadius="md">
                        {selectedPush.pusher_key || '-'}
                      </Code>
                    </Box>
                    <HStack justify="space-between">
                      <Text color="gray.600">推送大小:</Text>
                      <Text>{formatSize(selectedPush.push_size)}</Text>
                    </HStack>
                  </VStack>
                </Box>

                {selectedPush.error_message && (
                  <>
                    <Divider />
                    <Box>
                      <Text fontWeight="bold" mb={2} color="red.500">错误信息</Text>
                      <Code
                        p={3}
                        borderRadius="md"
                        display="block"
                        whiteSpace="pre-wrap"
                        colorScheme="red"
                      >
                        {selectedPush.error_message}
                      </Code>
                    </Box>
                  </>
                )}

                {selectedPush.log_file && (
                  <>
                    <Divider />
                    <Box>
                      <Text fontWeight="bold" mb={2}>日志文件</Text>
                      <Code fontSize="xs">{selectedPush.log_file}</Code>
                    </Box>
                  </>
                )}
              </VStack>
            )}
          </ModalBody>
          <ModalFooter>
            <Button onClick={onClose}>关闭</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </>
  )
}

export default PushHistory


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
import { useTranslation } from '../hooks/useLanguage'
import { useErrorHandler } from '../hooks/useErrorHandler'
import { TOAST_DURATION } from '../constants'

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
  const t = useTranslation()
  const { handleError } = useErrorHandler()
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
        handleError(new Error(data.error || t.gitServer.pushHistoryFailed), {
          title: t.gitServer.pushHistoryFailed,
          description: data.error || t.common.unknownError,
        })
      }
    } catch (error) {
      handleError(error, {
        title: t.gitServer.networkError,
        description: t.gitServer.cannotGetPushHistory,
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
        return <Badge colorScheme="green">{t.common.success}</Badge>
      case 'failed':
        return <Badge colorScheme="red">{t.common.failed}</Badge>
      case 'pending':
        return <Badge colorScheme="yellow">{t.common.pending}</Badge>
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
    return date.toLocaleString()
  }

  const formatDuration = (ms: number) => {
    if (!ms || ms === 0) return '-'
    const seconds = Math.floor(ms / 1000)
    const minutes = Math.floor(seconds / 60)
    if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`
    }
    return `${seconds}s`
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
        <Text color="gray.500">{t.gitServer.pushHistory}</Text>
      </Box>
    )
  }

  return (
    <>
      <Box overflowX="auto">
        <Table variant="simple">
          <Thead>
            <Tr>
              <Th>{t.common.time}</Th>
              <Th>{t.gitServer.commits}</Th>
              <Th>{t.gitServer.defaultBranch}</Th>
              <Th>{t.gitServer.status}</Th>
              <Th>{t.common.duration}</Th>
              <Th>{t.common.user}</Th>
              <Th>{t.gitServer.actions}</Th>
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
                      {push.commit_message || '-'}
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
              <Text>{t.pushHistory.view_details}</Text>
            </HStack>
          </ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            {selectedPush && (
              <VStack align="stretch" spacing={4}>
                <Box>
                  <Text fontWeight="bold" mb={2}>{t.pathPrefixRules.basicInfo}</Text>
                  <VStack align="stretch" spacing={2} fontSize="sm">
                    <HStack justify="space-between">
                      <Text color="gray.600">ID:</Text>
                      <Code>{selectedPush.id}</Code>
                    </HStack>
                    <HStack justify="space-between">
                      <Text color="gray.600">{t.gitServer.appName}:</Text>
                      <Text>{selectedPush.app_name}</Text>
                    </HStack>
                    <HStack justify="space-between">
                      <Text color="gray.600">{t.gitServer.status}:</Text>
                      {getStatusBadge(selectedPush.status)}
                    </HStack>
                    <HStack justify="space-between">
                      <Text color="gray.600">{t.common.startTime}:</Text>
                      <Text>{formatDate(selectedPush.start_time)}</Text>
                    </HStack>
                    {selectedPush.end_time && (
                      <HStack justify="space-between">
                        <Text color="gray.600">{t.common.endTime}:</Text>
                        <Text>{formatDate(selectedPush.end_time)}</Text>
                      </HStack>
                    )}
                    <HStack justify="space-between">
                      <Text color="gray.600">{t.common.duration}:</Text>
                      <Text>{formatDuration(selectedPush.duration)}</Text>
                    </HStack>
                  </VStack>
                </Box>

                <Divider />

                <Box>
                  <Text fontWeight="bold" mb={2}>Git {t.common.info}</Text>
                  <VStack align="stretch" spacing={2} fontSize="sm">
                    <HStack justify="space-between">
                      <Text color="gray.600">{t.common.commitHash}:</Text>
                      <Code>{selectedPush.commit_hash || '-'}</Code>
                    </HStack>
                    <Box>
                      <Text color="gray.600" mb={1}>{t.common.commitMessage}:</Text>
                      <Code p={2} borderRadius="md" display="block" whiteSpace="pre-wrap">
                        {selectedPush.commit_message || '-'}
                      </Code>
                    </Box>
                    <HStack justify="space-between">
                      <Text color="gray.600">{t.gitServer.defaultBranch}:</Text>
                      <Badge colorScheme="blue">
                        {selectedPush.ref_name?.replace('refs/heads/', '') || '-'}
                      </Badge>
                    </HStack>
                  </VStack>
                </Box>

                <Divider />

                <Box>
                  <Text fontWeight="bold" mb={2}>{t.common.pusherInfo}</Text>
                  <VStack align="stretch" spacing={2} fontSize="sm">
                    <HStack justify="space-between">
                      <Text color="gray.600">{t.statistics.ipAddress}:</Text>
                      <Text>{selectedPush.client_ip || '-'}</Text>
                    </HStack>
                    <Box>
                      <Text color="gray.600" mb={1}>{t.gitServer.fingerprint}:</Text>
                      <Code fontSize="xs" display="block" p={2} borderRadius="md">
                        {selectedPush.pusher_key || '-'}
                      </Code>
                    </Box>
                    <HStack justify="space-between">
                      <Text color="gray.600">{t.common.pushSize}:</Text>
                      <Text>{formatSize(selectedPush.push_size)}</Text>
                    </HStack>
                  </VStack>
                </Box>

                {selectedPush.error_message && (
                  <>
                    <Divider />
                    <Box>
                      <Text fontWeight="bold" mb={2} color="red.500">{t.common.error}</Text>
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
                      <Text fontWeight="bold" mb={2}>{t.tunnels.logFile}</Text>
                      <Code fontSize="xs">{selectedPush.log_file}</Code>
                    </Box>
                  </>
                )}
              </VStack>
            )}
          </ModalBody>
          <ModalFooter>
            <Button onClick={onClose}>{t.common.close}</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </>
  )
}

export default PushHistory


import React, { useState, useEffect } from 'react'
import {
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  Button,
  VStack,
  HStack,
  Text,
  Badge,
  Box,
  Spinner,
  Icon,
  IconButton,
  useDisclosure,
  Divider,
} from '@chakra-ui/react'
import { FiClock, FiPlay, FiCheckCircle, FiXCircle, FiLoader, FiTerminal } from 'react-icons/fi'
import { useConfig, buildApiPath } from '../../contexts/ConfigContext'
import { useTranslation } from '../../hooks/useLanguage'

interface Deployment {
  id: string
  status: 'success' | 'failed' | 'running' | 'pending'
  created_at: string
  commit_sha: string
  commit_message: string
  commit_author: string
  started_at?: string
  completed_at?: string
  error?: string
}

interface DeployHistoryDialogProps {
  isOpen: boolean
  onClose: () => void
  appName: string
  onOpenLogs: (appName: string, deploymentId: string) => void
}

const DeployHistoryDialog: React.FC<DeployHistoryDialogProps> = ({
  isOpen,
  onClose,
  appName,
  onOpenLogs,
}) => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  const [deployments, setDeployments] = useState<Deployment[]>([])
  const [loading, setLoading] = useState(false)
  const [selectedDeployment, setSelectedDeployment] = useState<Deployment | null>(null)

  // 加载部署历史
  const loadDeployments = async () => {
    setLoading(true)
    try {
      const response = await fetch(
        buildApiPath(adminPrefix, `/api/git-server/deployments?app=${encodeURIComponent(appName)}`),
        {
          headers: {
            'Content-Type': 'application/json',
          },
        }
      )

      if (response.ok) {
        const data = await response.json()
        setDeployments(data.data || [])
      }
    } catch (error) {
      console.error('Failed to load deployments:', error)
    } finally {
      setLoading(false)
    }
  }

  // 当 modal 打开时加载数据
  useEffect(() => {
    if (isOpen && appName) {
      loadDeployments()
    }
  }, [isOpen, appName])

  // 获取状态颜色
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'success':
        return 'green'
      case 'failed':
        return 'red'
      case 'running':
        return 'blue'
      case 'pending':
        return 'yellow'
      default:
        return 'gray'
    }
  }

  // 获取状态图标
  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'success':
        return FiCheckCircle
      case 'failed':
        return FiXCircle
      case 'running':
        return FiLoader
      case 'pending':
        return FiClock
      default:
        return FiClock
    }
  }

  // 获取状态文本
  const getStatusText = (status: string) => {
    switch (status) {
      case 'success':
        return t.gitServer.statusSuccess || '成功'
      case 'failed':
        return t.gitServer.statusFailed || '失败'
      case 'running':
        return t.gitServer.statusRunning || '运行中'
      case 'pending':
        return t.gitServer.statusPending || '等待中'
      default:
        return status
    }
  }

  // 格式化时间
  const formatTime = (dateString: string) => {
    if (!dateString) return '-'
    const date = new Date(dateString)
    return date.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  // 查看日志
  const handleViewLogs = (deployment: Deployment) => {
    setSelectedDeployment(deployment)
    onOpenLogs(appName, deployment.id)
    onClose()
  }

  // 查看最新部署的日志
  const handleViewLatestLogs = () => {
    const latestDeployment = deployments[0]
    if (latestDeployment) {
      handleViewLogs(latestDeployment)
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} size="xl" scrollBehavior="inside">
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>
          <HStack>
            <Icon as={FiClock} />
            <Text>{t.gitServer.deployHistory || '部署历史'} - {appName}</Text>
          </HStack>
        </ModalHeader>
        <ModalCloseButton />

        <ModalBody>
          {loading ? (
            <HStack justify="center" py={8}>
              <Spinner />
              <Text>{t.common.loading || '加载中...'}</Text>
            </HStack>
          ) : deployments.length === 0 ? (
            <Box textAlign="center" py={8}>
              <Text color="gray.500">{t.gitServer.noDeployments || '暂无部署记录'}</Text>
            </Box>
          ) : (
            <VStack align="stretch" spacing={3}>
              {deployments.length > 0 && (
                <Button
                  leftIcon={<Icon as={FiTerminal} />}
                  colorScheme="blue"
                  size="sm"
                  onClick={handleViewLatestLogs}
                  alignSelf="flex-start"
                >
                  {t.gitServer.viewLatestLogs || '查看最新部署日志'}
                </Button>
              )}

              <Divider />

              {deployments.map((deployment, index) => (
                <Box
                  key={deployment.id}
                  p={4}
                  borderWidth="1px"
                  borderRadius="md"
                  _hover={{ bg: 'gray.50', shadow: 'md' }}
                  transition="all 0.2s"
                >
                  <HStack justify="space-between" mb={2}>
                    <HStack spacing={2}>
                      {index === 0 && (
                        <Badge colorScheme="blue" fontSize="xs">
                          {t.gitServer.latest || '最新'}
                        </Badge>
                      )}
                      <Badge colorScheme={getStatusColor(deployment.status)}>
                        <HStack spacing={1}>
                          <Icon as={getStatusIcon(deployment.status)} />
                          <Text>{getStatusText(deployment.status)}</Text>
                        </HStack>
                      </Badge>
                    </HStack>
                    <Text fontSize="xs" color="gray.500">
                      {formatTime(deployment.created_at)}
                    </Text>
                  </HStack>

                  <VStack align="start" spacing={1} mb={2}>
                    <HStack>
                      <Text fontSize="sm" fontWeight="bold">
                        {deployment.commit_sha.substring(0, 7)}
                      </Text>
                      <Text fontSize="sm" color="gray.600">
                        {deployment.commit_message}
                      </Text>
                    </HStack>
                    <Text fontSize="xs" color="gray.500">
                      {t.gitServer.author || '作者'}: {deployment.commit_author}
                    </Text>
                    {deployment.error && (
                      <Text fontSize="xs" color="red.500">
                        {t.gitServer.error || '错误'}: {deployment.error}
                      </Text>
                    )}
                  </VStack>

                  <HStack spacing={2}>
                    <Button
                      size="xs"
                      leftIcon={<Icon as={FiTerminal} />}
                      colorScheme="blue"
                      variant="outline"
                      onClick={() => handleViewLogs(deployment)}
                    >
                      {t.gitServer.viewLogs || '查看日志'}
                    </Button>
                  </HStack>
                </Box>
              ))}
            </VStack>
          )}
        </ModalBody>

        <ModalFooter>
          <Button onClick={onClose}>{t.common.close || '关闭'}</Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  )
}

export default DeployHistoryDialog

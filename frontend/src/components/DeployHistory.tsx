import React, { useState, useEffect } from 'react'
import {
  Box,
  VStack,
  HStack,
  Text,
  Badge,
  Button,
  Icon,
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
  useDisclosure,
  Alert,
  AlertIcon,
  Code,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  SimpleGrid,
  Card,
  CardBody,
  CardHeader,
  Heading,
  Tooltip,
  Progress,
} from '@chakra-ui/react'
import {
  FiClock,
  FiRefreshCw,
  FiRotateCcw,
  FiEye,
  FiGitCommit,
  FiCheckCircle,
  FiXCircle,
  FiLoader,
  FiAlertTriangle,
  FiActivity,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import RealtimeLogs from './RealtimeLogs'
import { useTranslation } from '../hooks/useLanguage'

interface DeployRecord {
  id: string
  timestamp: string
  status: string
  commit_hash: string
  commit_message: string
  duration: number
  logs?: string[]
  error?: string
  deploy_type: string
  image_name?: string
}

interface DeployStats {
  total_deploys: number
  successful_deploys: number
  failed_deploys: number
  average_duration: number
  last_deploy_time: string
  success_rate: number
}

interface DeployHistoryProps {
  appName: string
}

const DeployHistory: React.FC<DeployHistoryProps> = ({ appName }) => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  const [deployHistory, setDeployHistory] = useState<DeployRecord[]>([])
  const [deployStats, setDeployStats] = useState<DeployStats | null>(null)
  const [selectedDeploy, setSelectedDeploy] = useState<DeployRecord | null>(null)
  const [loading, setLoading] = useState(false)
  const [rollbackLoading, setRollbackLoading] = useState('')
  const toast = useToast()
  
  const { 
    isOpen: isLogsOpen, 
    onOpen: onLogsOpen, 
    onClose: onLogsClose 
  } = useDisclosure()

  // 加载部署历史
  const loadDeployHistory = async () => {
    setLoading(true)
    try {
      const response = await fetch(
        buildApiPath(adminPrefix, `/api/git-server/deploy/history?app=${appName}`),
        { credentials: 'include' }
      )
      
      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          setDeployHistory(data.data || [])
          setDeployStats(data.stats)
        }
      }
    } catch (error) {
      console.error('Failed to load deploy history:', error)
      toast({
        title: '加载失败',
        description: '无法加载部署历史',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  // 回滚到指定版本
  const rollbackToDeploy = async (deployId: string) => {
    setRollbackLoading(deployId)
    try {
      const response = await fetch(
        buildApiPath(adminPrefix, '/api/git-server/deploy/rollback'),
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            app_name: appName,
            deploy_id: deployId,
          }),
        }
      )
      
      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          toast({
            title: '回滚成功',
            description: `应用已回滚到部署版本 ${deployId.slice(-8)}`,
            status: 'success',
            duration: 3000,
            isClosable: true,
          })
          
          // 重新加载部署历史
          setTimeout(() => {
            loadDeployHistory()
          }, 1000)
        }
      }
    } catch (error) {
      console.error('Failed to rollback:', error)
      toast({
        title: '回滚失败',
        description: '无法回滚到指定版本',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setRollbackLoading('')
    }
  }

  // 查看部署日志
  const viewDeployLogs = (deploy: DeployRecord) => {
    setSelectedDeploy(deploy)
    onLogsOpen()
  }

  // 获取状态颜色
  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'success': return 'green'
      case 'failed': return 'red'
      case 'building': return 'yellow'
      case 'deploying': return 'blue'
      default: return 'gray'
    }
  }

  // 获取状态图标
  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'success': return FiCheckCircle
      case 'failed': return FiXCircle
      case 'building': 
      case 'deploying': return FiLoader
      default: return FiAlertTriangle
    }
  }

  // 格式化持续时间
  const formatDuration = (ms: number) => {
    if (ms < 1000) return `${ms}ms`
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
    return `${(ms / 60000).toFixed(1)}m`
  }

  // 格式化时间
  const formatTime = (timeStr: string) => {
    const date = new Date(timeStr)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    
    if (diffMs < 60000) return '刚刚'
    if (diffMs < 3600000) return `${Math.floor(diffMs / 60000)}分钟前`
    if (diffMs < 86400000) return `${Math.floor(diffMs / 3600000)}小时前`
    return date.toLocaleDateString()
  }

  useEffect(() => {
    loadDeployHistory()
    
    // 定期刷新部署历史
    const interval = setInterval(loadDeployHistory, 30000)
    return () => clearInterval(interval)
  }, [appName])

  return (
    <Box>
      {/* 部署统计 */}
      {deployStats && (
        <Card mb={6}>
          <CardHeader>
            <Heading size="md" display="flex" alignItems="center">
              <Icon as={FiActivity} mr={2} />
              部署统计
            </Heading>
          </CardHeader>
          <CardBody>
            <SimpleGrid columns={{ base: 2, md: 4 }} spacing={4}>
              <Stat>
                <StatLabel>总部署次数</StatLabel>
                <StatNumber>{deployStats.total_deploys}</StatNumber>
                <StatHelpText>
                  成功: {deployStats.successful_deploys} | 
                  失败: {deployStats.failed_deploys}
                </StatHelpText>
              </Stat>

              <Stat>
                <StatLabel>成功率</StatLabel>
                <StatNumber color={deployStats.success_rate > 80 ? 'green.500' : 'red.500'}>
                  {deployStats.success_rate.toFixed(1)}%
                </StatNumber>
                <StatHelpText>
                  <Progress 
                    value={deployStats.success_rate} 
                    size="sm" 
                    colorScheme={deployStats.success_rate > 80 ? 'green' : 'red'}
                  />
                </StatHelpText>
              </Stat>

              <Stat>
                <StatLabel>平均耗时</StatLabel>
                <StatNumber>{formatDuration(deployStats.average_duration)}</StatNumber>
                <StatHelpText>构建和部署时间</StatHelpText>
              </Stat>

              <Stat>
                <StatLabel>最后部署</StatLabel>
                <StatNumber fontSize="md">
                  {formatTime(deployStats.last_deploy_time)}
                </StatNumber>
                <StatHelpText>
                  {new Date(deployStats.last_deploy_time).toLocaleString()}
                </StatHelpText>
              </Stat>
            </SimpleGrid>
          </CardBody>
        </Card>
      )}

      {/* 部署历史列表 */}
      <Card>
        <CardHeader>
          <HStack justify="space-between">
            <Heading size="md" display="flex" alignItems="center">
              <Icon as={FiClock} mr={2} />
              部署历史 ({deployHistory.length})
            </Heading>
            <Button
              size="sm"
              leftIcon={<Icon as={FiRefreshCw} />}
              onClick={loadDeployHistory}
              isLoading={loading}
            >
              刷新
            </Button>
          </HStack>
        </CardHeader>
        <CardBody>
          {deployHistory.length === 0 ? (
            <Alert status="info">
              <AlertIcon />
              <VStack align="start">
                <Text>暂无部署历史</Text>
                <Text fontSize="sm">
                  推送代码到Git仓库时会自动记录部署历史
                </Text>
              </VStack>
            </Alert>
          ) : (
            <Table variant="simple" size="sm">
              <Thead>
                <Tr>
                  <Th>部署ID</Th>
                  <Th>状态</Th>
                  <Th>提交</Th>
                  <Th>类型</Th>
                  <Th>耗时</Th>
                  <Th>时间</Th>
                  <Th>操作</Th>
                </Tr>
              </Thead>
              <Tbody>
                {deployHistory.map((deploy, index) => (
                  <Tr key={deploy.id}>
                    <Td>
                      <Code fontSize="xs">
                        {deploy.id.slice(-8)}
                      </Code>
                    </Td>
                    <Td>
                      <Badge
                        colorScheme={getStatusColor(deploy.status)}
                        display="flex"
                        alignItems="center"
                        maxW="fit-content"
                      >
                        <Icon as={getStatusIcon(deploy.status)} mr={1} />
                        {deploy.status}
                      </Badge>
                    </Td>
                    <Td>
                      <VStack align="start" spacing={1}>
                        <Code fontSize="xs">
                          {deploy.commit_hash.slice(0, 8)}
                        </Code>
                        <Text fontSize="xs" color="gray.600" noOfLines={1}>
                          {deploy.commit_message}
                        </Text>
                      </VStack>
                    </Td>
                    <Td>
                      <Badge variant="outline" fontSize="xs">
                        {deploy.deploy_type}
                      </Badge>
                    </Td>
                    <Td>{formatDuration(deploy.duration)}</Td>
                    <Td>
                      <Tooltip label={new Date(deploy.timestamp).toLocaleString()}>
                        <Text fontSize="sm">
                          {formatTime(deploy.timestamp)}
                        </Text>
                      </Tooltip>
                    </Td>
                    <Td>
                      <HStack spacing={1}>
                        <Tooltip label={t.deployHistory.view_logs}>
                          <IconButton
                            aria-label={t.deployHistory.view_logs}
                            icon={<Icon as={FiEye} />}
                            size="sm"
                            variant="ghost"
                            onClick={() => viewDeployLogs(deploy)}
                          />
                        </Tooltip>
                        
                        {deploy.status === 'success' && index > 0 && (
                          <Tooltip label={t.deployHistory.rollback}>
                            <IconButton
                              aria-label={t.deployHistory.rollback}
                              icon={<Icon as={FiRotateCcw} />}
                              size="sm"
                              colorScheme="orange"
                              variant="ghost"
                              isLoading={rollbackLoading === deploy.id}
                              onClick={() => rollbackToDeploy(deploy.id)}
                            />
                          </Tooltip>
                        )}
                      </HStack>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          )}
        </CardBody>
      </Card>

      {/* 部署日志查看弹窗 */}
      <Modal isOpen={isLogsOpen} onClose={onLogsClose} size="6xl">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>
            部署日志 - {selectedDeploy?.id.slice(-8)}
            {selectedDeploy && (
              <HStack ml={4} spacing={2}>
                <Badge colorScheme={getStatusColor(selectedDeploy.status)}>
                  {selectedDeploy.status}
                </Badge>
                <Code fontSize="sm">
                  {selectedDeploy.commit_hash.slice(0, 8)}
                </Code>
                <Text fontSize="sm" color="gray.600">
                  {formatTime(selectedDeploy.timestamp)}
                </Text>
              </HStack>
            )}
          </ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            {selectedDeploy && (
              <VStack spacing={4} align="stretch">
                {/* 部署信息 */}
                <SimpleGrid columns={{ base: 2, md: 4 }} spacing={4}>
                  <Stat size="sm">
                    <StatLabel>部署类型</StatLabel>
                    <StatNumber fontSize="md">{selectedDeploy.deploy_type}</StatNumber>
                  </Stat>
                  
                  <Stat size="sm">
                    <StatLabel>耗时</StatLabel>
                    <StatNumber fontSize="md">{formatDuration(selectedDeploy.duration)}</StatNumber>
                  </Stat>
                  
                  <Stat size="sm">
                    <StatLabel>提交消息</StatLabel>
                    <StatNumber fontSize="sm" noOfLines={2}>
                      {selectedDeploy.commit_message}
                    </StatNumber>
                  </Stat>
                  
                  {selectedDeploy.image_name && (
                    <Stat size="sm">
                      <StatLabel>Docker镜像</StatLabel>
                      <StatNumber fontSize="sm" noOfLines={2}>
                        {selectedDeploy.image_name}
                      </StatNumber>
                    </Stat>
                  )}
                </SimpleGrid>

                {/* 错误信息 */}
                {selectedDeploy.error && (
                  <Alert status="error">
                    <AlertIcon />
                    <VStack align="start" spacing={1}>
                      <Text fontWeight="medium">部署失败原因</Text>
                      <Code fontSize="sm" colorScheme="red">
                        {selectedDeploy.error}
                      </Code>
                    </VStack>
                  </Alert>
                )}

                {/* 实时日志组件 */}
                <Box>
                  <Text fontWeight="medium" mb={2}>部署日志</Text>
                  <RealtimeLogs 
                    appName={appName} 
                    autoScroll={true}
                    maxLines={200}
                    showControls={false}
                  />
                </Box>
              </VStack>
            )}
          </ModalBody>

          <ModalFooter>
            {selectedDeploy?.status === 'success' && (
              <Button
                colorScheme="orange"
                leftIcon={<Icon as={FiRotateCcw} />}
                onClick={() => {
                  if (selectedDeploy) {
                    rollbackToDeploy(selectedDeploy.id)
                    onLogsClose()
                  }
                }}
                isLoading={rollbackLoading === selectedDeploy.id}
                mr={3}
              >
                回滚到此版本
              </Button>
            )}
            <Button variant="ghost" onClick={onLogsClose}>
              关闭
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default DeployHistory

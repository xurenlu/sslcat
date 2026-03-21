import React, { useState, useCallback, useEffect, useRef } from 'react'
import {
  Box,
  Card,
  CardBody,
  VStack,
  HStack,
  Text,
  Badge,
  Button,
  Icon,
  IconButton,
  Flex,
  Divider,
  useColorModeValue,
  Collapse,
  Code,
  Tooltip,
  Spinner,
  Progress,
} from '@chakra-ui/react'
import {
  FiGithub,
  FiUpload,
  FiTrash2,
  FiSettings,
  FiSliders,
  FiGlobe,
  FiChevronDown,
  FiChevronUp,
  FiActivity,
  FiClock,
  FiTerminal,
  FiCheckCircle,
  FiXCircle,
  FiLoader,
  FiExternalLink,
} from 'react-icons/fi'
import { useTranslation } from '../../hooks/useLanguage'
import { GitApp } from './types'
import { TOAST_DURATION } from '../../constants'
import RealtimeLogsDialog from './RealtimeLogsDialog'

interface DeployRecord {
  id: string
  timestamp: string
  status: string
  commit_hash: string
  commit_message: string
  duration: number
}

interface LogEntry {
  timestamp: string
  level: string
  message: string
}

interface AppCardProps {
  app: GitApp
  onDeploy: (appName: string) => void
  onDelete: (app: GitApp) => void
  onOpenEnvModal: (app: GitApp) => void
  onOpenRoutingModal: (app: GitApp) => void
}

const AppCard: React.FC<AppCardProps> = ({
  app,
  onDeploy,
  onDelete,
  onOpenEnvModal,
  onOpenRoutingModal,
}) => {
  const t = useTranslation()
  const [isDeployHistoryExpanded, setIsDeployHistoryExpanded] = useState(false)
  const [isLogsExpanded, setIsLogsExpanded] = useState(false)
  const [isDeploying, setIsDeploying] = useState(false)
  const [deployHistory, setDeployHistory] = useState<DeployRecord[]>([])
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [showLogsDialog, setShowLogsDialog] = useState(false)
  const logsEndRef = useRef<HTMLDivElement>(null)

  // Apple 风格配色
  const cardBg = useColorModeValue('rgba(255, 255, 255, 0.9)', 'rgba(26, 32, 44, 0.9)')
  const borderColor = useColorModeValue('rgba(0, 0, 0, 0.08)', 'rgba(255, 255, 255, 0.08)')
  const hoverShadow = '0 8px 30px rgba(0, 0, 0, 0.12)'
  const normalShadow = '0 2px 8px rgba(0, 0, 0, 0.06)'

  // 状态样式 - 兼容后端返回的状态值
  const getStatusConfig = (status: string) => {
    // 后端状态: running, building, deploying, failed, idle
    // 前端需要兼容映射
    switch (status) {
      case 'active':
      case 'running':
        return {
          color: 'green.500',
          bg: 'green.50',
          icon: FiCheckCircle,
          text: t.gitServer.statusActive || '运行中',
        }
      case 'deploying':
      case 'building':
        return {
          color: 'blue.500',
          bg: 'blue.50',
          icon: FiLoader,
          text: t.gitServer.statusDeploying || '部署中',
        }
      case 'inactive':
      case 'idle':
        return {
          color: 'gray.500',
          bg: 'gray.50',
          icon: FiClock,
          text: t.gitServer.statusInactive || '未部署',
        }
      case 'error':
      case 'failed':
        return {
          color: 'red.500',
          bg: 'red.50',
          icon: FiXCircle,
          text: t.gitServer.statusError || '错误',
        }
      default:
        return {
          color: 'gray.500',
          bg: 'gray.50',
          icon: FiClock,
          text: status,
        }
    }
  }

  // 加载部署历史
  const loadDeployHistory = useCallback(async () => {
    try {
      console.log('[AppCard] Loading deploy history for app:', app.name)
      const response = await fetch(`/admin/api/git-server/deploy/history?app=${encodeURIComponent(app.name)}`, {
        credentials: 'include',
      })
      console.log('[AppCard] Deploy history response status:', response.status)

      if (response.ok) {
        const data = await response.json()
        console.log('[AppCard] Deploy history response data:', data)
        if (data.success) {
          const history = data.data || []
          console.log('[AppCard] Deploy history loaded:', history.length, 'records')
          setDeployHistory(history)
        } else {
          console.warn('[AppCard] Deploy history API returned success=false:', data.message)
        }
      } else {
        console.error('[AppCard] Deploy history API error:', response.status, response.statusText)
        const errorData = await response.json().catch(() => ({ message: 'Unknown error' }))
        console.error('[AppCard] Error data:', errorData)
      }
    } catch (error) {
      console.error('[AppCard] Failed to load deploy history:', error)
    }
  }, [app.name])

  // 加载实时日志
  const loadLogs = useCallback(async () => {
    try {
      console.log('[AppCard] Loading logs for app:', app.name)
      const response = await fetch(`/admin/api/git-server/logs/stream?app=${encodeURIComponent(app.name)}&lines=20`, {
        credentials: 'include',
      })
      console.log('[AppCard] Logs response status:', response.status)

      if (response.ok) {
        const data = await response.json()
        console.log('[AppCard] Logs response data:', data)
        if (data.success) {
          const logData = data.data || []
          console.log('[AppCard] Logs loaded:', logData.length, 'entries')
          setLogs(logData)
          // 自动滚动到底部
          setTimeout(() => {
            logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
          }, 100)
        } else {
          console.warn('[AppCard] Logs API returned success=false:', data.message)
        }
      } else {
        console.error('[AppCard] Logs API error:', response.status, response.statusText)
        const errorData = await response.json().catch(() => ({ message: 'Unknown error' }))
        console.error('[AppCard] Error data:', errorData)
      }
    } catch (error) {
      console.error('[AppCard] Failed to load logs:', error)
    }
  }, [app.name])

  // 处理部署
  const handleDeploy = async () => {
    setIsDeploying(true)
    try {
      await onDeploy(app.name)
      // 部署后刷新数据
      setTimeout(() => {
        loadDeployHistory()
        loadLogs()
      }, 2000)
    } finally {
      setTimeout(() => setIsDeploying(false), 3000)
    }
  }

  // 初始加载数据
  useEffect(() => {
    loadDeployHistory()
    loadLogs()

    // 设置定时刷新日志
    const logInterval = setInterval(() => {
      if (isLogsExpanded) {
        loadLogs()
      }
    }, 3000)

    return () => clearInterval(logInterval)
  }, [loadDeployHistory, loadLogs, isLogsExpanded])

  const statusConfig = getStatusConfig(app.status)
  const StatusIcon = statusConfig.icon

  // 格式化时间
  const formatTime = (timeStr: string) => {
    const date = new Date(timeStr)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()

    if (diffMs < 60000) return '刚刚'
    if (diffMs < 3600000) return `${Math.floor(diffMs / 60000)} 分钟前`
    if (diffMs < 86400000) return `${Math.floor(diffMs / 3600000)} 小时前`
    return date.toLocaleDateString()
  }

  // 格式化持续时间
  const formatDuration = (ms: number) => {
    if (ms < 1000) return `${ms}ms`
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
    return `${(ms / 60000).toFixed(1)}m`
  }

  return (
    <Card
      bg={cardBg}
      borderWidth="1px"
      borderColor={borderColor}
      borderRadius="16px"
      boxShadow={normalShadow}
      transition="all 0.3s cubic-bezier(0.4, 0, 0.2, 1)"
      _hover={{
        boxShadow: hoverShadow,
        transform: 'translateY(-2px)',
      }}
      backdropFilter="blur(10px)"
      overflow="hidden"
    >
      <CardBody p={6}>
        <VStack spacing={4} align="stretch">
          {/* 头部：应用名称和状态 */}
          <Flex justify="space-between" align="flex-start">
            <VStack align="start" spacing={2}>
              <HStack spacing={3}>
                <Icon as={FiGithub} boxSize={6} color="blue.500" />
                <Text fontSize="xl" fontWeight="700" color="gray.800">
                  {app.name}
                </Text>
                <Badge
                  bg={statusConfig.bg}
                  color={statusConfig.color}
                  px={3}
                  py={1}
                  borderRadius="full"
                  fontWeight="600"
                  display="flex"
                  alignItems="center"
                  gap={1}
                >
                  <Icon as={StatusIcon} boxSize={3} />
                  {statusConfig.text}
                </Badge>
              </HStack>

              {app.domain && (
                <HStack spacing={2} pl={9}>
                  <Icon as={FiGlobe} boxSize={3} color="gray.400" />
                  <Text fontSize="sm" color="gray.600">
                    {app.domain}
                  </Text>
                  {app.autoSSL && (
                    <Badge size="sm" colorScheme="green" variant="subtle">
                      SSL
                    </Badge>
                  )}
                </HStack>
              )}

              <HStack spacing={4} pl={9}>
                {app.port && (
                  <Text fontSize="xs" color="gray.500">
                    端口: {app.port}
                  </Text>
                )}
                {app.lastDeploy && (
                  <Text fontSize="xs" color="gray.500">
                    最后部署: {formatTime(app.lastDeploy)}
                  </Text>
                )}
              </HStack>
            </VStack>

            {/* 快速操作按钮 */}
            <HStack spacing={2}>
              <Tooltip label="环境变量">
                <IconButton
                  aria-label="环境变量"
                  icon={<Icon as={FiSliders} />}
                  size="sm"
                  variant="ghost"
                  colorScheme="blue"
                  onClick={() => onOpenEnvModal(app)}
                />
              </Tooltip>
              <Tooltip label="路由配置">
                <IconButton
                  aria-label="路由配置"
                  icon={<Icon as={FiGlobe} />}
                  size="sm"
                  variant="ghost"
                  colorScheme="purple"
                  onClick={() => onOpenRoutingModal(app)}
                />
              </Tooltip>
              <Tooltip label="删除应用">
                <IconButton
                  aria-label="删除应用"
                  icon={<Icon as={FiTrash2} />}
                  size="sm"
                  variant="ghost"
                  colorScheme="red"
                  onClick={() => onDelete(app)}
                />
              </Tooltip>
            </HStack>
          </Flex>

          <Divider borderColor="gray.200" />

          {/* 部署历史 - 可折叠 */}
          <Box>
            <Flex
              justify="space-between"
              align="center"
              cursor="pointer"
              onClick={() => setIsDeployHistoryExpanded(!isDeployHistoryExpanded)}
              py={2}
            >
              <HStack spacing={2} color="gray.700">
                <Icon as={FiClock} boxSize={4} />
                <Text fontWeight="600" fontSize="sm">
                  最近部署
                </Text>
                {deployHistory.length > 0 && (
                  <Badge size="sm" colorScheme="gray" variant="subtle">
                    {deployHistory.length}
                  </Badge>
                )}
              </HStack>
              <Icon
                as={isDeployHistoryExpanded ? FiChevronUp : FiChevronDown}
                boxSize={4}
                color="gray.400"
              />
            </Flex>

            <Collapse in={isDeployHistoryExpanded} animateOpacity>
              <Box mt={3}>
                {deployHistory.length === 0 ? (
                  <Text fontSize="sm" color="gray.400" textAlign="center" py={4}>
                    暂无部署记录
                  </Text>
                ) : (
                  <VStack spacing={2} align="stretch">
                    {deployHistory.slice(0, 5).map((deploy) => {
                      const isSuccess = deploy.status === 'success'
                      const DeployStatusIcon = isSuccess ? FiCheckCircle : FiXCircle

                      return (
                        <HStack
                          key={deploy.id}
                          p={3}
                          bg="gray.50"
                          borderRadius="8px"
                          fontSize="sm"
                          _hover={{ bg: 'gray.100' }}
                          transition="background 0.2s"
                        >
                          <Icon
                            as={DeployStatusIcon}
                            boxSize={4}
                            color={isSuccess ? 'green.500' : 'red.500'}
                          />
                          <Code fontSize="xs" bg="white" px={2} py={0.5} borderRadius="4">
                            {deploy.commit_hash.slice(0, 8)}
                          </Code>
                          <Text flex={1} noOfLines={1} color="gray.700">
                            {deploy.commit_message || '无消息'}
                          </Text>
                          <Text fontSize="xs" color="gray.500">
                            {formatTime(deploy.timestamp)}
                          </Text>
                          <Badge size="sm" colorScheme={isSuccess ? 'green' : 'red'} variant="subtle">
                            {formatDuration(deploy.duration)}
                          </Badge>
                        </HStack>
                      )
                    })}
                  </VStack>
                )}
              </Box>
            </Collapse>
          </Box>

          <Divider borderColor="gray.200" />

          {/* 实时日志 - 可折叠，可点击展开到对话框 */}
          <Box>
            <Flex
              justify="space-between"
              align="center"
              py={2}
            >
              <HStack
                spacing={2}
                color="gray.700"
                cursor="pointer"
                onClick={() => setIsLogsExpanded(!isLogsExpanded)}
                flex={1}
              >
                <Icon as={FiTerminal} boxSize={4} />
                <Text fontWeight="600" fontSize="sm">
                  实时日志
                </Text>
                {app.status === 'deploying' && (
                  <Spinner size="xs" color="blue.500" />
                )}
                <Icon
                  as={isLogsExpanded ? FiChevronUp : FiChevronDown}
                  boxSize={4}
                  color="gray.400"
                />
              </HStack>

              {/* 展开到全屏对话框按钮 */}
              <Tooltip label="在对话框中查看实时日志">
                <IconButton
                  aria-label="展开实时日志"
                  icon={<Icon as={FiExternalLink} />}
                  size="xs"
                  variant="ghost"
                  colorScheme="blue"
                  onClick={() => setShowLogsDialog(true)}
                />
              </Tooltip>
            </Flex>

            <Collapse in={isLogsExpanded} animateOpacity>
              <Box
                mt={3}
                bg="gray.900"
                borderRadius="8px"
                p={4}
                maxH="300px"
                overflowY="auto"
                fontFamily="mono"
                fontSize="xs"
                cursor="pointer"
                onClick={() => setShowLogsDialog(true)}
                title="点击展开到全屏查看"
              >
                {logs.length === 0 ? (
                  <Text color="gray.500">等待日志...（点击展开查看更多）</Text>
                ) : (
                  <VStack spacing={1} align="stretch">
                    {logs.slice(-10).map((log, index) => (
                      <Text key={index} color={getLogColor(log.level)} wordBreak="break-all">
                        {log.timestamp} {log.message}
                      </Text>
                    ))}
                    {logs.length > 10 && (
                      <Text color="gray.500" fontSize="xs" textAlign="center">
                        ...还有 {logs.length - 10} 条日志，点击展开查看全部...
                      </Text>
                    )}
                    <div ref={logsEndRef} />
                  </VStack>
                )}
              </Box>
            </Collapse>
          </Box>

          <Divider borderColor="gray.200" />

          {/* 底部操作栏 */}
          <HStack spacing={3} justify="flex-end">
            <Button
              size="sm"
              leftIcon={<Icon as={FiSettings} />}
              variant="outline"
              colorScheme="gray"
              onClick={() => onOpenRoutingModal(app)}
            >
              配置
            </Button>
            <Button
              size="sm"
              leftIcon={<Icon as={FiActivity} />}
              variant="outline"
              colorScheme="blue"
              onClick={() => onOpenEnvModal(app)}
            >
              环境变量
              {app.envVars && Object.keys(app.envVars).length > 0 && (
                <Badge ml={2} size="sm" colorScheme="blue">
                  {Object.keys(app.envVars).length}
                </Badge>
              )}
            </Button>
            <Button
              size="sm"
              leftIcon={<Icon as={FiUpload} />}
              colorScheme="blue"
              onClick={handleDeploy}
              isLoading={isDeploying}
              loadingText="部署中"
            >
              重新部署
            </Button>
          </HStack>
        </VStack>
      </CardBody>

      {/* 实时日志对话框 */}
      <RealtimeLogsDialog
        appName={app.name}
        isOpen={showLogsDialog}
        onClose={() => setShowLogsDialog(false)}
      />
    </Card>
  )
}

// 获取日志颜色
const getLogColor = (level: string): string => {
  switch (level.toLowerCase()) {
    case 'error':
    case 'fatal':
      return '#FC8181'
    case 'warn':
    case 'warning':
      return '#F6AD55'
    case 'info':
      return '#63B3ED'
    case 'debug':
      return '#A0AEC0'
    default:
      return '#E2E8F0'
  }
}

export default AppCard

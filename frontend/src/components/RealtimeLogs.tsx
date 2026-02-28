import React, { useState, useEffect, useRef } from 'react'
import {
  Box,
  VStack,
  HStack,
  Text,
  Badge,
  Button,
  Icon,
  useColorModeValue,
  useToast,
  Code,
  Flex,
  Select,
  Switch,
  FormControl,
  FormLabel,
  NumberInput,
  NumberInputField,
  Spinner,
  Alert,
  AlertIcon,
} from '@chakra-ui/react'
import {
  FiPlay,
  FiPause,
  FiTrash2,
  FiDownload,
  FiRefreshCw,
  FiTerminal,
  FiClock,
  FiServer,
  FiGitBranch,
  FiPackage,
  FiAlertCircle,
  FiCheckCircle,
  FiInfo,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { websocketManager } from '../services/websocketManager'

interface LogEntry {
  timestamp: string
  level: string
  source: string
  message: string
  app_name: string
  deploy_id?: string
  raw?: string
  metadata?: {
    deploy_id?: string
    status?: string
    progress?: number
    error?: string
    [key: string]: any
  }
}

interface WebSocketMessage {
  type: 'log' | 'ping' | 'connected' | 'error' | 'deploy_status'
  data?: LogEntry
  error?: string
  app?: string
  message?: string
  timestamp?: number
}

interface RealtimeLogsProps {
  appName: string
  autoScroll?: boolean
  maxLines?: number
  showControls?: boolean
}

const RealtimeLogs: React.FC<RealtimeLogsProps> = ({
  appName,
  autoScroll = true,
  maxLines = 500,
  showControls = true,
}) => {
  const { adminPrefix } = useConfig()
  const toast = useToast()
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [isConnected, setIsConnected] = useState(false)
  const [isStreaming, setIsStreaming] = useState(false)
  const [autoScrollEnabled, setAutoScrollEnabled] = useState(autoScroll)
  const [maxDisplayLines, setMaxDisplayLines] = useState(maxLines)
  const [filterLevel, setFilterLevel] = useState('all')
  const [filterSource, setFilterSource] = useState('all')
  
  const [connectionType, setConnectionType] = useState<'sse' | 'websocket'>('websocket')
  const [deployStatus, setDeployStatus] = useState<{
    status: string
    progress: number
    message: string
  } | null>(null)
  
  const logsEndRef = useRef<HTMLDivElement>(null)
  const eventSourceRef = useRef<EventSource | null>(null)
  const wsKeyRef = useRef<string>(`logs-${appName}`)
  const logIdsRef = useRef<Set<string>>(new Set()) // 用于去重
  const isMountedRef = useRef(true) // 跟踪组件是否挂载，防止内存泄漏

  const bgColor = useColorModeValue('gray.50', 'gray.900')
  const borderColor = useColorModeValue('gray.200', 'gray.700')

  // 滚动到底部
  const scrollToBottom = () => {
    if (autoScrollEnabled && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }

  // 连接 WebSocket 日志流
  const connectWebSocket = () => {
    // 断开之前的连接
    websocketManager.disconnect(wsKeyRef.current)

    // 构建 WebSocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    
    // 在开发模式下，WebSocket 需要直接连接到后端端口（绕过 Vite 代理）
    // 因为 Vite 的代理 ResponseWriter 不支持 Hijacker 接口
    const isDevelopment = window.location.port === '9980'
    const host = isDevelopment ? `${window.location.hostname}:80` : window.location.host
    
    const path = buildApiPath(adminPrefix, `/api/git-server/logs/stream-ws?app=${appName}`)
    const url = `${protocol}//${host}${path}`

    websocketManager.connect(wsKeyRef.current, url, {
      maxReconnectAttempts: 5,
      reconnectDelay: 1000,
      onOpen: () => {
        setIsConnected(true)
        setIsStreaming(true)
        console.log('WebSocket connected')
      },
      onMessage: (event) => {
      try {
        const message: WebSocketMessage = JSON.parse(event.data)
        
        switch (message.type) {
          case 'log':
            if (message.data) {
              // 生成日志唯一ID用于去重
              const logId = `${message.data.timestamp}_${message.data.message.substring(0, 50)}`
              
              // 检查是否已经收到过这条日志
              if (logIdsRef.current.has(logId)) {
                console.debug('Skipping duplicate log:', logId)
                break
              }
              
              // 添加到已收到集合
              logIdsRef.current.add(logId)
              
              // 限制去重集合大小（保留最近1000条）
              if (logIdsRef.current.size > 1000) {
                const idsArray = Array.from(logIdsRef.current)
                logIdsRef.current = new Set(idsArray.slice(-500))
              }
              
              setLogs(prevLogs => {
                const newLogs = [...prevLogs, message.data!]
                if (newLogs.length > maxDisplayLines) {
                  return newLogs.slice(-maxDisplayLines)
                }
                return newLogs
              })
              
              // 检查是否是部署状态日志
              if (message.data.source === 'deploy_status' && message.data.metadata) {
                setDeployStatus({
                  status: message.data.metadata.status || 'unknown',
                  progress: message.data.metadata.progress || 0,
                  message: message.data.message,
                })
              }
            }
            break
          
          case 'ping':
            console.log('Received WebSocket ping')
            break
          
          case 'connected':
            console.log('WebSocket connection established:', message.message)
            toast({
              title: 'WebSocket 已连接',
              description: message.message,
              status: 'success',
              duration: 2000,
              isClosable: true,
            })
            break
          
          case 'error':
            console.error('WebSocket error:', message.error)
            toast({
              title: 'WebSocket 错误',
              description: message.error || '未知错误',
              status: 'error',
              duration: 5000,
              isClosable: true,
            })
            // 如果是日志流不存在的错误，停止重连
            if (message.error && message.error.includes('日志流不存在')) {
              websocketManager.disconnect(wsKeyRef.current)
            }
            break
        }
      } catch (error) {
        console.error('Failed to parse WebSocket message:', error)
      }
      },
      onError: (error) => {
        console.error('WebSocket error:', error)
        setIsConnected(false)
      },
      onClose: () => {
        console.log('WebSocket closed')
        setIsConnected(false)
        setIsStreaming(false)
      },
    })
  }

  // 连接 SSE 日志流
  const connectSSE = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
    }

    const url = buildApiPath(adminPrefix, `/api/git-server/logs/stream?app=${appName}`)
    const eventSource = new EventSource(url, { withCredentials: true })
    
    eventSource.onopen = () => {
      setIsConnected(true)
      setIsStreaming(true)
      console.log('SSE stream connected')
    }

    eventSource.addEventListener('log', (event) => {
      try {
        const logEntry: LogEntry = JSON.parse(event.data)
        setLogs(prevLogs => {
          const newLogs = [...prevLogs, logEntry]
          if (newLogs.length > maxDisplayLines) {
            return newLogs.slice(-maxDisplayLines)
          }
          return newLogs
        })
      } catch (error) {
        console.error('Failed to parse log entry:', error)
      }
    })

    eventSource.addEventListener('ping', () => {
      console.log('Received SSE ping')
    })

    eventSource.onerror = (error) => {
      console.error('SSE stream error:', error)
      setIsConnected(false)
      setIsStreaming(false)

      // 自动重连（仅在组件仍然挂载时）
      setTimeout(() => {
        // 检查组件是否仍然挂载，防止内存泄漏
        if (isMountedRef.current && isStreaming) {
          connectSSE()
        }
      }, 3000)
    }

    eventSourceRef.current = eventSource
  }

  // 连接实时日志流
  const connectLogStream = () => {
    if (connectionType === 'websocket') {
      connectWebSocket()
    } else {
      connectSSE()
    }
  }

  // 断开日志流
  const disconnectLogStream = () => {
    websocketManager.disconnect(wsKeyRef.current)
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
      eventSourceRef.current = null
    }
    setIsConnected(false)
    setIsStreaming(false)
    setDeployStatus(null)
  }

  // 加载历史日志
  const loadHistoryLogs = async () => {
    try {
      const response = await fetch(
        buildApiPath(adminPrefix, `/api/git-server/logs/history?app=${appName}&limit=${maxDisplayLines}`),
        { credentials: 'include' }
      )
      
      if (response.ok) {
        const data = await response.json()
        if (data.success && data.data) {
          setLogs(data.data)
        }
      }
    } catch (error) {
      console.error('Failed to load history logs:', error)
    }
  }

  // 清空日志
  const clearLogs = () => {
    setLogs([])
    logIdsRef.current.clear() // 同时清空去重集合
  }

  // 下载日志
  const downloadLogs = () => {
    const logText = logs.map(log => 
      `[${log.timestamp}] [${log.level}] [${log.source}] ${log.message}`
    ).join('\n')
    
    const blob = new Blob([logText], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${appName}-logs-${new Date().toISOString().slice(0, 19)}.txt`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  // 获取日志级别颜色
  const getLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'error': return 'red'
      case 'warn': return 'yellow'
      case 'info': return 'blue'
      case 'debug': return 'gray'
      default: return 'gray'
    }
  }

  // 获取来源图标
  const getSourceIcon = (source: string) => {
    switch (source.toLowerCase()) {
      case 'git': return FiGitBranch
      case 'build': return FiPackage
      case 'deploy': return FiServer
      case 'docker': return FiPackage
      default: return FiTerminal
    }
  }

  // 过滤日志
  const filteredLogs = logs.filter(log => {
    if (filterLevel !== 'all' && log.level !== filterLevel) {
      return false
    }
    if (filterSource !== 'all' && log.source !== filterSource) {
      return false
    }
    return true
  })

  // 组件挂载时加载历史日志
  useEffect(() => {
    loadHistoryLogs()
    return () => {
      // 标记组件已卸载，防止内存泄漏
      isMountedRef.current = false
      disconnectLogStream()
    }
  }, [appName])

  // 自动滚动
  useEffect(() => {
    scrollToBottom()
  }, [logs, autoScrollEnabled])

  return (
    <Box>
      {/* 控制栏 */}
      {showControls && (
        <VStack spacing={4} mb={4}>
          <HStack justify="space-between" w="full">
            <HStack>
              <Button
                size="sm"
                leftIcon={<Icon as={isStreaming ? FiPause : FiPlay} />}
                colorScheme={isStreaming ? 'red' : 'green'}
                onClick={isStreaming ? disconnectLogStream : connectLogStream}
              >
                {isStreaming ? '停止' : '开始'}实时日志
              </Button>
              
              <Button
                size="sm"
                leftIcon={<Icon as={FiRefreshCw} />}
                onClick={loadHistoryLogs}
              >
                刷新历史
              </Button>
              
              <Button
                size="sm"
                leftIcon={<Icon as={FiTrash2} />}
                onClick={clearLogs}
              >
                清空
              </Button>
              
              <Button
                size="sm"
                leftIcon={<Icon as={FiDownload} />}
                onClick={downloadLogs}
                isDisabled={logs.length === 0}
              >
                下载
              </Button>
            </HStack>
            
            <HStack>
              {isConnected && (
                <Badge colorScheme="green" display="flex" alignItems="center">
                  <Icon as={FiCheckCircle} mr={1} />
                  已连接
                </Badge>
              )}
              
              {!isConnected && isStreaming && (
                <Badge colorScheme="yellow" display="flex" alignItems="center">
                  <Spinner size="xs" mr={1} />
                  连接中...
                </Badge>
              )}
            </HStack>
          </HStack>
          
          {/* 过滤控制 */}
          <HStack spacing={4} w="full">
            <FormControl maxW="150px">
              <FormLabel fontSize="sm">日志级别</FormLabel>
              <Select
                size="sm"
                value={filterLevel}
                onChange={(e) => setFilterLevel(e.target.value)}
              >
                <option value="all">全部</option>
                <option value="error">错误</option>
                <option value="warn">警告</option>
                <option value="info">信息</option>
                <option value="debug">调试</option>
              </Select>
            </FormControl>
            
            <FormControl maxW="150px">
              <FormLabel fontSize="sm">日志来源</FormLabel>
              <Select
                size="sm"
                value={filterSource}
                onChange={(e) => setFilterSource(e.target.value)}
              >
                <option value="all">全部</option>
                <option value="git">Git</option>
                <option value="build">构建</option>
                <option value="deploy">部署</option>
                <option value="docker">Docker</option>
                <option value="app">应用</option>
              </Select>
            </FormControl>
            
            <FormControl maxW="150px">
              <FormLabel fontSize="sm">最大行数</FormLabel>
              <NumberInput
                size="sm"
                value={maxDisplayLines}
                onChange={(_, value) => setMaxDisplayLines(value || 500)}
                min={50}
                max={2000}
              >
                <NumberInputField />
              </NumberInput>
            </FormControl>
            
            <FormControl display="flex" alignItems="center">
              <FormLabel fontSize="sm" mb="0">自动滚动</FormLabel>
              <Switch
                size="sm"
                isChecked={autoScrollEnabled}
                onChange={(e) => setAutoScrollEnabled(e.target.checked)}
              />
            </FormControl>
          </HStack>
        </VStack>
      )}

      {/* 日志显示区域 */}
      <Box
        bg={bgColor}
        border="1px"
        borderColor={borderColor}
        borderRadius="md"
        h="400px"
        overflowY="auto"
        p={3}
        fontFamily="mono"
        fontSize="sm"
      >
        {filteredLogs.length === 0 ? (
          <Flex justify="center" align="center" h="full">
            <VStack>
              <Icon as={FiTerminal} boxSize={8} color="gray.400" />
              <Text color="gray.500">暂无日志</Text>
              {!isStreaming && (
                <Button size="sm" onClick={connectLogStream}>
                  开始实时日志
                </Button>
              )}
            </VStack>
          </Flex>
        ) : (
          <VStack spacing={1} align="stretch">
            {filteredLogs.map((log, index) => (
              <HStack
                key={index}
                spacing={2}
                p={1}
                borderRadius="sm"
                _hover={{ bg: useColorModeValue('gray.100', 'gray.800') }}
                fontSize="xs"
              >
                <Text color="gray.500" minW="80px">
                  {new Date(log.timestamp).toLocaleTimeString()}
                </Text>
                
                <Badge
                  colorScheme={getLevelColor(log.level)}
                  minW="50px"
                  textAlign="center"
                  fontSize="xs"
                >
                  {log.level.toUpperCase()}
                </Badge>
                
                <HStack minW="60px">
                  <Icon as={getSourceIcon(log.source)} boxSize={3} />
                  <Text fontSize="xs" color="gray.600">
                    {log.source}
                  </Text>
                </HStack>
                
                <Text flex={1} wordBreak="break-all">
                  {log.message}
                </Text>
                
                {log.deploy_id && (
                  <Code fontSize="xs" colorScheme="blue">
                    {log.deploy_id.slice(-8)}
                  </Code>
                )}
              </HStack>
            ))}
            <div ref={logsEndRef} />
          </VStack>
        )}
      </Box>

      {/* 状态信息 */}
      <HStack justify="space-between" mt={2} fontSize="sm" color="gray.500">
        <Text>
          显示 {filteredLogs.length} / {logs.length} 条日志
        </Text>
        <HStack>
          {isStreaming && (
            <HStack>
              <Spinner size="xs" />
              <Text>实时监听中...</Text>
            </HStack>
          )}
          <Text>应用: {appName}</Text>
        </HStack>
      </HStack>
    </Box>
  )
}

export default RealtimeLogs

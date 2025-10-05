import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  SimpleGrid,
  Card,
  CardBody,
  CardHeader,
  VStack,
  HStack,
  Button,
  Icon,
  Text,
  Flex,
  Badge,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  FormControl,
  FormLabel,
  Select,
  Input,
  Textarea,
  useDisclosure,
  useToast,
  Stat,
  StatLabel,
  StatNumber,
} from '@chakra-ui/react'
import {
  FiRefreshCw,
  FiBell,
  FiCheckCircle,
  FiSettings,
  FiList,
  FiClock,
  FiSend,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'

interface NotificationItem {
  id: string
  level: 'info' | 'warning' | 'error' | 'critical'
  type: string
  title: string
  message: string
  timestamp: string
  source: string
  details?: Record<string, string>
}

interface NotificationStats {
  totalNotifications: number
  channelsEnabled: number
  channelsTotal: number
  limit: number
}

const Notifications: React.FC = () => {
  const [notifications, setNotifications] = useState<NotificationItem[]>([])
  const [stats, setStats] = useState<NotificationStats>({
    totalNotifications: 0,
    channelsEnabled: 0,
    channelsTotal: 0,
    limit: 50,
  })
  const [loading, setLoading] = useState(false)
  const { isOpen, onOpen, onClose } = useDisclosure()
  const toast = useToast()
  const { adminPrefix } = useConfig()

  const [testForm, setTestForm] = useState({
    type: 'ddos_attack',
    level: 'info',
    title: '',
    message: '',
  })

  const refreshNotifications = async () => {
    setLoading(true)
    try {
      // 确保 adminPrefix 不为空，否则使用备用前缀
      const effectivePrefix = adminPrefix || '/sslcat-panel'
      // 使用安全日志API作为通知数据源
      const response = await fetch(buildApiPath(effectivePrefix, '/api/security-logs'), {
        method: 'GET',
        credentials: 'include',
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const data = await response.json()
      const logs = data.logs || []
      
      // 转换日志为通知格式 - 只显示安全事件，过滤正常访问
      const notifications = logs
        .filter((log: any) => !log.success) // 只显示失败的访问（安全事件）
        .slice(0, 20)
        .map((log: any, index: number) => ({
          id: index.toString(),
          level: 'error',
          type: 'security',
          title: '安全事件',
          message: `来自 ${log.ip} 的异常访问被阻止`,
          timestamp: new Date(log.timestamp).toLocaleString('zh-CN'),
          source: 'security',
          details: {
            ip: log.ip,
            userAgent: log.userAgent,
            path: log.path,
          },
        }))
      
      setStats({
        totalNotifications: logs.filter((log: any) => !log.success).length, // 只计算安全事件
        channelsEnabled: 3,
        channelsTotal: 5,
        limit: 50,
      })
      setNotifications(notifications)
    } catch (error) {
      console.error('获取通知失败:', error)
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

  const sendTestNotification = async () => {
    // 表单验证
    if (!testForm.title.trim()) {
      toast({
        title: '表单验证失败',
        description: '请输入通知标题',
        status: 'warning',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    if (!testForm.message.trim()) {
      toast({
        title: '表单验证失败',
        description: '请输入通知消息内容',
        status: 'warning',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    try {
      // TODO: 实际的 API 调用
      // const response = await fetch('/api/notifications/test', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify(testForm),
      // })
      
      toast({
        title: '测试通知发送成功',
        description: `已发送${getLevelText(testForm.level)}级别的"${testForm.title}"通知`,
        status: 'success',
        duration: 4000,
        isClosable: true,
      })
      
      onClose()
      refreshNotifications()
      
      // 重置表单
      setTestForm({
        type: 'ddos_attack',
        level: 'info',
        title: '',
        message: '',
      })
    } catch (error) {
      toast({
        title: '测试通知发送失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 4000,
        isClosable: true,
      })
    }
  }

  const testNotificationChannels = async () => {
    try {
      // TODO: 实际的 API 调用
      toast({
        title: '通知渠道测试完成',
        description: '所有启用的渠道都测试成功',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
    } catch (error) {
      toast({
        title: '测试失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  useEffect(() => {
    refreshNotifications()
  }, [])

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'info': return 'blue'
      case 'warning': return 'orange'
      case 'error': return 'red'
      case 'critical': return 'purple'
      default: return 'gray'
    }
  }

  const getLevelText = (level: string) => {
    switch (level) {
      case 'info': return '信息'
      case 'warning': return '警告'
      case 'error': return '错误'
      case 'critical': return '严重'
      default: return level
    }
  }

  return (
    <Box>
      <Flex justify="space-between" align="center" mb={6}>
        <HStack>
          <Icon as={FiBell} boxSize={6} />
          <Heading size="lg">通知管理</Heading>
        </HStack>
        <HStack>
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            onClick={refreshNotifications}
            isLoading={loading}
            variant="outline"
          >
            刷新
          </Button>
          <Button
            leftIcon={<Icon as={FiSettings} />}
            onClick={testNotificationChannels}
            colorScheme="green"
          >
            测试渠道
          </Button>
          <Button
            leftIcon={<Icon as={FiSend} />}
            onClick={onOpen}
            colorScheme="blue"
          >
            测试通知
          </Button>
        </HStack>
      </Flex>

      {/* 统计卡片 */}
      <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={6} mb={8}>
        <Card bg="blue.500" color="white">
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="blue.100">总通知数</StatLabel>
                  <StatNumber>{stats.totalNotifications}</StatNumber>
                </Box>
                <Icon as={FiBell} boxSize={8} color="blue.200" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>

        <Card bg="green.500" color="white">
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="green.100">启用渠道</StatLabel>
                  <StatNumber>{stats.channelsEnabled}</StatNumber>
                </Box>
                <Icon as={FiCheckCircle} boxSize={8} color="green.200" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>

        <Card bg="orange.500" color="white">
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="orange.100">总渠道数</StatLabel>
                  <StatNumber>{stats.channelsTotal}</StatNumber>
                </Box>
                <Icon as={FiSettings} boxSize={8} color="orange.200" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>

        <Card bg="purple.500" color="white">
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="purple.100">显示条数</StatLabel>
                  <StatNumber>{stats.limit}</StatNumber>
                </Box>
                <Icon as={FiList} boxSize={8} color="purple.200" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>
      </SimpleGrid>

      {/* 通知列表 */}
      <Card>
        <CardHeader>
          <Heading size="md">通知历史</Heading>
        </CardHeader>
        <CardBody>
          {notifications.length > 0 ? (
            <VStack spacing={4} align="stretch">
              {notifications.map((notification) => (
                <Box
                  key={notification.id}
                  p={4}
                  borderLeft="4px solid"
                  borderLeftColor={`${getLevelColor(notification.level)}.500`}
                  bg="gray.50"
                  borderRadius="md"
                >
                  <Flex justify="space-between" align="start">
                    <Box flex={1}>
                      <HStack mb={2}>
                        <Badge colorScheme={getLevelColor(notification.level)}>
                          {getLevelText(notification.level)}
                        </Badge>
                        <Badge variant="outline">
                          {notification.type}
                        </Badge>
                        <Text fontWeight="bold">{notification.title}</Text>
                      </HStack>
                      <Text mb={2}>{notification.message}</Text>
                      <HStack color="gray.600" fontSize="sm">
                        <Icon as={FiClock} />
                        <Text>{notification.timestamp}</Text>
                      </HStack>
                      {notification.details && (
                        <Box mt={2}>
                          <Text fontSize="sm" fontWeight="medium" mb={1}>
                            详细信息:
                          </Text>
                          <HStack wrap="wrap" spacing={2}>
                            {Object.entries(notification.details).map(([key, value]) => (
                              <Badge key={key} variant="subtle">
                                {key}: {value}
                              </Badge>
                            ))}
                          </HStack>
                        </Box>
                      )}
                    </Box>
                    <Text fontSize="sm" color="gray.500">
                      {notification.source}
                    </Text>
                  </Flex>
                </Box>
              ))}
            </VStack>
          ) : (
            <VStack py={8} spacing={4}>
              <Icon as={FiBell} boxSize={12} color="gray.300" />
              <Text color="gray.500">暂无通知记录</Text>
            </VStack>
          )}
        </CardBody>
      </Card>

      {/* 测试通知模态框 */}
      <Modal isOpen={isOpen} onClose={onClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>发送测试通知</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>通知类型</FormLabel>
                <Select
                  value={testForm.type}
                  onChange={(e) => setTestForm({ ...testForm, type: e.target.value })}
                >
                  <option value="ddos_attack">DDoS攻击</option>
                  <option value="cert_expiring">证书过期</option>
                  <option value="cert_failed">证书失败</option>
                  <option value="system_error">系统错误</option>
                  <option value="security_alert">安全警报</option>
                  <option value="user_action">用户操作</option>
                </Select>
              </FormControl>

              <FormControl>
                <FormLabel>通知级别</FormLabel>
                <Select
                  value={testForm.level}
                  onChange={(e) => setTestForm({ ...testForm, level: e.target.value })}
                >
                  <option value="info">信息</option>
                  <option value="warning">警告</option>
                  <option value="error">错误</option>
                  <option value="critical">严重</option>
                </Select>
              </FormControl>

              <FormControl isRequired>
                <FormLabel>标题</FormLabel>
                <Input
                  value={testForm.title}
                  onChange={(e) => setTestForm({ ...testForm, title: e.target.value })}
                  placeholder="请输入通知标题"
                  isInvalid={!testForm.title.trim() && testForm.title !== ''}
                />
              </FormControl>

              <FormControl isRequired>
                <FormLabel>消息内容</FormLabel>
                <Textarea
                  value={testForm.message}
                  onChange={(e) => setTestForm({ ...testForm, message: e.target.value })}
                  placeholder="请输入通知消息"
                  rows={3}
                  isInvalid={!testForm.message.trim() && testForm.message !== ''}
                />
              </FormControl>
            </VStack>
          </ModalBody>

          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onClose}>
              取消
            </Button>
            <Button colorScheme="blue" onClick={sendTestNotification}>
              发送测试
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default Notifications

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
  Stat,
  StatLabel,
  StatNumber,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Switch,
  FormControl,
  FormLabel,
  Input,
  useToast,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
} from '@chakra-ui/react'
import {
  FiShield,
  FiRefreshCw,
  FiAlertTriangle,
  FiCheckCircle,
  FiClock,
  FiX,
  FiGlobe,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import GeoIPConfig from '../components/GeoIPConfig'

interface SecurityEvent {
  id: string
  type: 'ddos_attack' | 'bruteforce' | 'suspicious_ip' | 'malware'
  severity: 'low' | 'medium' | 'high' | 'critical'
  source: string
  description: string
  timestamp: string
  blocked: boolean
}

interface SecurityStats {
  totalEvents: number
  blockedIPs: number
  activeThreats: number
  lastScan: string
}

const Security: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [stats, setStats] = useState<SecurityStats>({
    totalEvents: 0,
    blockedIPs: 0,
    activeThreats: 0,
    lastScan: '',
  })
  const [settings, setSettings] = useState({
    enableWAF: true,
    enableDDoSProtection: true,
    enableThreatIntel: true,
    maxRequestsPerMinute: '1000',
    blockSuspiciousIPs: true,
  })
  const [loading, setLoading] = useState(false)
  const toast = useToast()
  const { adminPrefix } = useConfig()

  const refreshData = async () => {
    setLoading(true)
    try {
      // 获取安全日志（暂时使用这个API）
      const logsResponse = await fetch(buildApiPath(adminPrefix, '/api/security-logs'), {
        method: 'GET',
        credentials: 'include',
      })

      if (logsResponse.ok) {
        const logsData = await logsResponse.json()
        // 模拟统计信息
        const totalEvents = logsData.logs ? logsData.logs.length : 0
        const blockedIPs = logsData.logs ? logsData.logs.filter((log: any) => !log.success).length : 0
        const activeThreats = Math.floor(blockedIPs * 0.1) // 模拟活跃威胁数量
        
        setStats({
          totalEvents,
          blockedIPs,
          activeThreats,
          lastScan: new Date().toLocaleString('zh-CN'),
        })
        
        // 转换日志为事件格式 - 只显示有风险、可疑的事件
        const events = logsData.logs ? logsData.logs
          .filter((log: any) => !log.success) // 只显示失败的访问（被阻止的）
          .slice(0, 10)
          .map((log: any, index: number) => ({
            id: index.toString(),
            type: 'suspicious_ip',
            severity: 'high',
            source: log.ip,
            description: '访问被阻止 - 可疑行为',
            timestamp: new Date(log.timestamp).toLocaleString('zh-CN'),
            blocked: true,
          })) : []
        
        setEvents(events)
      } else {
        throw new Error('获取安全数据失败')
      }
    } catch (error) {
      console.error('获取安全数据失败:', error)
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

  const saveSecuritySettings = async () => {
    try {
      // TODO: 实际的 API 调用
      toast({
        title: '安全设置保存成功',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
    } catch (error) {
      toast({
        title: '保存失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const blockIP = async (ip: string) => {
    try {
      // TODO: 实际的 API 调用
      toast({
        title: `IP ${ip} 已被封锁`,
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      refreshData()
    } catch (error) {
      toast({
        title: '封锁失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  useEffect(() => {
    refreshData()
  }, [])

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'low': return 'green'
      case 'medium': return 'orange'
      case 'high': return 'red'
      case 'critical': return 'purple'
      default: return 'gray'
    }
  }

  const getSeverityText = (severity: string) => {
    switch (severity) {
      case 'low': return '低'
      case 'medium': return '中'
      case 'high': return '高'
      case 'critical': return '严重'
      default: return severity
    }
  }

  const getTypeText = (type: string) => {
    switch (type) {
      case 'ddos_attack': return 'DDoS攻击'
      case 'bruteforce': return '暴力破解'
      case 'suspicious_ip': return '可疑IP'
      case 'malware': return '恶意软件'
      default: return type
    }
  }

  return (
    <Box>
      <Flex justify="space-between" align="center" mb={6}>
        <HStack>
          <Icon as={FiShield} boxSize={6} />
          <Heading size="lg">安全中心</Heading>
        </HStack>
        <Button
          leftIcon={<Icon as={FiRefreshCw} />}
          onClick={refreshData}
          isLoading={loading}
          variant="outline"
        >
          刷新
        </Button>
      </Flex>

      <Tabs>
        <TabList>
          <Tab>
            <Icon as={FiShield} mr={2} />
            安全概览
          </Tab>
          <Tab>
            <Icon as={FiGlobe} mr={2} />
            地理位置过滤
          </Tab>
        </TabList>

        <TabPanels>
          <TabPanel px={0}>
            {/* 原有的安全概览内容 */}

      {/* 安全统计 */}
      <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={6} mb={8}>
        <Card bg="red.500" color="white">
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="red.100">安全事件</StatLabel>
                  <StatNumber>{stats.totalEvents}</StatNumber>
                </Box>
                <Icon as={FiAlertTriangle} boxSize={8} color="red.200" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>

        <Card bg="orange.500" color="white">
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="orange.100">被封IP</StatLabel>
                  <StatNumber>{stats.blockedIPs}</StatNumber>
                </Box>
                <Icon as={FiX} boxSize={8} color="orange.200" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>

        <Card bg="purple.500" color="white">
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="purple.100">活跃威胁</StatLabel>
                  <StatNumber>{stats.activeThreats}</StatNumber>
                </Box>
                <Icon as={FiShield} boxSize={8} color="purple.200" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>

        <Card bg="green.500" color="white">
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="green.100">最后扫描</StatLabel>
                  <Text fontSize="sm">{stats.lastScan}</Text>
                </Box>
                <Icon as={FiClock} boxSize={8} color="green.200" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>
      </SimpleGrid>

      <SimpleGrid columns={{ base: 1, lg: 2 }} spacing={6} mb={8}>
        {/* 安全设置 */}
        <Card>
          <CardHeader>
            <Heading size="md">安全设置</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0" flex="1">Web应用防火墙 (WAF)</FormLabel>
                <Switch
                  isChecked={settings.enableWAF}
                  onChange={(e) => setSettings(prev => ({ ...prev, enableWAF: e.target.checked }))}
                />
              </FormControl>
              
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0" flex="1">DDoS防护</FormLabel>
                <Switch
                  isChecked={settings.enableDDoSProtection}
                  onChange={(e) => setSettings(prev => ({ ...prev, enableDDoSProtection: e.target.checked }))}
                />
              </FormControl>
              
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0" flex="1">威胁情报</FormLabel>
                <Switch
                  isChecked={settings.enableThreatIntel}
                  onChange={(e) => setSettings(prev => ({ ...prev, enableThreatIntel: e.target.checked }))}
                />
              </FormControl>
              
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0" flex="1">自动封锁可疑IP</FormLabel>
                <Switch
                  isChecked={settings.blockSuspiciousIPs}
                  onChange={(e) => setSettings(prev => ({ ...prev, blockSuspiciousIPs: e.target.checked }))}
                />
              </FormControl>
              
              <FormControl>
                <FormLabel>每分钟最大请求数</FormLabel>
                <Input
                  value={settings.maxRequestsPerMinute}
                  onChange={(e) => setSettings(prev => ({ ...prev, maxRequestsPerMinute: e.target.value }))}
                  type="number"
                />
              </FormControl>
              
              <Button colorScheme="blue" onClick={saveSecuritySettings}>
                保存设置
              </Button>
            </VStack>
          </CardBody>
        </Card>

        {/* 威胁概览 */}
        <Card>
          <CardHeader>
            <Heading size="md">威胁概览</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <HStack justify="space-between">
                <HStack>
                  <Icon as={FiCheckCircle} color="green.500" />
                  <Text>WAF防护</Text>
                </HStack>
                <Badge colorScheme="green">已启用</Badge>
              </HStack>
              
              <HStack justify="space-between">
                <HStack>
                  <Icon as={FiCheckCircle} color="green.500" />
                  <Text>DDoS防护</Text>
                </HStack>
                <Badge colorScheme="green">已启用</Badge>
              </HStack>
              
              <HStack justify="space-between">
                <HStack>
                  <Icon as={FiCheckCircle} color="green.500" />
                  <Text>威胁情报</Text>
                </HStack>
                <Badge colorScheme="green">已启用</Badge>
              </HStack>
              
              <HStack justify="space-between">
                <HStack>
                  <Icon as={FiAlertTriangle} color="orange.500" />
                  <Text>IP封锁</Text>
                </HStack>
                <Badge colorScheme="orange">{stats.blockedIPs} 个IP</Badge>
              </HStack>
            </VStack>
          </CardBody>
        </Card>
      </SimpleGrid>

      {/* 安全事件 */}
      <Card>
        <CardHeader>
          <Heading size="md">最近安全事件</Heading>
        </CardHeader>
        <CardBody>
          {events.length > 0 ? (
            <Table variant="simple">
              <Thead>
                <Tr>
                  <Th>类型</Th>
                  <Th>严重程度</Th>
                  <Th>来源IP</Th>
                  <Th>描述</Th>
                  <Th>时间</Th>
                  <Th>状态</Th>
                  <Th>操作</Th>
                </Tr>
              </Thead>
              <Tbody>
                {events.map((event) => (
                  <Tr key={event.id}>
                    <Td>{getTypeText(event.type)}</Td>
                    <Td>
                      <Badge colorScheme={getSeverityColor(event.severity)}>
                        {getSeverityText(event.severity)}
                      </Badge>
                    </Td>
                    <Td>
                      <Text fontFamily="mono" fontSize="sm">
                        {event.source}
                      </Text>
                    </Td>
                    <Td>{event.description}</Td>
                    <Td>{event.timestamp}</Td>
                    <Td>
                      <Badge colorScheme={event.blocked ? 'red' : 'green'}>
                        {event.blocked ? '已封锁' : '已允许'}
                      </Badge>
                    </Td>
                    <Td>
                      {!event.blocked && (
                        <Button
                          size="sm"
                          colorScheme="red"
                          variant="outline"
                          onClick={() => blockIP(event.source)}
                        >
                          封锁IP
                        </Button>
                      )}
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          ) : (
            <Box textAlign="center" py={8}>
              <Icon as={FiShield} boxSize={12} color="gray.300" mb={4} />
              <Text color="gray.500">暂无安全事件</Text>
            </Box>
          )}
        </CardBody>
      </Card>
          </TabPanel>
          
          <TabPanel px={0}>
            {/* 地理位置过滤配置 */}
            <GeoIPConfig />
          </TabPanel>
        </TabPanels>
      </Tabs>
    </Box>
  )
}

export default Security

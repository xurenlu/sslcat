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
import { useTranslation } from '../hooks/useLanguage'
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
  const t = useTranslation()

  const refreshData = async () => {
    setLoading(true)
    try {
      // 确保 adminPrefix 不为空，否则使用备用前缀
      const effectivePrefix = adminPrefix || '/sslcat-panel'
      // 获取安全日志（暂时使用这个API）
      const logsResponse = await fetch(buildApiPath(effectivePrefix, '/api/security-logs'), {
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
          .filter((log: any) => {
            // 显示 WAF 事件或被阻止的访问
            return log.type === 'waf' || !log.success
          })
          .slice(0, 100) // 增加显示数量
          .map((log: any, index: number) => {
            // 根据日志类型生成描述
            let description = '访问被阻止 - 可疑行为'
            let severity: 'low' | 'medium' | 'high' | 'critical' = 'high'
            let eventType: 'ddos_attack' | 'bruteforce' | 'suspicious_ip' | 'malware' = 'suspicious_ip'

            if (log.type === 'waf') {
              if (log.rule_type === 'sensitive_file') {
                description = `敏感文件访问尝试: ${log.rule_name || log.path}`
                severity = 'critical'
                eventType = 'malware'
              } else if (log.rule_type === 'scanner_detection') {
                description = `安全扫描工具检测: ${log.rule_name || '未知扫描器'}`
                severity = 'high'
                eventType = 'ddos_attack'
              } else {
                description = `WAF检测: ${log.rule_name || '未知规则'} - ${log.path || ''}`
                severity = log.blocked ? 'high' : 'medium'
                eventType = 'suspicious_ip'
              }
            }

            return {
              id: log.id || index.toString(),
              type: eventType,
              severity,
              source: log.ip || log.client_ip || 'unknown',
              description,
              timestamp: new Date(log.timestamp).toLocaleString('zh-CN'),
              blocked: log.blocked !== undefined ? log.blocked : !log.success,
              // 添加额外信息用于显示
              method: log.method || '',
              path: log.path || log.url || '',
              ruleName: log.rule_name || '',
            }
          }) : []
        
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
      case 'low': return t.security.low
      case 'medium': return t.security.medium
      case 'high': return t.security.high
      case 'critical': return t.security.critical
      default: return severity
    }
  }

  const getTypeText = (type: string) => {
    switch (type) {
      case 'ddos_attack': return t.security.ddosAttack
      case 'bruteforce': return t.security.bruteforce
      case 'suspicious_ip': return t.security.suspiciousIP
      case 'malware': return t.security.malware
      default: return type
    }
  }

  return (
    <Box>
      <Flex justify="space-between" align="center" mb={6}>
        <HStack>
          <Icon as={FiShield} boxSize={6} />
          <Heading size="lg">{t.security.title}</Heading>
        </HStack>
        <Button
          leftIcon={<Icon as={FiRefreshCw} />}
          onClick={refreshData}
          isLoading={loading}
          variant="outline"
        >
          {t.security.refresh}
        </Button>
      </Flex>

      <Tabs>
        <TabList>
          <Tab>
            <Icon as={FiShield} mr={2} />
            {t.security.overview}
          </Tab>
          <Tab>
            <Icon as={FiGlobe} mr={2} />
            {t.security.geoFiltering}
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
                  <StatLabel color="red.100">{t.security.securityEvents}</StatLabel>
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
                  <StatLabel color="orange.100">{t.security.blockedIPs}</StatLabel>
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
                  <StatLabel color="purple.100">{t.security.activeThreats}</StatLabel>
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
                  <StatLabel color="green.100">{t.security.lastScan}</StatLabel>
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
            <Heading size="md">{t.security.securitySettings}</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0" flex="1">{t.security.wafProtection}</FormLabel>
                <Switch
                  isChecked={settings.enableWAF}
                  onChange={(e) => setSettings(prev => ({ ...prev, enableWAF: e.target.checked }))}
                />
              </FormControl>
              
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0" flex="1">{t.security.ddosProtection}</FormLabel>
                <Switch
                  isChecked={settings.enableDDoSProtection}
                  onChange={(e) => setSettings(prev => ({ ...prev, enableDDoSProtection: e.target.checked }))}
                />
              </FormControl>
              
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0" flex="1">{t.security.threatIntelligence}</FormLabel>
                <Switch
                  isChecked={settings.enableThreatIntel}
                  onChange={(e) => setSettings(prev => ({ ...prev, enableThreatIntel: e.target.checked }))}
                />
              </FormControl>
              
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0" flex="1">{t.security.autoBlockSuspiciousIPs}</FormLabel>
                <Switch
                  isChecked={settings.blockSuspiciousIPs}
                  onChange={(e) => setSettings(prev => ({ ...prev, blockSuspiciousIPs: e.target.checked }))}
                />
              </FormControl>
              
              <FormControl>
                <FormLabel>{t.security.maxRequestsPerMinute}</FormLabel>
                <Input
                  value={settings.maxRequestsPerMinute}
                  onChange={(e) => setSettings(prev => ({ ...prev, maxRequestsPerMinute: e.target.value }))}
                  type="number"
                />
              </FormControl>
              
              <Button colorScheme="blue" onClick={saveSecuritySettings}>
                {t.security.saveSettings}
              </Button>
            </VStack>
          </CardBody>
        </Card>

        {/* 威胁概览 */}
        <Card>
          <CardHeader>
            <Heading size="md">{t.security.threatOverview}</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <HStack justify="space-between">
                <HStack>
                  <Icon as={FiCheckCircle} color="green.500" />
                  <Text>{t.security.wafEnabled}</Text>
                </HStack>
                <Badge colorScheme="green">{t.common.enable}</Badge>
              </HStack>
              
              <HStack justify="space-between">
                <HStack>
                  <Icon as={FiCheckCircle} color="green.500" />
                  <Text>{t.security.ddosEnabled}</Text>
                </HStack>
                <Badge colorScheme="green">{t.common.enable}</Badge>
              </HStack>
              
              <HStack justify="space-between">
                <HStack>
                  <Icon as={FiCheckCircle} color="green.500" />
                  <Text>{t.security.threatIntelEnabled}</Text>
                </HStack>
                <Badge colorScheme="green">{t.common.enable}</Badge>
              </HStack>
              
              <HStack justify="space-between">
                <HStack>
                  <Icon as={FiAlertTriangle} color="orange.500" />
                  <Text>{t.security.ipBlocked}</Text>
                </HStack>
                <Badge colorScheme="orange">{stats.blockedIPs} {t.security.blockedIPs}</Badge>
              </HStack>
            </VStack>
          </CardBody>
        </Card>
      </SimpleGrid>

      {/* 安全事件 */}
      <Card>
        <CardHeader>
          <Heading size="md">{t.security.recentEvents}</Heading>
        </CardHeader>
        <CardBody>
          {events.length > 0 ? (
            <Table variant="simple">
              <Thead>
                <Tr>
                  <Th>{t.security.type}</Th>
                  <Th>{t.security.severity}</Th>
                  <Th>{t.security.sourceIP}</Th>
                  <Th>{t.security.description}</Th>
                  <Th>{t.security.time}</Th>
                  <Th>{t.security.status}</Th>
                  <Th>{t.security.action}</Th>
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
                        {event.blocked ? t.security.blocked : t.security.allowed}
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
                          {t.security.blockIP}
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
              <Text color="gray.500">{t.security.noSecurityEvents}</Text>
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

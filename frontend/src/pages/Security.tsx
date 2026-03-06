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
  IconButton,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Spinner,
  Center,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  MenuDivider,
} from '@chakra-ui/react'
import {
  FiShield,
  FiRefreshCw,
  FiAlertTriangle,
  FiCheckCircle,
  FiClock,
  FiX,
  FiGlobe,
  FiActivity,
  FiPlus,
  FiEdit,
  FiTrash2,
  FiUpload,
  FiDownload,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'
import GeoIPConfig from '../components/GeoIPConfig'
import WAFRulesList from '../components/WAFRulesList'
import WAFRuleEditor from '../components/WAFRuleEditor'
import WAFRuleTestTool from '../components/WAFRuleTestTool'
import { WAFStatsResponse, WAFRulesResponse, WAFEventsResponse, WAFRule, WAFEvent } from '../types/waf'
import { FeatureGate } from '../components/FeatureGate'
import { AttackFlow } from '../components/AttackFlow'

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

interface WAFStats {
  enabled: boolean
  totalRules: number
  totalEvents: number
  blockedEvents: number
  detectionRate: number
}

interface SecuritySettings {
  enableWAF: boolean
  enableDDoSProtection: boolean
  enableThreatIntel: boolean
  maxRequestsPerMinute: string
  blockSuspiciousIPs: boolean
}

const Security: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [stats, setStats] = useState<SecurityStats>({
    totalEvents: 0,
    blockedIPs: 0,
    activeThreats: 0,
    lastScan: '',
  })
  const [settings, setSettings] = useState<SecuritySettings>({
    enableWAF: true,
    enableDDoSProtection: true,
    enableThreatIntel: true,
    maxRequestsPerMinute: '1000',
    blockSuspiciousIPs: true,
  })
  const [settingsLoaded, setSettingsLoaded] = useState(false)
  
  // WAF 相关状态
  const [wafStats, setWafStats] = useState<WAFStats>({
    enabled: false,
    totalRules: 0,
    totalEvents: 0,
    blockedEvents: 0,
    detectionRate: 0,
  })
  const [wafRules, setWafRules] = useState<WAFRule[]>([])
  const [wafEvents, setWafEvents] = useState<WAFEvent[]>([])
  const [wafLoading, setWafLoading] = useState(false)

  // WAF 规则管理状态
  const [isRuleEditorOpen, setIsRuleEditorOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<WAFRule | null>(null)
  const [activeRuleTab, setActiveRuleTab] = useState<'list' | 'test'>('list')

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
        
        // 先过滤出需要显示的安全事件（WAF 事件或被阻止的访问）
        const securityEvents = logsData.logs ? logsData.logs.filter((log: any) => {
          // 显示 WAF 事件或被阻止的访问
          return log.type === 'waf' || !log.success
        }) : []
        
        // 统计信息 - 使用过滤后的事件数量，与列表保持一致
        const totalEvents = securityEvents.length
        const blockedIPs = securityEvents.filter((log: any) => !log.success).length
        const activeThreats = Math.floor(blockedIPs * 0.1) // 模拟活跃威胁数量
        
        setStats({
          totalEvents,
          blockedIPs,
          activeThreats,
          lastScan: new Date().toLocaleString('zh-CN'),
        })
        
        // 转换日志为事件格式 - 只显示有风险、可疑的事件
        const events = securityEvents
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
            }
          })
        
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

  const refreshWAFData = async () => {
    setWafLoading(true)
    try {
      const effectivePrefix = adminPrefix || '/sslcat-panel'
      
      // 获取 WAF 统计
      const statsResponse = await fetch(buildApiPath(effectivePrefix, '/api/waf/stats'), {
        method: 'GET',
        credentials: 'include',
      })
      
      if (statsResponse.ok) {
        const statsData: WAFStatsResponse = await statsResponse.json()
        if (statsData.success && statsData.data) {
          setWafStats({
            enabled: statsData.data.enabled,
            totalRules: statsData.data.total_rules || 0,
            totalEvents: statsData.data.total_events || 0,
            blockedEvents: statsData.data.blocked_events || 0,
            detectionRate: statsData.data.detection_rate || 0,
          })
        }
      }
      
      // 获取 WAF 规则
      const rulesResponse = await fetch(buildApiPath(effectivePrefix, '/api/waf/rules'), {
        method: 'GET',
        credentials: 'include',
      })
      
      if (rulesResponse.ok) {
        const rulesData: WAFRulesResponse = await rulesResponse.json()
        if (rulesData.success && rulesData.rules) {
          setWafRules(rulesData.rules)
        }
      }
      
      // 获取 WAF 事件
      const eventsResponse = await fetch(buildApiPath(effectivePrefix, '/api/waf/events?limit=50'), {
        method: 'GET',
        credentials: 'include',
      })
      
      if (eventsResponse.ok) {
        const eventsData: WAFEventsResponse = await eventsResponse.json()
        if (eventsData.success && eventsData.events) {
          setWafEvents(eventsData.events)
        }
      }
      
    } catch (error) {
      console.error('获取 WAF 数据失败:', error)
      toast({
        title: 'WAF 数据加载失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setWafLoading(false)
    }
  }

  const toggleWAF = async () => {
    try {
      const effectivePrefix = adminPrefix || '/sslcat-panel'
      const response = await fetch(buildApiPath(effectivePrefix, '/api/waf/config'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          enabled: !wafStats.enabled,
        }),
      })
      
      if (response.ok) {
        const data: WAFStatsResponse = await response.json()
        if (data.success) {
          toast({
            title: t.security.wafConfigUpdated,
            status: 'success',
            duration: 3000,
            isClosable: true,
          })
          refreshWAFData()
        }
      } else {
        throw new Error('更新 WAF 配置失败')
      }
    } catch (error) {
      console.error('更新 WAF 配置失败:', error)
      toast({
        title: t.security.wafConfigFailed,
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  // WAF 规则管理函数
  const handleOpenRuleEditor = (rule?: WAFRule) => {
    setEditingRule(rule || null)
    setIsRuleEditorOpen(true)
  }

  const handleCloseRuleEditor = () => {
    setIsRuleEditorOpen(false)
    setEditingRule(null)
  }

  const handleSaveRule = () => {
    refreshWAFData()
    handleCloseRuleEditor()
  }

  const handleDeleteRule = async (ruleId: string) => {
    try {
      const effectivePrefix = adminPrefix || '/sslcat-panel'
      const response = await fetch(buildApiPath(effectivePrefix, `/api/waf/rule/delete?id=${ruleId}`), {
        method: 'POST',
        credentials: 'include',
      })

      if (response.ok) {
        toast({
          title: '规则已删除',
          status: 'success',
          duration: 3000,
        })
        refreshWAFData()
      } else {
        throw new Error('删除规则失败')
      }
    } catch (error) {
      toast({
        title: '删除失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 5000,
      })
    }
  }

  const handleExportRules = async (format: 'json' | 'yaml') => {
    try {
      const effectivePrefix = adminPrefix || '/sslcat-panel'
      const response = await fetch(buildApiPath(effectivePrefix, `/api/waf/rules/export?format=${format}`), {
        method: 'GET',
        credentials: 'include',
      })

      if (response.ok) {
        const data = await response.text()
        const blob = new Blob([data], { type: format === 'json' ? 'application/json' : 'text/yaml' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `waf-rules.${format}`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)

        toast({
          title: '导出成功',
          status: 'success',
          duration: 3000,
        })
      } else {
        throw new Error('导出规则失败')
      }
    } catch (error) {
      toast({
        title: '导出失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 5000,
      })
    }
  }

  const handleImportRules = async (file: File, format: 'json' | 'yaml') => {
    try {
      const text = await file.text()
      const effectivePrefix = adminPrefix || '/sslcat-panel'
      const response = await fetch(buildApiPath(effectivePrefix, `/api/waf/rules/import?format=${format}`), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: text,
      })

      if (response.ok) {
        const result = await response.json()
        toast({
          title: '导入成功',
          description: `成功导入 ${result.imported_count || 0} 条规则`,
          status: 'success',
          duration: 3000,
        })
        refreshWAFData()
      } else {
        throw new Error('导入规则失败')
      }
    } catch (error) {
      toast({
        title: '导入失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 5000,
      })
    }
  }

  const saveSecuritySettings = async () => {
    try {
      const effectivePrefix = adminPrefix || '/sslcat-panel'
      const response = await fetch(buildApiPath(effectivePrefix, '/api/settings/update'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          security: {
            enable_waf: settings.enableWAF,
            enable_ddos: settings.enableDDoSProtection,
            max_attempts_5min: parseInt(settings.maxRequestsPerMinute) || 1000,
          },
        }),
      })

      if (response.ok) {
        const result = await response.json()
        if (result.success) {
          toast({
            title: '安全设置保存成功',
            status: 'success',
            duration: 3000,
            isClosable: true,
          })
          // 重新加载设置以确保同步
          await loadSecuritySettings()
        } else {
          throw new Error(result.message || '保存失败')
        }
      } else {
        throw new Error('保存失败')
      }
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

  // 加载安全设置
  const loadSecuritySettings = async () => {
    try {
      const effectivePrefix = adminPrefix || '/sslcat-panel'
      const response = await fetch(buildApiPath(effectivePrefix, '/api/settings'), {
        credentials: 'include',
      })

      if (response.ok) {
        const result = await response.json()
        if (result.success && result.data) {
          const securitySettings = result.data.security || {}
          setSettings({
            enableWAF: securitySettings.enable_waf ?? true,
            enableDDoSProtection: securitySettings.enable_ddos ?? true,
            enableThreatIntel: true,
            maxRequestsPerMinute: String(securitySettings.max_attempts_5min || 1000),
            blockSuspiciousIPs: true,
          })
          setSettingsLoaded(true)
        }
      }
    } catch (error) {
      console.error('加载安全设置失败:', error)
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
    refreshWAFData()
    loadSecuritySettings()
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
          onClick={() => {
            refreshData()
            refreshWAFData()
          }}
          isLoading={loading || wafLoading}
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
            <Icon as={FiActivity} mr={2} />
            {t.security.wafTab}
          </Tab>
          <Tab>
            <Icon as={FiEdit} mr={2} />
            规则管理
          </Tab>
          <Tab>
            <Icon as={FiGlobe} mr={2} />
            {t.security.geoFiltering}
          </Tab>
        </TabList>

        <TabPanels>
          {/* 安全概览标签页 */}
          <TabPanel px={0}>
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
                      <FormLabel htmlFor="waf-protection" mb="0" flex="1">
                        {t.security.wafProtection}
                      </FormLabel>
                      <Switch
                        id="waf-protection"
                        isChecked={settings.enableWAF}
                        onChange={(e) => setSettings({ ...settings, enableWAF: e.target.checked })}
                      />
                    </FormControl>

                    <FormControl display="flex" alignItems="center">
                      <FormLabel htmlFor="ddos-protection" mb="0" flex="1">
                        {t.security.ddosProtection}
                      </FormLabel>
                      <Switch
                        id="ddos-protection"
                        isChecked={settings.enableDDoSProtection}
                        onChange={(e) => setSettings({ ...settings, enableDDoSProtection: e.target.checked })}
                      />
                    </FormControl>

                    <FormControl display="flex" alignItems="center">
                      <FormLabel htmlFor="threat-intel" mb="0" flex="1">
                        {t.security.threatIntelligence}
                      </FormLabel>
                      <Switch
                        id="threat-intel"
                        isChecked={settings.enableThreatIntel}
                        onChange={(e) => setSettings({ ...settings, enableThreatIntel: e.target.checked })}
                      />
                    </FormControl>

                    <FormControl display="flex" alignItems="center">
                      <FormLabel htmlFor="block-suspicious" mb="0" flex="1">
                        {t.security.autoBlockSuspiciousIPs}
                      </FormLabel>
                      <Switch
                        id="block-suspicious"
                        isChecked={settings.blockSuspiciousIPs}
                        onChange={(e) => setSettings({ ...settings, blockSuspiciousIPs: e.target.checked })}
                      />
                    </FormControl>

                    <FormControl>
                      <FormLabel>{t.security.maxRequestsPerMinute}</FormLabel>
                      <Input
                        type="number"
                        value={settings.maxRequestsPerMinute}
                        onChange={(e) => setSettings({ ...settings, maxRequestsPerMinute: e.target.value })}
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
                        <Icon as={FiShield} color="green.500" />
                        <Text>{t.security.wafEnabled}</Text>
                      </HStack>
                      <Badge colorScheme={settings.enableWAF ? 'green' : 'red'}>
                        {settings.enableWAF ? t.security.ruleEnabled : t.security.ruleDisabled}
                      </Badge>
                    </HStack>

                    <HStack justify="space-between">
                      <HStack>
                        <Icon as={FiShield} color="blue.500" />
                        <Text>{t.security.ddosEnabled}</Text>
                      </HStack>
                      <Badge colorScheme={settings.enableDDoSProtection ? 'green' : 'red'}>
                        {settings.enableDDoSProtection ? t.security.ruleEnabled : t.security.ruleDisabled}
                      </Badge>
                    </HStack>

                    <HStack justify="space-between">
                      <HStack>
                        <Icon as={FiShield} color="purple.500" />
                        <Text>{t.security.threatIntelEnabled}</Text>
                      </HStack>
                      <Badge colorScheme={settings.enableThreatIntel ? 'green' : 'red'}>
                        {settings.enableThreatIntel ? t.security.ruleEnabled : t.security.ruleDisabled}
                      </Badge>
                    </HStack>

                    <HStack justify="space-between">
                      <HStack>
                        <Icon as={FiX} color="red.500" />
                        <Text>{t.security.ipBlocked}</Text>
                      </HStack>
                      <Badge colorScheme={settings.blockSuspiciousIPs ? 'green' : 'red'}>
                        {settings.blockSuspiciousIPs ? t.security.ruleEnabled : t.security.ruleDisabled}
                      </Badge>
                    </HStack>
                  </VStack>
                </CardBody>
              </Card>
            </SimpleGrid>

            {/* 攻击流可视化 */}
            {events.length > 0 && (
              <Card mb={6}>
                <CardHeader>
                  <Heading size="md">攻击流可视化</Heading>
                </CardHeader>
                <CardBody>
                  <FeatureGate
                    require={['canvas2d']}
                    fallback={
                      <Box p={4} textAlign="center" color="gray.500">
                        <Text>您的浏览器不支持 Canvas，请使用表格视图查看安全事件</Text>
                      </Box>
                    }
                    showFallbackNotice={false}
                  >
                    <AttackFlow events={events.slice(0, 20)} height={400} />
                  </FeatureGate>
                </CardBody>
              </Card>
            )}

            {/* 安全事件列表 */}
            <Card>
              <CardHeader>
                <Heading size="md">{t.security.recentEvents}</Heading>
              </CardHeader>
              <CardBody>
                {events.length === 0 ? (
                  <Text color="gray.500" textAlign="center" py={4}>
                    {t.security.noSecurityEvents}
                  </Text>
                ) : (
                  <Box overflowX="auto">
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
                            <Td>
                              <Badge colorScheme="blue">{getTypeText(event.type)}</Badge>
                            </Td>
                            <Td>
                              <Badge colorScheme={getSeverityColor(event.severity)}>
                                {getSeverityText(event.severity)}
                              </Badge>
                            </Td>
                            <Td>
                              <Text fontSize="sm" fontFamily="mono">
                                {event.source}
                              </Text>
                            </Td>
                            <Td>
                              <Text fontSize="sm" noOfLines={2}>
                                {event.description}
                              </Text>
                            </Td>
                            <Td>
                              <Text fontSize="sm">{event.timestamp}</Text>
                            </Td>
                            <Td>
                              <HStack>
                                <Icon
                                  as={event.blocked ? FiX : FiCheckCircle}
                                  color={event.blocked ? 'red.500' : 'green.500'}
                                />
                                <Text fontSize="sm">
                                  {event.blocked ? t.security.blocked : t.security.allowed}
                                </Text>
                              </HStack>
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
                  </Box>
                )}
              </CardBody>
            </Card>
          </TabPanel>

          {/* WAF 防护标签页 */}
          <TabPanel px={0}>
            {wafLoading ? (
              <Center py={8}>
                <Spinner size="xl" color="blue.500" />
              </Center>
            ) : (
              <VStack spacing={6} align="stretch">
                {/* WAF 统计卡片 */}
                <SimpleGrid columns={{ base: 1, md: 2, lg: 5 }} spacing={6}>
                  <Card>
                    <CardBody>
                      <Stat>
                        <StatLabel>{t.security.wafStatus}</StatLabel>
                        <HStack mt={2}>
                          <Badge colorScheme={wafStats.enabled ? 'green' : 'red'} fontSize="md" px={3} py={1}>
                            {wafStats.enabled ? t.security.ruleEnabled : t.security.ruleDisabled}
                          </Badge>
                        </HStack>
                      </Stat>
                    </CardBody>
                  </Card>

                  <Card>
                    <CardBody>
                      <Stat>
                        <StatLabel>{t.security.totalRules}</StatLabel>
                        <StatNumber color="blue.500">{wafStats.totalRules}</StatNumber>
                      </Stat>
                    </CardBody>
                  </Card>

                  <Card>
                    <CardBody>
                      <Stat>
                        <StatLabel>{t.security.totalEvents}</StatLabel>
                        <StatNumber color="purple.500">{wafStats.totalEvents}</StatNumber>
                      </Stat>
                    </CardBody>
                  </Card>

                  <Card>
                    <CardBody>
                      <Stat>
                        <StatLabel>{t.security.totalBlocked}</StatLabel>
                        <StatNumber color="red.500">{wafStats.blockedEvents}</StatNumber>
                      </Stat>
                    </CardBody>
                  </Card>

                  <Card>
                    <CardBody>
                      <Stat>
                        <StatLabel>{t.security.detectionRate}</StatLabel>
                        <StatNumber color="green.500">{wafStats.detectionRate.toFixed(1)}%</StatNumber>
                      </Stat>
                    </CardBody>
                  </Card>
                </SimpleGrid>

                {/* WAF 配置 */}
                <Card>
                  <CardHeader>
                    <Heading size="md">{t.security.wafConfig}</Heading>
                  </CardHeader>
                  <CardBody>
                    <HStack justify="space-between">
                      <VStack align="start" spacing={1}>
                        <Text fontWeight="medium">{t.security.wafProtection}</Text>
                        <Text fontSize="sm" color="gray.600">
                          {wafStats.enabled ? '当前 WAF 正在保护您的应用' : '建议启用 WAF 以增强安全性'}
                        </Text>
                      </VStack>
                      <Switch
                        size="lg"
                        isChecked={wafStats.enabled}
                        onChange={toggleWAF}
                        colorScheme="green"
                      />
                    </HStack>
                  </CardBody>
                </Card>

                {/* WAF 规则列表 */}
                <Card>
                  <CardHeader>
                    <Heading size="md">{t.security.wafRules}</Heading>
                  </CardHeader>
                  <CardBody>
                    {wafRules.length === 0 ? (
                      <Text color="gray.500" textAlign="center" py={4}>
                        {t.security.noRules}
                      </Text>
                    ) : (
                      <WAFRulesList rules={wafRules} />
                    )}
                  </CardBody>
                </Card>

                {/* 最近的 WAF 事件 */}
                <Card>
                  <CardHeader>
                    <Heading size="md">{t.security.recentEvents}</Heading>
                  </CardHeader>
                  <CardBody>
                    {wafEvents.length === 0 ? (
                      <Text color="gray.500" textAlign="center" py={4}>
                        {t.security.noEvents}
                      </Text>
                    ) : (
                      <Box overflowX="auto">
                        <Table variant="simple" size="sm">
                          <Thead>
                            <Tr>
                              <Th>{t.security.time}</Th>
                              <Th>{t.security.sourceIP}</Th>
                              <Th>URL</Th>
                              <Th>{t.security.ruleName}</Th>
                              <Th>{t.security.ruleType}</Th>
                              <Th>{t.security.ruleAction}</Th>
                              <Th>{t.security.status}</Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {wafEvents.map((event) => (
                              <Tr key={event.id}>
                                <Td>
                                  <Text fontSize="xs">
                                    {new Date(event.timestamp).toLocaleString('zh-CN')}
                                  </Text>
                                </Td>
                                <Td>
                                  <Text fontSize="xs" fontFamily="mono">
                                    {event.client_ip}
                                  </Text>
                                </Td>
                                <Td>
                                  <Text fontSize="xs" noOfLines={1} maxW="200px">
                                    {event.url}
                                  </Text>
                                </Td>
                                <Td>
                                  <Text fontSize="xs">{event.rule_name}</Text>
                                </Td>
                                <Td>
                                  <Badge colorScheme="blue" fontSize="xs">
                                    {event.rule_type}
                                  </Badge>
                                </Td>
                                <Td>
                                  <Badge
                                    colorScheme={
                                      event.action === 'block' ? 'red' : event.action === 'warn' ? 'orange' : 'blue'
                                    }
                                    fontSize="xs"
                                  >
                                    {event.action}
                                  </Badge>
                                </Td>
                                <Td>
                                  <HStack>
                                    <Icon
                                      as={event.blocked ? FiX : FiCheckCircle}
                                      color={event.blocked ? 'red.500' : 'green.500'}
                                      boxSize={3}
                                    />
                                    <Text fontSize="xs">
                                      {event.blocked ? t.security.blocked : t.security.allowed}
                                    </Text>
                                  </HStack>
                                </Td>
                              </Tr>
                            ))}
                          </Tbody>
                        </Table>
                      </Box>
                    )}
                  </CardBody>
                </Card>
              </VStack>
            )}
          </TabPanel>

          {/* WAF 规则管理标签页 */}
          <TabPanel px={0}>
            <VStack spacing={6} align="stretch">
              {/* 操作栏 */}
              <Card>
                <CardBody>
                  <HStack justify="space-between">
                    <Text fontSize="lg" fontWeight="bold">
                      WAF 规则管理
                    </Text>
                    <HStack spacing={2}>
                      <Button
                        size="sm"
                        colorScheme="blue"
                        leftIcon={<FiPlus />}
                        onClick={() => handleOpenRuleEditor()}
                      >
                        新建规则
                      </Button>
                      <Menu>
                        <MenuButton as={Button} size="sm" variant="outline">
                          导入/导出
                        </MenuButton>
                        <MenuList>
                          <MenuItem icon={<FiDownload />} onClick={() => handleExportRules('json')}>
                            导出为 JSON
                          </MenuItem>
                          <MenuItem icon={<FiDownload />} onClick={() => handleExportRules('yaml')}>
                            导出为 YAML
                          </MenuItem>
                          <MenuDivider />
                          <MenuItem icon={<FiUpload />}>
                            <label htmlFor="import-json" style={{ cursor: 'pointer', width: '100%', display: 'block' }}>
                              导入 JSON
                            </label>
                          </MenuItem>
                          <MenuItem icon={<FiUpload />}>
                            <label htmlFor="import-yaml" style={{ cursor: 'pointer', width: '100%', display: 'block' }}>
                              导入 YAML
                            </label>
                          </MenuItem>
                          <input
                            id="import-json"
                            type="file"
                            accept=".json"
                            style={{ display: 'none' }}
                            onChange={(e) => {
                              const file = e.target.files?.[0]
                              if (file) handleImportRules(file, 'json')
                            }}
                          />
                          <input
                            id="import-yaml"
                            type="file"
                            accept=".yaml,.yml"
                            style={{ display: 'none' }}
                            onChange={(e) => {
                              const file = e.target.files?.[0]
                              if (file) handleImportRules(file, 'yaml')
                            }}
                          />
                        </MenuList>
                      </Menu>
                    </HStack>
                  </HStack>
                </CardBody>
              </Card>

              {/* 规则列表和测试工具 */}
              <Tabs>
                <TabList>
                  <Tab>规则列表</Tab>
                  <Tab>测试工具</Tab>
                </TabList>
                <TabPanels>
                  {/* 规则列表子标签页 */}
                  <TabPanel>
                    {wafLoading ? (
                      <Center py={8}>
                        <Spinner size="xl" color="blue.500" />
                      </Center>
                    ) : (
                      <Card>
                        <CardBody>
                          {wafRules.length === 0 ? (
                            <VStack py={8} spacing={4}>
                              <Text color="gray.500">暂无 WAF 规则</Text>
                              <Button
                                colorScheme="blue"
                                leftIcon={<FiPlus />}
                                onClick={() => handleOpenRuleEditor()}
                              >
                                创建第一条规则
                              </Button>
                            </VStack>
                          ) : (
                            <Table variant="simple">
                              <Thead>
                                <Tr>
                                  <Th>规则名称</Th>
                                  <Th>类型</Th>
                                  <Th>动作</Th>
                                  <Th>状态</Th>
                                  <Th>操作</Th>
                                </Tr>
                              </Thead>
                              <Tbody>
                                {wafRules.map((rule) => (
                                  <Tr key={rule.id}>
                                    <Td>
                                      <VStack align="start" spacing={0}>
                                        <Text fontWeight="medium">{rule.name}</Text>
                                        <Text fontSize="xs" color="gray.500">
                                          {rule.id}
                                        </Text>
                                      </VStack>
                                    </Td>
                                    <Td>
                                      <Badge colorScheme="blue">{rule.type}</Badge>
                                    </Td>
                                    <Td>
                                      <Badge colorScheme={
                                        rule.action === 'block' ? 'red' :
                                        rule.action === 'log' ? 'blue' : 'gray'
                                      }>
                                        {rule.action}
                                      </Badge>
                                    </Td>
                                    <Td>
                                      <Badge colorScheme={rule.enabled ? 'green' : 'gray'}>
                                        {rule.enabled ? '启用' : '禁用'}
                                      </Badge>
                                    </Td>
                                    <Td>
                                      <HStack spacing={2}>
                                        <IconButton
                                          size="sm"
                                          aria-label="编辑规则"
                                          icon={<FiEdit />}
                                          onClick={() => handleOpenRuleEditor(rule)}
                                        />
                                        <IconButton
                                          size="sm"
                                          aria-label="删除规则"
                                          icon={<FiTrash2 />}
                                          colorScheme="red"
                                          variant="ghost"
                                          onClick={() => {
                                            if (window.confirm(`确定要删除规则 "${rule.name}" 吗？`)) {
                                              handleDeleteRule(rule.id)
                                            }
                                          }}
                                        />
                                      </HStack>
                                    </Td>
                                  </Tr>
                                ))}
                              </Tbody>
                            </Table>
                          )}
                        </CardBody>
                      </Card>
                    )}
                  </TabPanel>

                  {/* 测试工具子标签页 */}
                  <TabPanel>
                    <WAFRuleTestTool existingRules={wafRules} />
                  </TabPanel>
                </TabPanels>
              </Tabs>
            </VStack>
          </TabPanel>

          {/* 地理位置过滤标签页 */}
          <TabPanel px={0}>
            <GeoIPConfig />
          </TabPanel>
        </TabPanels>
      </Tabs>

      {/* WAF 规则编辑器模态框 */}
      <WAFRuleEditor
        isOpen={isRuleEditorOpen}
        onClose={handleCloseRuleEditor}
        onSave={handleSaveRule}
        editRule={editingRule}
      />
    </Box>
  )
}

export default Security

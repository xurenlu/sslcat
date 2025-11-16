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
  FormControl,
  FormLabel,
  Input,
  Select,
  Switch,
  useToast,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Divider,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
  Code,
  Link,
  Spinner,
  Center,
} from '@chakra-ui/react'
import {
  FiRefreshCw,
  FiCheckCircle,
  FiSettings,
  FiAlertTriangle,
  FiClock,
  FiSave,
  FiZap,
  FiShield,
} from 'react-icons/fi'
import { FaRobot } from 'react-icons/fa'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'
import { TOAST_DURATION } from '../constants'

interface AISecurityConfig {
  enabled: boolean
  api_key: string
  api_endpoint: string
  model: string
  check_interval: string
  max_tokens: number
  temperature: number
  min_threat_level: string
  min_events: number
  language: string
}

interface ThreatDetection {
  type: string
  severity: string
  description_zh?: string
  description_en?: string
  description?: string
  indicators?: string[]
  confidence: number
  action_zh?: string
  action_en?: string
  action?: string
}

interface AnalysisResult {
  timestamp: string
  threat_level: string
  summary_zh?: string
  summary_en?: string
  summary?: string
  threats: ThreatDetection[]
  recommendations_zh?: string[]
  recommendations_en?: string[]
  recommendations?: string[]
  confidence: number
}

const AISecurityAnalysis: React.FC = () => {
  const [config, setConfig] = useState<AISecurityConfig>({
    enabled: false,
    api_key: '',
    api_endpoint: '',
    model: 'gpt-4o-mini',
    check_interval: '1h',
    max_tokens: 3000,
    temperature: 0.3,
    min_threat_level: 'medium',
    min_events: 10,
    language: 'zh-CN',
  })
  const [lastAnalysis, setLastAnalysis] = useState<AnalysisResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [testing, setTesting] = useState(false)
  const [analyzing, setAnalyzing] = useState(false)
  const [apiProvider, setApiProvider] = useState('openai')
  
  const toast = useToast()
  const { adminPrefix } = useConfig()
  const t = useTranslation()

  // 加载配置
  useEffect(() => {
    loadConfig()
  }, [])

  const loadConfig = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/ai-security/config'), {
        credentials: 'include'
      })
      
      if (response.ok) {
        const data = await response.json()
        if (data.success && data.config) {
          // 确保所有字段都有值
          const loadedConfig = {
            enabled: data.config.enabled || false,
            api_key: data.config.api_key || '',
            api_endpoint: data.config.api_endpoint || '',
            model: data.config.model || 'gpt-4o-mini',
            check_interval: data.config.check_interval || '1h',
            max_tokens: data.config.max_tokens || 3000,
            temperature: data.config.temperature !== undefined ? data.config.temperature : 0.3,
            min_threat_level: data.config.min_threat_level || 'medium',
            min_events: data.config.min_events || 10,
            language: data.config.language || 'zh-CN',
          }
          setConfig(loadedConfig)
          
          // 根据 endpoint 判断 provider
          const endpoint = data.config.api_endpoint || ''
          if (endpoint.includes('poe.com')) {
            setApiProvider('poe')
          } else if (endpoint.includes('azure')) {
            setApiProvider('azure')
          } else if (endpoint && endpoint !== '' && endpoint !== 'https://api.openai.com/v1/chat/completions') {
            setApiProvider('custom')
          } else {
            setApiProvider('openai')
          }
        }
      }
    } catch (error) {
      console.error('Failed to load config:', error)
    }
  }

  // 保存配置
  const saveConfig = async () => {
    setLoading(true)
    try {
      // 根据 provider 设置 endpoint
      let endpoint = config.api_endpoint
      if (apiProvider === 'openai') {
        endpoint = 'https://api.openai.com/v1/chat/completions'
      } else if (apiProvider === 'poe') {
        endpoint = 'https://api.poe.com/v1/chat/completions'
      }

      const saveData = { ...config, api_endpoint: endpoint }
      
      const response = await fetch(buildApiPath(adminPrefix, '/api/ai-security/config'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(saveData)
      })
      
      const data = await response.json()
      if (data.success) {
        toast({
          title: t.common.success,
          status: 'success',
          duration: TOAST_DURATION.SHORT,
          isClosable: true,
        })
        loadConfig()
      } else {
        toast({
          title: t.common.error,
          description: data.error || t.common.error,
          status: 'error',
          duration: TOAST_DURATION.MEDIUM,
          isClosable: true,
        })
      }
    } catch (error) {
      toast({
        title: t.common.error,
        description: String(error),
        status: 'error',
        duration: 5000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  // 测试 API 连接
  const testAPI = async () => {
    if (!config.api_key) {
      toast({
        title: t.common.warning,
        status: 'warning',
        duration: TOAST_DURATION.SHORT,
      })
      return
    }

    setTesting(true)
    try {
      let endpoint = config.api_endpoint
      if (apiProvider === 'openai') {
        endpoint = 'https://api.openai.com/v1/chat/completions'
      } else if (apiProvider === 'poe') {
        endpoint = 'https://api.poe.com/v1/chat/completions'
      }

      const response = await fetch(buildApiPath(adminPrefix, '/api/ai-security/test'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          api_key: config.api_key,
          api_endpoint: endpoint,
          model: config.model
        })
      })
      
      const data = await response.json()
      if (data.success) {
        toast({
          title: `✅ ${t.common.success}`,
          description: `${t.aiSecurity.model}: ${data.model}`,
          status: 'success',
          duration: TOAST_DURATION.MEDIUM,
          isClosable: true,
        })
      } else {
        toast({
          title: `❌ ${t.common.error}`,
          description: data.error || t.common.error,
          status: 'error',
          duration: TOAST_DURATION.MEDIUM,
          isClosable: true,
        })
      }
    } catch (error) {
      toast({
        title: t.common.error,
        description: String(error),
        status: 'error',
        duration: 5000,
        isClosable: true,
      })
    } finally {
      setTesting(false)
    }
  }

  // 立即执行分析
  const analyzeNow = async () => {
    setAnalyzing(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/ai-security/analyze-now'), {
        method: 'POST',
        credentials: 'include'
      })
      
      const data = await response.json()
      if (data.success) {
        toast({
          title: `✅ ${t.common.success}`,
          description: `${t.aiSecurity.threatLevel}: ${data.threat_level}\n${t.aiSecurity.aiConfidence}: ${Math.round(data.confidence * 100)}%`,
          status: 'success',
          duration: TOAST_DURATION.MEDIUM,
          isClosable: true,
        })
        // 重新加载分析结果
        setTimeout(() => window.location.reload(), 1000)
      } else {
        toast({
          title: t.common.error,
          description: data.error || t.common.error,
          status: 'error',
          duration: TOAST_DURATION.MEDIUM,
          isClosable: true,
        })
      }
    } catch (error) {
      toast({
        title: t.common.error,
        description: String(error),
        status: 'error',
        duration: 5000,
        isClosable: true,
      })
    } finally {
      setAnalyzing(false)
    }
  }

  const getThreatColor = (level: string) => {
    switch (level?.toLowerCase()) {
      case 'critical': return 'purple'
      case 'high': return 'red'
      case 'medium': return 'orange'
      case 'low': return 'blue'
      default: return 'gray'
    }
  }

  return (
    <Box p={8}>
      <Flex justify="space-between" align="center" mb={6}>
        <HStack>
          <Icon as={FaRobot} boxSize={8} color="purple.500" />
          <Heading size="lg">{t.aiSecurity.title}</Heading>
          <Badge colorScheme="purple" fontSize="sm">AI Powered</Badge>
        </HStack>
        <Button
          leftIcon={<FiRefreshCw />}
          onClick={() => window.location.reload()}
          size="sm"
          variant="outline"
        >
          {t.common.refresh}
        </Button>
      </Flex>

      {/* 配置卡片 */}
      <Card mb={6}>
        <CardHeader>
          <HStack>
            <Icon as={FiSettings} />
            <Heading size="md">{t.aiSecurity.config}</Heading>
          </HStack>
        </CardHeader>
        <CardBody>
          <VStack spacing={4} align="stretch">
            {/* 启用开关 */}
            <FormControl display="flex" alignItems="center">
              <FormLabel mb={0} flex={1}>
                {t.aiSecurity.enable}
              </FormLabel>
              <Switch
                isChecked={config.enabled}
                onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
                colorScheme="purple"
              />
            </FormControl>

            {config.enabled && (
              <>
                <Divider />
                
                {/* API 配置 */}
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                  <FormControl>
                    <FormLabel>{t.aiSecurity.apiProvider}</FormLabel>
                    <Select
                      value={apiProvider}
                      onChange={(e) => setApiProvider(e.target.value)}
                    >
                      <option value="openai">OpenAI 官方</option>
                      <option value="poe">POE ({t.aiSecurity.recommended})</option>
                      <option value="azure">Azure OpenAI</option>
                      <option value="custom">自定义端点</option>
                    </Select>
                  </FormControl>

                  <FormControl isRequired>
                    <FormLabel>{t.aiSecurity.apiKey}</FormLabel>
                    <Input
                      type="password"
                      value={config.api_key}
                      onChange={(e) => setConfig({ ...config, api_key: e.target.value })}
                      placeholder={t.ai.api_key_placeholder}
                    />
                    <Text fontSize="xs" color="gray.500" mt={1}>
                      <Link href="https://platform.openai.com/api-keys" isExternal color="blue.500">
                        {t.aiSecurity.getOpenAIKey}
                      </Link>
                      {' | '}
                      <Link href="https://poe.com/api_key" isExternal color="blue.500">
                        {t.aiSecurity.getPOEKey}
                      </Link>
                    </Text>
                  </FormControl>

                  {apiProvider === 'custom' && (
                    <FormControl>
                      <FormLabel>{t.aiSecurity.apiEndpoint}</FormLabel>
                      <Input
                        value={config.api_endpoint}
                        onChange={(e) => setConfig({ ...config, api_endpoint: e.target.value })}
                        placeholder="https://api.openai.com/v1/chat/completions"
                      />
                    </FormControl>
                  )}

                  <FormControl>
                    <FormLabel>{t.aiSecurity.model}</FormLabel>
                    <Select
                      value={config.model}
                      onChange={(e) => setConfig({ ...config, model: e.target.value })}
                    >
                      <optgroup label="OpenAI">
                        <option value="gpt-4o-mini">GPT-4 mini (最便宜)</option>
                        <option value="gpt-4o">GPT-4o</option>
                        <option value="gpt-4-turbo">GPT-4 Turbo</option>
                        <option value="gpt-3.5-turbo">GPT-3.5 Turbo</option>
                      </optgroup>
                      <optgroup label={t.ai.poe_models_label}>
                        <option value="GPT-4-Turbo">GPT-4-Turbo (推荐)</option>
                        <option value="Claude-3-Sonnet">Claude-3-Sonnet (性价比)</option>
                        <option value="Claude-3-Opus">Claude-3-Opus (最高准确度)</option>
                        <option value="GPT-3.5-Turbo">GPT-3.5-Turbo (最快)</option>
                      </optgroup>
                    </Select>
                  </FormControl>

                  <FormControl>
                    <FormLabel>{t.aiSecurity.checkInterval}</FormLabel>
                    <Select
                      value={config.check_interval}
                      onChange={(e) => setConfig({ ...config, check_interval: e.target.value })}
                    >
                      <option value="30m">30 分钟</option>
                      <option value="1h">1 小时 ({t.aiSecurity.recommended})</option>
                      <option value="2h">2 小时</option>
                      <option value="4h">4 小时</option>
                      <option value="6h">6 小时</option>
                      <option value="12h">12 小时</option>
                    </Select>
                  </FormControl>

                  <FormControl>
                    <FormLabel>🌐 分析语言 / Analysis Language</FormLabel>
                    <Select
                      value={config.language || 'zh-CN'}
                      onChange={(e) => setConfig({ ...config, language: e.target.value })}
                    >
                      <option value="zh-CN">🇨🇳 简体中文 (Chinese Simplified)</option>
                      <option value="en-US">🇺🇸 English (英语)</option>
                    </Select>
                    <Text fontSize="xs" color="gray.500" mt={1}>
                      AI 分析结果和邮件通知将使用此语言
                    </Text>
                  </FormControl>

                  <FormControl>
                    <FormLabel>{t.aiSecurity.maxTokens}</FormLabel>
                    <Input
                      type="number"
                      value={config.max_tokens}
                      onChange={(e) => setConfig({ ...config, max_tokens: parseInt(e.target.value) })}
                      min={500}
                      max={8000}
                    />
                    <Text fontSize="xs" color="gray.500">{t.aiSecurity.maxTokensDesc}</Text>
                  </FormControl>

                  <FormControl>
                    <FormLabel>{t.aiSecurity.temperature}</FormLabel>
                    <Input
                      type="number"
                      value={config.temperature}
                      onChange={(e) => setConfig({ ...config, temperature: parseFloat(e.target.value) })}
                      min={0}
                      max={1}
                      step={0.1}
                    />
                    <Text fontSize="xs" color="gray.500">{t.aiSecurity.temperatureDesc}</Text>
                  </FormControl>

                  <FormControl>
                    <FormLabel>{t.aiSecurity.minThreatLevel}</FormLabel>
                    <Select
                      value={config.min_threat_level}
                      onChange={(e) => setConfig({ ...config, min_threat_level: e.target.value })}
                    >
                      <option value="low">Low - 所有威胁</option>
                      <option value="medium">Medium - 中等及以上</option>
                      <option value="high">High - 高危及以上</option>
                      <option value="critical">Critical - 仅严重威胁</option>
                    </Select>
                  </FormControl>

                  <FormControl>
                    <FormLabel>{t.aiSecurity.minEvents}</FormLabel>
                    <Input
                      type="number"
                      value={config.min_events}
                      onChange={(e) => setConfig({ ...config, min_events: parseInt(e.target.value) })}
                      min={1}
                    />
                    <Text fontSize="xs" color="gray.500">{t.aiSecurity.minEventsDesc}</Text>
                  </FormControl>
                </SimpleGrid>

                {/* 测试连接按钮 */}
                <HStack justify="flex-end" mt={4}>
                  <Button
                    leftIcon={<FiCheckCircle />}
                    onClick={testAPI}
                    isLoading={testing}
                    loadingText={t.aiSecurity.testing}
                    colorScheme="gray"
                    variant="outline"
                  >
                    {t.aiSecurity.testConnection}
                  </Button>
                </HStack>
              </>
            )}

            {/* 保存按钮 - 始终显示，即使开关关闭时也可以保存关闭状态 */}
            <HStack justify="flex-end" mt={4}>
                  <Button
                    leftIcon={<FiSave />}
                    onClick={saveConfig}
                    isLoading={loading}
                    loadingText={t.aiSecurity.saving}
                    colorScheme="purple"
                  >
                    {t.aiSecurity.saveConfig}
                  </Button>
                </HStack>
          </VStack>
        </CardBody>
      </Card>

      {/* 统计卡片 */}
      {config.enabled && (
        <>
          <SimpleGrid columns={{ base: 1, md: 4 }} spacing={4} mb={6}>
            <Card>
              <CardBody>
                <Stat>
                  <StatLabel>
                    <HStack>
                      <Icon as={FiClock} />
                      <Text>{t.aiSecurity.lastAnalysis}</Text>
                    </HStack>
                  </StatLabel>
                  <StatNumber fontSize="xl">
                    {lastAnalysis ? new Date(lastAnalysis.timestamp).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }) : '--:--'}
                  </StatNumber>
                  <StatHelpText>
                    {lastAnalysis && new Date(lastAnalysis.timestamp).toLocaleDateString('zh-CN')}
                  </StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card>
              <CardBody>
                <Stat>
                  <StatLabel>
                    <HStack>
                      <Icon as={FiAlertTriangle} />
                      <Text>{t.aiSecurity.threatLevel}</Text>
                    </HStack>
                  </StatLabel>
                  <StatNumber fontSize="xl">
                    {lastAnalysis ? (
                      <Badge colorScheme={getThreatColor(lastAnalysis.threat_level)} fontSize="lg">
                        {lastAnalysis.threat_level?.toUpperCase() || 'UNKNOWN'}
                      </Badge>
                    ) : '--'}
                  </StatNumber>
                </Stat>
              </CardBody>
            </Card>

            <Card>
              <CardBody>
                <Stat>
                  <StatLabel>
                    <HStack>
                      <Icon as={FaRobot} />
                      <Text>{t.aiSecurity.aiConfidence}</Text>
                    </HStack>
                  </StatLabel>
                  <StatNumber fontSize="xl">
                    {lastAnalysis ? `${Math.round(lastAnalysis.confidence * 100)}%` : '--'}
                  </StatNumber>
                </Stat>
              </CardBody>
            </Card>

            <Card>
              <CardBody>
                <Stat>
                  <StatLabel>
                    <HStack>
                      <Icon as={FiShield} />
                      <Text>{t.aiSecurity.threatsFound}</Text>
                    </HStack>
                  </StatLabel>
                  <StatNumber fontSize="xl">
                    {lastAnalysis?.threats?.length || 0}
                  </StatNumber>
                  <StatHelpText>
                    <Button
                      size="xs"
                      leftIcon={<FiZap />}
                      onClick={analyzeNow}
                      isLoading={analyzing}
                      colorScheme="purple"
                      variant="ghost"
                    >
                      {t.aiSecurity.analyzeNow}
                    </Button>
                  </StatHelpText>
                </Stat>
              </CardBody>
            </Card>
          </SimpleGrid>

          {/* 最新分析结果 */}
          {lastAnalysis ? (
            <Card mb={6}>
              <CardHeader bg={`${getThreatColor(lastAnalysis.threat_level)}.50`}>
                <HStack justify="space-between">
                  <Heading size="md">📄 {t.aiSecurity.latestResult}</Heading>
                  <Badge colorScheme={getThreatColor(lastAnalysis.threat_level)} fontSize="md">
                    {lastAnalysis.threat_level?.toUpperCase()}
                  </Badge>
                </HStack>
              </CardHeader>
              <CardBody>
                <VStack spacing={4} align="stretch">
                  {/* 总结 */}
                  <Box>
                    <Text fontWeight="bold" mb={2}>💡 {t.aiSecurity.summary}:</Text>
                    {lastAnalysis.summary_zh && (
                      <Alert status="info" mb={2}>
                        <AlertIcon />
                        <Box flex={1}>
                          <AlertTitle fontSize="sm">{t.aiSecurity.chinese}:</AlertTitle>
                          <AlertDescription fontSize="sm">{lastAnalysis.summary_zh}</AlertDescription>
                        </Box>
                      </Alert>
                    )}
                    {lastAnalysis.summary_en && (
                      <Alert status="info">
                        <AlertIcon />
                        <Box flex={1}>
                          <AlertTitle fontSize="sm">{t.aiSecurity.english}:</AlertTitle>
                          <AlertDescription fontSize="sm">{lastAnalysis.summary_en}</AlertDescription>
                        </Box>
                      </Alert>
                    )}
                  </Box>

                  {/* 威胁列表 */}
                  {lastAnalysis.threats && lastAnalysis.threats.length > 0 && (
                    <Box>
                      <Text fontWeight="bold" mb={2}>🚨 {t.aiSecurity.detectedThreats}:</Text>
                      <Accordion allowMultiple>
                        {lastAnalysis.threats.map((threat, index) => (
                          <AccordionItem key={index}>
                            <AccordionButton>
                              <Box flex={1} textAlign="left">
                                <HStack>
                                  <Badge colorScheme={getThreatColor(threat.severity)}>
                                    {threat.severity?.toUpperCase()}
                                  </Badge>
                                  <Text fontWeight="bold">{threat.type}</Text>
                                  <Text fontSize="sm" color="gray.500">
                                    ({t.aiSecurity.confidence}: {Math.round(threat.confidence * 100)}%)
                                  </Text>
                                </HStack>
                              </Box>
                              <AccordionIcon />
                            </AccordionButton>
                            <AccordionPanel pb={4}>
                              <VStack align="stretch" spacing={3}>
                                {threat.description_zh && (
                                  <Box>
                                    <Text fontSize="sm" fontWeight="bold">📝 {t.aiSecurity.description} ({t.aiSecurity.chinese}):</Text>
                                    <Text fontSize="sm" color="gray.700">{threat.description_zh}</Text>
                                  </Box>
                                )}
                                {threat.description_en && (
                                  <Box>
                                    <Text fontSize="sm" fontWeight="bold">📝 {t.aiSecurity.description} ({t.aiSecurity.english}):</Text>
                                    <Text fontSize="sm" color="gray.700">{threat.description_en}</Text>
                                  </Box>
                                )}
                                {threat.indicators && threat.indicators.length > 0 && (
                                  <Box>
                                    <Text fontSize="sm" fontWeight="bold">🎯 {t.aiSecurity.indicators}:</Text>
                                    <HStack wrap="wrap">
                                      {threat.indicators.map((ind, i) => (
                                        <Code key={i} fontSize="xs">{ind}</Code>
                                      ))}
                                    </HStack>
                                  </Box>
                                )}
                                {threat.action_zh && (
                                  <Box>
                                    <Text fontSize="sm" fontWeight="bold">💡 {t.aiSecurity.action} ({t.aiSecurity.chinese}):</Text>
                                    <Text fontSize="sm" color="gray.700">{threat.action_zh}</Text>
                                  </Box>
                                )}
                                {threat.action_en && (
                                  <Box>
                                    <Text fontSize="sm" fontWeight="bold">💡 {t.aiSecurity.action} ({t.aiSecurity.english}):</Text>
                                    <Text fontSize="sm" color="gray.700">{threat.action_en}</Text>
                                  </Box>
                                )}
                              </VStack>
                            </AccordionPanel>
                          </AccordionItem>
                        ))}
                      </Accordion>
                    </Box>
                  )}

                  {/* 安全建议 */}
                  {((lastAnalysis.recommendations_zh && lastAnalysis.recommendations_zh.length > 0) ||
                    (lastAnalysis.recommendations_en && lastAnalysis.recommendations_en.length > 0)) && (
                    <Box>
                      <Text fontWeight="bold" mb={2}>💼 {t.aiSecurity.recommendations}:</Text>
                      {lastAnalysis.recommendations_zh && lastAnalysis.recommendations_zh.length > 0 && (
                        <Box mb={2}>
                          <Text fontSize="sm" fontWeight="bold" color="gray.600">【{t.aiSecurity.chinese}】</Text>
                          <VStack align="stretch" spacing={1} mt={1}>
                            {lastAnalysis.recommendations_zh.map((rec, i) => (
                              <Text key={i} fontSize="sm" pl={4}>
                                {i + 1}. {rec}
                              </Text>
                            ))}
                          </VStack>
                        </Box>
                      )}
                      {lastAnalysis.recommendations_en && lastAnalysis.recommendations_en.length > 0 && (
                        <Box>
                          <Text fontSize="sm" fontWeight="bold" color="gray.600">【{t.aiSecurity.english}】</Text>
                          <VStack align="stretch" spacing={1} mt={1}>
                            {lastAnalysis.recommendations_en.map((rec, i) => (
                              <Text key={i} fontSize="sm" pl={4}>
                                {i + 1}. {rec}
                              </Text>
                            ))}
                          </VStack>
                        </Box>
                      )}
                    </Box>
                  )}

                  <Divider />

                  {/* 元数据 */}
                  <SimpleGrid columns={{ base: 1, md: 2 }} spacing={2} fontSize="sm" color="gray.500">
                    <Text>⏱️ {t.aiSecurity.analysisTime}: {new Date(lastAnalysis.timestamp).toLocaleString('zh-CN')}</Text>
                    <Text>🤖 {t.aiSecurity.aiEngine}: {config.model}</Text>
                  </SimpleGrid>
                </VStack>
              </CardBody>
            </Card>
          ) : (
            <Alert status="info" mb={6}>
              <AlertIcon />
              <Box>
                <AlertTitle>{t.aiSecurity.noResults}</AlertTitle>
                <AlertDescription>
                  {t.aiSecurity.noResultsDesc}
                </AlertDescription>
              </Box>
            </Alert>
          )}

          {/* 成本估算 */}
          <Card>
            <CardHeader>
              <Heading size="md">💰 {t.aiSecurity.costEstimate}</Heading>
            </CardHeader>
            <CardBody>
              <SimpleGrid columns={{ base: 1, md: 3 }} spacing={4}>
                <Box>
                  <Text fontWeight="bold">{t.aiSecurity.openaiMini}</Text>
                  <Text fontSize="sm">{t.aiSecurity.singleCost}: $0.001-0.003</Text>
                  <Text fontSize="xs" color="gray.500">{t.aiSecurity.monthlyCost}: $0.7-2</Text>
                </Box>
                <Box>
                  <Text fontWeight="bold">{t.aiSecurity.poeSubscription} <Badge colorScheme="green">{t.aiSecurity.recommended}</Badge></Text>
                  <Text fontSize="sm">$20/{t.aiSecurity.monthlyCost}</Text>
                  <Text fontSize="xs" color="gray.500">{t.aiSecurity.unlimited}</Text>
                </Box>
                <Box>
                  <Text fontWeight="bold">{t.aiSecurity.openaiTurbo}</Text>
                  <Text fontSize="sm">{t.aiSecurity.singleCost}: $0.01-0.03</Text>
                  <Text fontSize="xs" color="gray.500">{t.aiSecurity.monthlyCost}: $5-8</Text>
                </Box>
              </SimpleGrid>
              <Alert status="warning" mt={4}>
                <AlertIcon />
                <AlertDescription fontSize="sm">
                  <strong>{t.aiSecurity.recommended}:</strong> {t.aiSecurity.costSuggestion}
                </AlertDescription>
              </Alert>
            </CardBody>
          </Card>
        </>
      )}
    </Box>
  )
}

export default AISecurityAnalysis


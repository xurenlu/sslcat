import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  Text,
  Card,
  CardBody,
  SimpleGrid,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  HStack,
  VStack,
  Button,
  Icon,
  useToast,
  Badge,
  Divider,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Spinner,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Progress,
  Select,
  Input,
  InputGroup,
  InputLeftElement,
  Tooltip,
  Alert,
  AlertIcon,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  useColorModeValue,
} from '@chakra-ui/react'
import {
  FiTrendingUp,
  FiActivity,
  FiClock,
  FiAlertCircle,
  FiRefreshCw,
  FiSearch,
  FiFilter,
  FiBarChart2,
  FiZap,
  FiCheckCircle,
  FiXCircle,
  FiList,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

interface APIPerformanceStats {
  path: string
  domain?: string
  method: string
  total_requests: number
  success_requests: number
  error_requests: number
  business_success_requests?: number
  business_error_requests?: number
  business_status_source?: string
  business_status_codes?: { [key: string]: number }
  avg_response_time: number
  min_response_time: number
  max_response_time: number
  p50_response_time: number
  p95_response_time: number
  p99_response_time: number
  response_time_buckets: { [key: string]: number }
  status_codes: { [key: number]: number }
  first_seen: string
  last_seen: string
}

interface PerformanceSummary {
  total_apis: number
  total_requests: number
  avg_response_time: number
  error_rate: number
  business_success_rate?: number
  business_requests?: number
  slow_apis_count: number
  fast_apis_count: number
  generated: string
}

const APIPerformance: React.FC = () => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  const toast = useToast()

  const [summary, setSummary] = useState<PerformanceSummary | null>(null)
  const [apis, setApis] = useState<APIPerformanceStats[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  // 筛选和排序
  const [sortBy, setSortBy] = useState<'slow' | 'error' | 'business_error' | 'active'>('slow')
  const [methodFilter, setMethodFilter] = useState<string>('')
  const [pathFilter, setPathFilter] = useState('')
  const [domainFilter, setDomainFilter] = useState('')
  const [domains, setDomains] = useState<string[]>([])
  const [limit, setLimit] = useState(50)

  // 失败样本弹窗状态
  const [showFailedSamples, setShowFailedSamples] = useState(false)
  const [selectedAPI, setSelectedAPI] = useState<{ method: string; path: string } | null>(null)
  const [failedSamples, setFailedSamples] = useState<any[]>([])
  const [loadingFailedSamples, setLoadingFailedSamples] = useState(false)

  const bgColor = useColorModeValue('white', 'gray.800')
  const borderColor = useColorModeValue('gray.200', 'gray.700')

  const loadSummary = async () => {
    try {
      const url = domainFilter
        ? buildApiPath(adminPrefix, `/api/performance/summary?domain=${encodeURIComponent(domainFilter)}`)
        : buildApiPath(adminPrefix, '/api/performance/summary')
      const response = await fetch(url, { credentials: 'include' })
      if (response.ok) {
        const data = await response.json()
        setSummary(data)
      }
    } catch (error) {
      console.error('Error loading summary:', error)
    }
  }

  const loadDomains = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/performance/domains'), {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setDomains(data.domains || [])
      }
    } catch (error) {
      console.error('Error loading domains:', error)
    }
  }

  const loadAPIs = async () => {
    try {
      const params = new URLSearchParams({
        sort: sortBy,
        limit: limit.toString(),
      })
      if (methodFilter) params.append('method', methodFilter)
      if (pathFilter) params.append('path_prefix', pathFilter)
      if (domainFilter) params.append('domain', domainFilter)

      const response = await fetch(buildApiPath(adminPrefix, `/api/performance/apis?${params}`), {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setApis(data.apis || [])
      }
    } catch (error) {
      console.error('Error loading APIs:', error)
      toast({
        title: t.apiPerformance?.loadFailed ?? '加载失败',
        description: t.apiPerformance?.loadFailedDesc ?? '无法加载 API 性能数据',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const loadData = async () => {
    setLoading(true)
    await Promise.all([loadDomains(), loadSummary(), loadAPIs()])
    setLoading(false)
  }

  const handleRefresh = async () => {
    setRefreshing(true)
    await loadData()
    setRefreshing(false)
    toast({
      title: t.apiPerformance?.refreshSuccess ?? '刷新成功',
      status: 'success',
      duration: 2000,
      isClosable: true,
    })
  }

  // 加载失败样本
  const loadFailedSamples = async (method: string, path: string) => {
    setLoadingFailedSamples(true)
    try {
      const url = buildApiPath(adminPrefix, `/api/performance/failed-samples?method=${encodeURIComponent(method)}&path=${encodeURIComponent(path)}&limit=10`)
      const response = await fetch(url, { credentials: 'include' })
      if (response.ok) {
        const data = await response.json()
        setFailedSamples(data.samples || [])
      } else {
        toast({
          title: t.apiPerformance?.loadFailed ?? '加载失败',
          description: t.apiPerformance?.loadFailedSamplesDesc ?? '无法加载失败样本',
          status: 'error',
          duration: 3000,
        })
      }
    } catch (error) {
      console.error('Error loading failed samples:', error)
      toast({
        title: t.apiPerformance?.loadFailed ?? '加载失败',
        description: t.apiPerformance?.networkError ?? '网络错误',
        status: 'error',
        duration: 3000,
      })
    }
    setLoadingFailedSamples(false)
  }

  // 打开失败样本弹窗
  const handleShowFailedSamples = (method: string, path: string) => {
    setSelectedAPI({ method, path })
    setShowFailedSamples(true)
    loadFailedSamples(method, path)
  }

  useEffect(() => {
    loadData()
  }, [adminPrefix, sortBy, methodFilter, domainFilter, limit])

  const getResponseTimeColor = (ms: number) => {
    if (ms < 100) return 'green'
    if (ms < 200) return 'blue'
    if (ms < 500) return 'yellow'
    return 'red'
  }

  const getResponseTimeLabel = (ms: number) => {
    if (ms < 100) return t.apiPerformance?.excellentLabel ?? '优秀'
    if (ms < 200) return t.apiPerformance?.goodLabel ?? '良好'
    if (ms < 500) return t.apiPerformance?.normalLabel ?? '一般'
    return t.apiPerformance?.slowLabel ?? '较慢'
  }

  const getMethodColor = (method: string) => {
    switch (method) {
      case 'GET': return 'green'
      case 'POST': return 'blue'
      case 'PUT': return 'orange'
      case 'DELETE': return 'red'
      case 'PATCH': return 'purple'
      default: return 'gray'
    }
  }

  const formatDuration = (ms: number) => {
    if (ms < 1000) return `${ms.toFixed(0)}ms`
    return `${(ms / 1000).toFixed(2)}s`
  }

  const calculateErrorRate = (api: APIPerformanceStats) => {
    if (api.total_requests === 0) return 0
    return (api.error_requests / api.total_requests * 100).toFixed(2)
  }

  // 业务成功率（JSON 内 code/status 等字段判定，非 HTTP 状态码）
  const calculateBusinessSuccessRate = (api: APIPerformanceStats) => {
    const ok = api.business_success_requests ?? 0
    const err = api.business_error_requests ?? 0
    const total = ok + err
    if (total === 0) return null
    return ((ok / total) * 100).toFixed(2)
  }

  const hasBusinessStats = (api: APIPerformanceStats) =>
    (api.business_success_requests ?? 0) + (api.business_error_requests ?? 0) > 0

  // 压缩域名显示：domain:path -> ***:path，节省空间，完整 URL 放 tooltip
  const compressPathDisplay = (path: string) => {
    const idx = path.indexOf(':')
    if (idx > 0 && !path.slice(0, idx).includes('/')) {
      return '***' + path.slice(idx)
    }
    return path
  }

  if (loading) {
    return (
      <Box p={6} display="flex" justifyContent="center" alignItems="center" minH="400px">
        <VStack spacing={4}>
          <Spinner size="xl" thickness="4px" speed="0.65s" emptyColor="gray.200" color="blue.500" />
          <Text>{t.common.loading}</Text>
        </VStack>
      </Box>
    )
  }

  return (
    <Box p={6}>
      <VStack spacing={6} align="stretch">
        {/* Header */}
        <HStack justify="space-between">
          <Heading size="lg" display="flex" alignItems="center">
            <Icon as={FiBarChart2} mr={3} />
            {t.apiPerformance?.title ?? 'API 性能排行榜'}
          </Heading>
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            variant="outline"
            onClick={handleRefresh}
            isLoading={refreshing}
          >
            {t.apiPerformance?.refresh ?? '刷新'}
          </Button>
        </HStack>

        {/* Summary Cards */}
        {summary && (
          <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={4}>
            <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center">
                    <Icon as={FiActivity} mr={2} color="blue.500" />
                    {t.apiPerformance?.monitoredApis ?? '监控 API 数'}
                  </StatLabel>
                  <StatNumber>{summary.total_apis}</StatNumber>
                  <StatHelpText>{t.apiPerformance?.totalRequests ?? '总请求数'}: {summary.total_requests.toLocaleString()}</StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center">
                    <Icon as={FiClock} mr={2} color="purple.500" />
                    {t.apiPerformance?.avgResponseTime ?? '平均响应时间'}
                  </StatLabel>
                  <StatNumber>{formatDuration(summary.avg_response_time)}</StatNumber>
                  <StatHelpText>
                    {t.apiPerformance?.slowApis ?? '慢API'}: {summary.slow_apis_count} | {t.apiPerformance?.fastApis ?? '快API'}: {summary.fast_apis_count}
                  </StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center">
                    <Icon as={FiAlertCircle} mr={2} color="orange.500" />
                    {t.apiPerformance?.httpErrorRate ?? 'HTTP 错误率'}
                  </StatLabel>
                  <StatNumber>{summary.error_rate.toFixed(2)}%</StatNumber>
                  <StatHelpText>
                    {summary.error_rate < 1 ? (t.apiPerformance?.healthy ?? '健康') : (t.apiPerformance?.needsAttention ?? '需要关注')}
                  </StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            {(summary.business_requests ?? 0) > 0 && (
              <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
                <CardBody>
                  <Stat>
                    <Tooltip label={t.apiPerformance?.businessSuccessRateTooltip ?? 'JSON 内 code/status 等业务字段判定的成功率'}>
                      <StatLabel display="flex" alignItems="center" cursor="help">
                        <Icon as={FiCheckCircle} mr={2} color="teal.500" />
                        {t.apiPerformance?.businessSuccessRate ?? '业务成功率'}
                      </StatLabel>
                    </Tooltip>
                    <StatNumber
                      color={
                        (summary.business_success_rate ?? 0) >= 99
                          ? 'green.500'
                          : (summary.business_success_rate ?? 0) >= 95
                            ? 'yellow.500'
                            : 'red.500'
                      }
                    >
                      {(summary.business_success_rate ?? 0).toFixed(2)}%
                    </StatNumber>
                    <StatHelpText>
                      {summary.business_requests?.toLocaleString()}{t.apiPerformance?.businessRecords ?? ' 条业务判定'}
                    </StatHelpText>
                  </Stat>
                </CardBody>
              </Card>
            )}

            <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center">
                    <Icon as={FiZap} mr={2} color="green.500" />
                    {t.apiPerformance?.performanceStatus ?? '性能状态'}
                  </StatLabel>
                  <StatNumber>
                    {summary.avg_response_time < 200 && summary.error_rate < 1 ? (t.apiPerformance?.excellent ?? '优秀') : (t.apiPerformance?.good ?? '良好')}
                  </StatNumber>
                  <StatHelpText>{t.apiPerformance?.basedOnResponseAndError ?? '基于响应时间和错误率'}</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
          </SimpleGrid>
        )}

        {/* Filters */}
        <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
          <CardBody>
            <VStack spacing={4}>
              <HStack spacing={4} width="full" wrap="wrap">
                <Box flex="1" minW="200px">
                  <Text fontSize="sm" mb={2} fontWeight="medium">
                    {t.apiPerformance?.sortBy ?? '排序方式'}
                  </Text>
                  <Select
                    value={sortBy}
                    onChange={(e) => setSortBy(e.target.value as any)}
                  >
                    <option value="slow">{t.apiPerformance?.sortSlowest ?? '最慢的 API'}</option>
                    <option value="error">{t.apiPerformance?.sortHttpError ?? 'HTTP 错误率最高'}</option>
                    <option value="business_error">{t.apiPerformance?.sortBusinessError ?? '业务失败率最高'}</option>
                    <option value="active">{t.apiPerformance?.sortActive ?? '请求量最大'}</option>
                  </Select>
                </Box>

                <Box flex="1" minW="180px">
                  <Text fontSize="sm" mb={2} fontWeight="medium">
                    {t.apiPerformance?.domainFilter ?? '域名'}
                  </Text>
                  <Select
                    value={domainFilter}
                    onChange={(e) => setDomainFilter(e.target.value)}
                  >
                    <option value="">{t.apiPerformance?.domainFilterAll ?? '全部域名'}</option>
                    {domains.map((d) => (
                      <option key={d} value={d}>
                        {d}
                      </option>
                    ))}
                  </Select>
                </Box>

                <Box flex="1" minW="150px">
                  <Text fontSize="sm" mb={2} fontWeight="medium">
                    {t.apiPerformance?.httpMethod ?? 'HTTP 方法'}
                  </Text>
                  <Select
                    value={methodFilter}
                    onChange={(e) => setMethodFilter(e.target.value)}
                  >
                    <option value="">{t.apiPerformance?.all ?? '全部'}</option>
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                    <option value="PATCH">PATCH</option>
                  </Select>
                </Box>

                <Box flex="1" minW="200px">
                  <Text fontSize="sm" mb={2} fontWeight="medium">
                    {t.apiPerformance?.pathPrefix ?? '路径前缀'}
                  </Text>
                  <InputGroup>
                    <InputLeftElement pointerEvents="none">
                      <Icon as={FiSearch} color="gray.400" />
                    </InputLeftElement>
                    <Input
                      placeholder="/api/statistics"
                      value={pathFilter}
                      onChange={(e) => setPathFilter(e.target.value)}
                      onKeyPress={(e) => {
                        if (e.key === 'Enter') loadAPIs()
                      }}
                    />
                  </InputGroup>
                </Box>

                <Box flex="1" minW="150px">
                  <Text fontSize="sm" mb={2} fontWeight="medium">
                    {t.apiPerformance?.displayCount ?? '显示数量'}
                  </Text>
                  <Select
                    value={limit.toString()}
                    onChange={(e) => setLimit(parseInt(e.target.value))}
                  >
                    <option value="20">20</option>
                    <option value="50">50</option>
                    <option value="100">100</option>
                    <option value="200">200</option>
                  </Select>
                </Box>
              </HStack>
            </VStack>
          </CardBody>
        </Card>

        {/* API List */}
        <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
          <CardBody>
            <VStack spacing={4} align="stretch">
              <Heading size="md">{t.apiPerformance?.performanceRanking ?? '性能排行榜'}</Heading>

              {apis.length === 0 ? (
                <Alert status="info">
                  <AlertIcon />
                  <Box>
                    <Text fontWeight="bold">{t.apiPerformance?.noData ?? '暂无数据'}</Text>
                    <Text fontSize="sm">{t.apiPerformance?.noDataDesc ?? 'API 性能数据收集中，请稍后再查看'}</Text>
                  </Box>
                </Alert>
              ) : (
                <Box overflowX="auto">
                  <Table size="sm">
                    <Thead>
                      <Tr>
                        <Th>{t.apiPerformance?.apiEndpoint ?? 'API 端点'}</Th>
                        <Th>{t.apiPerformance?.requests ?? '请求数'}</Th>
                        <Th>{t.apiPerformance?.avgResponse ?? '平均响应'}</Th>
                        <Th>P95</Th>
                        <Th>P99</Th>
                        <Th>
                          <Tooltip label="HTTP 4xx/5xx">
                            <Text as="span" cursor="help">{t.apiPerformance?.httpErrorRate ?? 'HTTP 错误率'}</Text>
                          </Tooltip>
                        </Th>
                        <Th>
                          <Tooltip label={t.apiPerformance?.businessSuccessRateTooltip ?? 'JSON 内 code/status 等业务字段判定的成功率'}>
                            <Text as="span" cursor="help">{t.apiPerformance?.businessSuccessRate ?? '业务成功率'}</Text>
                          </Tooltip>
                        </Th>
                        <Th>{t.apiPerformance?.performanceRating ?? '性能评级'}</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {apis.map((api, idx) => (
                        <Tr key={idx}>
                          <Td>
                            <VStack align="start" spacing={1}>
                              <HStack>
                                <Badge colorScheme={getMethodColor(api.method)}>
                                  {api.method}
                                </Badge>
                                <Tooltip label={api.path} placement="top" hasArrow>
                                  <Text fontSize="sm" fontFamily="mono" noOfLines={1} maxW="400px" cursor="help">
                                    {compressPathDisplay(api.path)}
                                  </Text>
                                </Tooltip>
                              </HStack>
                              <Text fontSize="xs" color="gray.500">
                                {t.apiPerformance?.firstSeen ?? '首次'}: {new Date(api.first_seen).toLocaleString()}
                              </Text>
                            </VStack>
                          </Td>
                          <Td>
                            <HStack>
                              <Text fontWeight="bold">{api.total_requests.toLocaleString()}</Text>
                              <Text fontSize="xs" color="green.500">
                                ({api.success_requests.toLocaleString()} {t.apiPerformance?.success ?? '成功'})
                              </Text>
                            </HStack>
                          </Td>
                          <Td>
                            <HStack>
                              <Text
                                fontWeight="bold"
                                color={getResponseTimeColor(api.avg_response_time) + '.500'}
                              >
                                {formatDuration(api.avg_response_time)}
                              </Text>
                              <Tooltip label={`最小: ${formatDuration(api.min_response_time)}, 最大: ${formatDuration(api.max_response_time)}`}>
                                <Icon as={FiTrendingUp} color="gray.400" cursor="help" />
                              </Tooltip>
                            </HStack>
                          </Td>
                          <Td>
                            <Text color={getResponseTimeColor(api.p95_response_time) + '.500'}>
                              {formatDuration(api.p95_response_time)}
                            </Text>
                          </Td>
                          <Td>
                            <Text color={getResponseTimeColor(api.p99_response_time) + '.500'}>
                              {formatDuration(api.p99_response_time)}
                            </Text>
                          </Td>
                          <Td>
                            <HStack>
                              <Text
                                fontWeight="bold"
                                color={parseFloat(String(calculateErrorRate(api))) > 5 ? 'red.500' : 'green.500'}
                              >
                                {calculateErrorRate(api)}%
                              </Text>
                              {api.error_requests > 0 && (
                                <Tooltip label={(t.apiPerformance?.httpErrorsCount ?? '{n} 个 HTTP 错误').replace('{n}', String(api.error_requests))}>
                                  <Icon as={FiAlertCircle} color="orange.500" />
                                </Tooltip>
                              )}
                            </HStack>
                          </Td>
                          <Td>
                            {hasBusinessStats(api) ? (
                              <HStack>
                                <Tooltip label={`${t.apiPerformance?.source ?? '来源'}: ${api.business_status_source || 'code/status'}${parseFloat(calculateBusinessSuccessRate(api)!) < 100 ? '\n' + (t.apiPerformance?.clickToViewFailedSamples ?? '点击查看失败样本') : ''}`}>
                                  <Text
                                    fontWeight="bold"
                                    color={
                                      parseFloat(calculateBusinessSuccessRate(api)!) >= 99
                                        ? 'green.500'
                                        : parseFloat(calculateBusinessSuccessRate(api)!) >= 95
                                          ? 'yellow.500'
                                          : 'red.500'
                                    }
                                    cursor={parseFloat(calculateBusinessSuccessRate(api)!) < 100 ? 'pointer' : 'default'}
                                    onClick={() => {
                                      if (parseFloat(calculateBusinessSuccessRate(api)!) < 100) {
                                        handleShowFailedSamples(api.method, api.path)
                                      }
                                    }}
                                  >
                                    {calculateBusinessSuccessRate(api)}%
                                  </Text>
                                </Tooltip>
                                {parseFloat(calculateBusinessSuccessRate(api)!) < 100 && (
                                  <Tooltip label={t.apiPerformance?.viewFailedSamples ?? '查看失败样本'}>
                                    <Button
                                      size="xs"
                                      variant="ghost"
                                      colorScheme="red"
                                      onClick={() => handleShowFailedSamples(api.method, api.path)}
                                    >
                                      <Icon as={FiList} boxSize={3} />
                                    </Button>
                                  </Tooltip>
                                )}
                              </HStack>
                            ) : (
                              <Text fontSize="sm" color="gray.500">—</Text>
                            )}
                          </Td>
                          <Td>
                            <Badge
                              colorScheme={getResponseTimeColor(api.avg_response_time)}
                              display="flex"
                              alignItems="center"
                              gap={1}
                            >
                              {getResponseTimeLabel(api.avg_response_time)}
                              {parseFloat(String(calculateErrorRate(api))) < 1 && api.avg_response_time < 200 ? (
                                <Icon as={FiCheckCircle} boxSize={3} />
                              ) : (
                                <Icon as={FiXCircle} boxSize={3} />
                              )}
                            </Badge>
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </Box>
              )}
            </VStack>
          </CardBody>
        </Card>

        {/* Performance Tips */}
        <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
          <CardBody>
            <Heading size="md" mb={4}>{t.apiPerformance?.optimizationTips ?? '性能优化建议'}</Heading>
            <SimpleGrid columns={{ base: 1, md: 3 }} spacing={4}>
              <Box p={4} borderRadius="md" bg="red.50" _dark={{ bg: 'red.900' }}>
                <Icon as={FiAlertCircle} color="red.500" boxSize={6} mb={2} />
                <Text fontWeight="bold" mb={1}>{t.apiPerformance?.slowApiTip ?? '慢 API (>500ms)'}</Text>
                <Text fontSize="sm" color="gray.600" _dark={{ color: 'gray.400' }}>
                  {t.apiPerformance?.slowApiTipDesc ?? '检查数据库查询、外部API调用或复杂计算逻辑'}
                </Text>
              </Box>
              <Box p={4} borderRadius="md" bg="yellow.50" _dark={{ bg: 'yellow.900' }}>
                <Icon as={FiClock} color="yellow.500" boxSize={6} mb={2} />
                <Text fontWeight="bold" mb={1}>{t.apiPerformance?.normalApiTip ?? '一般 API (200-500ms)'}</Text>
                <Text fontSize="sm" color="gray.600" _dark={{ color: 'gray.400' }}>
                  {t.apiPerformance?.normalApiTipDesc ?? '考虑添加缓存、优化算法或使用异步处理'}
                </Text>
              </Box>
              <Box p={4} borderRadius="md" bg="green.50" _dark={{ bg: 'green.900' }}>
                <Icon as={FiCheckCircle} color="green.500" boxSize={6} mb={2} />
                <Text fontWeight="bold" mb={1}>{t.apiPerformance?.excellentApiTip ?? '优秀 API (<200ms)'}</Text>
                <Text fontSize="sm" color="gray.600" _dark={{ color: 'gray.400' }}>
                  {t.apiPerformance?.excellentApiTipDesc ?? '性能良好，继续保持！可考虑进一步优化用户体验'}
                </Text>
              </Box>
            </SimpleGrid>
          </CardBody>
        </Card>
      </VStack>

      {/* 失败样本弹窗 */}
      <Modal isOpen={showFailedSamples} onClose={() => setShowFailedSamples(false)} size="xl">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>
            {t.apiPerformance?.failedSamplesTitle ?? '失败样本详情'}
            {selectedAPI && (
              <Text fontSize="sm" fontWeight="normal" mt={1}>
                <Badge colorScheme={getMethodColor(selectedAPI.method)} mr={2}>{selectedAPI.method}</Badge>
                <Text fontSize="xs">{selectedAPI.path}</Text>
              </Text>
            )}
          </ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            {loadingFailedSamples ? (
              <HStack justify="center" py={8}>
                <Spinner />
                <Text>{t.common.loading}</Text>
              </HStack>
            ) : failedSamples.length === 0 ? (
              <Alert status="info">
                <AlertIcon />
                <Box>
                  <Text fontWeight="bold">{t.apiPerformance?.noFailedSamples ?? '暂无失败样本'}</Text>
                  <Text fontSize="sm">{t.apiPerformance?.noFailedSamplesDesc ?? '该 API 暂无记录到的失败请求'}</Text>
                </Box>
              </Alert>
            ) : (
              <VStack align="stretch" spacing={4}>
                <Text fontSize="sm" color="gray.500">
                  {(t.apiPerformance?.showingSamples ?? '显示最近 {n} 个失败样本').replace('{n}', String(failedSamples.length))}
                </Text>
                {failedSamples.map((sample, idx) => (
                  <Card key={idx} size="sm" variant="outline">
                    <CardBody>
                      <VStack align="stretch" spacing={2}>
                        <HStack justify="space-between">
                          <HStack>
                            <Badge colorScheme="red">HTTP {sample.status}</Badge>
                            <Text fontSize="xs" color="gray.500">
                              {new Date(sample.timestamp).toLocaleString('zh-CN')}
                            </Text>
                          </HStack>
                          <Text fontSize="sm" color="gray.500">
                            {t.apiPerformance?.responseTime ?? '响应时间'}: {sample.response_time ? `${sample.response_time}ms` : 'N/A'}
                          </Text>
                        </HStack>

                        {sample.business_status && (
                          <Box p={2} bg="orange.50" _dark={{ bg: 'orange.900' }} borderRadius="md">
                            <Text fontSize="sm" fontWeight="bold" mb={1}>{t.apiPerformance?.businessStatus ?? '业务状态'}:</Text>
                            <HStack>
                              <Badge colorScheme={sample.business_status.is_success ? 'green' : 'red'}>
                                {sample.business_status.code}
                              </Badge>
                              <Text fontSize="sm">{sample.business_status.message}</Text>
                              <Text fontSize="xs" color="gray.500">
                                {t.apiPerformance?.source ?? '来源'}: {sample.business_status.source}
                              </Text>
                            </HStack>
                          </Box>
                        )}

                        {sample.user_agent && (
                          <Text fontSize="xs" color="gray.500">
                            UA: {sample.user_agent.substring(0, 100)}
                            {sample.user_agent.length > 100 ? '...' : ''}
                          </Text>
                        )}
                      </VStack>
                    </CardBody>
                  </Card>
                ))}
              </VStack>
            )}
          </ModalBody>
          <ModalFooter>
            <Button onClick={() => setShowFailedSamples(false)}>{t.apiPerformance?.close ?? t.common.close}</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default APIPerformance

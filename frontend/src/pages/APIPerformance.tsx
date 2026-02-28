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
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

interface APIPerformanceStats {
  path: string
  method: string
  total_requests: number
  success_requests: number
  error_requests: number
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
  const [sortBy, setSortBy] = useState<'slow' | 'error' | 'active'>('slow')
  const [methodFilter, setMethodFilter] = useState<string>('')
  const [pathFilter, setPathFilter] = useState('')
  const [limit, setLimit] = useState(50)

  const bgColor = useColorModeValue('white', 'gray.800')
  const borderColor = useColorModeValue('gray.200', 'gray.700')

  const loadSummary = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/performance/summary'), {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setSummary(data)
      }
    } catch (error) {
      console.error('Error loading summary:', error)
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
        title: '加载失败',
        description: '无法加载 API 性能数据',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const loadData = async () => {
    setLoading(true)
    await Promise.all([loadSummary(), loadAPIs()])
    setLoading(false)
  }

  const handleRefresh = async () => {
    setRefreshing(true)
    await loadData()
    setRefreshing(false)
    toast({
      title: '刷新成功',
      status: 'success',
      duration: 2000,
      isClosable: true,
    })
  }

  useEffect(() => {
    loadData()
  }, [adminPrefix, sortBy, methodFilter, limit])

  const getResponseTimeColor = (ms: number) => {
    if (ms < 100) return 'green'
    if (ms < 200) return 'blue'
    if (ms < 500) return 'yellow'
    return 'red'
  }

  const getResponseTimeLabel = (ms: number) => {
    if (ms < 100) return '优秀'
    if (ms < 200) return '良好'
    if (ms < 500) return '一般'
    return '较慢'
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

  if (loading) {
    return (
      <Box p={6} display="flex" justifyContent="center" alignItems="center" minH="400px">
        <VStack spacing={4}>
          <Spinner size="xl" thickness="4px" speed="0.65s" emptyColor="gray.200" color="blue.500" />
          <Text>加载中...</Text>
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
            API 性能排行榜
          </Heading>
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            variant="outline"
            onClick={handleRefresh}
            isLoading={refreshing}
          >
            刷新
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
                    监控 API 数
                  </StatLabel>
                  <StatNumber>{summary.total_apis}</StatNumber>
                  <StatHelpText>总请求数: {summary.total_requests.toLocaleString()}</StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center">
                    <Icon as={FiClock} mr={2} color="purple.500" />
                    平均响应时间
                  </StatLabel>
                  <StatNumber>{formatDuration(summary.avg_response_time)}</StatNumber>
                  <StatHelpText>
                    慢API: {summary.slow_apis_count} | 快API: {summary.fast_apis_count}
                  </StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center">
                    <Icon as={FiAlertCircle} mr={2} color="orange.500" />
                    错误率
                  </StatLabel>
                  <StatNumber>{summary.error_rate.toFixed(2)}%</StatNumber>
                  <StatHelpText>
                    {summary.error_rate < 1 ? '健康' : '需要关注'}
                  </StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center">
                    <Icon as={FiZap} mr={2} color="green.500" />
                    性能状态
                  </StatLabel>
                  <StatNumber>
                    {summary.avg_response_time < 200 && summary.error_rate < 1 ? '优秀' : '良好'}
                  </StatNumber>
                  <StatHelpText>基于响应时间和错误率</StatHelpText>
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
                    排序方式
                  </Text>
                  <Select
                    value={sortBy}
                    onChange={(e) => setSortBy(e.target.value as any)}
                  >
                    <option value="slow">最慢的 API</option>
                    <option value="error">错误率最高</option>
                    <option value="active">请求量最大</option>
                  </Select>
                </Box>

                <Box flex="1" minW="150px">
                  <Text fontSize="sm" mb={2} fontWeight="medium">
                    HTTP 方法
                  </Text>
                  <Select
                    value={methodFilter}
                    onChange={(e) => setMethodFilter(e.target.value)}
                  >
                    <option value="">全部</option>
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                    <option value="PUT">PUT</option>
                    <option value="DELETE">DELETE</option>
                    <option value="PATCH">PATCH</option>
                  </Select>
                </Box>

                <Box flex="1" minW="200px">
                  <Text fontSize="sm" mb={2} fontWeight="medium">
                    路径前缀
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
                    显示数量
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
              <Heading size="md">性能排行榜</Heading>

              {apis.length === 0 ? (
                <Alert status="info">
                  <AlertIcon />
                  <Box>
                    <Text fontWeight="bold">暂无数据</Text>
                    <Text fontSize="sm">API 性能数据收集中，请稍后再查看</Text>
                  </Box>
                </Alert>
              ) : (
                <Box overflowX="auto">
                  <Table size="sm">
                    <Thead>
                      <Tr>
                        <Th>API 端点</Th>
                        <Th>请求数</Th>
                        <Th>平均响应</Th>
                        <Th>P95</Th>
                        <Th>P99</Th>
                        <Th>错误率</Th>
                        <Th>性能评级</Th>
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
                                <Text fontSize="sm" fontFamily="mono" noOfLines={1} maxW="400px">
                                  {api.path}
                                </Text>
                              </HStack>
                              <Text fontSize="xs" color="gray.500">
                                首次: {new Date(api.first_seen).toLocaleString('zh-CN')}
                              </Text>
                            </VStack>
                          </Td>
                          <Td>
                            <HStack>
                              <Text fontWeight="bold">{api.total_requests.toLocaleString()}</Text>
                              <Text fontSize="xs" color="green.500">
                                ({api.success_requests.toLocaleString()} 成功)
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
                                <Tooltip label={`${api.error_requests} 个错误请求`}>
                                  <Icon as={FiAlertCircle} color="orange.500" />
                                </Tooltip>
                              )}
                            </HStack>
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
            <Heading size="md" mb={4}>性能优化建议</Heading>
            <SimpleGrid columns={{ base: 1, md: 3 }} spacing={4}>
              <Box p={4} borderRadius="md" bg="red.50" _dark={{ bg: 'red.900' }}>
                <Icon as={FiAlertCircle} color="red.500" boxSize={6} mb={2} />
                <Text fontWeight="bold" mb={1}>慢 API (&gt;500ms)</Text>
                <Text fontSize="sm" color="gray.600" _dark={{ color: 'gray.400' }}>
                  检查数据库查询、外部API调用或复杂计算逻辑
                </Text>
              </Box>
              <Box p={4} borderRadius="md" bg="yellow.50" _dark={{ bg: 'yellow.900' }}>
                <Icon as={FiClock} color="yellow.500" boxSize={6} mb={2} />
                <Text fontWeight="bold" mb={1}>一般 API (200-500ms)</Text>
                <Text fontSize="sm" color="gray.600" _dark={{ color: 'gray.400' }}>
                  考虑添加缓存、优化算法或使用异步处理
                </Text>
              </Box>
              <Box p={4} borderRadius="md" bg="green.50" _dark={{ bg: 'green.900' }}>
                <Icon as={FiCheckCircle} color="green.500" boxSize={6} mb={2} />
                <Text fontWeight="bold" mb={1}>优秀 API (&lt;200ms)</Text>
                <Text fontSize="sm" color="gray.600" _dark={{ color: 'gray.400' }}>
                  性能良好，继续保持！可考虑进一步优化用户体验
                </Text>
              </Box>
            </SimpleGrid>
          </CardBody>
        </Card>
      </VStack>
    </Box>
  )
}

export default APIPerformance

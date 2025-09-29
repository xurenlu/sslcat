import React, { useEffect, useState } from 'react'
import {
  Box,
  Heading,
  SimpleGrid,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Card,
  CardBody,
  VStack,
  HStack,
  Button,
  Icon,
  Text,
  Flex,
  useToast,
  Spinner,
  Alert,
  AlertIcon,
  Select,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  Progress,
  Divider,
  ButtonGroup,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  IconButton,
  Tooltip,
} from '@chakra-ui/react'
import {
  FiRefreshCw,
  FiCalendar,
  FiClock,
  FiTrendingUp,
  FiTrendingDown,
  FiBarChart2,
  FiSettings,
  FiDownload,
  FiMapPin,
  FiMonitor,
  FiGlobe,
  FiChevronDown,
} from 'react-icons/fi'
import { useTranslation } from '../hooks/useLanguage'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'

// 时间维度类型
type TimeDimension = 'hour' | 'day' | 'month'

// 统计数据类型
interface RequestStats {
  total_requests: number
  non_success_count: number
  unique_ips: number
  unique_user_agents: number
}

interface TopEntry {
  key: string
  count: number
  score?: number
}

interface StatisticsData {
  dimension: TimeDimension
  time_key: string
  domain_stats: Record<string, RequestStats>
  top_ips: TopEntry[]
  top_user_agents: TopEntry[]
  top_cities: TopEntry[]
  generated: string
}

interface TimeKey {
  key: string
  label: string
}

const Statistics: React.FC = () => {
  const [data, setData] = useState<StatisticsData | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [dimension, setDimension] = useState<TimeDimension>('hour')
  const [timeKey, setTimeKey] = useState<string>('')
  const [domain, setDomain] = useState<string>('all')
  const [timeKeys, setTimeKeys] = useState<TimeKey[]>([])
  const [config, setConfig] = useState<any>(null)
  const [topN, setTopN] = useState<number>(20)
  
  const toast = useToast()
  const t = useTranslation()
  const { adminPrefix } = useConfig()

  // 获取时间键列表
  const fetchTimeKeys = async (selectedDimension: TimeDimension) => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, `/statistics/time-keys?dimension=${selectedDimension}`), {
        credentials: 'include',
      })
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }
      
      const result = await response.json()
      if (result.success) {
        setTimeKeys(result.time_keys || [])
        // 如果没有选中的时间键或当前选择的键不在新列表中，选择第一个
        if (!timeKey || !result.time_keys.find((tk: TimeKey) => tk.key === timeKey)) {
          setTimeKey(result.time_keys[0]?.key || '')
        }
      }
    } catch (error) {
      console.error('获取时间键失败:', error)
    }
  }

  // 获取统计数据
  const fetchStatistics = async () => {
    setLoading(true)
    setError(null)
    
    try {
      const params = new URLSearchParams({
        dimension,
        top_n: topN.toString(),
      })
      
      if (timeKey) params.append('time_key', timeKey)
      if (domain !== 'all') params.append('domain', domain)
      
      const response = await fetch(buildApiPath(adminPrefix, `/statistics?${params}`), {
        credentials: 'include',
      })
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }
      
      const result = await response.json()
      if (result.success) {
        setData(result.data)
      } else {
        throw new Error(result.message || '获取统计数据失败')
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : '未知错误'
      setError(errorMessage)
      toast({
        title: '数据获取失败',
        description: errorMessage,
        status: 'error',
        duration: 4000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  // 获取配置
  const fetchConfig = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/statistics/config'), {
        credentials: 'include',
      })
      
      if (response.ok) {
        const result = await response.json()
        if (result.success) {
          setConfig(result.config)
          setTopN(result.config.top_n || 20)
        }
      }
    } catch (error) {
      console.error('获取配置失败:', error)
    }
  }

  // 更新配置
  const updateConfig = async (updates: any) => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/statistics/config'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(updates),
      })
      
      if (response.ok) {
        const result = await response.json()
        if (result.success) {
          setConfig(result.config)
          toast({
            title: '配置更新成功',
            status: 'success',
            duration: 2000,
            isClosable: true,
          })
        }
      }
    } catch (error) {
      toast({
        title: '配置更新失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 4000,
        isClosable: true,
      })
    }
  }

  // 维度改变时更新时间键
  useEffect(() => {
    fetchTimeKeys(dimension)
  }, [dimension])

  // 初始化时获取配置和时间键
  useEffect(() => {
    fetchConfig()
    fetchTimeKeys(dimension)
  }, [])

  // 数据依赖变化时重新获取
  useEffect(() => {
    if (timeKey) {
      fetchStatistics()
    }
  }, [dimension, timeKey, domain, topN])

  // 格式化数字
  const formatNumber = (num: number) => {
    if (num >= 1000000) {
      return (num / 1000000).toFixed(1) + 'M'
    } else if (num >= 1000) {
      return (num / 1000).toFixed(1) + 'K'
    }
    return num.toString()
  }

  // 计算成功率
  const getSuccessRate = (stats: RequestStats) => {
    if (stats.total_requests === 0) return 100
    return ((stats.total_requests - stats.non_success_count) / stats.total_requests * 100)
  }

  // 获取维度显示名称
  const getDimensionLabel = (dim: TimeDimension) => {
    switch (dim) {
      case 'hour': return '小时'
      case 'day': return '天'
      case 'month': return '月'
      default: return dim
    }
  }

  // 计算总计数据
  const getTotalStats = (): RequestStats => {
    if (!data) return { total_requests: 0, non_success_count: 0, unique_ips: 0, unique_user_agents: 0 }
    
    return Object.values(data.domain_stats).reduce((total, stats) => ({
      total_requests: total.total_requests + stats.total_requests,
      non_success_count: total.non_success_count + stats.non_success_count,
      unique_ips: total.unique_ips + stats.unique_ips,
      unique_user_agents: total.unique_user_agents + stats.unique_user_agents,
    }), { total_requests: 0, non_success_count: 0, unique_ips: 0, unique_user_agents: 0 })
  }

  const totalStats = getTotalStats()

  return (
    <Box p={6}>
      {/* 页面标题和控制面板 */}
      <Flex justify="space-between" align="center" mb={6}>
        <VStack align="start" spacing={1}>
          <Heading size="lg">访问统计</Heading>
          <Text color="gray.600">网站访问数据分析和高频访问者统计</Text>
        </VStack>
        
        <HStack spacing={4}>
          {/* 时间维度选择 */}
          <Select value={dimension} onChange={(e) => setDimension(e.target.value as TimeDimension)} width="120px">
            <option value="hour">按小时</option>
            <option value="day">按天</option>
            <option value="month">按月</option>
          </Select>
          
          {/* 时间选择 */}
          <Select value={timeKey} onChange={(e) => setTimeKey(e.target.value)} width="200px">
            {timeKeys.map((tk) => (
              <option key={tk.key} value={tk.key}>
                {tk.label}
              </option>
            ))}
          </Select>
          
          {/* 域名选择 */}
          <Select value={domain} onChange={(e) => setDomain(e.target.value)} width="150px">
            <option value="all">所有域名</option>
            {data && Object.keys(data.domain_stats).map((domainName) => (
              <option key={domainName} value={domainName}>
                {domainName}
              </option>
            ))}
          </Select>
          
          {/* 配置菜单 */}
          <Menu>
            <MenuButton as={IconButton} icon={<FiSettings />} variant="outline" />
            <MenuList>
              <MenuItem onClick={() => updateConfig({ enabled: !config?.enabled })}>
                {config?.enabled ? '禁用统计' : '启用统计'}
              </MenuItem>
              <MenuItem onClick={() => updateConfig({ geoip_enabled: !config?.geoip_enabled })}>
                {config?.geoip_enabled ? '禁用地理位置' : '启用地理位置'}
              </MenuItem>
            </MenuList>
          </Menu>
          
          {/* 刷新按钮 */}
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            onClick={fetchStatistics}
            isLoading={loading}
            variant="outline"
          >
            刷新
          </Button>
        </HStack>
      </Flex>

      {/* 错误提示 */}
      {error && (
        <Alert status="error" mb={6}>
          <AlertIcon />
          {error}
        </Alert>
      )}

      {/* 配置状态提示 */}
      {config && !config.enabled && (
        <Alert status="warning" mb={6}>
          <AlertIcon />
          统计功能当前已禁用，请在配置中启用以收集数据
        </Alert>
      )}

      {/* 主要统计数据 */}
      <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={6} mb={8}>
        <Card>
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="blue.500" fontWeight="bold">总请求数</StatLabel>
                  <StatNumber fontSize="2xl">{formatNumber(totalStats.total_requests)}</StatNumber>
                  <StatHelpText>当前{getDimensionLabel(dimension)}</StatHelpText>
                </Box>
                <Icon as={FiBarChart2} boxSize={8} color="blue.300" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="red.500" fontWeight="bold">错误请求数</StatLabel>
                  <StatNumber fontSize="2xl">{formatNumber(totalStats.non_success_count)}</StatNumber>
                  <StatHelpText>非2xx状态码</StatHelpText>
                </Box>
                <Icon as={FiTrendingDown} boxSize={8} color="red.300" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="green.500" fontWeight="bold">成功率</StatLabel>
                  <StatNumber fontSize="2xl">{getSuccessRate(totalStats).toFixed(1)}%</StatNumber>
                  <StatHelpText>请求成功率</StatHelpText>
                </Box>
                <Icon as={FiTrendingUp} boxSize={8} color="green.300" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="purple.500" fontWeight="bold">独立访客</StatLabel>
                  <StatNumber fontSize="2xl">{formatNumber(totalStats.unique_ips)}</StatNumber>
                  <StatHelpText>唯一IP数量</StatHelpText>
                </Box>
                <Icon as={FiGlobe} boxSize={8} color="purple.300" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>
      </SimpleGrid>

      {/* 成功率进度条 */}
      <Card mb={8}>
        <CardBody>
          <VStack align="stretch" spacing={4}>
            <Heading size="md">请求成功率趋势</Heading>
            <Box>
              <Text fontSize="sm" color="gray.600" mb={2}>
                成功请求: {totalStats.total_requests - totalStats.non_success_count} / 总请求: {totalStats.total_requests}
              </Text>
              <Progress 
                value={getSuccessRate(totalStats)} 
                colorScheme={getSuccessRate(totalStats) >= 95 ? 'green' : getSuccessRate(totalStats) >= 80 ? 'yellow' : 'red'}
                size="lg"
                hasStripe
              />
            </Box>
          </VStack>
        </CardBody>
      </Card>

      {/* 排行榜数据 */}
      <SimpleGrid columns={{ base: 1, lg: 3 }} spacing={6} mb={8}>
        {/* 高访问IP排行 */}
        <Card>
          <CardBody>
            <VStack align="stretch" spacing={4}>
              <HStack justify="space-between">
                <Heading size="md">高访问IP Top {topN}</Heading>
                <Tooltip label="基于漏斗模型过滤">
                  <Icon as={FiMonitor} color="gray.400" />
                </Tooltip>
              </HStack>
              
              {loading ? (
                <Spinner />
              ) : (
                <Table size="sm">
                  <Thead>
                    <Tr>
                      <Th>排名</Th>
                      <Th>IP地址</Th>
                      <Th isNumeric>访问次数</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {(data?.top_ips || []).slice(0, 10).map((item, index) => (
                      <Tr key={item.key}>
                        <Td>
                          <Badge colorScheme={index < 3 ? 'red' : 'gray'}>
                            #{index + 1}
                          </Badge>
                        </Td>
                        <Td>
                          <Text fontSize="sm" fontFamily="mono">
                            {item.key}
                          </Text>
                        </Td>
                        <Td isNumeric>{formatNumber(item.count)}</Td>
                      </Tr>
                    ))}
                  </Tbody>
                </Table>
              )}
            </VStack>
          </CardBody>
        </Card>

        {/* 高访问User-Agent排行 */}
        <Card>
          <CardBody>
            <VStack align="stretch" spacing={4}>
              <HStack justify="space-between">
                <Heading size="md">User-Agent Top {topN}</Heading>
                <Tooltip label="基于漏斗模型过滤">
                  <Icon as={FiMonitor} color="gray.400" />
                </Tooltip>
              </HStack>
              
              {loading ? (
                <Spinner />
              ) : (
                <Table size="sm">
                  <Thead>
                    <Tr>
                      <Th>排名</Th>
                      <Th>User-Agent</Th>
                      <Th isNumeric>访问次数</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {(data?.top_user_agents || []).slice(0, 10).map((item, index) => (
                      <Tr key={item.key}>
                        <Td>
                          <Badge colorScheme={index < 3 ? 'blue' : 'gray'}>
                            #{index + 1}
                          </Badge>
                        </Td>
                        <Td>
                          <Text fontSize="sm" maxW="200px" isTruncated>
                            {item.key || 'Unknown'}
                          </Text>
                        </Td>
                        <Td isNumeric>{formatNumber(item.count)}</Td>
                      </Tr>
                    ))}
                  </Tbody>
                </Table>
              )}
            </VStack>
          </CardBody>
        </Card>

        {/* 高访问城市排行 */}
        <Card>
          <CardBody>
            <VStack align="stretch" spacing={4}>
              <HStack justify="space-between">
                <Heading size="md">访问城市 Top {topN}</Heading>
                <Tooltip label="需要启用地理位置功能">
                  <Icon as={FiMapPin} color="gray.400" />
                </Tooltip>
              </HStack>
              
              {!config?.geoip_enabled ? (
                <Text color="gray.500" fontSize="sm">
                  地理位置功能未启用
                </Text>
              ) : loading ? (
                <Spinner />
              ) : (
                <Table size="sm">
                  <Thead>
                    <Tr>
                      <Th>排名</Th>
                      <Th>城市</Th>
                      <Th isNumeric>访问次数</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {(data?.top_cities || []).slice(0, 10).map((item, index) => (
                      <Tr key={item.key}>
                        <Td>
                          <Badge colorScheme={index < 3 ? 'green' : 'gray'}>
                            #{index + 1}
                          </Badge>
                        </Td>
                        <Td>
                          <Text fontSize="sm">
                            {item.key || 'Unknown'}
                          </Text>
                        </Td>
                        <Td isNumeric>{formatNumber(item.count)}</Td>
                      </Tr>
                    ))}
                  </Tbody>
                </Table>
              )}
            </VStack>
          </CardBody>
        </Card>
      </SimpleGrid>

      {/* 域名详细统计 */}
      {domain === 'all' && data && Object.keys(data.domain_stats).length > 1 && (
        <Card>
          <CardBody>
            <VStack align="stretch" spacing={4}>
              <Heading size="md">域名详细统计</Heading>
              
              <Table>
                <Thead>
                  <Tr>
                    <Th>域名</Th>
                    <Th isNumeric>总请求数</Th>
                    <Th isNumeric>错误请求</Th>
                    <Th isNumeric>成功率</Th>
                    <Th isNumeric>独立IP</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {Object.entries(data.domain_stats).map(([domainName, stats]) => (
                    <Tr key={domainName}>
                      <Td>
                        <Text fontWeight="medium">{domainName}</Text>
                      </Td>
                      <Td isNumeric>{formatNumber(stats.total_requests)}</Td>
                      <Td isNumeric>
                        <Text color={stats.non_success_count > 0 ? 'red.500' : 'green.500'}>
                          {formatNumber(stats.non_success_count)}
                        </Text>
                      </Td>
                      <Td isNumeric>
                        <Text color={getSuccessRate(stats) >= 95 ? 'green.500' : getSuccessRate(stats) >= 80 ? 'yellow.500' : 'red.500'}>
                          {getSuccessRate(stats).toFixed(1)}%
                        </Text>
                      </Td>
                      <Td isNumeric>{formatNumber(stats.unique_ips)}</Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </VStack>
          </CardBody>
        </Card>
      )}

      {/* 漏斗模型说明 */}
      <Card mt={8}>
        <CardBody>
          <VStack align="stretch" spacing={3}>
            <Heading size="sm">关于漏斗模型统计</Heading>
            <Text fontSize="sm" color="gray.600">
              高访问排行榜采用漏斗模型算法，不是简单的频次统计：
            </Text>
            <VStack align="start" spacing={2} pl={4}>
              <Text fontSize="sm">• 只有达到最小访问次数阈值的IP/User-Agent才会进入候选列表</Text>
              <Text fontSize="sm">• 必须在一定时间跨度内持续访问才能被统计</Text>
              <Text fontSize="sm">• 采用时间衰减算法，越近期的访问权重越高</Text>
              <Text fontSize="sm">• 这样可以避免偶发的大量访问对服务器性能造成影响</Text>
            </VStack>
            {config && (
              <Text fontSize="xs" color="gray.500">
                当前配置：IP最少{config.ip_funnel?.min_occurrences || 5}次访问，
                User-Agent最少{config.ua_funnel?.min_occurrences || 3}次访问，
                城市最少{config.city_funnel?.min_occurrences || 10}次访问
              </Text>
            )}
          </VStack>
        </CardBody>
      </Card>
    </Box>
  )
}

export default Statistics

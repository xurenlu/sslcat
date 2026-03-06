import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  Card,
  CardBody,
  CardHeader,
  VStack,
  HStack,
  FormControl,
  FormLabel,
  Switch,
  Button,
  Icon,
  useToast,
  SimpleGrid,
  Text,
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  NumberIncrementStepper,
  NumberDecrementStepper,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Alert,
  AlertIcon,
  AlertDescription,
  Spinner,
  Divider,
  Select,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
} from '@chakra-ui/react'
import {
  FiActivity,
  FiSave,
  FiRefreshCw,
  FiCpu,
  FiHardDrive,
  FiAlertTriangle,
  FiTrendingUp,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'
import { DEFAULTS } from '../constants'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'

interface MonitoringConfig {
  enabled: boolean
  memory_max_usage_percent: number
  memory_release_cooldown_sec: number
  watchdog_enabled: boolean
  watchdog_check_interval_sec: number
  watchdog_cpu_threshold_percent: number
  watchdog_cpu_increase_threshold_percent: number
  watchdog_cpu_increase_window_sec: number
  watchdog_alert_cooldown_sec: number
  watchdog_memory_threshold_mb: number
  watchdog_memory_threshold_percent: number
  watchdog_memory_increase_threshold_mb: number
  watchdog_memory_increase_window_sec: number
  watchdog_exit_on_memory_threshold: boolean
  watchdog_exit_on_cpu_threshold: boolean
}

interface MonitoringStats {
  cpu_percent: number
  memory_percent: number
  memory_rss_mb: number
  timestamp: string
}

interface ProcessMetric {
  id: number
  timestamp: string
  granularity: string
  cpu_percent: number
  memory_mb: number
  memory_percent: number
  sample_count: number
}

interface MetricsQueryResult {
  data: ProcessMetric[]
  summary: {
    total_samples: number
    avg_cpu: number
    avg_memory_mb: number
    max_cpu: number
    max_memory_mb: number
  }
}

const Monitoring: React.FC = () => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  const toast = useToast()

  const [config, setConfig] = useState<MonitoringConfig>({
    enabled: true,
    memory_max_usage_percent: 20,
    memory_release_cooldown_sec: 300,
    watchdog_enabled: false,
    watchdog_check_interval_sec: 30,
    watchdog_cpu_threshold_percent: 30,
    watchdog_cpu_increase_threshold_percent: 15,
    watchdog_cpu_increase_window_sec: 180,
    watchdog_alert_cooldown_sec: 3600,
    watchdog_memory_threshold_mb: 0,
    watchdog_memory_threshold_percent: 0,
    watchdog_memory_increase_threshold_mb: 0,
    watchdog_memory_increase_window_sec: 0,
    watchdog_exit_on_memory_threshold: false,
    watchdog_exit_on_cpu_threshold: false,
  })

  const [stats, setStats] = useState<MonitoringStats>({
    cpu_percent: 0,
    memory_percent: 0,
    memory_rss_mb: 0,
    timestamp: '',
  })

  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [statsLoading, setStatsLoading] = useState(false)
  const [metricsLoading, setMetricsLoading] = useState(false)
  const [metricsData, setMetricsData] = useState<MetricsQueryResult | null>(null)
  const [timeRange, setTimeRange] = useState<'today' | '7days' | '30days' | '90days'>('today')
  const [granularity, setGranularity] = useState<'1min' | '5min' | '15min'>('1min')

  // 加载配置
  const loadConfig = async () => {
    setLoading(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/monitoring/config'), {
        credentials: 'include',
      })
      if (response.ok) {
        const result = await response.json()
        if (result.success && result.data) {
          setConfig(result.data)
        }
      }
    } catch (error) {
      console.error('Failed to load monitoring config:', error)
    } finally {
      setLoading(false)
    }
  }

  // 加载实时统计
  const loadStats = async () => {
    setStatsLoading(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/monitoring/stats'), {
        credentials: 'include',
      })
      if (response.ok) {
        const result = await response.json()
        if (result.success && result.data) {
          setStats(result.data)
        }
      }
    } catch (error) {
      console.error('Failed to load monitoring stats:', error)
    } finally {
      setStatsLoading(false)
    }
  }

  // 保存配置
  const saveConfig = async () => {
    setSaving(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/monitoring/config'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(config),
      })

      if (response.ok) {
        const result = await response.json()
        if (result.success) {
          toast({
            title: t.monitoring?.save_success || '监控配置已保存',
            status: 'success',
            duration: DEFAULTS.TOAST_DURATION,
          })
          // 重新加载配置以确保同步
          await loadConfig()
        } else {
          throw new Error(result.error || '保存失败')
        }
      } else {
        const result = await response.json()
        throw new Error(result.error || '保存失败')
      }
    } catch (error: any) {
      toast({
        title: t.monitoring?.save_failed || '保存失败',
        description: error.message || '未知错误',
        status: 'error',
        duration: DEFAULTS.TOAST_DURATION,
      })
    } finally {
      setSaving(false)
    }
  }

  // 加载历史指标数据
  const loadMetrics = async (range: 'today' | '7days' | '30days' | '90days', selectedGranularity?: '1min' | '5min' | '15min') => {
    setMetricsLoading(true)
    try {
      const now = new Date()
      let startTime: Date
      const useGranularity = selectedGranularity || granularity

      switch (range) {
        case 'today':
          startTime = new Date(now.getFullYear(), now.getMonth(), now.getDate())
          break
        case '7days':
          startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)
          break
        case '30days':
          startTime = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000)
          break
        case '90days':
          startTime = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000)
          break
        default:
          startTime = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)
      }

      const params = new URLSearchParams({
        start_time: startTime.toISOString(),
        end_time: now.toISOString(),
        granularity: useGranularity,
      })

      const response = await fetch(
        buildApiPath(adminPrefix, `/api/monitoring/metrics?${params.toString()}`),
        {
          credentials: 'include',
        }
      )

      if (response.ok) {
        const result = await response.json()
        if (result.success && result.data) {
          // 确保 data 字段始终是数组，如果为 null 则设为空数组
          const metricsResult = {
            ...result.data,
            data: result.data.data || [],
            summary: result.data.summary || {
              total_samples: 0,
              avg_cpu: 0,
              avg_memory_mb: 0,
              max_cpu: 0,
              max_memory_mb: 0,
            },
          }
          setMetricsData(metricsResult)
        }
      }
    } catch (error) {
      console.error('Failed to load metrics:', error)
    } finally {
      setMetricsLoading(false)
    }
  }

  // 定时刷新统计数据
  useEffect(() => {
    loadConfig()
    loadStats()
    loadMetrics(timeRange, granularity)

    const interval = setInterval(() => {
      loadStats()
    }, 5000) // 每5秒刷新一次

    return () => clearInterval(interval)
  }, [adminPrefix])

  // 当时间范围或粒度改变时重新加载数据
  useEffect(() => {
    loadMetrics(timeRange, granularity)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [timeRange, granularity])

  return (
    <Box>
      <HStack mb={6} justify="space-between">
        <Heading size="lg" color="gray.700">
          <Icon as={FiActivity} mr={2} />
          {t.monitoring?.title || '系统监控'}
        </Heading>
        <HStack>
          <Button
            leftIcon={<FiRefreshCw />}
            onClick={() => {
              loadConfig()
              loadStats()
            }}
            isLoading={loading || statsLoading}
          >
            {t.common?.refresh || '刷新'}
          </Button>
        </HStack>
      </HStack>

      {/* 实时监控卡片 */}
      <Card mb={6}>
        <CardHeader>
          <Heading size="md">{t.monitoring?.realtime_stats || '实时监控'}</Heading>
        </CardHeader>
        <CardBody>
          <SimpleGrid columns={{ base: 1, md: 3 }} spacing={6}>
            <Stat>
              <StatLabel>
                <Icon as={FiCpu} mr={2} />
                {t.monitoring?.cpu_usage || 'CPU 使用率'}
              </StatLabel>
              <StatNumber>
                {statsLoading ? (
                  <Spinner size="sm" />
                ) : (
                  `${stats.cpu_percent.toFixed(2)}%`
                )}
              </StatNumber>
              <StatHelpText>{t.monitoring?.realtime_cpu_usage ?? '实时 CPU 占用'}</StatHelpText>
            </Stat>
            <Stat>
              <StatLabel>
                <Icon as={FiHardDrive} mr={2} />
                {t.monitoring?.memory_usage || '内存使用'}
              </StatLabel>
              <StatNumber>
                {statsLoading ? (
                  <Spinner size="sm" />
                ) : (
                  `${stats.memory_percent.toFixed(2)}%`
                )}
              </StatNumber>
              <StatHelpText>
                {stats.memory_rss_mb > 0
                  ? `${stats.memory_rss_mb.toFixed(0)} MB`
                  : (t.monitoring?.memory_realtime_usage ?? '实时内存占用')}
              </StatHelpText>
            </Stat>
            <Stat>
              <StatLabel>{t.monitoring?.update_time ?? '更新时间'}</StatLabel>
              <StatNumber fontSize="md">
                {stats.timestamp
                  ? new Date(stats.timestamp).toLocaleTimeString()
                  : '-'}
              </StatNumber>
              <StatHelpText>{t.monitoring?.last_refresh_time ?? '最后刷新时间'}</StatHelpText>
            </Stat>
          </SimpleGrid>
        </CardBody>
      </Card>

      {/* 历史数据图表 */}
      <Card mb={6}>
        <CardHeader>
          <HStack justify="space-between">
            <Heading size="md">
              <Icon as={FiTrendingUp} mr={2} />
              {t.monitoring?.history_charts || '历史数据图表'}
            </Heading>
            <HStack>
              <Select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value as any)}
                width="150px"
              >
                <option value="today">{t.monitoring?.today ?? '今天'}</option>
                <option value="7days">{t.monitoring?.last7days ?? '最近7天'}</option>
                <option value="30days">{t.monitoring?.last30days ?? '最近30天'}</option>
                <option value="90days">{t.monitoring?.last90days ?? '最近90天'}</option>
              </Select>
              <Select
                value={granularity}
                onChange={(e) => setGranularity(e.target.value as '1min' | '5min' | '15min')}
                width="120px"
              >
                <option value="1min">{t.monitoring?.one_min ?? '1分钟'}</option>
                <option value="5min">{t.monitoring?.five_min ?? '5分钟'}</option>
                <option value="15min">{t.monitoring?.fifteen_min ?? '15分钟'}</option>
              </Select>
              <Button
                size="sm"
                leftIcon={<FiRefreshCw />}
                onClick={() => loadMetrics(timeRange, granularity)}
                isLoading={metricsLoading}
              >
                {t.common?.refresh ?? '刷新'}
              </Button>
            </HStack>
          </HStack>
        </CardHeader>
        <CardBody>
          {metricsLoading ? (
            <Box textAlign="center" py={10}>
              <Spinner size="lg" />
              <Text mt={4}>{t.monitoring?.loading_history_data ?? '加载历史数据中...'}</Text>
            </Box>
          ) : metricsData && metricsData.data && Array.isArray(metricsData.data) && metricsData.data.length > 0 ? (
            <Tabs>
              <TabList>
                <Tab>{t.monitoring?.cpu_usage ?? 'CPU 使用率'}</Tab>
                <Tab>{t.monitoring?.memory_usage ?? '内存使用'}</Tab>
              </TabList>
              <TabPanels>
                <TabPanel>
                  <Box height="400px">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={metricsData.data.map((item) => ({
                        time: new Date(item.timestamp).toLocaleString('zh-CN', {
                          month: 'short',
                          day: 'numeric',
                          hour: timeRange === 'today' ? '2-digit' : undefined,
                          minute: timeRange === 'today' ? '2-digit' : undefined,
                        }),
                        timestamp: item.timestamp,
                        value: item.cpu_percent,
                      }))}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis
                          dataKey="time"
                          angle={-45}
                          textAnchor="end"
                          height={80}
                          interval="preserveStartEnd"
                        />
                        <YAxis label={{ value: 'CPU (%)', angle: -90, position: 'insideLeft' }} />
                        <Tooltip
                          formatter={(value: any) => [`${Number(value).toFixed(2)}%`, t.monitoring?.cpu_usage ?? 'CPU 使用率']}
                          labelFormatter={(label) => `${t.monitoring?.time_label ?? '时间'}: ${label}`}
                        />
                        <Legend />
                        <Line
                          type="monotone"
                          dataKey="value"
                          stroke="#3182CE"
                          strokeWidth={2}
                          dot={{ r: 3 }}
                          name={t.monitoring?.cpu_usage ?? 'CPU 使用率'}
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  </Box>
                  {metricsData.summary && (
                    <SimpleGrid columns={{ base: 2, md: 4 }} spacing={4} mt={4}>
                      <Stat>
                        <StatLabel>{t.monitoring?.avg_cpu ?? '平均 CPU'}</StatLabel>
                        <StatNumber fontSize="lg">{metricsData.summary.avg_cpu.toFixed(2)}%</StatNumber>
                      </Stat>
                      <Stat>
                        <StatLabel>{t.monitoring?.max_cpu ?? '最大 CPU'}</StatLabel>
                        <StatNumber fontSize="lg">{metricsData.summary.max_cpu.toFixed(2)}%</StatNumber>
                      </Stat>
                      <Stat>
                        <StatLabel>{t.monitoring?.data_points ?? '数据点数'}</StatLabel>
                        <StatNumber fontSize="lg">{metricsData.summary.total_samples}</StatNumber>
                      </Stat>
                    </SimpleGrid>
                  )}
                </TabPanel>
                <TabPanel>
                  <Box height="400px">
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart data={metricsData.data.map((item) => ({
                        time: new Date(item.timestamp).toLocaleString('zh-CN', {
                          month: 'short',
                          day: 'numeric',
                          hour: timeRange === 'today' ? '2-digit' : undefined,
                          minute: timeRange === 'today' ? '2-digit' : undefined,
                        }),
                        timestamp: item.timestamp,
                        value: item.memory_mb,
                        percent: item.memory_percent,
                      }))}>
                        <CartesianGrid strokeDasharray="3 3" />
                        <XAxis
                          dataKey="time"
                          angle={-45}
                          textAnchor="end"
                          height={80}
                          interval="preserveStartEnd"
                        />
                        <YAxis
                          yAxisId="left"
                          label={{ value: '内存 (MB)', angle: -90, position: 'insideLeft' }}
                        />
                        <YAxis
                          yAxisId="right"
                          orientation="right"
                          label={{ value: '内存 (%)', angle: 90, position: 'insideRight' }}
                        />
                        <Tooltip
                          formatter={(value: any, name: string) => {
                            if (name === '内存MB') {
                              return [`${Number(value).toFixed(2)} MB`, t.monitoring?.memory_usage ?? '内存使用']
                            } else {
                              return [`${Number(value).toFixed(2)}%`, t.monitoring?.memory_percent ?? '内存百分比']
                            }
                          }}
                          labelFormatter={(label) => `${t.monitoring?.time_label ?? '时间'}: ${label}`}
                        />
                        <Legend />
                        <Line
                          yAxisId="left"
                          type="monotone"
                          dataKey="value"
                          stroke="#38A169"
                          strokeWidth={2}
                          dot={{ r: 3 }}
                          name={t.monitoring?.memory_mb ?? '内存MB'}
                        />
                        <Line
                          yAxisId="right"
                          type="monotone"
                          dataKey="percent"
                          stroke="#805AD5"
                          strokeWidth={2}
                          dot={{ r: 3 }}
                          name={t.monitoring?.memory_percent ?? '内存百分比'}
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  </Box>
                  {metricsData.summary && (
                    <SimpleGrid columns={{ base: 2, md: 4 }} spacing={4} mt={4}>
                      <Stat>
                        <StatLabel>{t.monitoring?.avg_memory ?? '平均内存'}</StatLabel>
                        <StatNumber fontSize="lg">{metricsData.summary.avg_memory_mb.toFixed(2)} MB</StatNumber>
                      </Stat>
                      <Stat>
                        <StatLabel>{t.monitoring?.max_memory ?? '最大内存'}</StatLabel>
                        <StatNumber fontSize="lg">{metricsData.summary.max_memory_mb.toFixed(2)} MB</StatNumber>
                      </Stat>
                      <Stat>
                        <StatLabel>{t.monitoring?.data_points ?? '数据点数'}</StatLabel>
                        <StatNumber fontSize="lg">{metricsData.summary.total_samples}</StatNumber>
                      </Stat>
                    </SimpleGrid>
                  )}
                </TabPanel>
              </TabPanels>
            </Tabs>
          ) : (
            <Box textAlign="center" py={10}>
              <Text color="gray.500">{t.monitoring?.no_history_data ?? '暂无历史数据'}</Text>
              <Text fontSize="sm" color="gray.400" mt={2}>
                {t.monitoring?.history_data_will_collect ?? '历史数据将在启用指标存储后开始收集'}
              </Text>
            </Box>
          )}
        </CardBody>
      </Card>

      {/* 基础监控配置 */}
      <Card mb={6}>
        <CardHeader>
          <Heading size="md">{t.monitoring?.basic_config || '基础监控配置'}</Heading>
        </CardHeader>
        <CardBody>
          <VStack spacing={4} align="stretch">
            <FormControl>
              <FormLabel>{t.monitoring?.memory_max_usage_percent ?? '内存最大使用百分比 (%)'}</FormLabel>
              <NumberInput
                value={config.memory_max_usage_percent}
                min={5}
                max={90}
                onChange={(_, value) =>
                  setConfig({ ...config, memory_max_usage_percent: value || 20 })
                }
              >
                <NumberInputField />
                <NumberInputStepper>
                  <NumberIncrementStepper />
                  <NumberDecrementStepper />
                </NumberInputStepper>
              </NumberInput>
            </FormControl>
            <FormControl>
              <FormLabel>{t.monitoring?.memory_release_cooldown_sec ?? '内存释放冷却时间 (秒)'}</FormLabel>
              <NumberInput
                value={config.memory_release_cooldown_sec}
                min={60}
                onChange={(_, value) =>
                  setConfig({ ...config, memory_release_cooldown_sec: value || 300 })
                }
              >
                <NumberInputField />
                <NumberInputStepper>
                  <NumberIncrementStepper />
                  <NumberDecrementStepper />
                </NumberInputStepper>
              </NumberInput>
            </FormControl>
          </VStack>
        </CardBody>
      </Card>

      {/* 看门狗配置 */}
      <Card mb={6}>
        <CardHeader>
          <Heading size="md">{t.monitoring?.watchdog_config || '看门狗配置'}</Heading>
        </CardHeader>
        <CardBody>
          <VStack spacing={6} align="stretch">
            <FormControl display="flex" alignItems="center">
              <FormLabel mb={0} flex="1">
                {t.monitoring?.watchdog_enabled || '启用看门狗'}
              </FormLabel>
              <Switch
                isChecked={config.watchdog_enabled}
                onChange={(e) =>
                  setConfig({ ...config, watchdog_enabled: e.target.checked })
                }
              />
            </FormControl>

            {config.watchdog_enabled && (
              <>
                <Divider />
                <Heading size="sm">{t.monitoring?.cpu_monitor_config ?? 'CPU 监控配置'}</Heading>
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                  <FormControl>
                    <FormLabel>
                      {t.monitoring?.cpu_threshold || 'CPU 绝对阈值 (%)'}
                    </FormLabel>
                    <NumberInput
                      value={config.watchdog_cpu_threshold_percent}
                      min={1}
                      max={100}
                      onChange={(_, value) =>
                        setConfig({
                          ...config,
                          watchdog_cpu_threshold_percent: value || 30,
                        })
                      }
                    >
                      <NumberInputField />
                      <NumberInputStepper>
                        <NumberIncrementStepper />
                        <NumberDecrementStepper />
                      </NumberInputStepper>
                    </NumberInput>
                  </FormControl>
                  <FormControl>
                    <FormLabel>
                      {t.monitoring?.cpu_increase_threshold || 'CPU 增长阈值 (%)'}
                    </FormLabel>
                    <NumberInput
                      value={config.watchdog_cpu_increase_threshold_percent}
                      min={1}
                      max={100}
                      onChange={(_, value) =>
                        setConfig({
                          ...config,
                          watchdog_cpu_increase_threshold_percent: value || 15,
                        })
                      }
                    >
                      <NumberInputField />
                      <NumberInputStepper>
                        <NumberIncrementStepper />
                        <NumberDecrementStepper />
                      </NumberInputStepper>
                    </NumberInput>
                  </FormControl>
                  <FormControl>
                    <FormLabel>
                      {t.monitoring?.cpu_increase_window || 'CPU 增长检测窗口 (秒)'}
                    </FormLabel>
                    <NumberInput
                      value={config.watchdog_cpu_increase_window_sec}
                      min={60}
                      max={3600}
                      onChange={(_, value) =>
                        setConfig({
                          ...config,
                          watchdog_cpu_increase_window_sec: value || 180,
                        })
                      }
                    >
                      <NumberInputField />
                      <NumberInputStepper>
                        <NumberIncrementStepper />
                        <NumberDecrementStepper />
                      </NumberInputStepper>
                    </NumberInput>
                  </FormControl>
                  <FormControl>
                    <FormLabel>
                      {t.monitoring?.check_interval || '检查间隔 (秒)'}
                    </FormLabel>
                    <NumberInput
                      value={config.watchdog_check_interval_sec}
                      min={10}
                      max={300}
                      onChange={(_, value) =>
                        setConfig({
                          ...config,
                          watchdog_check_interval_sec: value || 30,
                        })
                      }
                    >
                      <NumberInputField />
                      <NumberInputStepper>
                        <NumberIncrementStepper />
                        <NumberDecrementStepper />
                      </NumberInputStepper>
                    </NumberInput>
                  </FormControl>
                </SimpleGrid>

                <Divider />
                <Heading size="sm">{t.monitoring?.memory_monitor_config ?? '内存监控配置'}</Heading>
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                  <FormControl>
                    <FormLabel>
                      {t.monitoring?.memory_threshold_mb || '内存绝对阈值 (MB)'}
                    </FormLabel>
                    <NumberInput
                      value={config.watchdog_memory_threshold_mb}
                      min={0}
                      onChange={(_, value) =>
                        setConfig({
                          ...config,
                          watchdog_memory_threshold_mb: value || 0,
                        })
                      }
                    >
                      <NumberInputField />
                      <NumberInputStepper>
                        <NumberIncrementStepper />
                        <NumberDecrementStepper />
                      </NumberInputStepper>
                    </NumberInput>
                    <Text fontSize="sm" color="gray.500" mt={1}>
                      {t.monitoring?.zero_disable ?? '0 表示禁用'}
                    </Text>
                  </FormControl>
                  <FormControl>
                    <FormLabel>
                      {t.monitoring?.memory_threshold_percent || '内存占用百分比阈值 (%)'}
                    </FormLabel>
                    <NumberInput
                      value={config.watchdog_memory_threshold_percent}
                      min={0}
                      max={100}
                      onChange={(_, value) =>
                        setConfig({
                          ...config,
                          watchdog_memory_threshold_percent: value || 0,
                        })
                      }
                    >
                      <NumberInputField />
                      <NumberInputStepper>
                        <NumberIncrementStepper />
                        <NumberDecrementStepper />
                      </NumberInputStepper>
                    </NumberInput>
                    <Text fontSize="sm" color="gray.500" mt={1}>
                      {t.monitoring?.zero_disable ?? '0 表示禁用'}
                    </Text>
                  </FormControl>
                  <FormControl>
                    <FormLabel>
                      {t.monitoring?.memory_increase_threshold || '内存增长阈值 (MB)'}
                    </FormLabel>
                    <NumberInput
                      value={config.watchdog_memory_increase_threshold_mb}
                      min={0}
                      onChange={(_, value) =>
                        setConfig({
                          ...config,
                          watchdog_memory_increase_threshold_mb: value || 0,
                        })
                      }
                    >
                      <NumberInputField />
                      <NumberInputStepper>
                        <NumberIncrementStepper />
                        <NumberDecrementStepper />
                      </NumberInputStepper>
                    </NumberInput>
                  </FormControl>
                  <FormControl>
                    <FormLabel>
                      {t.monitoring?.memory_increase_window || '内存增长检测窗口 (秒)'}
                    </FormLabel>
                    <NumberInput
                      value={config.watchdog_memory_increase_window_sec}
                      min={60}
                      max={3600}
                      onChange={(_, value) =>
                        setConfig({
                          ...config,
                          watchdog_memory_increase_window_sec: value || 0,
                        })
                      }
                    >
                      <NumberInputField />
                      <NumberInputStepper>
                        <NumberIncrementStepper />
                        <NumberDecrementStepper />
                      </NumberInputStepper>
                    </NumberInput>
                  </FormControl>
                </SimpleGrid>

                <Divider />
                <Heading size="sm">{t.monitoring?.alert_config ?? '报警配置'}</Heading>
                <FormControl>
                  <FormLabel>
                    {t.monitoring?.alert_cooldown || '报警冷却时间 (秒)'}
                  </FormLabel>
                  <NumberInput
                    value={config.watchdog_alert_cooldown_sec}
                    min={60}
                    max={86400}
                    onChange={(_, value) =>
                      setConfig({
                        ...config,
                        watchdog_alert_cooldown_sec: value || 3600,
                      })
                    }
                  >
                    <NumberInputField />
                    <NumberInputStepper>
                      <NumberIncrementStepper />
                      <NumberDecrementStepper />
                    </NumberInputStepper>
                  </NumberInput>
                </FormControl>

                <Divider />
                <Heading size="sm">{t.monitoring?.auto_exit_config ?? '自动退出配置'}</Heading>
                {(config.watchdog_exit_on_memory_threshold ||
                  config.watchdog_exit_on_cpu_threshold) && (
                  <Alert status="warning">
                    <AlertIcon as={FiAlertTriangle} />
                    <AlertDescription>
                      {t.monitoring?.exit_warning ||
                        '⚠️ 启用自动退出后，进程将在超过阈值时退出。systemd 会在 5 秒后自动重启进程。请确保使用 systemd 管理 SSLcat 服务。'}
                    </AlertDescription>
                  </Alert>
                )}
                <FormControl display="flex" alignItems="center">
                  <FormLabel mb={0} flex="1">
                    {t.monitoring?.exit_on_memory || '内存超阈值时自动退出'}
                  </FormLabel>
                  <Switch
                    isChecked={config.watchdog_exit_on_memory_threshold}
                    onChange={(e) =>
                      setConfig({
                        ...config,
                        watchdog_exit_on_memory_threshold: e.target.checked,
                      })
                    }
                  />
                </FormControl>
                <FormControl display="flex" alignItems="center">
                  <FormLabel mb={0} flex="1">
                    {t.monitoring?.exit_on_cpu || 'CPU 超阈值时自动退出'}
                  </FormLabel>
                  <Switch
                    isChecked={config.watchdog_exit_on_cpu_threshold}
                    onChange={(e) =>
                      setConfig({
                        ...config,
                        watchdog_exit_on_cpu_threshold: e.target.checked,
                      })
                    }
                  />
                </FormControl>
              </>
            )}
          </VStack>
        </CardBody>
      </Card>

      {/* 保存按钮 - 放在页面底部 */}
      <HStack justify="flex-end" mt={6}>
        <Button
          leftIcon={<FiSave />}
          colorScheme="blue"
          onClick={saveConfig}
          isLoading={saving}
          size="lg"
        >
          {t.common?.save || '保存'}
        </Button>
      </HStack>
    </Box>
  )
}

export default Monitoring


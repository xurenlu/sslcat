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
} from '@chakra-ui/react'
import {
  FiActivity,
  FiSave,
  FiRefreshCw,
  FiCpu,
  FiHardDrive,
  FiAlertTriangle,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'
import { TOAST_DURATION } from '../constants'

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
            duration: TOAST_DURATION,
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
        duration: TOAST_DURATION,
      })
    } finally {
      setSaving(false)
    }
  }

  // 定时刷新统计数据
  useEffect(() => {
    loadConfig()
    loadStats()

    const interval = setInterval(() => {
      loadStats()
    }, 5000) // 每5秒刷新一次

    return () => clearInterval(interval)
  }, [adminPrefix])

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
          <Button
            leftIcon={<FiSave />}
            colorScheme="blue"
            onClick={saveConfig}
            isLoading={saving}
          >
            {t.common?.save || '保存'}
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
              <StatHelpText>实时 CPU 占用</StatHelpText>
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
                  : '实时内存占用'}
              </StatHelpText>
            </Stat>
            <Stat>
              <StatLabel>更新时间</StatLabel>
              <StatNumber fontSize="md">
                {stats.timestamp
                  ? new Date(stats.timestamp).toLocaleTimeString('zh-CN')
                  : '-'}
              </StatNumber>
              <StatHelpText>最后刷新时间</StatHelpText>
            </Stat>
          </SimpleGrid>
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
              <FormLabel>内存最大使用百分比 (%)</FormLabel>
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
              <FormLabel>内存释放冷却时间 (秒)</FormLabel>
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
                <Heading size="sm">CPU 监控配置</Heading>
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
                <Heading size="sm">内存监控配置</Heading>
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
                      0 表示禁用
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
                      0 表示禁用
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
                <Heading size="sm">报警配置</Heading>
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
                <Heading size="sm">自动退出配置</Heading>
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
    </Box>
  )
}

export default Monitoring


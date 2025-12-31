import React, { useState, useEffect } from 'react'
import {
  Box,
  VStack,
  HStack,
  FormControl,
  FormLabel,
  Switch,
  Select,
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  NumberIncrementStepper,
  NumberDecrementStepper,
  Button,
  useToast,
  Text,
  Divider,
  Badge,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  SimpleGrid,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  IconButton,
  Spinner,
  Center,
} from '@chakra-ui/react'
import { FiTrash2, FiRefreshCw } from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'

interface BotDetectionConfigProps {
  domain: string
}

interface BotConfig {
  mode: string
  low_risk_threshold: number
  medium_risk_threshold: number
  high_risk_threshold: number
  max_requests_per_minute: number
  max_requests_per_hour: number
  whitelist_duration: number
  token_duration: number
  skip_paths: string[]
}

interface WhitelistEntry {
  id: number
  ip: string
  domain: string
  added_at: string
  expires_at: string
  verified_count: number
  last_verified_at: string
}

const BotDetectionConfig: React.FC<BotDetectionConfigProps> = ({ domain }) => {
  const { adminPrefix } = useConfig()
  const toast = useToast()
  
  const [enabled, setEnabled] = useState(false)
  const [botConfig, setBotConfig] = useState<BotConfig>({
    mode: 'monitor',
    low_risk_threshold: 30,
    medium_risk_threshold: 50,
    high_risk_threshold: 70,
    max_requests_per_minute: 60,
    max_requests_per_hour: 1000,
    whitelist_duration: 168,
    token_duration: 24,
    skip_paths: [],
  })
  
  const [whitelist, setWhitelist] = useState<WhitelistEntry[]>([])
  const [stats, setStats] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [botAPIPrefix, setBotAPIPrefix] = useState<string>('')

  // 加载 Bot API 前缀
  useEffect(() => {
    loadBotAPIPrefix()
  }, [])

  // 加载配置
  useEffect(() => {
    if (botAPIPrefix) {
      loadConfig()
      loadWhitelist()
      loadStats()
    }
  }, [domain, botAPIPrefix])

  const loadBotAPIPrefix = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/config/bot-api-prefix'), {
        credentials: 'include',
      })
      const data = await response.json()
      if (data.success && data.prefix) {
        setBotAPIPrefix(data.prefix)
      } else {
        // 兼容旧版本，使用默认前缀
        setBotAPIPrefix('/bot-api')
      }
    } catch (error) {
      console.error('Failed to load bot API prefix:', error)
      setBotAPIPrefix('/bot-api')
    }
  }

  const loadConfig = async () => {
    try {
      setLoading(true)
      const response = await fetch(buildApiPath(adminPrefix, `${botAPIPrefix}/config?domain=${domain}`), {
        credentials: 'include',
      })
      const data = await response.json()
      if (data.success) {
        setEnabled(data.enabled || false)
        if (data.config) {
          setBotConfig(data.config)
        }
      }
    } catch (error) {
      console.error('Failed to load bot detection config:', error)
    } finally {
      setLoading(false)
    }
  }

  const loadWhitelist = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, `${botAPIPrefix}/whitelist?domain=${domain}`), {
        credentials: 'include',
      })
      const data = await response.json()
      if (data.success) {
        setWhitelist(data.entries || [])
      }
    } catch (error) {
      console.error('Failed to load whitelist:', error)
    }
  }

  const loadStats = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, `${botAPIPrefix}/stats`), {
        credentials: 'include',
      })
      const data = await response.json()
      if (data.success) {
        setStats(data.stats)
      }
    } catch (error) {
      console.error('Failed to load stats:', error)
    }
  }

  const handleSave = async () => {
    try {
      setSaving(true)
      const response = await fetch(buildApiPath(adminPrefix, `${botAPIPrefix}/config`), {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          domain,
          enabled,
          config: botConfig,
        }),
      })
      
      const data = await response.json()
      if (data.success) {
        toast({
          title: '保存成功',
          description: '机器人检测配置已更新',
          status: 'success',
          duration: 3000,
        })
      } else {
        throw new Error(data.message || '保存失败')
      }
    } catch (error: any) {
      toast({
        title: '保存失败',
        description: error.message,
        status: 'error',
        duration: 5000,
      })
    } finally {
      setSaving(false)
    }
  }

  const handleRemoveWhitelist = async (ip: string) => {
    try {
      const response = await fetch(
        buildApiPath(adminPrefix, `${botAPIPrefix}/whitelist?ip=${ip}&domain=${domain}`),
        {
          method: 'DELETE',
          credentials: 'include',
        }
      )
      
      const data = await response.json()
      if (data.success) {
        toast({
          title: '删除成功',
          status: 'success',
          duration: 2000,
        })
        loadWhitelist()
      }
    } catch (error) {
      toast({
        title: '删除失败',
        status: 'error',
        duration: 3000,
      })
    }
  }

  if (loading) {
    return (
      <Center py={10}>
        <Spinner size="xl" />
      </Center>
    )
  }

  return (
    <VStack spacing={6} align="stretch">
      {/* 统计信息 */}
      {stats && (
        <SimpleGrid columns={{ base: 1, md: 3 }} spacing={4}>
          <Stat>
            <StatLabel>白名单数量</StatLabel>
            <StatNumber>{stats.whitelist_count || 0}</StatNumber>
            <StatHelpText>已验证的 IP</StatHelpText>
          </Stat>
          <Stat>
            <StatLabel>追踪 IP 数</StatLabel>
            <StatNumber>{stats.analyzer?.tracked_ips || 0}</StatNumber>
            <StatHelpText>正在监控中</StatHelpText>
          </Stat>
          <Stat>
            <StatLabel>活跃挑战</StatLabel>
            <StatNumber>{stats.active_challenges || 0}</StatNumber>
            <StatHelpText>待验证</StatHelpText>
          </Stat>
        </SimpleGrid>
      )}

      <Divider />

      {/* 基本配置 */}
      <Box>
        <FormControl display="flex" alignItems="center" mb={4}>
          <FormLabel htmlFor="bot-enabled" mb="0">
            启用机器人检测
          </FormLabel>
          <Switch
            id="bot-enabled"
            isChecked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
        </FormControl>

        {enabled && (
          <VStack spacing={4} align="stretch">
            <FormControl>
              <FormLabel>检测模式</FormLabel>
              <Select
                value={botConfig.mode}
                onChange={(e) => setBotConfig({ ...botConfig, mode: e.target.value })}
              >
                <option value="monitor">监控模式（仅记录）</option>
                <option value="challenge">验证模式（弹出验证）</option>
              </Select>
              <Text fontSize="sm" color="gray.600" mt={1}>
                监控模式仅记录可疑行为，验证模式会要求用户完成验证
              </Text>
            </FormControl>

            <SimpleGrid columns={{ base: 1, md: 3 }} spacing={4}>
              <FormControl>
                <FormLabel>低风险阈值</FormLabel>
                <NumberInput
                  value={botConfig.low_risk_threshold}
                  onChange={(_, val) => setBotConfig({ ...botConfig, low_risk_threshold: val })}
                  min={0}
                  max={100}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
              </FormControl>

              <FormControl>
                <FormLabel>中风险阈值</FormLabel>
                <NumberInput
                  value={botConfig.medium_risk_threshold}
                  onChange={(_, val) => setBotConfig({ ...botConfig, medium_risk_threshold: val })}
                  min={0}
                  max={100}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
              </FormControl>

              <FormControl>
                <FormLabel>高风险阈值</FormLabel>
                <NumberInput
                  value={botConfig.high_risk_threshold}
                  onChange={(_, val) => setBotConfig({ ...botConfig, high_risk_threshold: val })}
                  min={0}
                  max={100}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
              </FormControl>
            </SimpleGrid>

            <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
              <FormControl>
                <FormLabel>每分钟最大请求数</FormLabel>
                <NumberInput
                  value={botConfig.max_requests_per_minute}
                  onChange={(_, val) => setBotConfig({ ...botConfig, max_requests_per_minute: val })}
                  min={1}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
              </FormControl>

              <FormControl>
                <FormLabel>每小时最大请求数</FormLabel>
                <NumberInput
                  value={botConfig.max_requests_per_hour}
                  onChange={(_, val) => setBotConfig({ ...botConfig, max_requests_per_hour: val })}
                  min={1}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
              </FormControl>
            </SimpleGrid>

            <HStack spacing={4}>
              <Button
                colorScheme="blue"
                onClick={handleSave}
                isLoading={saving}
                loadingText="保存中..."
              >
                保存配置
              </Button>
              <Button variant="outline" onClick={loadConfig}>
                重置
              </Button>
            </HStack>
          </VStack>
        )}
      </Box>

      {/* 白名单管理 */}
      {enabled && whitelist.length > 0 && (
        <>
          <Divider />
          <Box>
            <HStack justify="space-between" mb={4}>
              <Text fontSize="lg" fontWeight="bold">
                白名单 ({whitelist.length})
              </Text>
              <IconButton
                aria-label="刷新"
                icon={<FiRefreshCw />}
                size="sm"
                onClick={loadWhitelist}
              />
            </HStack>

            <Box overflowX="auto">
              <Table size="sm">
                <Thead>
                  <Tr>
                    <Th>IP 地址</Th>
                    <Th>验证次数</Th>
                    <Th>添加时间</Th>
                    <Th>过期时间</Th>
                    <Th>操作</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {whitelist.map((entry) => (
                    <Tr key={entry.id}>
                      <Td>{entry.ip}</Td>
                      <Td>
                        <Badge colorScheme="green">{entry.verified_count}</Badge>
                      </Td>
                      <Td>{new Date(entry.added_at).toLocaleString()}</Td>
                      <Td>{new Date(entry.expires_at).toLocaleString()}</Td>
                      <Td>
                        <IconButton
                          aria-label="删除"
                          icon={<FiTrash2 />}
                          size="sm"
                          colorScheme="red"
                          variant="ghost"
                          onClick={() => handleRemoveWhitelist(entry.ip)}
                        />
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </Box>
          </Box>
        </>
      )}
    </VStack>
  )
}

export default BotDetectionConfig


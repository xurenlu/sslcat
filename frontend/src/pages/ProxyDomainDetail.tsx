import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  Button,
  Card,
  CardBody,
  HStack,
  VStack,
  Text,
  Badge,
  Icon,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  useToast,
  Spinner,
  Flex,
  SimpleGrid,
  Stat,
  StatLabel,
  StatNumber,
  Tooltip,
  Progress,
} from '@chakra-ui/react'
import { motion, AnimatePresence } from 'framer-motion'
import { FiArrowLeft, FiEdit, FiGlobe, FiZap, FiActivity, FiServer } from 'react-icons/fi'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useConfig, buildPath, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

const MotionBox = motion(Box)
const MotionCard = motion(Card)

const ALGORITHM_LABELS: Record<string, string> = {
  round_robin: '轮询 (Round Robin)',
  weighted_round_robin: '加权轮询',
  least_conn: '最少连接',
  ip_hash: 'IP 哈希',
  random: '随机',
  consistent_hash: '一致性哈希',
}

interface ProxyBackend {
  id: string
  host: string
  port: number
  weight?: number
  health_check_enabled?: boolean
}

interface BackendStats {
  id: string
  host: string
  port: number
  is_healthy: boolean
  active_connections: number
  total_requests: number
  failed_requests: number
  success_rate: number
  average_response_time: number
  last_health_check: string
  last_failure: string
}

interface LoadBalancerStats {
  algorithm: string
  total_backends: number
  healthy_backends: number
  unhealthy_backends: number
  total_requests: number
  total_failures: number
  average_response_time: number
  backend_stats: BackendStats[]
}

interface ProxyRuleData {
  domain: string
  target: string
  port: number
  enabled: boolean
  ssl_only: boolean
  backends?: ProxyBackend[]
  load_balancer_algorithm?: string
  session_affinity_enabled?: boolean
  session_affinity_method?: string
  health_check_enabled?: boolean
  cdn_enabled?: boolean
  auth_enabled?: boolean
}

// 响应时间配色：绿 < 100ms, 黄 < 300ms, 橙 < 800ms, 红 >= 800
const responseTimeColor = (ms: number): string => {
  if (ms < 0) return 'gray'
  if (ms < 100) return 'green'
  if (ms < 300) return 'yellow'
  if (ms < 800) return 'orange'
  return 'red'
}

const ProxyDomainDetail: React.FC = () => {
  const [searchParams] = useSearchParams()
  const domain = searchParams.get('domain') || ''
  const navigate = useNavigate()
  const toast = useToast()
  const { adminPrefix } = useConfig()
  const t = useTranslation()

  const [rule, setRule] = useState<ProxyRuleData | null>(null)
  const [lbStats, setLbStats] = useState<LoadBalancerStats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    if (!domain) {
      toast({ title: '缺少域名参数', status: 'warning', isClosable: true })
      navigate(buildPath(adminPrefix, '/proxy'))
      return
    }
    const fetchRule = async () => {
      setLoading(true)
      try {
        const res = await fetch(
          buildApiPath(adminPrefix, `/proxy/rule?domain=${encodeURIComponent(domain)}&detail=true`),
          { method: 'GET', credentials: 'include' }
        )
        if (!res.ok) {
          if (res.status === 404) {
            toast({ title: '规则不存在', status: 'error', isClosable: true })
            navigate(buildPath(adminPrefix, '/proxy'))
            return
          }
          throw new Error(`HTTP ${res.status}`)
        }
        const data = await res.json()
        if (data.success && data.data) {
          setRule(data.data)
          setLbStats(data.load_balancer_stats || null)
        }
      } catch (e) {
        console.error(e)
        toast({
          title: '加载失败',
          description: e instanceof Error ? e.message : '未知错误',
          status: 'error',
          isClosable: true,
        })
      } finally {
        setLoading(false)
      }
    }
    fetchRule()
  }, [domain, adminPrefix, navigate, toast])

  const backends = rule?.backends?.length
    ? rule.backends
    : rule
      ? [{ id: 'default', host: rule.target, port: rule.port, weight: 1 }]
      : []
  const isMultiUpstream = backends.length > 1
  const algorithmLabel =
    (rule?.load_balancer_algorithm && ALGORITHM_LABELS[rule.load_balancer_algorithm]) ||
    rule?.load_balancer_algorithm ||
    '—'

  if (loading) {
    return (
      <Flex justify="center" align="center" minH="280px">
        <VStack spacing={4}>
          <Spinner size="xl" thickness="3px" color="blue.500" />
          <Text color="gray.500" fontSize="sm">加载规则与实时统计…</Text>
        </VStack>
      </Flex>
    )
  }

  if (!rule) {
    return null
  }

  return (
    <MotionBox
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.25 }}
    >
      {/* 顶部：返回 + 域名 + 编辑 */}
      <Flex
        mb={6}
        align="center"
        justify="space-between"
        flexWrap="wrap"
        gap={4}
        p={4}
        borderRadius="xl"
        bg="white"
        _dark={{ bg: 'whiteAlpha.50' }}
        boxShadow="sm"
        borderWidth="1px"
        borderColor="gray.100"
        _dark={{ borderColor: 'whiteAlpha.100' }}
      >
        <HStack spacing={4}>
          <Button
            leftIcon={<Icon as={FiArrowLeft} />}
            variant="ghost"
            size="sm"
            onClick={() => navigate(buildPath(adminPrefix, '/proxy'))}
          >
            {t.common.back}
          </Button>
          <HStack spacing={3} align="center">
            <Flex
              align="center"
              justify="center"
              w={10}
              h={10}
              borderRadius="lg"
              bg="blue.50"
              _dark={{ bg: 'blue.900/40' }}
            >
              <Icon as={FiGlobe} boxSize={5} color="blue.500" />
            </Flex>
            <Heading size="md" fontFamily="mono" fontWeight="600">
              {rule.domain}
            </Heading>
            <HStack spacing={2}>
              <Badge colorScheme={rule.enabled ? 'green' : 'gray'} variant="subtle" px={2} py={0.5}>
                {rule.enabled ? t.common.enable : t.common.disable}
              </Badge>
              <Badge colorScheme={rule.ssl_only ? 'blue' : 'orange'} variant="subtle" px={2} py={0.5}>
                {rule.ssl_only ? 'HTTPS' : 'HTTP'}
              </Badge>
              {isMultiUpstream && (
                <Badge colorScheme="purple" variant="subtle" px={2} py={0.5}>
                  {t.proxyDetail.multiUpstream}
                </Badge>
              )}
            </HStack>
          </HStack>
        </HStack>
        <Button
          leftIcon={<Icon as={FiEdit} />}
          colorScheme="blue"
          size="sm"
          onClick={() =>
            navigate(buildPath(adminPrefix, `/proxy/edit?domain=${encodeURIComponent(rule.domain)}`))
          }
        >
          {t.proxyDetail.editBackend}
        </Button>
      </Flex>

      <Tabs variant="soft-rounded" colorScheme="blue" size="sm">
        <TabList
          mb={4}
          p={1}
          borderRadius="lg"
          bg="gray.50"
          _dark={{ bg: 'whiteAlpha.100' }}
          gap={1}
        >
          <Tab _selected={{ bg: 'white', shadow: 'sm', color: 'blue.600' }} _dark={{ _selected: { bg: 'gray.800' } }}>
            {t.proxyDetail.overview}
          </Tab>
          <Tab _selected={{ bg: 'white', shadow: 'sm', color: 'blue.600' }} _dark={{ _selected: { bg: 'gray.800' } }}>
            {t.proxyDetail.forwardingRules}
          </Tab>
          <Tab _selected={{ bg: 'white', shadow: 'sm', color: 'blue.600' }} _dark={{ _selected: { bg: 'gray.800' } }}>
            {t.proxyDetail.healthCheck}
          </Tab>
        </TabList>

        <TabPanels>
          {/* 概览：统计卡片 + 流量走向缩略 */}
          <TabPanel px={0}>
            <SimpleGrid columns={{ base: 1, md: 2, lg: 3 }} spacing={4} mb={6}>
              {[
                {
                  label: t.proxyDetail.targetAddress,
                  value:
                    backends.length === 1
                      ? `${backends[0].host}:${backends[0].port}`
                      : `${backends.length} ${t.proxyDetail.backends}`,
                  accent: 'blue',
                  mono: true,
                },
                ...(isMultiUpstream
                  ? [
                      {
                        label: t.proxyDetail.loadBalanceAlgorithm,
                        value: algorithmLabel,
                        accent: 'purple' as const,
                        mono: false,
                      },
                      {
                        label: t.proxyDetail.sessionAffinity,
                        value: rule.session_affinity_enabled
                          ? rule.session_affinity_method || 'cookie'
                          : '—',
                        accent: 'teal' as const,
                        mono: false,
                      },
                    ]
                  : []),
                ...(lbStats
                  ? [
                      {
                        label: `${t.proxyDetail.healthy} / ${t.proxyDetail.backends}`,
                        value: `${lbStats.healthy_backends}/${lbStats.total_backends}`,
                        accent: 'green' as const,
                        mono: false,
                      },
                      {
                        label: t.proxyDetail.totalRequests,
                        value: String(lbStats.total_requests),
                        accent: 'cyan' as const,
                        mono: true,
                      },
                    ]
                  : []),
              ].map((item, i) => (
                <MotionCard
                  key={i}
                  initial={{ opacity: 0, y: 12 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.06, duration: 0.3 }}
                  borderLeftWidth="4px"
                  borderLeftColor={`${item.accent}.400`}
                  _dark={{ borderLeftColor: `${item.accent}.500` }}
                >
                  <CardBody>
                    <Stat>
                      <StatLabel color="gray.600" _dark={{ color: 'gray.400' }} fontSize="sm">
                        {item.label}
                      </StatLabel>
                      <StatNumber fontFamily={item.mono ? 'mono' : undefined} fontSize="lg">
                        {item.value}
                      </StatNumber>
                    </Stat>
                  </CardBody>
                </MotionCard>
              ))}
            </SimpleGrid>
            <HStack spacing={2} flexWrap="wrap">
              {rule.cdn_enabled && <Badge colorScheme="purple">CDN</Badge>}
              {rule.auth_enabled && <Badge colorScheme="red">认证</Badge>}
            </HStack>
          </TabPanel>

          {/* 转发规则：炫酷流量图 + 上游卡片 */}
          <TabPanel px={0}>
            <MotionBox
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.3 }}
            >
              <Card
                overflow="hidden"
                bg="linear-gradient(135deg, var(--chakra-colors-gray-50) 0%, var(--chakra-colors-white) 100%)"
                _dark={{
                  bg: 'linear-gradient(135deg, var(--chakra-colors-whiteAlpha-50) 0%, var(--chakra-colors-whiteAlpha-100) 0%)',
                }}
                borderWidth="1px"
                borderColor="gray.200"
                _dark={{ borderColor: 'whiteAlpha.200' }}
              >
                <CardBody p={6}>
                  <Text fontWeight="semibold" mb={5} fontSize="md" color="gray.700" _dark={{ color: 'gray.200' }}>
                    {t.proxyDetail.flowDiagram}
                  </Text>

                  {/* SVG 流动拓扑：客户端 -> Gateway -> 上游们（keyframes 放同一父级） */}
                  <Box
                    sx={{
                      '@keyframes flowDash': {
                        '0%': { strokeDashoffset: 24 },
                        '100%': { strokeDashoffset: 0 },
                      },
                    }}
                  >
                    <VStack align="stretch" spacing={6}>
                      <Flex align="center" justify="center" flexWrap="wrap" gap={{ base: 4, md: 6 }}>
                        {/* 客户端节点 */}
                        <MotionBox
                          initial={{ scale: 0.9, opacity: 0 }}
                          animate={{ scale: 1, opacity: 1 }}
                          transition={{ duration: 0.35 }}
                          px={5}
                          py={4}
                          borderRadius="xl"
                          bg="blue.500"
                          color="white"
                          fontWeight="600"
                          boxShadow="lg"
                          _hover={{ shadow: 'xl', scale: 1.02 }}
                          style={{ originX: 0.5, originY: 0.5 }}
                        >
                          👤 {t.proxyDetail.clientToGateway}
                        </MotionBox>

                        <Flex align="center" minW={10} justify="center">
                          <Box as="svg" width="48" height="24" viewBox="0 0 48 24" fill="none">
                            <path
                              d="M 0 12 L 44 12"
                              stroke="var(--chakra-colors-blue-400)"
                              strokeWidth="2"
                              strokeDasharray="6 6"
                              style={{ animation: 'flowDash 0.8s linear infinite' }}
                            />
                            <path d="M 40 8 L 48 12 L 40 16 Z" fill="var(--chakra-colors-blue-400)" />
                          </Box>
                        </Flex>

                        <MotionBox
                          initial={{ scale: 0.9, opacity: 0 }}
                          animate={{ scale: 1, opacity: 1 }}
                          transition={{ delay: 0.1, duration: 0.35 }}
                          px={5}
                          py={4}
                          borderRadius="xl"
                          bgGradient="linear(to-br, teal.400, teal.600)"
                          color="white"
                          fontWeight="600"
                          boxShadow="lg"
                          display="flex"
                          alignItems="center"
                          gap={2}
                        >
                          <Icon as={FiZap} boxSize={5} />
                          SSLcat Gateway
                        </MotionBox>

                        <Flex align="center" minW={10} justify="center">
                          <Box as="svg" width="48" height="24" viewBox="0 0 48 24" fill="none">
                            <path
                              d="M 0 12 L 44 12"
                              stroke="var(--chakra-colors-teal-400)"
                              strokeWidth="2"
                              strokeDasharray="6 6"
                              style={{ animation: 'flowDash 0.8s linear infinite' }}
                            />
                            <path d="M 40 8 L 48 12 L 40 16 Z" fill="var(--chakra-colors-teal-400)" />
                          </Box>
                        </Flex>
                      </Flex>

                    <Text fontSize="sm" color="gray.600" _dark={{ color: 'gray.400' }}>
                      {t.proxyDetail.gatewayToUpstreams}
                      {isMultiUpstream && (
                        <Badge colorScheme="purple" ml={2} variant="subtle">
                          {algorithmLabel}
                        </Badge>
                      )}
                    </Text>

                    {/* 上游卡片：带健康脉冲 */}
                    <SimpleGrid
                      columns={{ base: 1, sm: 2, md: Math.min(backends.length, 4) }}
                      spacing={4}
                    >
                      <AnimatePresence>
                        {backends.map((be, i) => {
                          const stat = lbStats?.backend_stats?.find((s) => s.id === be.id)
                          const healthy = stat?.is_healthy !== false
                          return (
                            <MotionBox
                              key={be.id}
                              initial={{ opacity: 0, y: 16 }}
                              animate={{ opacity: 1, y: 0 }}
                              transition={{ delay: 0.15 + i * 0.08, duration: 0.35 }}
                            >
                              <Box
                                p={4}
                                borderRadius="xl"
                                borderWidth="2px"
                                borderColor={healthy ? 'green.300' : 'red.300'}
                                _dark={{
                                  borderColor: healthy ? 'green.500' : 'red.500',
                                }}
                                bg="white"
                                _dark={{ bg: 'gray.800' }}
                                boxShadow="md"
                                position="relative"
                                overflow="hidden"
                                _hover={{ shadow: 'lg' }}
                                sx={
                                  healthy
                                    ? {
                                        '&::before': {
                                          content: '""',
                                          position: 'absolute',
                                          inset: 0,
                                          borderRadius: 'inherit',
                                          padding: '2px',
                                          background: 'linear-gradient(135deg, transparent 40%, rgba(72, 187, 120, 0.4) 50%, transparent 60%)',
                                          WebkitMask: 'linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)',
                                          mask: 'linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0)',
                                          WebkitMaskComposite: 'xor',
                                          maskComposite: 'exclude',
                                          animation: 'shimmer 2.5s ease-in-out infinite',
                                        },
                                        '@keyframes shimmer': {
                                          '0%, 100%': { opacity: 0 },
                                          '50%': { opacity: 1 },
                                        },
                                      }
                                    : undefined
                                }
                              >
                                <HStack mb={2} spacing={2}>
                                  <Flex
                                    w={8}
                                    h={8}
                                    align="center"
                                    justify="center"
                                    borderRadius="md"
                                    bg={healthy ? 'green.50' : 'red.50'}
                                    _dark={{ bg: healthy ? 'green.900/30' : 'red.900/30' }}
                                  >
                                    <Icon
                                      as={FiServer}
                                      color={healthy ? 'green.500' : 'red.500'}
                                      boxSize={4}
                                    />
                                  </Flex>
                                  <Text fontFamily="mono" fontWeight="700" fontSize="sm">
                                    {be.host}:{be.port}
                                  </Text>
                                </HStack>
                                {be.weight != null && be.weight !== 1 && (
                                  <Text fontSize="xs" color="gray.500" mb={1}>
                                    权重 {be.weight}
                                  </Text>
                                )}
                                {stat && (
                                  <HStack mt={2} spacing={2}>
                                    <Badge
                                      colorScheme={healthy ? 'green' : 'red'}
                                      size="sm"
                                      variant="solid"
                                    >
                                      {healthy ? t.proxyDetail.healthy : t.proxyDetail.unhealthy}
                                    </Badge>
                                    {stat.average_response_time >= 0 && (
                                      <Text fontSize="xs" color="gray.600" _dark={{ color: 'gray.400' }}>
                                        {stat.average_response_time} ms
                                      </Text>
                                    )}
                                  </HStack>
                                )}
                              </Box>
                            </MotionBox>
                          )
                        })}
                      </AnimatePresence>
                    </SimpleGrid>
                    </VStack>
                  </Box>
                </CardBody>
              </Card>
            </MotionBox>
          </TabPanel>

          {/* 健康检查：表格式 + 响应时间条、成功率条 */}
          <TabPanel px={0}>
            {lbStats?.backend_stats?.length ? (
              <MotionBox
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.3 }}
              >
                <Card>
                  <CardBody overflowX="auto">
                    <Table variant="simple" size="sm">
                      <Thead>
                        <Tr>
                          <Th>{t.proxyDetail.targetAddress}</Th>
                          <Th>{t.ssl.status}</Th>
                          <Th>{t.proxyDetail.responseTime}</Th>
                          <Th>{t.proxyDetail.lastCheck}</Th>
                          <Th>{t.proxyDetail.activeConnections}</Th>
                          <Th>{t.proxyDetail.totalRequests}</Th>
                          <Th>{t.proxyDetail.failedRequests}</Th>
                          <Th>{t.proxyDetail.successRate}</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {lbStats.backend_stats.map((s, i) => (
                          <Tr key={s.id}>
                            <Td fontFamily="mono" fontWeight="600">
                              {s.host}:{s.port}
                            </Td>
                            <Td>
                              <HStack spacing={2}>
                                <Box
                                  w={2}
                                  h={2}
                                  borderRadius="full"
                                  bg={s.is_healthy ? 'green.500' : 'red.500'}
                                  flexShrink={0}
                                  sx={
                                    s.is_healthy
                                      ? {
                                          boxShadow: '0 0 0 2px rgba(72, 187, 120, 0.4)',
                                          animation: 'pulse-dot 1.5s ease-in-out infinite',
                                          '@keyframes pulse-dot': {
                                            '0%, 100%': { opacity: 1, transform: 'scale(1)' },
                                            '50%': { opacity: 0.8, transform: 'scale(1.2)' },
                                          },
                                        }
                                      : undefined
                                  }
                                />
                                <Badge colorScheme={s.is_healthy ? 'green' : 'red'} size="sm">
                                  {s.is_healthy ? t.proxyDetail.healthy : t.proxyDetail.unhealthy}
                                </Badge>
                              </HStack>
                            </Td>
                            <Td>
                              {s.average_response_time >= 0 ? (
                                <Tooltip label={`${s.average_response_time} ms`}>
                                  <HStack spacing={2} maxW="120px">
                                    <Progress
                                      value={Math.min(100, (s.average_response_time / 500) * 100)}
                                      size="sm"
                                      colorScheme={responseTimeColor(s.average_response_time)}
                                      borderRadius="full"
                                      flex={1}
                                    />
                                    <Text fontSize="xs" fontFamily="mono" whiteSpace="nowrap">
                                      {s.average_response_time} ms
                                    </Text>
                                  </HStack>
                                </Tooltip>
                              ) : (
                                '—'
                              )}
                            </Td>
                            <Td fontSize="xs" color="gray.600">
                              {s.last_health_check
                                ? new Date(s.last_health_check).toLocaleString()
                                : '—'}
                            </Td>
                            <Td fontFamily="mono">{s.active_connections}</Td>
                            <Td fontFamily="mono">{s.total_requests}</Td>
                            <Td fontFamily="mono">{s.failed_requests}</Td>
                            <Td>
                              {s.success_rate >= 0 ? (
                                <Tooltip label={`${s.success_rate.toFixed(2)}%`}>
                                  <HStack spacing={2} maxW="100px">
                                    <Progress
                                      value={s.success_rate}
                                      size="sm"
                                      colorScheme={s.success_rate >= 99 ? 'green' : s.success_rate >= 95 ? 'yellow' : 'red'}
                                      borderRadius="full"
                                      flex={1}
                                    />
                                    <Text fontSize="xs" whiteSpace="nowrap">
                                      {s.success_rate.toFixed(1)}%
                                    </Text>
                                  </HStack>
                                </Tooltip>
                              ) : (
                                '—'
                              )}
                            </Td>
                          </Tr>
                        ))}
                      </Tbody>
                    </Table>
                  </CardBody>
                </Card>
              </MotionBox>
            ) : (
              <Card>
                <CardBody>
                  <Flex align="center" gap={4} py={6}>
                    <Icon as={FiActivity} boxSize={10} color="gray.400" />
                    <Text color="gray.600" _dark={{ color: 'gray.400' }}>
                      {t.proxyDetail.noHealthCheckData}
                    </Text>
                  </Flex>
                </CardBody>
              </Card>
            )}
          </TabPanel>
        </TabPanels>
      </Tabs>
    </MotionBox>
  )
}

export default ProxyDomainDetail

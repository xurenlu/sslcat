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
  StatHelpText,
  Tooltip,
} from '@chakra-ui/react'
import { FiArrowLeft, FiEdit, FiGlobe, FiZap, FiActivity, FiServer } from 'react-icons/fi'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useConfig, buildPath, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

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
      <Flex justify="center" align="center" minH="200px">
        <Spinner size="xl" />
      </Flex>
    )
  }

  if (!rule) {
    return null
  }

  return (
    <Box>
      <HStack mb={6} spacing={4}>
        <Button
          leftIcon={<Icon as={FiArrowLeft} />}
          variant="ghost"
          onClick={() => navigate(buildPath(adminPrefix, '/proxy'))}
        >
          {t.common.back}
        </Button>
        <HStack flex={1} align="center">
          <Icon as={FiGlobe} boxSize={6} />
          <Heading size="lg" fontFamily="mono">
            {rule.domain}
          </Heading>
          <Badge colorScheme={rule.enabled ? 'green' : 'gray'}>
            {rule.enabled ? t.common.enable : t.common.disable}
          </Badge>
          <Badge colorScheme={rule.ssl_only ? 'blue' : 'orange'}>
            {rule.ssl_only ? 'HTTPS' : 'HTTP'}
          </Badge>
          {isMultiUpstream && (
            <Badge colorScheme="purple">{t.proxyDetail.multiUpstream}</Badge>
          )}
        </HStack>
        <Button
          leftIcon={<Icon as={FiEdit} />}
          colorScheme="blue"
          onClick={() =>
            navigate(buildPath(adminPrefix, `/proxy/edit?domain=${encodeURIComponent(rule.domain)}`))
          }
        >
          {t.proxyDetail.editBackend}
        </Button>
      </HStack>

      <Tabs variant="enclosed" colorScheme="blue">
        <TabList>
          <Tab>{t.proxyDetail.overview}</Tab>
          <Tab>{t.proxyDetail.forwardingRules}</Tab>
          <Tab>{t.proxyDetail.healthCheck}</Tab>
        </TabList>
        <TabPanels>
          <TabPanel>
            <SimpleGrid columns={{ base: 1, md: 2, lg: 3 }} spacing={4}>
              <Card>
                <CardBody>
                  <Stat>
                    <StatLabel>{t.proxyDetail.targetAddress}</StatLabel>
                    <StatNumber fontFamily="mono" fontSize="md">
                      {backends.length === 1
                        ? `${backends[0].host}:${backends[0].port}`
                        : `${backends.length} ${t.proxyDetail.backends}`}
                    </StatNumber>
                  </Stat>
                </CardBody>
              </Card>
              {isMultiUpstream && (
                <>
                  <Card>
                    <CardBody>
                      <Stat>
                        <StatLabel>{t.proxyDetail.loadBalanceAlgorithm}</StatLabel>
                        <StatNumber fontSize="md">{algorithmLabel}</StatNumber>
                      </Stat>
                    </CardBody>
                  </Card>
                  <Card>
                    <CardBody>
                      <Stat>
                        <StatLabel>{t.proxyDetail.sessionAffinity}</StatLabel>
                        <StatNumber fontSize="md">
                          {rule.session_affinity_enabled
                            ? rule.session_affinity_method || 'cookie'
                            : '—'}
                        </StatNumber>
                      </Stat>
                    </CardBody>
                  </Card>
                </>
              )}
              {lbStats && (
                <>
                  <Card>
                    <CardBody>
                      <Stat>
                        <StatLabel>{t.proxyDetail.healthy} / {t.proxyDetail.backends}</StatLabel>
                        <StatNumber color="green.500">
                          {lbStats.healthy_backends}/{lbStats.total_backends}
                        </StatNumber>
                      </Stat>
                    </CardBody>
                  </Card>
                  <Card>
                    <CardBody>
                      <Stat>
                        <StatLabel>{t.proxyDetail.totalRequests}</StatLabel>
                        <StatNumber>{lbStats.total_requests}</StatNumber>
                      </Stat>
                    </CardBody>
                  </Card>
                </>
              )}
            </SimpleGrid>
            <HStack mt={4} spacing={2}>
              {rule.cdn_enabled && <Badge colorScheme="purple">CDN</Badge>}
              {rule.auth_enabled && <Badge colorScheme="red">认证</Badge>}
            </HStack>
          </TabPanel>

          <TabPanel>
            <Card bg="gray.50" _dark={{ bg: 'whiteAlpha.100' }}>
              <CardBody>
                <Text fontWeight="semibold" mb={4}>
                  {t.proxyDetail.flowDiagram}
                </Text>
                <VStack align="stretch" spacing={6}>
                  <HStack spacing={4} flexWrap="wrap">
                    <Box
                      px={4}
                      py={3}
                      borderRadius="lg"
                      bg="blue.100"
                      _dark={{ bg: 'blue.900' }}
                      fontWeight="medium"
                    >
                      👤 {t.proxyDetail.clientToGateway}
                    </Box>
                    <Icon as={FiZap} boxSize={5} />
                    <Box
                      px={4}
                      py={3}
                      borderRadius="lg"
                      bg="teal.100"
                      _dark={{ bg: 'teal.900' }}
                      fontWeight="medium"
                    >
                      SSLcat Gateway
                    </Box>
                  </HStack>
                  <HStack spacing={2} align="center">
                    <Text fontSize="sm" color="gray.600" _dark={{ color: 'gray.400' }}>
                      {t.proxyDetail.gatewayToUpstreams}
                    </Text>
                    {isMultiUpstream && (
                      <Badge colorScheme="purple" ml={2}>
                        {algorithmLabel}
                      </Badge>
                    )}
                  </HStack>
                  <SimpleGrid columns={{ base: 1, sm: 2, md: Math.min(backends.length, 4) }} spacing={3}>
                    {backends.map((be, i) => (
                      <Box
                        key={be.id}
                        p={4}
                        borderRadius="lg"
                        borderWidth="2px"
                        borderColor={lbStats?.backend_stats?.find((s) => s.id === be.id)?.is_healthy !== false ? 'green.300' : 'red.300'}
                        bg="white"
                        _dark={{ bg: 'gray.800' }}
                      >
                        <HStack mb={2}>
                          <Icon as={FiServer} />
                          <Text fontFamily="mono" fontWeight="semibold">
                            {be.host}:{be.port}
                          </Text>
                        </HStack>
                        {be.weight != null && be.weight !== 1 && (
                          <Text fontSize="sm" color="gray.600">
                            权重 {be.weight}
                          </Text>
                        )}
                        {lbStats?.backend_stats?.find((s) => s.id === be.id) && (
                          <Badge
                            colorScheme={
                              lbStats.backend_stats.find((s) => s.id === be.id)?.is_healthy
                                ? 'green'
                                : 'red'
                            }
                            mt={2}
                          >
                            {lbStats.backend_stats.find((s) => s.id === be.id)?.is_healthy
                              ? t.proxyDetail.healthy
                              : t.proxyDetail.unhealthy}
                          </Badge>
                        )}
                      </Box>
                    ))}
                  </SimpleGrid>
                </VStack>
              </CardBody>
            </Card>
          </TabPanel>

          <TabPanel>
            {lbStats?.backend_stats?.length ? (
              <Card>
                <CardBody>
                  <Table variant="simple">
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
                      {lbStats.backend_stats.map((s) => (
                        <Tr key={s.id}>
                          <Td fontFamily="mono">
                            {s.host}:{s.port}
                          </Td>
                          <Td>
                            <Badge colorScheme={s.is_healthy ? 'green' : 'red'}>
                              {s.is_healthy ? t.proxyDetail.healthy : t.proxyDetail.unhealthy}
                            </Badge>
                          </Td>
                          <Td>
                            {s.average_response_time >= 0 ? `${s.average_response_time} ms` : '—'}
                          </Td>
                          <Td>
                            {s.last_health_check
                              ? new Date(s.last_health_check).toLocaleString()
                              : '—'}
                          </Td>
                          <Td>{s.active_connections}</Td>
                          <Td>{s.total_requests}</Td>
                          <Td>{s.failed_requests}</Td>
                          <Td>
                            {s.success_rate >= 0 ? (
                              <Tooltip label={`${s.success_rate.toFixed(2)}%`}>
                                <Text>{s.success_rate.toFixed(1)}%</Text>
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
            ) : (
              <Card>
                <CardBody>
                  <Flex align="center" gap={3} py={4}>
                    <Icon as={FiActivity} boxSize={8} color="gray.400" />
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
    </Box>
  )
}

export default ProxyDomainDetail

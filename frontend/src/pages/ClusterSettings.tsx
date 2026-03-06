import React, { useEffect, useState } from 'react'
import {
  Box,
  Container,
  Heading,
  Card,
  CardHeader,
  CardBody,
  VStack,
  HStack,
  FormControl,
  FormLabel,
  Input,
  Select,
  Switch,
  Button,
  Text,
  useToast,
  SimpleGrid,
  Alert,
  AlertIcon,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Badge,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  IconButton,
} from '@chakra-ui/react'
import {
  FiSettings,
  FiActivity,
  FiServer,
  FiRefreshCw,
  FiCheckCircle,
  FiXCircle,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'
import axios from 'axios'

interface ServiceMeshConfig {
  enabled: boolean;
  type: string;
  stats: {
    services_discovered: number;
    requests_via_mesh: number;
    requests_direct: number;
    retries_attempted: number;
    circuit_breaker_trips: number;
    last_discovery_time: string;
    mesh_api_calls: number;
    mesh_api_errors: number;
  };
  services: ServiceInfo[];
  circuit_breakers: Record<string, CircuitBreakerState>;
}

interface ServiceInfo {
  name: string;
  namespace: string;
  addresses: string[];
  ports: number[];
  healthy: boolean;
  last_check: string;
}

interface CircuitBreakerState {
  service: string;
  state: string;
  open_count: number;
  last_state_change: string;
  failure_count: number;
  success_count: number;
}

const ClusterSettings: React.FC = () => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  const toast = useToast()

  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [refreshingMesh, setRefreshingMesh] = useState(false)
  const [cfg, setCfg] = useState<any>({
    mode: 'standalone',
    node_name: 'Node-1',
    master: { host: '', port: 8443, auth_key: '', timeout: 30, retry_interval: 10 },
    sync: { config_enabled: true, cert_enabled: true, interval: 30, timeout: 10, exclude_configs: [] },
    port: 8443,
    auth_key: '',
  })
  const [meshConfig, setMeshConfig] = useState<ServiceMeshConfig | null>(null)

  const load = async () => {
    try {
      setLoading(true)
      const resp = await fetch(`${adminPrefix}/api/cluster/settings`, { credentials: 'include' })
      if (!resp.ok) throw new Error('Failed to load')
      const data = await resp.json()
      if (data.success && data.data) {
        setCfg(data.data)
      }
    } catch (e) {
      // no-op
    } finally {
      setLoading(false)
    }
  }

  const updateField = (path: string, value: any) => {
    setCfg((prev: any) => {
      const next = { ...prev }
      const keys = path.split('.')
      let obj: any = next
      for (let i = 0; i < keys.length - 1; i++) {
        obj[keys[i]] = obj[keys[i]] ?? {}
        obj = obj[keys[i]]
      }
      obj[keys[keys.length - 1]] = value
      return next
    })
  }

  const save = async () => {
    try {
      setSaving(true)
      const resp = await fetch(`${adminPrefix}/api/cluster/settings`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cfg),
      })
      const data = await resp.json()
      if (!resp.ok || !data.success) throw new Error(data.error || data.message || 'Save failed')
      toast({ title: t.common.success, status: 'success', duration: 2000 })
      load()
    } catch (e: any) {
      toast({ title: t.common.error, description: e.message, status: 'error' })
    } finally {
      setSaving(false)
    }
  }

  const syncACMEToDisk = async () => {
    try {
      const resp = await fetch(`${adminPrefix}/ssl/sync-acme`, { method: 'POST', credentials: 'include' })
      if (resp.ok) toast({ title: t.ssl.syncACMECertificates, status: 'success', duration: 2000 })
    } catch {}
  }

  const syncCertsFromMaster = async () => {
    try {
      const resp = await fetch(`${adminPrefix}/api/cluster/sync-certs`, { method: 'POST', credentials: 'include' })
      const data = await resp.json().catch(() => ({}))
      if (!resp.ok || data.success === false) throw new Error(data.error || data.message || 'Sync failed')
      toast({ title: t.cluster.syncCertsSuccess, status: 'success', duration: 2000 })
    } catch (e: any) {
      toast({ title: t.common.error, description: e.message, status: 'error' })
    }
  }

  // Service Mesh functions
  const fetchMeshConfig = async () => {
    try {
      setRefreshingMesh(true)
      const response = await axios.get(buildApiPath(adminPrefix, '/api/service-mesh/config'))
      setMeshConfig(response.data)
    } catch (error) {
      // Silently fail if Service Mesh is not enabled
      setMeshConfig(null)
    } finally {
      setRefreshingMesh(false)
    }
  }

  useEffect(() => {
    if (adminPrefix) {
      load()
      fetchMeshConfig()
    }
  }, [adminPrefix])

  const handleToggleMeshEnabled = async () => {
    try {
      const newEnabled = !meshConfig?.enabled
      const response = await axios.post(buildApiPath(adminPrefix, '/api/service-mesh/config'), {
        enabled: newEnabled,
        type: meshConfig?.type || 'istio',
      })
      setMeshConfig(response.data)
      toast({
        title: t.common.success,
        description: !meshConfig?.enabled ? (t.cluster?.serviceMeshEnabled ?? 'Service Mesh 已启用') : (t.cluster?.serviceMeshDisabled ?? 'Service Mesh 已禁用'),
        status: 'success',
        duration: 3000,
      })
    } catch (error) {
      toast({
        title: t.common.error,
        description: t.cluster?.serviceMeshUpdateFailed ?? '无法更新 Service Mesh 配置',
        status: 'error',
        duration: 3000,
      })
    }
  }

  const handleResetBreaker = async (service: string) => {
    try {
      await axios.post(buildApiPath(adminPrefix, '/api/service-mesh/circuit-breaker/reset'), { service })
      await fetchMeshConfig()
      toast({
        title: t.common.success,
        description: (t.cluster?.breakerResetSuccess ?? '熔断器 {service} 已重置').replace('{service}', service),
        status: 'success',
        duration: 3000,
      })
    } catch (error) {
      toast({
        title: t.common.error,
        description: t.cluster?.breakerResetFailed ?? '无法重置熔断器',
        status: 'error',
        duration: 3000,
      })
    }
  }

  const handleDiscoverServices = async () => {
    try {
      await axios.post(buildApiPath(adminPrefix, '/api/service-mesh/discover'))
      await fetchMeshConfig()
      toast({
        title: t.common.success,
        description: t.cluster?.discoverTriggered ?? '服务发现已触发',
        status: 'success',
        duration: 3000,
      })
    } catch (error) {
      toast({
        title: t.common.error,
        description: t.cluster?.discoverFailed ?? '无法触发服务发现',
        status: 'error',
        duration: 3000,
      })
    }
  }

  const handleHealthCheck = async () => {
    try {
      await axios.post(buildApiPath(adminPrefix, '/api/service-mesh/health-check'))
      await fetchMeshConfig()
      toast({
        title: t.common.success,
        description: t.cluster?.healthCheckTriggered ?? '健康检查已触发',
        status: 'success',
        duration: 3000,
      })
    } catch (error) {
      toast({
        title: t.common.error,
        description: t.cluster?.healthCheckFailed ?? '无法触发健康检查',
        status: 'error',
        duration: 3000,
      })
    }
  }

  return (
    <Container maxW="container.xl" py={8}>
      <Heading size="lg" mb={6}>{t.cluster.title}</Heading>

      {cfg.mode === 'slave' && (
        <Alert status="info" mb={4} borderRadius="md">
          <AlertIcon />
          <Text>{t.cluster.slaveNotice}</Text>
        </Alert>
      )}

      <Tabs>
        <TabList>
          <Tab>{t.cluster?.nodeConfig ?? '节点配置'}</Tab>
          <Tab>{t.cluster?.serviceMesh ?? 'Service Mesh'}</Tab>
        </TabList>

        <TabPanels>
          {/* Node Configuration Tab */}
          <TabPanel>
            <SimpleGrid columns={{ base: 1, md: 2 }} spacing={6}>
              <Card>
                <CardHeader>
                  <Heading size="md">{t.cluster.basic}</Heading>
                </CardHeader>
                <CardBody>
                  <VStack spacing={4} align="stretch">
                    <FormControl>
                      <FormLabel>{t.cluster.mode}</FormLabel>
                      <Select value={cfg.mode} onChange={(e) => updateField('mode', e.target.value)} disabled={loading}>
                        <option value="standalone">{t.cluster.modeStandalone}</option>
                        <option value="master">{t.cluster.modeMaster}</option>
                        <option value="slave">{t.cluster.modeSlave}</option>
                      </Select>
                    </FormControl>
                    <FormControl>
                      <FormLabel>{t.cluster.nodeName}</FormLabel>
                      <Input value={cfg.node_name || ''} onChange={(e) => updateField('node_name', e.target.value)} />
                    </FormControl>
                    <FormControl>
                      <FormLabel>{t.cluster.clusterPort}</FormLabel>
                      <Input type="number" value={cfg.port || 0} onChange={(e) => updateField('port', parseInt(e.target.value || '0'))} />
                    </FormControl>
                    <FormControl>
                      <FormLabel>{t.cluster.clusterKey}</FormLabel>
                      <Input value={cfg.auth_key || ''} onChange={(e) => updateField('auth_key', e.target.value)} placeholder="********" />
                    </FormControl>
                    <HStack>
                      <Button colorScheme="blue" onClick={save} isLoading={saving}>{t.common.save}</Button>
                      <Button onClick={load} isLoading={loading}>{t.common.refresh}</Button>
                    </HStack>
                  </VStack>
                </CardBody>
              </Card>

              <Card>
                <CardHeader>
                  <Heading size="md">{t.cluster.masterConfig}</Heading>
                </CardHeader>
                <CardBody>
                  <VStack spacing={4} align="stretch">
                    <FormControl>
                      <FormLabel>{t.cluster.masterHost}</FormLabel>
                      <Input value={cfg.master?.host || ''} onChange={(e) => updateField('master.host', e.target.value)} />
                    </FormControl>
                    <FormControl>
                      <FormLabel>{t.cluster.masterPort}</FormLabel>
                      <Input type="number" value={cfg.master?.port || 0} onChange={(e) => updateField('master.port', parseInt(e.target.value || '0'))} />
                    </FormControl>
                    <FormControl>
                      <FormLabel>{t.cluster.masterKey}</FormLabel>
                      <Input value={cfg.master?.auth_key || ''} onChange={(e) => updateField('master.auth_key', e.target.value)} placeholder="********" />
                    </FormControl>
                    <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                      <FormControl>
                        <FormLabel>{t.cluster.timeout}</FormLabel>
                        <Input type="number" value={cfg.master?.timeout || 0} onChange={(e) => updateField('master.timeout', parseInt(e.target.value || '0'))} />
                      </FormControl>
                      <FormControl>
                        <FormLabel>{t.cluster.retryInterval}</FormLabel>
                        <Input type="number" value={cfg.master?.retry_interval || 0} onChange={(e) => updateField('master.retry_interval', parseInt(e.target.value || '0'))} />
                      </FormControl>
                    </SimpleGrid>
                    <HStack>
                      <Button colorScheme="blue" onClick={save} isLoading={saving}>{t.common.save}</Button>
                    </HStack>
                  </VStack>
                </CardBody>
              </Card>

              <Card>
                <CardHeader>
                  <Heading size="md">{t.cluster.sync}</Heading>
                </CardHeader>
                <CardBody>
                  <VStack spacing={4} align="stretch">
                    <FormControl display="flex" alignItems="center">
                      <FormLabel mb="0">{t.cluster.syncConfig}</FormLabel>
                      <Switch isChecked={!!cfg.sync?.config_enabled} onChange={(e) => updateField('sync.config_enabled', e.target.checked)} />
                    </FormControl>
                    <FormControl display="flex" alignItems="center">
                      <FormLabel mb="0">{t.cluster.syncCerts}</FormLabel>
                      <Switch isChecked={!!cfg.sync?.cert_enabled} onChange={(e) => updateField('sync.cert_enabled', e.target.checked)} />
                    </FormControl>
                    <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                      <FormControl>
                        <FormLabel>{t.cluster.syncInterval}</FormLabel>
                        <Input type="number" value={cfg.sync?.interval || 0} onChange={(e) => updateField('sync.interval', parseInt(e.target.value || '0'))} />
                      </FormControl>
                      <FormControl>
                        <FormLabel>{t.cluster.syncTimeout}</FormLabel>
                        <Input type="number" value={cfg.sync?.timeout || 0} onChange={(e) => updateField('sync.timeout', parseInt(e.target.value || '0'))} />
                      </FormControl>
                    </SimpleGrid>
                    <HStack>
                      <Button colorScheme="blue" onClick={save} isLoading={saving}>{t.common.save}</Button>
                      <Button variant="outline" onClick={syncACMEToDisk}>{t.ssl.syncACMECertificates}</Button>
                      <Button variant="outline" onClick={syncCertsFromMaster}>{t.cluster.syncCertsFromMaster}</Button>
                    </HStack>
                  </VStack>
                </CardBody>
              </Card>
            </SimpleGrid>
          </TabPanel>

          {/* Service Mesh Tab */}
          <TabPanel>
            <VStack spacing={6} align="stretch">
              {/* 实验性功能警告 */}
              <Alert status="warning" borderRadius="md">
                <AlertIcon />
                <Box>
                  <Text fontWeight="bold">{t.cluster?.experimentalFeature ?? '实验性功能'}</Text>
                  <Text fontSize="sm">{t.cluster?.serviceMeshDesc ?? 'Service Mesh 功能尚未完全实现，有待生产环境测试。请在测试环境中谨慎使用。'}</Text>
                </Box>
              </Alert>

              <Box display="flex" justifyContent="space-between" alignItems="center">
                <Heading size="md">{t.cluster?.serviceMeshManagement ?? 'Service Mesh 管理'}</Heading>
                <HStack>
                  <Switch
                    isChecked={meshConfig?.enabled}
                    onChange={handleToggleMeshEnabled}
                    colorScheme="green"
                  />
                  <IconButton
                    aria-label="刷新"
                    icon={<FiRefreshCw />}
                    onClick={fetchMeshConfig}
                    isLoading={refreshingMesh}
                  />
                </HStack>
              </Box>

              {!meshConfig?.enabled && (
                <Alert status="info" borderRadius="md">
                  <AlertIcon />
                  {t.cluster?.serviceMeshNotEnabled ?? 'Service Mesh 当前未启用'}
                </Alert>
              )}

              {meshConfig?.enabled && (
                <>
                  {/* Stats Cards */}
                  <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={4}>
                    <Card>
                      <CardBody>
                        <Stat>
                          <StatLabel>{t.cluster?.servicesDiscovered ?? '已发现服务'}</StatLabel>
                          <StatNumber>{meshConfig.stats.services_discovered.toLocaleString()}</StatNumber>
                          <StatHelpText>{t.cluster?.servicesRegistered ?? '已注册服务'}</StatHelpText>
                        </Stat>
                      </CardBody>
                    </Card>

                    <Card>
                      <CardBody>
                        <Stat>
                          <StatLabel>{t.cluster?.meshRequests ?? 'Mesh 请求'}</StatLabel>
                          <StatNumber>{meshConfig.stats.requests_via_mesh.toLocaleString()}</StatNumber>
                          <StatHelpText>{t.cluster?.viaServiceMesh ?? '通过 Service Mesh'}</StatHelpText>
                        </Stat>
                      </CardBody>
                    </Card>

                    <Card>
                      <CardBody>
                        <Stat>
                          <StatLabel>{t.cluster?.directRequests ?? '直接请求'}</StatLabel>
                          <StatNumber>{meshConfig.stats.requests_direct.toLocaleString()}</StatNumber>
                          <StatHelpText>{t.cluster?.bypassServiceMesh ?? '绕过 Service Mesh'}</StatHelpText>
                        </Stat>
                      </CardBody>
                    </Card>

                    <Card>
                      <CardBody>
                        <Stat>
                          <StatLabel>{t.cluster?.meshApiCalls ?? 'API 调用'}</StatLabel>
                          <StatNumber>{meshConfig.stats.mesh_api_calls.toLocaleString()}</StatNumber>
                          <StatHelpText>Mesh API 请求</StatHelpText>
                        </Stat>
                      </CardBody>
                    </Card>
                  </SimpleGrid>

                  {/* Mesh Content Tabs */}
                  <Tabs>
                    <TabList>
                      <Tab>
                        <Box display="flex" alignItems="center" gap={2}>
                          <FiServer />
                          {t.cluster?.serviceList ?? '服务列表'}
                        </Box>
                      </Tab>
                      <Tab>
                        <Box display="flex" alignItems="center" gap={2}>
                          <FiActivity />
                          {t.cluster?.circuitBreakerStatus ?? '熔断器状态'}
                        </Box>
                      </Tab>
                    </TabList>

                    <TabPanels>
                      {/* Services Panel */}
                      <TabPanel>
                        <Card>
                          <CardHeader display="flex" justifyContent="space-between">
                            <Heading size="md">{t.cluster?.serviceList ?? '服务列表'}</Heading>
                            <Button
                              leftIcon={<FiRefreshCw />}
                              size="sm"
                              onClick={handleDiscoverServices}
                            >
                              {t.cluster?.refreshServices ?? '刷新服务'}
                            </Button>
                          </CardHeader>
                          <CardBody>
                            {!meshConfig.services || meshConfig.services.length === 0 ? (
                              <Alert status="info">
                                <AlertIcon />
                                {t.cluster?.noServices ?? '暂无服务'}
                              </Alert>
                            ) : (
                              <Table variant="simple">
                                <Thead>
                                  <Tr>
                                    <Th>{t.cluster?.serviceName ?? '服务名'}</Th>
                                    <Th>{t.cluster?.namespace ?? '命名空间'}</Th>
                                    <Th>{t.cluster?.address ?? '地址'}</Th>
                                    <Th>{t.cluster?.port ?? '端口'}</Th>
                                    <Th>{t.cluster?.status ?? '状态'}</Th>
                                    <Th>{t.cluster?.lastCheck ?? '最后检查'}</Th>
                                  </Tr>
                                </Thead>
                                <Tbody>
                                  {(meshConfig.services || []).map((service) => (
                                    <Tr key={service.name}>
                                      <Td>{service.name}</Td>
                                      <Td>{service.namespace}</Td>
                                      <Td>
                                        {service.addresses.map((addr) => (
                                          <Text key={addr} fontSize="sm">
                                            {addr}
                                          </Text>
                                        ))}
                                      </Td>
                                      <Td>
                                        {service.ports.map((port) => (
                                          <Badge key={port} mr={1}>
                                            {port}
                                          </Badge>
                                        ))}
                                      </Td>
                                      <Td>
                                        {service.healthy ? (
                                          <Badge colorScheme="green">
                                            <Box display="flex" alignItems="center" gap={1}>
                                              <FiCheckCircle />
                                              {t.cluster?.healthy ?? '健康'}
                                            </Box>
                                          </Badge>
                                        ) : (
                                          <Badge colorScheme="red">
                                            <Box display="flex" alignItems="center" gap={1}>
                                              <FiXCircle />
                                              {t.cluster?.unhealthy ?? '不健康'}
                                            </Box>
                                          </Badge>
                                        )}
                                      </Td>
                                      <Td fontSize="sm">
                                        {new Date(service.last_check).toLocaleString()}
                                      </Td>
                                    </Tr>
                                  ))}
                                </Tbody>
                              </Table>
                            )}
                          </CardBody>
                        </Card>
                      </TabPanel>

                      {/* Circuit Breakers Panel */}
                      <TabPanel>
                        <Card>
                          <CardHeader display="flex" justifyContent="space-between">
                            <Heading size="md">{t.cluster?.circuitBreakerStatus ?? '熔断器状态'}</Heading>
                            <Button
                              leftIcon={<FiActivity />}
                              size="sm"
                              onClick={handleHealthCheck}
                            >
                              {t.cluster?.triggerHealthCheck ?? '触发健康检查'}
                            </Button>
                          </CardHeader>
                          <CardBody>
                            {!meshConfig.circuit_breakers || Object.keys(meshConfig.circuit_breakers).length === 0 ? (
                              <Alert status="info">
                                <AlertIcon />
                                {t.cluster?.noBreakers ?? '暂无熔断器'}
                              </Alert>
                            ) : (
                              <Table variant="simple">
                                <Thead>
                                  <Tr>
                                    <Th>{t.cluster?.service ?? '服务'}</Th>
                                    <Th>{t.cluster?.status ?? '状态'}</Th>
                                    <Th>{t.cluster?.breakerOpenCount ?? '开启次数'}</Th>
                                    <Th>{t.cluster?.failureCount ?? '失败数'}</Th>
                                    <Th>{t.cluster?.successCount ?? '成功数'}</Th>
                                    <Th>{t.cluster?.lastStateChange ?? '最后状态变更'}</Th>
                                    <Th>{t.common.actions}</Th>
                                  </Tr>
                                </Thead>
                                <Tbody>
                                  {Object.values(meshConfig.circuit_breakers || {}).map((breaker) => (
                                    <Tr key={breaker.service}>
                                      <Td>{breaker.service}</Td>
                                      <Td>
                                        {breaker.state === 'closed' ? (
                                          <Badge colorScheme="green">{t.cluster?.breakerClosed ?? '关闭'}</Badge>
                                        ) : breaker.state === 'open' ? (
                                          <Badge colorScheme="red">{t.cluster?.breakerOpen ?? '开启'}</Badge>
                                        ) : (
                                          <Badge colorScheme="yellow">{t.cluster?.breakerHalfOpen ?? '半开'}</Badge>
                                        )}
                                      </Td>
                                      <Td>{breaker.open_count}</Td>
                                      <Td>{breaker.failure_count}</Td>
                                      <Td>{breaker.success_count}</Td>
                                      <Td fontSize="sm">
                                        {new Date(breaker.last_state_change).toLocaleString()}
                                      </Td>
                                      <Td>
                                        {breaker.state !== 'closed' && (
                                          <Button
                                            size="sm"
                                            leftIcon={<FiRefreshCw />}
                                            onClick={() => handleResetBreaker(breaker.service)}
                                          >
                                            {t.cluster?.breakerReset ?? '重置'}
                                          </Button>
                                        )}
                                      </Td>
                                    </Tr>
                                  ))}
                                </Tbody>
                              </Table>
                            )}
                          </CardBody>
                        </Card>
                      </TabPanel>
                    </TabPanels>
                  </Tabs>
                </>
              )}
            </VStack>
          </TabPanel>
        </TabPanels>
      </Tabs>
    </Container>
  )
}

export default ClusterSettings

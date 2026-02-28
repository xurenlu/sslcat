import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Heading,
  Text,
  SimpleGrid,
  Card,
  CardHeader,
  CardBody,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Badge,
  Button,
  Switch,
  FormControl,
  FormLabel,
  Input,
  Select,
  VStack,
  HStack,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  useToast,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Alert,
  AlertIcon,
  IconButton,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  useDisclosure,
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  NumberIncrementStepper,
  NumberDecrementStepper,
  Progress,
} from '@chakra-ui/react';
import {
  FiGlobe,
  FiMapPin,
  FiActivity,
  FiRefreshCw,
  FiPlus,
  FiEdit,
  FiTrash2,
  FiCheck,
  FiX,
  FiTrendingUp,
} from 'react-icons/fi';
import axios from 'axios';
import { useConfig, buildApiPath } from '../contexts/ConfigContext';

interface EdgeRoutingConfig {
  enabled: boolean;
  default_cluster_id: string;
  fallback_strategy: string;
  health_check_interval_ms: number;
  health_check_timeout_ms: number;
  max_retries: number;
  retry_delay_ms: number;
  latency_threshold_ms: number;
}

interface EdgeCluster {
  id: string;
  name: string;
  locations: EdgeLocation[];
  load_balance: string;
  created_at: string;
}

interface EdgeLocation {
  id: string;
  name: string;
  region: string;
  country: string;
  city: string;
  latitude: number;
  longitude: number;
  priority: number;
  enabled: boolean;
  healthy: boolean;
  last_check: string;
}

interface EdgeMetrics {
  total_requests: number;
  requests_by_region: Record<string, number>;
  requests_by_cluster: Record<string, number>;
  avg_latency: Record<string, number>;
  failed_requests: number;
  health_check_failures: number;
}

const EdgeRouting: React.FC = () => {
  const { adminPrefix } = useConfig();
  const [config, setConfig] = useState<EdgeRoutingConfig | null>(null);
  const [clusters, setClusters] = useState<Record<string, EdgeCluster>>({});
  const [locations, setLocations] = useState<Record<string, EdgeLocation>>({});
  const [metrics, setMetrics] = useState<EdgeMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const toast = useToast();

  const { isOpen: isLocationOpen, onOpen: onLocationOpen, onClose: onLocationClose } = useDisclosure();
  const { isOpen: isClusterOpen, onOpen: onClusterOpen, onClose: onClusterClose } = useDisclosure();
  const [editingLocation, setEditingLocation] = useState<EdgeLocation | null>(null);

  const fetchConfig = async () => {
    try {
      setRefreshing(true);
      const [configRes, clustersRes, locationsRes, metricsRes] = await Promise.all([
        axios.get(buildApiPath(adminPrefix, '/api/edge-routing/config')),
        axios.get(buildApiPath(adminPrefix, '/api/edge-routing/clusters')),
        axios.get(buildApiPath(adminPrefix, '/api/edge-routing/locations')),
        axios.get(buildApiPath(adminPrefix, '/api/edge-routing/metrics')),
      ]);

      setConfig(configRes.data);
      setClusters(clustersRes.data.clusters || {});
      setLocations(locationsRes.data.locations || {});
      setMetrics(metricsRes.data);
    } catch (error) {
      toast({
        title: '加载失败',
        description: '无法加载边缘路由配置',
        status: 'error',
        duration: 3000,
      });
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchConfig();
    const interval = setInterval(fetchConfig, 15000); // 每15秒刷新
    return () => clearInterval(interval);
  }, []);

  const handleToggleEnabled = async () => {
    try {
      const response = await axios.post(buildApiPath(adminPrefix, '/api/edge-routing/config'), {
        ...config,
        enabled: !config?.enabled,
      });
      // 直接使用服务器返回的最新配置
      setConfig(response.data);
      toast({
        title: '成功',
        description: `边缘路由已${!config?.enabled ? '启用' : '禁用'}`,
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: '操作失败',
        description: '无法更新边缘路由配置',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleUpdateConfig = async (newConfig: EdgeRoutingConfig) => {
    try {
      await axios.post(buildApiPath(adminPrefix, '/api/edge-routing/config'), newConfig);
      await fetchConfig();
      toast({
        title: '成功',
        description: '配置已更新',
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: '操作失败',
        description: '无法更新配置',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleToggleLocation = async (locationId: string, enabled: boolean) => {
    try {
      await axios.post(buildApiPath(adminPrefix, '/api/edge-routing/location/enable'), {
        location_id: locationId,
        enabled,
      });
      await fetchConfig();
      toast({
        title: '成功',
        description: `边缘节点已${enabled ? '启用' : '禁用'}`,
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: '操作失败',
        description: '无法更新边缘节点状态',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleTestBestEdge = async (clientIP: string) => {
    try {
      const response = await axios.post(buildApiPath(adminPrefix, '/api/edge-routing/select-best'), { client_ip: clientIP });
      toast({
        title: '最佳边缘节点',
        description: `推荐节点: ${response.data.location?.name || '无'}`,
        status: 'success',
        duration: 5000,
      });
    } catch (error) {
      toast({
        title: '测试失败',
        description: '无法测试最佳边缘节点选择',
        status: 'error',
        duration: 3000,
      });
    }
  };

  if (loading) {
    return (
      <Container maxW="container.xl" py={8}>
        <Text>加载中...</Text>
      </Container>
    );
  }

  return (
    <Container maxW="container.xl" py={8}>
      <VStack spacing={6} align="stretch">
        {/* Header */}
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Box>
            <Heading size="lg" display="flex" alignItems="center" gap={2}>
              <FiGlobe />
              边缘计算管理
            </Heading>
            <Text color="gray.500" mt={2}>
              管理多区域部署和智能路由
            </Text>
          </Box>
          <HStack>
            <Switch
              isChecked={config?.enabled}
              onChange={handleToggleEnabled}
              colorScheme="green"
            />
            <IconButton
              aria-label="刷新"
              icon={<FiRefreshCw />}
              onClick={fetchConfig}
              isLoading={refreshing}
            />
          </HStack>
        </Box>

        {!config?.enabled && (
          <Alert status="warning">
            <AlertIcon />
            边缘路由当前未启用
          </Alert>
        )}

        {config?.enabled && (
          <>
            {/* Stats Cards */}
            <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={4}>
              <Card>
                <CardBody>
                  <Stat>
                    <StatLabel>总请求数</StatLabel>
                    <StatNumber>{metrics?.total_requests.toLocaleString()}</StatNumber>
                    <StatHelpText>边缘路由请求</StatHelpText>
                  </Stat>
                </CardBody>
              </Card>

              <Card>
                <CardBody>
                  <Stat>
                    <StatLabel>失败请求</StatLabel>
                    <StatNumber color="red.500">{metrics?.failed_requests.toLocaleString()}</StatNumber>
                    <StatHelpText>路由失败</StatHelpText>
                  </Stat>
                </CardBody>
              </Card>

              <Card>
                <CardBody>
                  <Stat>
                    <StatLabel>活跃节点</StatLabel>
                    <StatNumber>
                      {Object.values(locations).filter((l) => l.enabled && l.healthy).length}
                    </StatNumber>
                    <StatHelpText>/ {Object.values(locations).length} 总节点</StatHelpText>
                  </Stat>
                </CardBody>
              </Card>

              <Card>
                <CardBody>
                  <Stat>
                    <StatLabel>健康检查失败</StatLabel>
                    <StatNumber color="orange.500">{metrics?.health_check_failures}</StatNumber>
                    <StatHelpText>需要关注</StatHelpText>
                  </Stat>
                </CardBody>
              </Card>
            </SimpleGrid>

            {/* Main Tabs */}
            <Tabs>
              <TabList>
                <Tab>
                  <Box display="flex" alignItems="center" gap={2}>
                    <FiMapPin />
                    边缘节点
                  </Box>
                </Tab>
                <Tab>
                  <Box display="flex" alignItems="center" gap={2}>
                    <FiActivity />
                    流量统计
                  </Box>
                </Tab>
                <Tab>
                  <Box display="flex" alignItems="center" gap={2}>
                    <FiTrendingUp />
                    配置
                  </Box>
                </Tab>
              </TabList>

              <TabPanels>
                {/* Locations Panel */}
                <TabPanel>
                  <Card>
                    <CardHeader display="flex" justifyContent="space-between">
                      <Heading size="md">边缘节点列表</Heading>
                      <Button leftIcon={<FiPlus />} size="sm" colorScheme="blue">
                        添加节点
                      </Button>
                    </CardHeader>
                    <CardBody>
                      <Table variant="simple">
                        <Thead>
                          <Tr>
                            <Th>节点名称</Th>
                            <Th>位置</Th>
                            <Th>区域</Th>
                            <Th>优先级</Th>
                            <Th>状态</Th>
                            <Th>健康</Th>
                            <Th>平均延迟</Th>
                            <Th>操作</Th>
                          </Tr>
                        </Thead>
                        <Tbody>
                          {Object.values(locations).map((location) => (
                            <Tr key={location.id}>
                              <Td>
                                <VStack align="start" spacing={0}>
                                  <Text fontWeight="bold">{location.name}</Text>
                                  <Text fontSize="xs" color="gray.500">
                                    {location.id}
                                  </Text>
                                </VStack>
                              </Td>
                              <Td>
                                <VStack align="start" spacing={0}>
                                  <Text>{location.city}</Text>
                                  <Text fontSize="xs" color="gray.500">
                                    {location.country}
                                  </Text>
                                </VStack>
                              </Td>
                              <Td>
                                <Badge colorScheme="blue">{location.region}</Badge>
                              </Td>
                              <Td>
                                <Badge colorScheme={location.priority <= 2 ? 'green' : location.priority <= 4 ? 'yellow' : 'red'}>
                                  {location.priority}
                                </Badge>
                              </Td>
                              <Td>
                                <Badge colorScheme={location.enabled ? 'green' : 'gray'}>
                                  {location.enabled ? '启用' : '禁用'}
                                </Badge>
                              </Td>
                              <Td>
                                {location.healthy ? (
                                  <Badge colorScheme="green">
                                    <Box display="flex" alignItems="center" gap={1}>
                                      <FiCheck />
                                      健康
                                    </Box>
                                  </Badge>
                                ) : (
                                  <Badge colorScheme="red">
                                    <Box display="flex" alignItems="center" gap={1}>
                                      <FiX />
                                      不健康
                                    </Box>
                                  </Badge>
                                )}
                              </Td>
                              <Td>
                                {metrics?.avg_latency[location.id] ? (
                                  <Text>{metrics.avg_latency[location.id]}ms</Text>
                                ) : (
                                  <Text color="gray.400">-</Text>
                                )}
                              </Td>
                              <Td>
                                <HStack spacing={2}>
                                  <Button
                                    size="xs"
                                    onClick={() => handleToggleLocation(location.id, !location.enabled)}
                                  >
                                    {location.enabled ? '禁用' : '启用'}
                                  </Button>
                                </HStack>
                              </Td>
                            </Tr>
                          ))}
                        </Tbody>
                      </Table>
                    </CardBody>
                  </Card>
                </TabPanel>

                {/* Traffic Stats Panel */}
                <TabPanel>
                  <SimpleGrid columns={{ base: 1, lg: 2 }} spacing={4}>
                    <Card>
                      <CardHeader>
                        <Heading size="md">按区域统计</Heading>
                      </CardHeader>
                      <CardBody>
                        <VStack spacing={3} align="stretch">
                          {Object.entries(metrics?.requests_by_region || {}).map(([region, count]) => (
                            <Box key={region}>
                              <HStack justify="space-between" mb={2}>
                                <Text>{region}</Text>
                                <Text>{count.toLocaleString()}</Text>
                              </HStack>
                              <Progress
                                value={(count / (metrics?.total_requests || 1)) * 100}
                                colorScheme="blue"
                              />
                            </Box>
                          ))}
                        </VStack>
                      </CardBody>
                    </Card>

                    <Card>
                      <CardHeader>
                        <Heading size="md">按集群统计</Heading>
                      </CardHeader>
                      <CardBody>
                        <VStack spacing={3} align="stretch">
                          {Object.entries(metrics?.requests_by_cluster || {}).map(([cluster, count]) => (
                            <Box key={cluster}>
                              <HStack justify="space-between" mb={2}>
                                <Text>{cluster}</Text>
                                <Text>{count.toLocaleString()}</Text>
                              </HStack>
                              <Progress
                                value={(count / (metrics?.total_requests || 1)) * 100}
                                colorScheme="green"
                              />
                            </Box>
                          ))}
                        </VStack>
                      </CardBody>
                    </Card>
                  </SimpleGrid>
                </TabPanel>

                {/* Configuration Panel */}
                <TabPanel>
                  <Card>
                    <CardHeader>
                      <Heading size="md">边缘路由配置</Heading>
                    </CardHeader>
                    <CardBody>
                      <VStack spacing={4} align="stretch">
                        <HStack spacing={4}>
                          <FormControl>
                            <FormLabel>回退策略</FormLabel>
                            <Select
                              value={config.fallback_strategy}
                              onChange={(e) => {
                                const newConfig = { ...config, fallback_strategy: e.target.value };
                                setConfig(newConfig);
                                handleUpdateConfig(newConfig);
                              }}
                            >
                              <option value="local">本地优先</option>
                              <option value="any">任意节点</option>
                              <option value="closest">最近节点</option>
                            </Select>
                          </FormControl>

                          <FormControl>
                            <FormLabel>最大重试次数</FormLabel>
                            <NumberInput
                              value={config.max_retries}
                              min={0}
                              max={10}
                              onChange={(value) => {
                                const newConfig = { ...config, max_retries: parseInt(value) };
                                setConfig(newConfig);
                                handleUpdateConfig(newConfig);
                              }}
                            >
                              <NumberInputField />
                              <NumberInputStepper>
                                <NumberIncrementStepper />
                                <NumberDecrementStepper />
                              </NumberInputStepper>
                            </NumberInput>
                          </FormControl>

                          <FormControl>
                            <FormLabel>重试延迟 (ms)</FormLabel>
                            <NumberInput
                              value={config.retry_delay_ms}
                              min={0}
                              max={5000}
                              step={50}
                              onChange={(value) => {
                                const newConfig = { ...config, retry_delay_ms: parseInt(value) };
                                setConfig(newConfig);
                                handleUpdateConfig(newConfig);
                              }}
                            >
                              <NumberInputField />
                              <NumberInputStepper>
                                <NumberIncrementStepper />
                                <NumberDecrementStepper />
                              </NumberInputStepper>
                            </NumberInput>
                          </FormControl>
                        </HStack>

                        <HStack spacing={4}>
                          <FormControl>
                            <FormLabel>健康检查间隔 (ms)</FormLabel>
                            <NumberInput
                              value={config.health_check_interval_ms}
                              min={5000}
                              max={300000}
                              step={5000}
                              onChange={(value) => {
                                const newConfig = { ...config, health_check_interval_ms: parseInt(value) };
                                setConfig(newConfig);
                                handleUpdateConfig(newConfig);
                              }}
                            >
                              <NumberInputField />
                              <NumberInputStepper>
                                <NumberIncrementStepper />
                                <NumberDecrementStepper />
                              </NumberInputStepper>
                            </NumberInput>
                          </FormControl>

                          <FormControl>
                            <FormLabel>健康检查超时 (ms)</FormLabel>
                            <NumberInput
                              value={config.health_check_timeout_ms}
                              min={1000}
                              max={30000}
                              step={1000}
                              onChange={(value) => {
                                const newConfig = { ...config, health_check_timeout_ms: parseInt(value) };
                                setConfig(newConfig);
                                handleUpdateConfig(newConfig);
                              }}
                            >
                              <NumberInputField />
                              <NumberInputStepper>
                                <NumberIncrementStepper />
                                <NumberDecrementStepper />
                              </NumberInputStepper>
                            </NumberInput>
                          </FormControl>

                          <FormControl>
                            <FormLabel>延迟阈值 (ms)</FormLabel>
                            <NumberInput
                              value={config.latency_threshold_ms}
                              min={100}
                              max={5000}
                              step={100}
                              onChange={(value) => {
                                const newConfig = { ...config, latency_threshold_ms: parseInt(value) };
                                setConfig(newConfig);
                                handleUpdateConfig(newConfig);
                              }}
                            >
                              <NumberInputField />
                              <NumberInputStepper>
                                <NumberIncrementStepper />
                                <NumberDecrementStepper />
                              </NumberInputStepper>
                            </NumberInput>
                          </FormControl>
                        </HStack>

                        <Card>
                          <CardHeader>
                            <Heading size="sm">测试最佳节点选择</Heading>
                          </CardHeader>
                          <CardBody>
                            <HStack spacing={2}>
                              <Input
                                placeholder="输入客户端 IP 地址"
                                defaultValue="127.0.0.1"
                              />
                              <Button
                                colorScheme="blue"
                                onClick={() => handleTestBestEdge("127.0.0.1")}
                              >
                                测试
                              </Button>
                            </HStack>
                          </CardBody>
                        </Card>
                      </VStack>
                    </CardBody>
                  </Card>
                </TabPanel>
              </TabPanels>
            </Tabs>
          </>
        )}
      </VStack>
    </Container>
  );
};

export default EdgeRouting;

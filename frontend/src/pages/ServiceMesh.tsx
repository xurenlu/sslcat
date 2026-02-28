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
  StatGroup,
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
  Tooltip,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  useDisclosure,
} from '@chakra-ui/react';
import {
  FiSettings,
  FiActivity,
  FiServer,
  FiRefreshCw,
  FiCheckCircle,
  FiXCircle,
  FiAlertTriangle,
  FiPlay,
  FiPause,
} from 'react-icons/fi';
import axios from 'axios';
import { useConfig, buildApiPath } from '../contexts/ConfigContext';

interface ServiceMeshConfig {
  enabled: boolean;
  type: string;
  stats: {
    total_requests: number;
    mesh_requests: number;
    fallback_requests: number;
    avg_latency: number;
    error_rate: number;
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

const ServiceMesh: React.FC = () => {
  const { adminPrefix } = useConfig();
  const [config, setConfig] = useState<ServiceMeshConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const toast = useToast();
  const { isOpen, onOpen, onClose } = useDisclosure();

  const fetchConfig = async () => {
    try {
      setRefreshing(true);
      const response = await axios.get(buildApiPath(adminPrefix, '/api/service-mesh/config'));
      setConfig(response.data);
    } catch (error) {
      toast({
        title: '加载失败',
        description: '无法加载 Service Mesh 配置',
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
    const interval = setInterval(fetchConfig, 10000); // 每10秒刷新
    return () => clearInterval(interval);
  }, []);

  const handleToggleEnabled = async () => {
    try {
      await axios.post(buildApiPath(adminPrefix, '/api/service-mesh/config'), {
        enabled: !config?.enabled,
        type: config?.type || 'istio',
        config: {
          enabled: !config?.enabled,
          type: config?.type || 'istio',
        },
      });
      await fetchConfig();
      toast({
        title: '成功',
        description: `Service Mesh 已${!config?.enabled ? '启用' : '禁用'}`,
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: '操作失败',
        description: '无法更新 Service Mesh 配置',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleResetBreaker = async (service: string) => {
    try {
      await axios.post(buildApiPath(adminPrefix, '/api/service-mesh/circuit-breaker/reset'), { service });
      await fetchConfig();
      toast({
        title: '成功',
        description: `熔断器 ${service} 已重置`,
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: '操作失败',
        description: '无法重置熔断器',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleDiscoverServices = async () => {
    try {
      await axios.post(buildApiPath(adminPrefix, '/api/service-mesh/discover'));
      await fetchConfig();
      toast({
        title: '成功',
        description: '服务发现已触发',
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: '操作失败',
        description: '无法触发服务发现',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleHealthCheck = async () => {
    try {
      await axios.post(buildApiPath(adminPrefix, '/api/service-mesh/health-check'));
      await fetchConfig();
      toast({
        title: '成功',
        description: '健康检查已触发',
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: '操作失败',
        description: '无法触发健康检查',
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
              <FiSettings />
              Service Mesh 管理
            </Heading>
            <Text color="gray.500" mt={2}>
              管理服务网格、熔断器和服务发现
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
            <AlertIcon as={FiAlertTriangle} />
            Service Mesh 当前未启用
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
                    <StatNumber>{config.stats.total_requests.toLocaleString()}</StatNumber>
                    <StatHelpText>累计请求</StatHelpText>
                  </Stat>
                </CardBody>
              </Card>

              <Card>
                <CardBody>
                  <Stat>
                    <StatLabel>Mesh 请求</StatLabel>
                    <StatNumber>{config.stats.mesh_requests.toLocaleString()}</StatNumber>
                    <StatHelpText>
                      通过 Service Mesh
                    </StatHelpText>
                  </Stat>
                </CardBody>
              </Card>

              <Card>
                <CardBody>
                  <Stat>
                    <StatLabel>平均延迟</StatLabel>
                    <StatNumber>{config.stats.avg_latency.toFixed(2)}ms</StatNumber>
                    <StatHelpText>响应时间</StatHelpText>
                  </Stat>
                </CardBody>
              </Card>

              <Card>
                <CardBody>
                  <Stat>
                    <StatLabel>错误率</StatLabel>
                    <StatNumber>
                      {(config.stats.error_rate * 100).toFixed(2)}%
                    </StatNumber>
                    <StatHelpText>请求失败率</StatHelpText>
                  </Stat>
                </CardBody>
              </Card>
            </SimpleGrid>

            {/* Main Tabs */}
            <Tabs>
              <TabList>
                <Tab>
                  <Box display="flex" alignItems="center" gap={2}>
                    <FiServer />
                    服务列表
                  </Box>
                </Tab>
                <Tab>
                  <Box display="flex" alignItems="center" gap={2}>
                    <FiActivity />
                    熔断器状态
                  </Box>
                </Tab>
                <Tab>
                  <Box display="flex" alignItems="center" gap={2}>
                    <FiSettings />
                    配置
                  </Box>
                </Tab>
              </TabList>

              <TabPanels>
                {/* Services Panel */}
                <TabPanel>
                  <Card>
                    <CardHeader display="flex" justifyContent="space-between">
                      <Heading size="md">服务列表</Heading>
                      <Button
                        leftIcon={<FiRefreshCw />}
                        size="sm"
                        onClick={handleDiscoverServices}
                      >
                        刷新服务
                      </Button>
                    </CardHeader>
                    <CardBody>
                      {config.services.length === 0 ? (
                        <Alert status="info">
                          <AlertIcon />
                          暂无服务
                        </Alert>
                      ) : (
                        <Table variant="simple">
                          <Thead>
                            <Tr>
                              <Th>服务名</Th>
                              <Th>命名空间</Th>
                              <Th>地址</Th>
                              <Th>端口</Th>
                              <Th>状态</Th>
                              <Th>最后检查</Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {config.services.map((service) => (
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
                                        健康
                                      </Box>
                                    </Badge>
                                  ) : (
                                    <Badge colorScheme="red">
                                      <Box display="flex" alignItems="center" gap={1}>
                                        <FiXCircle />
                                        不健康
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
                      <Heading size="md">熔断器状态</Heading>
                      <Button
                        leftIcon={<FiActivity />}
                        size="sm"
                        onClick={handleHealthCheck}
                      >
                        触发健康检查
                      </Button>
                    </CardHeader>
                    <CardBody>
                      {Object.keys(config.circuit_breakers).length === 0 ? (
                        <Alert status="info">
                          <AlertIcon />
                          暂无熔断器
                        </Alert>
                      ) : (
                        <Table variant="simple">
                          <Thead>
                            <Tr>
                              <Th>服务</Th>
                              <Th>状态</Th>
                              <Th>开启次数</Th>
                              <Th>失败数</Th>
                              <Th>成功数</Th>
                              <Th>最后状态变更</Th>
                              <Th>操作</Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {Object.values(config.circuit_breakers).map((breaker) => (
                              <Tr key={breaker.service}>
                                <Td>{breaker.service}</Td>
                                <Td>
                                  {breaker.state === 'closed' ? (
                                    <Badge colorScheme="green">关闭</Badge>
                                  ) : breaker.state === 'open' ? (
                                    <Badge colorScheme="red">开启</Badge>
                                  ) : (
                                    <Badge colorScheme="yellow">半开</Badge>
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
                                      重置
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

                {/* Configuration Panel */}
                <TabPanel>
                  <Card>
                    <CardHeader>
                      <Heading size="md">Service Mesh 配置</Heading>
                    </CardHeader>
                    <CardBody>
                      <VStack spacing={4} align="stretch">
                        <FormControl>
                          <FormLabel>Service Mesh 类型</FormLabel>
                          <Select value={config.type} isDisabled>
                            <option value="istio">Istio</option>
                            <option value="linkerd">Linkerd</option>
                            <option value="consul">Consul Connect</option>
                          </Select>
                        </FormControl>

                        <Alert status="info">
                          <AlertIcon />
                          更多配置选项即将推出
                        </Alert>
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

export default ServiceMesh;

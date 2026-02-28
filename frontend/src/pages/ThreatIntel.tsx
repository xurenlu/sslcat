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
  Progress,
  Code,
  Wrap,
  Tag,
  TagLabel,
  TagLeftIcon,
} from '@chakra-ui/react';
import {
  FiShield,
  FiAlertOctagon,
  FiDatabase,
  FiRefreshCw,
  FiSearch,
  FiActivity,
  FiGlobe,
  FiMapPin,
} from 'react-icons/fi';
import axios from 'axios';
import { useConfig, buildApiPath } from '../contexts/ConfigContext';

interface ThreatStats {
  total_iocs: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  sources_count: number;
  last_update: string;
}

interface ThreatSource {
  name: string;
  url: string;
  enabled: boolean;
  update_freq: number;
  last_update: string;
  iocs_count: number;
}

interface IOCDetail {
  value: string;
  type: string;
  threat_level: string;
  source: string;
  description: string;
  first_seen: string;
  last_seen: string;
  confidence: number;
  tags: string[];
}

const ThreatIntel: React.FC = () => {
  const { adminPrefix } = useConfig();
  const [stats, setStats] = useState<ThreatStats | null>(null);
  const [sources, setSources] = useState<ThreatSource[]>([]);
  const [recentIOCs, setRecentIOCs] = useState<IOCDetail[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchValue, setSearchValue] = useState('');
  const [searchType, setSearchType] = useState('domain');
  const [searchResult, setSearchResult] = useState<IOCDetail | null>(null);
  const [searching, setSearching] = useState(false);
  const toast = useToast();

  const fetchStats = async () => {
    try {
      setRefreshing(true);
      const response = await axios.get(buildApiPath(adminPrefix, '/api/threat-intel/stats'));
      setStats(response.data);
    } catch (error) {
      toast({
        title: '加载失败',
        description: '无法加载威胁情报统计',
        status: 'error',
        duration: 3000,
      });
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const fetchSources = async () => {
    try {
      const response = await axios.get(buildApiPath(adminPrefix, '/api/threat-intel/sources'));
      setSources(response.data.sources || []);
    } catch (error) {
      console.error('Failed to fetch sources:', error);
    }
  };

  const fetchRecentIOCs = async () => {
    try {
      const response = await axios.get(buildApiPath(adminPrefix, '/api/threat-intel/iocs?limit=20'));
      setRecentIOCs(response.data.iocs || []);
    } catch (error) {
      console.error('Failed to fetch recent IOCs:', error);
    }
  };

  const handleSearch = async () => {
    if (!searchValue.trim()) {
      toast({
        title: '请输入搜索内容',
        status: 'warning',
        duration: 3000,
      });
      return;
    }

    try {
      setSearching(true);
      const response = await axios.post(buildApiPath(adminPrefix, '/api/threat-intel/check'), {
        value: searchValue,
        type: searchType,
      });
      setSearchResult(response.data.ioc || null);

      if (!response.data.ioc) {
        toast({
          title: '未找到威胁',
          description: '该指标未在威胁情报库中找到',
          status: 'info',
          duration: 3000,
        });
      }
    } catch (error) {
      toast({
        title: '搜索失败',
        description: '无法查询威胁情报',
        status: 'error',
        duration: 3000,
      });
    } finally {
      setSearching(false);
    }
  };

  const handleUpdateSource = async (sourceName: string) => {
    try {
      await axios.post(buildApiPath(adminPrefix, `/api/threat-intel/sources/${sourceName}/update`));
      toast({
        title: '成功',
        description: `威胁情报源 ${sourceName} 更新已触发`,
        status: 'success',
        duration: 3000,
      });
      await fetchSources();
      await fetchStats();
    } catch (error) {
      toast({
        title: '更新失败',
        description: '无法更新威胁情报源',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleToggleSource = async (sourceName: string, enabled: boolean) => {
    try {
      await axios.put(buildApiPath(adminPrefix, `/api/threat-intel/sources/${sourceName}`), {
        enabled,
      });
      await fetchSources();
      toast({
        title: '成功',
        description: `威胁情报源 ${sourceName} 已${enabled ? '启用' : '禁用'}`,
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: '操作失败',
        description: '无法更新威胁情报源',
        status: 'error',
        duration: 3000,
      });
    }
  };

  useEffect(() => {
    fetchStats();
    fetchSources();
    fetchRecentIOCs();
    const interval = setInterval(() => {
      fetchStats();
      fetchSources();
    }, 30000); // 每30秒刷新
    return () => clearInterval(interval);
  }, []);

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'critical':
        return 'red';
      case 'high':
        return 'orange';
      case 'medium':
        return 'yellow';
      case 'low':
        return 'green';
      default:
        return 'gray';
    }
  };

  const getThreatLevelLabel = (level: string) => {
    switch (level) {
      case 'critical':
        return '严重';
      case 'high':
        return '高';
      case 'medium':
        return '中';
      case 'low':
        return '低';
      default:
        return '未知';
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
              <FiShield />
              威胁情报中心
            </Heading>
            <Text color="gray.500" mt={2}>
              实时监控和管理安全威胁情报
            </Text>
          </Box>
          <IconButton
            aria-label="刷新"
            icon={<FiRefreshCw />}
            onClick={() => {
              fetchStats();
              fetchSources();
              fetchRecentIOCs();
            }}
            isLoading={refreshing}
          />
        </Box>

        {/* Stats Cards */}
        <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={4}>
          <Card>
            <CardBody>
              <Stat>
                <StatLabel>总 IOC 数</StatLabel>
                <StatNumber>{stats?.total_iocs.toLocaleString()}</StatNumber>
                <StatHelpText>威胁指标总数</StatHelpText>
              </Stat>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <Stat>
                <StatLabel color="red.500">严重威胁</StatLabel>
                <StatNumber color="red.500">{stats?.critical_count}</StatNumber>
                <StatHelpText>需要立即处理</StatHelpText>
              </Stat>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <Stat>
                <StatLabel color="orange.500">高危威胁</StatLabel>
                <StatNumber color="orange.500">{stats?.high_count}</StatNumber>
                <StatHelpText>高优先级处理</StatHelpText>
              </Stat>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <Stat>
                <StatLabel>情报源数量</StatLabel>
                <StatNumber>{stats?.sources_count}</StatNumber>
                <StatHelpText>活跃数据源</StatHelpText>
              </Stat>
            </CardBody>
          </Card>
        </SimpleGrid>

        {/* Main Tabs */}
        <Tabs>
          <TabList>
            <Tab>
              <Box display="flex" alignItems="center" gap={2}>
                <FiActivity />
                概览
              </Box>
            </Tab>
            <Tab>
              <Box display="flex" alignItems="center" gap={2}>
                <FiDatabase />
                情报源
              </Box>
            </Tab>
            <Tab>
              <Box display="flex" alignItems="center" gap={2}>
                <FiSearch />
                IOC 查询
              </Box>
            </Tab>
            <Tab>
              <Box display="flex" alignItems="center" gap={2}>
                <FiGlobe />
                最新威胁
              </Box>
            </Tab>
          </TabList>

          <TabPanels>
            {/* Overview Panel */}
            <TabPanel>
              <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                <Card>
                  <CardHeader>
                    <Heading size="md">威胁等级分布</Heading>
                  </CardHeader>
                  <CardBody>
                    <VStack spacing={3} align="stretch">
                      <Box>
                        <HStack justify="space-between" mb={2}>
                          <Text>严重</Text>
                          <Text>{stats?.critical_count}</Text>
                        </HStack>
                        <Progress
                          value={stats ? (stats.critical_count / stats.total_iocs) * 100 : 0}
                          colorScheme="red"
                        />
                      </Box>
                      <Box>
                        <HStack justify="space-between" mb={2}>
                          <Text>高</Text>
                          <Text>{stats?.high_count}</Text>
                        </HStack>
                        <Progress
                          value={stats ? (stats.high_count / stats.total_iocs) * 100 : 0}
                          colorScheme="orange"
                        />
                      </Box>
                      <Box>
                        <HStack justify="space-between" mb={2}>
                          <Text>中</Text>
                          <Text>{stats?.medium_count}</Text>
                        </HStack>
                        <Progress
                          value={stats ? (stats.medium_count / stats.total_iocs) * 100 : 0}
                          colorScheme="yellow"
                        />
                      </Box>
                      <Box>
                        <HStack justify="space-between" mb={2}>
                          <Text>低</Text>
                          <Text>{stats?.low_count}</Text>
                        </HStack>
                        <Progress
                          value={stats ? (stats.low_count / stats.total_iocs) * 100 : 0}
                          colorScheme="green"
                        />
                      </Box>
                    </VStack>
                  </CardBody>
                </Card>

                <Card>
                  <CardHeader>
                    <Heading size="md">系统状态</Heading>
                  </CardHeader>
                  <CardBody>
                    <VStack spacing={3} align="stretch">
                      <HStack justify="space-between">
                        <Text>活跃情报源</Text>
                        <Badge colorScheme="green">{sources.filter((s) => s.enabled).length}</Badge>
                      </HStack>
                      <HStack justify="space-between">
                        <Text>最后更新</Text>
                        <Text fontSize="sm">
                          {stats?.last_update
                            ? new Date(stats.last_update).toLocaleString()
                            : '未知'}
                        </Text>
                      </HStack>
                      <HStack justify="space-between">
                        <Text>总更新频率</Text>
                        <Text>
                          {sources.reduce((acc, s) => acc + (s.enabled ? s.update_freq : 0), 0)} 次/小时
                        </Text>
                      </HStack>
                    </VStack>
                  </CardBody>
                </Card>
              </SimpleGrid>
            </TabPanel>

            {/* Sources Panel */}
            <TabPanel>
              <Card>
                <CardHeader>
                  <Heading size="md">威胁情报源</Heading>
                </CardHeader>
                <CardBody>
                  <Table variant="simple">
                    <Thead>
                      <Tr>
                        <Th>名称</Th>
                        <Th>状态</Th>
                        <Th>IOC 数量</Th>
                        <Th>更新频率</Th>
                        <Th>最后更新</Th>
                        <Th>操作</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {sources.map((source) => (
                        <Tr key={source.name}>
                          <Td>{source.name}</Td>
                          <Td>
                            <Badge colorScheme={source.enabled ? 'green' : 'gray'}>
                              {source.enabled ? '启用' : '禁用'}
                            </Badge>
                          </Td>
                          <Td>{source.iocs_count.toLocaleString()}</Td>
                          <Td>{source.update_freq / 3600}小时</Td>
                          <Td fontSize="sm">
                            {source.last_update
                              ? new Date(source.last_update).toLocaleString()
                              : '从未'}
                          </Td>
                          <Td>
                            <HStack spacing={2}>
                              <Button
                                size="xs"
                                onClick={() => handleUpdateSource(source.name)}
                              >
                                更新
                              </Button>
                              <Button
                                size="xs"
                                onClick={() => handleToggleSource(source.name, !source.enabled)}
                              >
                                {source.enabled ? '禁用' : '启用'}
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

            {/* IOC Search Panel */}
            <TabPanel>
              <VStack spacing={6} align="stretch">
                <Card>
                  <CardBody>
                    <VStack spacing={4}>
                      <HStack width="full">
                        <Select
                          value={searchType}
                          onChange={(e) => setSearchType(e.target.value)}
                          width="200px"
                        >
                          <option value="domain">域名</option>
                          <option value="ip">IP 地址</option>
                          <option value="url">URL</option>
                          <option value="hash">哈希值</option>
                        </Select>
                        <Input
                          placeholder={`输入${searchType === 'domain' ? '域名' : searchType === 'ip' ? 'IP 地址' : searchType === 'url' ? 'URL' : '哈希值'}...`}
                          value={searchValue}
                          onChange={(e) => setSearchValue(e.target.value)}
                          onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
                        />
                        <Button
                          leftIcon={<FiSearch />}
                          onClick={handleSearch}
                          isLoading={searching}
                        >
                          搜索
                        </Button>
                      </HStack>
                    </VStack>
                  </CardBody>
                </Card>

                {searchResult && (
                  <Card>
                    <CardHeader>
                      <Heading size="md">查询结果</Heading>
                    </CardHeader>
                    <CardBody>
                      <VStack spacing={4} align="stretch">
                        <HStack>
                          <Badge
                            colorScheme={getThreatLevelColor(searchResult.threat_level)}
                            fontSize="lg"
                            px={3}
                            py={1}
                          >
                            {getThreatLevelLabel(searchResult.threat_level)}威胁
                          </Badge>
                          <Badge colorScheme="blue">{searchResult.type}</Badge>
                          <Badge colorScheme="purple">
                            置信度: {(searchResult.confidence * 100).toFixed(0)}%
                          </Badge>
                        </HStack>

                        <Box>
                          <Text fontWeight="bold" mb={2}>
                            指标值:
                          </Text>
                          <Code p={2} display="block" bg="gray.100">
                            {searchResult.value}
                          </Code>
                        </Box>

                        <SimpleGrid columns={2} spacing={4}>
                          <Box>
                            <Text fontSize="sm" color="gray.500">
                              来源
                            </Text>
                            <Text>{searchResult.source}</Text>
                          </Box>
                          <Box>
                            <Text fontSize="sm" color="gray.500">
                              描述
                            </Text>
                            <Text>{searchResult.description}</Text>
                          </Box>
                          <Box>
                            <Text fontSize="sm" color="gray.500">
                              首次发现
                            </Text>
                            <Text fontSize="sm">
                              {new Date(searchResult.first_seen).toLocaleString()}
                            </Text>
                          </Box>
                          <Box>
                            <Text fontSize="sm" color="gray.500">
                              最后发现
                            </Text>
                            <Text fontSize="sm">
                              {new Date(searchResult.last_seen).toLocaleString()}
                            </Text>
                          </Box>
                        </SimpleGrid>

                        <Box>
                          <Text fontWeight="bold" mb={2}>
                            标签:
                          </Text>
                          <Wrap>
                            {searchResult.tags.map((tag) => (
                              <Tag key={tag} colorScheme="blue" mr={2} mb={2}>
                                <TagLeftIcon as={FiMapPin} />
                                <TagLabel>{tag}</TagLabel>
                              </Tag>
                            ))}
                          </Wrap>
                        </Box>
                      </VStack>
                    </CardBody>
                  </Card>
                )}
              </VStack>
            </TabPanel>

            {/* Recent Threats Panel */}
            <TabPanel>
              <Card>
                <CardHeader>
                  <Heading size="md">最新威胁指标</Heading>
                </CardHeader>
                <CardBody>
                  {recentIOCs.length === 0 ? (
                    <Alert status="info">
                      <AlertIcon />
                      暂无最近威胁
                    </Alert>
                  ) : (
                    <Table variant="simple">
                      <Thead>
                        <Tr>
                          <Th>指标值</Th>
                          <Th>类型</Th>
                          <Th>威胁等级</Th>
                          <Th>来源</Th>
                          <Th>置信度</Th>
                          <Th>最后发现</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {recentIOCs.map((ioc, index) => (
                          <Tr key={index}>
                            <Td>
                              <Code fontSize="sm">{ioc.value}</Code>
                            </Td>
                            <Td>
                              <Badge colorScheme="blue">{ioc.type}</Badge>
                            </Td>
                            <Td>
                              <Badge colorScheme={getThreatLevelColor(ioc.threat_level)}>
                                {getThreatLevelLabel(ioc.threat_level)}
                              </Badge>
                            </Td>
                            <Td>{ioc.source}</Td>
                            <Td>
                              <Progress
                                value={ioc.confidence * 100}
                                size="sm"
                                width="80px"
                              />
                            </Td>
                            <Td fontSize="sm">
                              {new Date(ioc.last_seen).toLocaleString()}
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
      </VStack>
    </Container>
  );
};

export default ThreatIntel;

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
  Badge,
  Code,
  IconButton,
  Tooltip,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  Spacer,
  InputGroup,
  InputLeftElement,
} from '@chakra-ui/react';
import {
  FiFileText,
  FiSearch,
  FiFilter,
  FiDownload,
  FiEye,
  FiCalendar,
  FiUser,
  FiActivity,
  FiShield,
  FiChevronDown,
  FiCopy,
} from 'react-icons/fi';
import axios from 'axios';

interface AuditLog {
  id: string;
  timestamp: string;
  user: string;
  resource: string;
  action: string;
  allowed: boolean;
  reason: string;
  ip_address: string;
  user_agent: string;
  details?: Record<string, any>;
}

interface LogStats {
  total_logs: number;
  allowed_actions: number;
  denied_actions: number;
  unique_users: number;
  top_resources: Array<{ resource: string; count: number }>;
  top_users: Array<{ user: string; count: number }>;
  action_distribution: Record<string, number>;
}

const AuditLogsPage: React.FC = () => {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [stats, setStats] = useState<LogStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterUser, setFilterUser] = useState('');
  const [filterAction, setFilterAction] = useState('');
  const [filterResource, setFilterResource] = useState('');
  const [filterAllowed, setFilterAllowed] = useState<string>('all');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize] = useState(50);
  const [expandedLog, setExpandedLog] = useState<string | null>(null);
  const toast = useToast();

  const fetchLogs = async () => {
    try {
      const params: any = {
        page,
        page_size: pageSize,
      };

      if (searchTerm) params.search = searchTerm;
      if (filterUser) params.user = filterUser;
      if (filterAction) params.action = filterAction;
      if (filterResource) params.resource = filterResource;
      if (filterAllowed !== 'all') params.allowed = filterAllowed === 'allowed';
      if (dateFrom) params.from = dateFrom;
      if (dateTo) params.to = dateTo;

      const response = await axios.get('/api/audit/logs', { params });
      setLogs(response.data.logs || []);
      setStats(response.data.stats || null);
    } catch (error) {
      toast({
        title: '加载失败',
        description: '无法加载审计日志',
        status: 'error',
        duration: 3000,
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [page, pageSize]);

  const handleExport = async (format: 'csv' | 'json') => {
    try {
      const params: any = {};
      if (searchTerm) params.search = searchTerm;
      if (filterUser) params.user = filterUser;
      if (filterAction) params.action = filterAction;
      if (filterResource) params.resource = filterResource;
      if (filterAllowed !== 'all') params.allowed = filterAllowed === 'allowed';
      if (dateFrom) params.from = dateFrom;
      if (dateTo) params.to = dateTo;

      const response = await axios.get('/api/audit/logs/export', {
        params: { ...params, format },
        responseType: 'blob',
      });

      const blob = new Blob([response.data], {
        type: format === 'csv' ? 'text/csv' : 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `audit_logs_${new Date().toISOString()}.${format}`;
      a.click();
      URL.revokeObjectURL(url);

      toast({
        title: '成功',
        description: `日志已导出为 ${format.toUpperCase()}`,
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: '导出失败',
        description: '无法导出审计日志',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleCopyLog = (log: AuditLog) => {
    const text = JSON.stringify(log, null, 2);
    navigator.clipboard.writeText(text);
    toast({
      title: '已复制',
      description: '日志详情已复制到剪贴板',
      status: 'success',
      duration: 2000,
    });
  };

  const getActionColor = (action: string) => {
    const actionColors: Record<string, string> = {
      create: 'green',
      read: 'blue',
      update: 'orange',
      delete: 'red',
      login: 'green',
      logout: 'gray',
      block: 'red',
      allow: 'green',
    };
    return actionColors[action.toLowerCase()] || 'gray';
  };

  const filteredLogs = logs;

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
              <FiFileText />
              审计日志
            </Heading>
            <Text color="gray.500" mt={2}>
              查看和搜索系统操作日志
            </Text>
          </Box>
          <Menu>
            <MenuButton as={Button} rightIcon={<FiChevronDown />} colorScheme="blue">
              <FiDownload /> 导出
            </MenuButton>
            <MenuList>
              <MenuItem onClick={() => handleExport('csv')}>导出为 CSV</MenuItem>
              <MenuItem onClick={() => handleExport('json')}>导出为 JSON</MenuItem>
            </MenuList>
          </Menu>
        </Box>

        {/* Stats Cards */}
        <SimpleGrid columns={{ base: 1, md: 4 }} spacing={4}>
          <StatCard
            label="总日志数"
            value={stats?.total_logs || 0}
            icon={FiFileText}
            color="blue"
          />
          <StatCard
            label="允许操作"
            value={stats?.allowed_actions || 0}
            icon={FiShield}
            color="green"
          />
          <StatCard
            label="拒绝操作"
            value={stats?.denied_actions || 0}
            icon={FiActivity}
            color="red"
          />
          <StatCard
            label="活跃用户"
            value={stats?.unique_users || 0}
            icon={FiUser}
            color="orange"
          />
        </SimpleGrid>

        {/* Filters */}
        <Card>
          <CardHeader>
            <Heading size="md" display="flex" alignItems="center" gap={2}>
              <FiFilter />
              筛选条件
            </Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={4}>
                <FormControl>
                  <InputGroup>
                    <InputLeftElement pointerEvents="none">
                      <FiSearch color="gray.300" />
                    </InputLeftElement>
                    <Input
                      placeholder="搜索日志..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                    />
                  </InputGroup>
                </FormControl>

                <FormControl>
                  <Input
                    placeholder="用户名"
                    value={filterUser}
                    onChange={(e) => setFilterUser(e.target.value)}
                  />
                </FormControl>

                <FormControl>
                  <Input
                    placeholder="资源"
                    value={filterResource}
                    onChange={(e) => setFilterResource(e.target.value)}
                  />
                </FormControl>

                <FormControl>
                  <Select
                    value={filterAllowed}
                    onChange={(e) => setFilterAllowed(e.target.value)}
                  >
                    <option value="all">全部状态</option>
                    <option value="allowed">仅允许</option>
                    <option value="denied">仅拒绝</option>
                  </Select>
                </FormControl>
              </SimpleGrid>

              <SimpleGrid columns={{ base: 1, md: 3 }} spacing={4}>
                <FormControl>
                  <FormLabel>开始日期</FormLabel>
                  <Input
                    type="datetime-local"
                    value={dateFrom}
                    onChange={(e) => setDateFrom(e.target.value)}
                  />
                </FormControl>

                <FormControl>
                  <FormLabel>结束日期</FormLabel>
                  <Input
                    type="datetime-local"
                    value={dateTo}
                    onChange={(e) => setDateTo(e.target.value)}
                  />
                </FormControl>

                <FormControl display="flex" alignItems="flex-end">
                  <Button
                    colorScheme="blue"
                    onClick={fetchLogs}
                    width="full"
                  >
                    <FiSearch /> 搜索
                  </Button>
                </FormControl>
              </SimpleGrid>
            </VStack>
          </CardBody>
        </Card>

        {/* Top Statistics */}
        <SimpleGrid columns={{ base: 1, lg: 2 }} spacing={4}>
          <Card>
            <CardHeader>
              <Heading size="sm">最常访问资源</Heading>
            </CardHeader>
            <CardBody>
              <VStack spacing={2} align="stretch">
                {stats?.top_resources?.slice(0, 5).map((item, index) => (
                  <HStack key={index} justify="space-between">
                    <Code fontSize="sm" noOfLines={1}>
                      {item.resource}
                    </Code>
                    <Badge>{item.count} 次</Badge>
                  </HStack>
                ))}
              </VStack>
            </CardBody>
          </Card>

          <Card>
            <CardHeader>
              <Heading size="sm">最活跃用户</Heading>
            </CardHeader>
            <CardBody>
              <VStack spacing={2} align="stretch">
                {stats?.top_users?.slice(0, 5).map((item, index) => (
                  <HStack key={index} justify="space-between">
                    <Text>{item.user}</Text>
                    <Badge>{item.count} 次操作</Badge>
                  </HStack>
                ))}
              </VStack>
            </CardBody>
          </Card>
        </SimpleGrid>

        {/* Logs Table */}
        <Card>
          <CardHeader>
            <Heading size="md">日志列表</Heading>
          </CardHeader>
          <CardBody>
            <Table variant="simple" size="sm">
              <Thead>
                <Tr>
                  <Th>时间</Th>
                  <Th>用户</Th>
                  <Th>操作</Th>
                  <Th>资源</Th>
                  <Th>结果</Th>
                  <Th>IP 地址</Th>
                  <Th>操作</Th>
                </Tr>
              </Thead>
              <Tbody>
                {filteredLogs.map((log) => (
                  <>
                    <Tr key={log.id}>
                      <Td fontSize="xs">
                        {new Date(log.timestamp).toLocaleString()}
                      </Td>
                      <Td>{log.user}</Td>
                      <Td>
                        <Badge colorScheme={getActionColor(log.action)}>
                          {log.action}
                        </Badge>
                      </Td>
                      <Td>
                        <Code fontSize="xs" maxW="200px" noOfLines={1}>
                          {log.resource}
                        </Code>
                      </Td>
                      <Td>
                        {log.allowed ? (
                          <Badge colorScheme="green">允许</Badge>
                        ) : (
                          <Badge colorScheme="red">拒绝</Badge>
                        )}
                      </Td>
                      <Td fontSize="xs">{log.ip_address}</Td>
                      <Td>
                        <HStack spacing={1}>
                          <Tooltip label="查看详情">
                            <IconButton
                              aria-label="查看详情"
                              icon={<FiEye />}
                              size="xs"
                              onClick={() =>
                                setExpandedLog(
                                  expandedLog === log.id ? null : log.id
                                )
                              }
                            />
                          </Tooltip>
                          <Tooltip label="复制">
                            <IconButton
                              aria-label="复制"
                              icon={<FiCopy />}
                              size="xs"
                              onClick={() => handleCopyLog(log)}
                            />
                          </Tooltip>
                        </HStack>
                      </Td>
                    </Tr>
                    {expandedLog === log.id && (
                      <Tr>
                        <Td colSpan={7} bg="gray.50">
                          <VStack align="start" spacing={2} p={4}>
                            <HStack>
                              <Text fontWeight="bold">原因:</Text>
                              <Text>{log.reason || '-'}</Text>
                            </HStack>
                            <HStack>
                              <Text fontWeight="bold">User Agent:</Text>
                              <Text fontSize="xs" noOfLines={1} maxW="600px">
                                {log.user_agent || '-'}
                              </Text>
                            </HStack>
                            {log.details && (
                              <Box width="full">
                                <Text fontWeight="bold" mb={2}>
                                  详细信息:
                                </Text>
                                <Code
                                  p={2}
                                  display="block"
                                  bg="white"
                                  maxH="200px"
                                  overflowY="auto"
                                >
                                  {JSON.stringify(log.details, null, 2)}
                                </Code>
                              </Box>
                            )}
                          </VStack>
                        </Td>
                      </Tr>
                    )}
                  </>
                ))}
              </Tbody>
            </Table>

            {/* Pagination */}
            <HStack mt={4} justify="space-between">
              <Text fontSize="sm" color="gray.500">
                显示 {filteredLogs.length} 条记录
              </Text>
              <HStack spacing={2}>
                <Button
                  size="sm"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  isDisabled={page === 1}
                >
                  上一页
                </Button>
                <Button size="sm" onClick={() => setPage((p) => p + 1)}>
                  下一页
                </Button>
              </HStack>
            </HStack>
          </CardBody>
        </Card>
      </VStack>
    </Container>
  );
};

const StatCard: React.FC<{
  label: string;
  value: number;
  icon: any;
  color: string;
}> = ({ label, value, icon: Icon, color }) => (
  <Card>
    <CardBody>
      <HStack spacing={4}>
        <Box color={`${color}.500`} fontSize="3xl">
          <Icon />
        </Box>
        <Box>
          <Text fontSize="sm" color="gray.500">
            {label}
          </Text>
          <Text fontSize="2xl" fontWeight="bold">
            {value.toLocaleString()}
          </Text>
        </Box>
      </HStack>
    </CardBody>
  </Card>
);

export default AuditLogsPage;

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
  Textarea,
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
  Badge,
  Code,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  useDisclosure,
  Switch,
  Progress,
  Wrap,
  Tag,
  TagLabel,
  TagCloseButton,
  Checkbox,
} from '@chakra-ui/react';
import {
  FiShield,
  FiPlus,
  FiEdit,
  FiTrash2,
  FiGlobe,
  FiMapPin,
  FiClock,
  FiUpload,
  FiDownload,
} from 'react-icons/fi';
import axios from 'axios';

interface IPEntry {
  id: string;
  ip_or_cidr: string;
  type: 'whitelist' | 'blacklist';
  comment: string;
  created_at: string;
  expires_at?: string;
  enabled: boolean;
  hit_count: number;
}

interface GeoRule {
  id: string;
  country_code: string;
  country_name: string;
  type: 'allow' | 'deny';
  comment: string;
  enabled: boolean;
}

interface TimeRule {
  id: string;
  name: string;
  start_time: string;
  end_time: string;
  days_of_week: number[];
  type: 'allow' | 'deny';
  enabled: boolean;
}

const AccessControl: React.FC = () => {
  const [ipEntries, setIpEntries] = useState<IPEntry[]>([]);
  const [geoRules, setGeoRules] = useState<GeoRule[]>([]);
  const [timeRules, setTimeRules] = useState<TimeRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [importText, setImportText] = useState('');
  const toast = useToast();

  const {
    isOpen: isIPModalOpen,
    onOpen: onIPModalOpen,
    onClose: onIPModalClose,
  } = useDisclosure();

  const {
    isOpen: isGeoModalOpen,
    onOpen: onGeoModalOpen,
    onClose: onGeoModalClose,
  } = useDisclosure();

  const {
    isOpen: isTimeModalOpen,
    onOpen: onTimeModalOpen,
    onClose: onTimeModalClose,
  } = useDisclosure();

  const [editingIP, setEditingIP] = useState<Partial<IPEntry> | null>(null);
  const [editingGeo, setEditingGeo] = useState<Partial<GeoRule> | null>(null);
  const [editingTime, setEditingTime] = useState<Partial<TimeRule> | null>(null);

  const fetchIPEntries = async () => {
    try {
      const response = await axios.get('/api/access-control/ip');
      setIpEntries(response.data.entries || []);
    } catch (error) {
      console.error('Failed to fetch IP entries:', error);
    }
  };

  const fetchGeoRules = async () => {
    try {
      const response = await axios.get('/api/access-control/geo');
      setGeoRules(response.data.rules || []);
    } catch (error) {
      console.error('Failed to fetch geo rules:', error);
    }
  };

  const fetchTimeRules = async () => {
    try {
      const response = await axios.get('/api/access-control/time');
      setTimeRules(response.data.rules || []);
    } catch (error) {
      console.error('Failed to fetch time rules:', error);
    }
  };

  useEffect(() => {
    const loadData = async () => {
      await Promise.all([
        fetchIPEntries(),
        fetchGeoRules(),
        fetchTimeRules(),
      ]);
      setLoading(false);
    };
    loadData();
  }, []);

  const handleSaveIP = async () => {
    try {
      if (editingIP?.id) {
        await axios.put(`/api/access-control/ip/${editingIP.id}`, editingIP);
        toast({
          title: '成功',
          description: 'IP 规则已更新',
          status: 'success',
          duration: 3000,
        });
      } else {
        await axios.post('/api/access-control/ip', editingIP);
        toast({
          title: '成功',
          description: 'IP 规则已添加',
          status: 'success',
          duration: 3000,
        });
      }
      await fetchIPEntries();
      onIPModalClose();
      setEditingIP(null);
    } catch (error) {
      toast({
        title: '操作失败',
        description: '无法保存 IP 规则',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleDeleteIP = async (id: string) => {
    try {
      await axios.delete(`/api/access-control/ip/${id}`);
      await fetchIPEntries();
      toast({
        title: '成功',
        description: 'IP 规则已删除',
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: '操作失败',
        description: '无法删除 IP 规则',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleToggleIP = async (id: string, enabled: boolean) => {
    try {
      await axios.patch(`/api/access-control/ip/${id}`, { enabled });
      await fetchIPEntries();
      toast({
        title: '成功',
        description: `IP 规则已${enabled ? '启用' : '禁用'}`,
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: '操作失败',
        description: '无法更新 IP 规则',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleImportIPs = async () => {
    if (!importText.trim()) {
      toast({
        title: '请输入要导入的 IP',
        status: 'warning',
        duration: 3000,
      });
      return;
    }

    try {
                      const lines = importText.split('\n').filter((line) => line.trim());
      const results = await Promise.all(
        lines.map((line) =>
          axios.post('/api/access-control/ip', {
            ip_or_cidr: line.trim(),
            type: 'blacklist' as const,
            enabled: true,
          })
        )
      );
      toast({
        title: '成功',
        description: `已导入 ${results.length} 条 IP 规则`,
        status: 'success',
        duration: 3000,
      });
      setImportText('');
      await fetchIPEntries();
    } catch (error) {
      toast({
        title: '导入失败',
        description: '无法导入 IP 规则',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleExportIPs = async (type: 'whitelist' | 'blacklist') => {
    const entries = ipEntries.filter((e) => e.type === type);
    const text = entries.map((e) => e.ip_or_cidr).join('\n');

    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${type}_ips.txt`;
    a.click();
    URL.revokeObjectURL(url);
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
        <Box>
          <Heading size="lg" display="flex" alignItems="center" gap={2}>
            <FiShield />
            访问控制管理
          </Heading>
          <Text color="gray.500" mt={2}>
            管理 IP 白名单/黑名单、地理位置和时间窗口访问控制
          </Text>
        </Box>

        {/* Stats */}
        <SimpleGrid columns={{ base: 1, md: 4 }} spacing={4}>
          <Card>
            <CardBody>
              <StatCard
                label="白名单 IP"
                value={ipEntries.filter((e) => e.type === 'whitelist').length}
                color="green"
              />
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <StatCard
                label="黑名单 IP"
                value={ipEntries.filter((e) => e.type === 'blacklist').length}
                color="red"
              />
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <StatCard
                label="地理规则"
                value={geoRules.length}
                color="blue"
              />
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <StatCard
                label="时间规则"
                value={timeRules.length}
                color="orange"
              />
            </CardBody>
          </Card>
        </SimpleGrid>

        {/* Main Tabs */}
        <Tabs>
          <TabList>
            <Tab>
              <Box display="flex" alignItems="center" gap={2}>
                <FiShield />
                IP 控制
              </Box>
            </Tab>
            <Tab>
              <Box display="flex" alignItems="center" gap={2}>
                <FiGlobe />
                地理位置
              </Box>
            </Tab>
            <Tab>
              <Box display="flex" alignItems="center" gap={2}>
                <FiClock />
                时间窗口
              </Box>
            </Tab>
          </TabList>

          <TabPanels>
            {/* IP Control Panel */}
            <TabPanel>
              <VStack spacing={6} align="stretch">
                <Card>
                  <CardHeader display="flex" justifyContent="space-between">
                    <Heading size="md">IP 规则列表</Heading>
                    <HStack spacing={2}>
                      <Button
                        leftIcon={<FiUpload />}
                        size="sm"
                        variant="outline"
                        onClick={() => setImportText('# 每行一个 IP 或 CIDR\n192.168.1.1\n10.0.0.0/8')}
                      >
                        导入
                      </Button>
                      <Button
                        leftIcon={<FiPlus />}
                        size="sm"
                        colorScheme="green"
                        onClick={() => {
                          setEditingIP({ type: 'whitelist', enabled: true });
                          onIPModalOpen();
                        }}
                      >
                        添加白名单
                      </Button>
                      <Button
                        leftIcon={<FiPlus />}
                        size="sm"
                        colorScheme="red"
                        onClick={() => {
                          setEditingIP({ type: 'blacklist', enabled: true });
                          onIPModalOpen();
                        }}
                      >
                        添加黑名单
                      </Button>
                    </HStack>
                  </CardHeader>
                  <CardBody>
                    {importText && (
                      <Box mb={4} p={4} bg="gray.50" borderRadius="md">
                        <VStack spacing={3} align="stretch">
                          <FormControl>
                            <FormLabel>批量导入 IP (每行一个)</FormLabel>
                            <Textarea
                              value={importText}
                              onChange={(e) => setImportText(e.target.value)}
                              placeholder="192.168.1.1&#10;10.0.0.0/8&#10;..."
                              rows={5}
                            />
                          </FormControl>
                          <HStack spacing={2}>
                            <Button
                              colorScheme="blue"
                              onClick={handleImportIPs}
                            >
                              导入
                            </Button>
                            <Button
                              variant="ghost"
                              onClick={() => setImportText('')}
                            >
                              取消
                            </Button>
                          </HStack>
                        </VStack>
                      </Box>
                    )}

                    <HStack spacing={2} mb={4}>
                      <Button
                        size="sm"
                        variant="outline"
                        leftIcon={<FiDownload />}
                        onClick={() => handleExportIPs('whitelist')}
                      >
                        导出白名单
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        leftIcon={<FiDownload />}
                        onClick={() => handleExportIPs('blacklist')}
                      >
                        导出黑名单
                      </Button>
                    </HStack>

                    <Table variant="simple">
                      <Thead>
                        <Tr>
                          <Th>IP / CIDR</Th>
                          <Th>类型</Th>
                          <Th>备注</Th>
                          <Th>命中次数</Th>
                          <Th>过期时间</Th>
                          <Th>状态</Th>
                          <Th>操作</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {ipEntries.map((entry) => (
                          <Tr key={entry.id}>
                            <Td>
                              <Code>{entry.ip_or_cidr}</Code>
                            </Td>
                            <Td>
                              <Badge colorScheme={entry.type === 'whitelist' ? 'green' : 'red'}>
                                {entry.type === 'whitelist' ? '白名单' : '黑名单'}
                              </Badge>
                            </Td>
                            <Td fontSize="sm">{entry.comment || '-'}</Td>
                            <Td>{entry.hit_count}</Td>
                            <Td fontSize="sm">
                              {entry.expires_at
                                ? new Date(entry.expires_at).toLocaleDateString()
                                : '永不过期'}
                            </Td>
                            <Td>
                              <Switch
                                size="sm"
                                isChecked={entry.enabled}
                                onChange={() => handleToggleIP(entry.id, !entry.enabled)}
                              />
                            </Td>
                            <Td>
                              <HStack spacing={1}>
                                <IconButton
                                  aria-label="编辑"
                                  icon={<FiEdit />}
                                  size="xs"
                                  onClick={() => {
                                    setEditingIP(entry);
                                    onIPModalOpen();
                                  }}
                                />
                                <IconButton
                                  aria-label="删除"
                                  icon={<FiTrash2 />}
                                  size="xs"
                                  colorScheme="red"
                                  onClick={() => handleDeleteIP(entry.id)}
                                />
                              </HStack>
                            </Td>
                          </Tr>
                        ))}
                      </Tbody>
                    </Table>
                  </CardBody>
                </Card>
              </VStack>
            </TabPanel>

            {/* Geo Control Panel */}
            <TabPanel>
              <Card>
                <CardHeader display="flex" justifyContent="space-between">
                  <Heading size="md">地理位置访问控制</Heading>
                  <Button
                    leftIcon={<FiPlus />}
                    size="sm"
                    colorScheme="blue"
                    onClick={() => {
                      setEditingGeo({ type: 'allow', enabled: true });
                      onGeoModalOpen();
                    }}
                  >
                    添加规则
                  </Button>
                </CardHeader>
                <CardBody>
                  <Alert status="info" mb={4}>
                    <AlertIcon />
                    基于客户端 IP 的地理位置进行访问控制
                  </Alert>

                  <Table variant="simple">
                    <Thead>
                      <Tr>
                        <Th>国家/地区</Th>
                        <Th>类型</Th>
                        <Th>备注</Th>
                        <Th>状态</Th>
                        <Th>操作</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {geoRules.map((rule) => (
                        <Tr key={rule.id}>
                          <Td>
                            <HStack>
                              <Text>{rule.country_name}</Text>
                              <Badge>{rule.country_code}</Badge>
                            </HStack>
                          </Td>
                          <Td>
                            <Badge colorScheme={rule.type === 'allow' ? 'green' : 'red'}>
                              {rule.type === 'allow' ? '允许' : '拒绝'}
                            </Badge>
                          </Td>
                          <Td fontSize="sm">{rule.comment || '-'}</Td>
                          <Td>
                            <Switch
                              size="sm"
                              isChecked={rule.enabled}
                              onChange={async () => {
                                try {
                                  await axios.patch(`/api/access-control/geo/${rule.id}`, {
                                    enabled: !rule.enabled,
                                  });
                                  await fetchGeoRules();
                                } catch (error) {
                                  toast({
                                    title: '操作失败',
                                    status: 'error',
                                    duration: 3000,
                                  });
                                }
                              }}
                            />
                          </Td>
                          <Td>
                            <IconButton
                              aria-label="删除"
                              icon={<FiTrash2 />}
                              size="xs"
                              colorScheme="red"
                              onClick={async () => {
                                try {
                                  await axios.delete(`/api/access-control/geo/${rule.id}`);
                                  await fetchGeoRules();
                                  toast({
                                    title: '成功',
                                    status: 'success',
                                    duration: 3000,
                                  });
                                } catch (error) {
                                  toast({
                                    title: '操作失败',
                                    status: 'error',
                                    duration: 3000,
                                  });
                                }
                              }}
                            />
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </CardBody>
              </Card>
            </TabPanel>

            {/* Time Window Panel */}
            <TabPanel>
              <Card>
                <CardHeader display="flex" justifyContent="space-between">
                  <Heading size="md">时间窗口访问控制</Heading>
                  <Button
                    leftIcon={<FiPlus />}
                    size="sm"
                    colorScheme="orange"
                    onClick={() => {
                      setEditingTime({
                        type: 'allow',
                        enabled: true,
                        days_of_week: [1, 2, 3, 4, 5],
                      });
                      onTimeModalOpen();
                    }}
                  >
                    添加规则
                  </Button>
                </CardHeader>
                <CardBody>
                  <Alert status="info" mb={4}>
                    <AlertIcon />
                    基于时间窗口的访问控制规则
                  </Alert>

                  <VStack spacing={4} align="stretch">
                    {timeRules.map((rule) => (
                      <Card key={rule.id} variant="outline">
                        <CardBody>
                          <HStack justify="space-between">
                            <VStack align="start" spacing={2}>
                              <Heading size="sm">{rule.name}</Heading>
                              <HStack>
                                <Text fontSize="sm">
                                  {rule.start_time} - {rule.end_time}
                                </Text>
                                <Badge colorScheme={rule.type === 'allow' ? 'green' : 'red'}>
                                  {rule.type === 'allow' ? '允许' : '拒绝'}
                                </Badge>
                              </HStack>
                              <Wrap>
                                {['日', '一', '二', '三', '四', '五', '六'].map((day, index) => (
                                  <Badge
                                    key={index}
                                    colorScheme={rule.days_of_week.includes(index) ? 'blue' : 'gray'}
                                  >
                                    {day}
                                  </Badge>
                                ))}
                              </Wrap>
                            </VStack>
                            <HStack>
                              <Switch
                                isChecked={rule.enabled}
                                onChange={async () => {
                                  try {
                                    await axios.patch(`/api/access-control/time/${rule.id}`, {
                                      enabled: !rule.enabled,
                                    });
                                    await fetchTimeRules();
                                  } catch (error) {
                                    toast({
                                      title: '操作失败',
                                      status: 'error',
                                      duration: 3000,
                                    });
                                  }
                                }}
                              />
                              <IconButton
                                aria-label="删除"
                                icon={<FiTrash2 />}
                                size="sm"
                                colorScheme="red"
                                onClick={async () => {
                                  try {
                                    await axios.delete(`/api/access-control/time/${rule.id}`);
                                    await fetchTimeRules();
                                    toast({
                                      title: '成功',
                                      status: 'success',
                                      duration: 3000,
                                    });
                                  } catch (error) {
                                    toast({
                                      title: '操作失败',
                                      status: 'error',
                                      duration: 3000,
                                    });
                                  }
                                }}
                              />
                            </HStack>
                          </HStack>
                        </CardBody>
                      </Card>
                    ))}
                  </VStack>
                </CardBody>
              </Card>
            </TabPanel>
          </TabPanels>
        </Tabs>
      </VStack>

      {/* IP Modal */}
      <Modal isOpen={isIPModalOpen} onClose={onIPModalClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>
            {editingIP?.id ? '编辑 IP 规则' : '添加 IP 规则'}
          </ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4} align="stretch">
              <FormControl isRequired>
                <FormLabel>IP / CIDR</FormLabel>
                <Input
                  value={editingIP?.ip_or_cidr || ''}
                  onChange={(e) =>
                    setEditingIP({ ...editingIP, ip_or_cidr: e.target.value })
                  }
                  placeholder="192.168.1.1 或 10.0.0.0/8"
                />
              </FormControl>

              <FormControl isRequired>
                <FormLabel>类型</FormLabel>
                <Select
                  value={editingIP?.type || 'whitelist'}
                  onChange={(e) =>
                    setEditingIP({ ...editingIP, type: e.target.value as 'whitelist' | 'blacklist' })
                  }
                >
                  <option value="whitelist">白名单</option>
                  <option value="blacklist">黑名单</option>
                </Select>
              </FormControl>

              <FormControl>
                <FormLabel>备注</FormLabel>
                <Input
                  value={editingIP?.comment || ''}
                  onChange={(e) =>
                    setEditingIP({ ...editingIP, comment: e.target.value })
                  }
                  placeholder="可选备注"
                />
              </FormControl>

              <FormControl>
                <FormLabel>过期时间</FormLabel>
                <Input
                  type="datetime-local"
                  value={editingIP?.expires_at || ''}
                  onChange={(e) =>
                    setEditingIP({ ...editingIP, expires_at: e.target.value })
                  }
                />
              </FormControl>

              <FormControl display="flex" alignItems="center">
                <Switch
                  isChecked={editingIP?.enabled ?? true}
                  onChange={(e) =>
                    setEditingIP({ ...editingIP, enabled: e.target.checked })
                  }
                />
                <FormLabel mb="0" ml={3}>
                  启用
                </FormLabel>
              </FormControl>
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button onClick={onIPModalClose}>取消</Button>
            <Button colorScheme="blue" onClick={handleSaveIP} ml={3}>
              保存
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Container>
  );
};

const StatCard: React.FC<{
  label: string;
  value: number;
  color: string;
}> = ({ label, value, color }) => (
  <HStack spacing={4}>
    <Box color={`${color}.500`} fontSize="3xl">
      <FiShield />
    </Box>
    <Box>
      <Text fontSize="sm" color="gray.500">
        {label}
      </Text>
      <Text fontSize="2xl" fontWeight="bold">
        {value}
      </Text>
    </Box>
  </HStack>
);

export default AccessControl;

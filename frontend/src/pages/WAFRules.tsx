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
  RadioGroup,
  Radio,
  Wrap,
  Tag,
  TagLabel,
  TagLeftIcon,
  TagCloseButton,
} from '@chakra-ui/react';
import {
  FiShield,
  FiPlus,
  FiEdit,
  FiTrash2,
  FiCopy,
  FiPlay,
  FiSave,
  FiEye,
  FiCode,
  FiCheck,
  FiX,
} from 'react-icons/fi';
import axios from 'axios';

interface WAFRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  rule_type: string;
  action: string;
  pattern: string;
  params: string[];
  severity: string;
  tags: string[];
  created_at: string;
  updated_at: string;
}

interface WAFTemplate {
  id: string;
  name: string;
  category: string;
  description: string;
  rule: Partial<WAFRule>;
}

interface RuleTestResult {
  success: boolean;
  match: boolean;
  action: string;
  error?: string;
}

const WAFRules: React.FC = () => {
  const [rules, setRules] = useState<WAFRule[]>([]);
  const [templates, setTemplates] = useState<WAFTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [editingRule, setEditingRule] = useState<Partial<WAFRule> | null>(null);
  const [testPattern, setTestPattern] = useState('');
  const [testURL, setTestURL] = useState('');
  const [testResult, setTestResult] = useState<RuleTestResult | null>(null);
  const [testing, setTesting] = useState(false);
  const toast = useToast();

  const {
    isOpen: isRuleModalOpen,
    onOpen: onRuleModalOpen,
    onClose: onRuleModalClose,
  } = useDisclosure();

  const {
    isOpen: isTemplateModalOpen,
    onOpen: onTemplateModalOpen,
    onClose: onTemplateModalClose,
  } = useDisclosure();

  const fetchRules = async () => {
    try {
      const response = await axios.get('/api/waf/rules');
      setRules(response.data.rules || []);
    } catch (error) {
      toast({
        title: '加载失败',
        description: '无法加载 WAF 规则',
        status: 'error',
        duration: 3000,
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchTemplates = async () => {
    try {
      const response = await axios.get('/api/waf/templates');
      setTemplates(response.data.templates || []);
    } catch (error) {
      console.error('Failed to fetch templates:', error);
    }
  };

  useEffect(() => {
    fetchRules();
    fetchTemplates();
  }, []);

  const handleSaveRule = async () => {
    try {
      if (editingRule?.id) {
        await axios.put(`/api/waf/rules/${editingRule.id}`, editingRule);
        toast({
          title: '成功',
          description: '规则已更新',
          status: 'success',
          duration: 3000,
        });
      } else {
        await axios.post('/api/waf/rules', editingRule);
        toast({
          title: '成功',
          description: '规则已创建',
          status: 'success',
          duration: 3000,
        });
      }
      await fetchRules();
      onRuleModalClose();
      setEditingRule(null);
    } catch (error) {
      toast({
        title: '操作失败',
        description: '无法保存规则',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleToggleRule = async (ruleId: string, enabled: boolean) => {
    try {
      await axios.patch(`/api/waf/rules/${ruleId}`, { enabled });
      await fetchRules();
      toast({
        title: '成功',
        description: `规则已${enabled ? '启用' : '禁用'}`,
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: '操作失败',
        description: '无法更新规则',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleDeleteRule = async (ruleId: string) => {
    if (!confirm('确定要删除此规则吗？')) {
      return;
    }
    try {
      await axios.delete(`/api/waf/rules/${ruleId}`);
      await fetchRules();
      toast({
        title: '成功',
        description: '规则已删除',
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: '操作失败',
        description: '无法删除规则',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleDuplicateRule = async (rule: WAFRule) => {
    const newRule = {
      ...rule,
      id: undefined,
      name: `${rule.name} (副本)`,
    };
    try {
      await axios.post('/api/waf/rules', newRule);
      await fetchRules();
      toast({
        title: '成功',
        description: '规则已复制',
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: '操作失败',
        description: '无法复制规则',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleTestRule = async () => {
    if (!testPattern || !testURL) {
      toast({
        title: '请输入测试数据',
        status: 'warning',
        duration: 3000,
      });
      return;
    }

    setTesting(true);
    try {
      const response = await axios.post('/api/waf/test', {
        pattern: testPattern,
        url: testURL,
      });
      setTestResult(response.data);
    } catch (error) {
      setTestResult({
        success: false,
        match: false,
        action: 'none',
        error: '测试失败',
      });
    } finally {
      setTesting(false);
    }
  };

  const handleApplyTemplate = async (template: WAFTemplate) => {
    setEditingRule({
      ...template.rule,
      name: `${template.rule.name}`,
      description: template.rule.description,
    });
    onTemplateModalClose();
    onRuleModalOpen();
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
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

  const getActionColor = (action: string) => {
    switch (action) {
      case 'block':
        return 'red';
      case 'allow':
        return 'green';
      case 'log':
        return 'blue';
      default:
        return 'gray';
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
              WAF 规则管理
            </Heading>
            <Text color="gray.500" mt={2}>
              管理和测试 Web 应用防火墙规则
            </Text>
          </Box>
          <HStack spacing={2}>
            <Button
              leftIcon={<FiCode />}
              variant="outline"
              onClick={onTemplateModalOpen}
            >
              规则模板
            </Button>
            <Button
              leftIcon={<FiPlus />}
              colorScheme="blue"
              onClick={() => {
                setEditingRule({
                  enabled: true,
                  rule_type: 'regex',
                  action: 'block',
                  severity: 'medium',
                  params: [],
                  tags: [],
                });
                onRuleModalOpen();
              }}
            >
              新建规则
            </Button>
          </HStack>
        </Box>

        {/* Stats */}
        <SimpleGrid columns={{ base: 1, md: 4 }} spacing={4}>
          <Card>
            <CardBody>
              <HStack spacing={4}>
                <Box color="blue.500" fontSize="3xl">
                  <FiShield />
                </Box>
                <Box>
                  <Text fontSize="sm" color="gray.500">
                    总规则数
                  </Text>
                  <Text fontSize="2xl" fontWeight="bold">
                    {rules.length}
                  </Text>
                </Box>
              </HStack>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <HStack spacing={4}>
                <Box color="green.500" fontSize="3xl">
                  <FiCheck />
                </Box>
                <Box>
                  <Text fontSize="sm" color="gray.500">
                    启用规则
                  </Text>
                  <Text fontSize="2xl" fontWeight="bold">
                    {rules.filter((r) => r.enabled).length}
                  </Text>
                </Box>
              </HStack>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <HStack spacing={4}>
                <Box color="red.500" fontSize="3xl">
                  <FiX />
                </Box>
                <Box>
                  <Text fontSize="sm" color="gray.500">
                    禁用规则
                  </Text>
                  <Text fontSize="2xl" fontWeight="bold">
                    {rules.filter((r) => !r.enabled).length}
                  </Text>
                </Box>
              </HStack>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <HStack spacing={4}>
                <Box color="orange.500" fontSize="3xl">
                  <FiEye />
                </Box>
                <Box>
                  <Text fontSize="sm" color="gray.500">
                    仅日志规则
                  </Text>
                  <Text fontSize="2xl" fontWeight="bold">
                    {rules.filter((r) => r.action === 'log').length}
                  </Text>
                </Box>
              </HStack>
            </CardBody>
          </Card>
        </SimpleGrid>

        {/* Rules Table */}
        <Card>
          <CardHeader>
            <Heading size="md">规则列表</Heading>
          </CardHeader>
          <CardBody>
            <Table variant="simple">
              <Thead>
                <Tr>
                  <Th>规则名称</Th>
                  <Th>类型</Th>
                  <Th>模式</Th>
                  <Th>严重性</Th>
                  <Th>动作</Th>
                  <Th>状态</Th>
                  <Th>操作</Th>
                </Tr>
              </Thead>
              <Tbody>
                {rules.map((rule) => (
                  <Tr key={rule.id}>
                    <Td>
                      <VStack align="start" spacing={1}>
                        <Text fontWeight="bold">{rule.name}</Text>
                        <Text fontSize="xs" color="gray.500">
                          {rule.description}
                        </Text>
                      </VStack>
                    </Td>
                    <Td>
                      <Badge colorScheme="blue">{rule.rule_type}</Badge>
                    </Td>
                    <Td>
                      <Code fontSize="xs" maxW="200px" noOfLines={1}>
                        {rule.pattern}
                      </Code>
                    </Td>
                    <Td>
                      <Badge colorScheme={getSeverityColor(rule.severity)}>
                        {rule.severity}
                      </Badge>
                    </Td>
                    <Td>
                      <Badge colorScheme={getActionColor(rule.action)}>
                        {rule.action}
                      </Badge>
                    </Td>
                    <Td>
                      <Switch
                        size="sm"
                        isChecked={rule.enabled}
                        onChange={() => handleToggleRule(rule.id, !rule.enabled)}
                      />
                    </Td>
                    <Td>
                      <HStack spacing={1}>
                        <IconButton
                          aria-label="编辑"
                          icon={<FiEdit />}
                          size="xs"
                          onClick={() => {
                            setEditingRule(rule);
                            onRuleModalOpen();
                          }}
                        />
                        <IconButton
                          aria-label="复制"
                          icon={<FiCopy />}
                          size="xs"
                          onClick={() => handleDuplicateRule(rule)}
                        />
                        <IconButton
                          aria-label="删除"
                          icon={<FiTrash2 />}
                          size="xs"
                          colorScheme="red"
                          onClick={() => handleDeleteRule(rule.id)}
                        />
                      </HStack>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </CardBody>
        </Card>

        {/* Rule Testing */}
        <Card>
          <CardHeader>
            <Heading size="md">规则测试</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <HStack spacing={4}>
                <FormControl flex={1}>
                  <FormLabel>测试模式</FormLabel>
                  <Input
                    placeholder="输入正则表达式或模式"
                    value={testPattern}
                    onChange={(e) => setTestPattern(e.target.value)}
                  />
                </FormControl>
                <FormControl flex={1}>
                  <FormLabel>测试 URL</FormLabel>
                  <Input
                    placeholder="输入要测试的 URL"
                    value={testURL}
                    onChange={(e) => setTestURL(e.target.value)}
                  />
                </FormControl>
                <Button
                  leftIcon={<FiPlay />}
                  colorScheme="blue"
                  onClick={handleTestRule}
                  isLoading={testing}
                  alignSelf="flex-end"
                >
                  测试
                </Button>
              </HStack>

              {testResult && (
                <Alert
                  status={testResult.match ? 'warning' : 'success'}
                  variant="subtle"
                >
                  <AlertIcon />
                  <Box>
                    <Text fontWeight="bold">
                      {testResult.match ? '匹配成功' : '未匹配'}
                    </Text>
                    <Text fontSize="sm">
                      动作: {testResult.action}
                      {testResult.error && ` | 错误: ${testResult.error}`}
                    </Text>
                  </Box>
                </Alert>
              )}
            </VStack>
          </CardBody>
        </Card>
      </VStack>

      {/* Edit/Create Rule Modal */}
      <Modal size="xl" isOpen={isRuleModalOpen} onClose={onRuleModalClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>
            {editingRule?.id ? '编辑规则' : '创建规则'}
          </ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4} align="stretch">
              <FormControl isRequired>
                <FormLabel>规则名称</FormLabel>
                <Input
                  value={editingRule?.name || ''}
                  onChange={(e) =>
                    setEditingRule({ ...editingRule, name: e.target.value })
                  }
                  placeholder="输入规则名称"
                />
              </FormControl>

              <FormControl>
                <FormLabel>描述</FormLabel>
                <Textarea
                  value={editingRule?.description || ''}
                  onChange={(e) =>
                    setEditingRule({ ...editingRule, description: e.target.value })
                  }
                  placeholder="输入规则描述"
                />
              </FormControl>

              <HStack spacing={4}>
                <FormControl>
                  <FormLabel>规则类型</FormLabel>
                  <Select
                    value={editingRule?.rule_type || 'regex'}
                    onChange={(e) =>
                      setEditingRule({ ...editingRule, rule_type: e.target.value })
                    }
                  >
                    <option value="regex">正则表达式</option>
                    <option value="string">字符串匹配</option>
                    <option value="size">大小限制</option>
                    <option value="logical">逻辑组合</option>
                  </Select>
                </FormControl>

                <FormControl>
                  <FormLabel>动作</FormLabel>
                  <Select
                    value={editingRule?.action || 'block'}
                    onChange={(e) =>
                      setEditingRule({ ...editingRule, action: e.target.value })
                    }
                  >
                    <option value="block">阻止</option>
                    <option value="allow">允许</option>
                    <option value="log">仅记录</option>
                    <option value="redirect">重定向</option>
                  </Select>
                </FormControl>

                <FormControl>
                  <FormLabel>严重性</FormLabel>
                  <Select
                    value={editingRule?.severity || 'medium'}
                    onChange={(e) =>
                      setEditingRule({ ...editingRule, severity: e.target.value })
                    }
                  >
                    <option value="critical">严重</option>
                    <option value="high">高</option>
                    <option value="medium">中</option>
                    <option value="low">低</option>
                  </Select>
                </FormControl>
              </HStack>

              <FormControl isRequired>
                <FormLabel>匹配模式</FormLabel>
                <Input
                  value={editingRule?.pattern || ''}
                  onChange={(e) =>
                    setEditingRule({ ...editingRule, pattern: e.target.value })
                  }
                  placeholder="输入匹配模式或正则表达式"
                />
              </FormControl>

              <FormControl>
                <FormLabel>应用参数</FormLabel>
                <Input
                  value={editingRule?.params?.join(', ') || ''}
                  onChange={(e) =>
                    setEditingRule({
                      ...editingRule,
                      params: e.target.value.split(',').map((s) => s.trim()),
                    })
                  }
                  placeholder="逗号分隔的参数列表，如: query, body, headers"
                />
              </FormControl>

              <FormControl display="flex" alignItems="center">
                <Switch
                  isChecked={editingRule?.enabled ?? true}
                  onChange={(e) =>
                    setEditingRule({ ...editingRule, enabled: e.target.checked })
                  }
                />
                <FormLabel mb="0" ml={3}>
                  启用规则
                </FormLabel>
              </FormControl>
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button onClick={onRuleModalClose}>取消</Button>
            <Button
              leftIcon={<FiSave />}
              colorScheme="blue"
              onClick={handleSaveRule}
              ml={3}
            >
              保存
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* Template Modal */}
      <Modal size="xl" isOpen={isTemplateModalOpen} onClose={onTemplateModalClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>WAF 规则模板库</ModalHeader>
          <ModalCloseButton />
          <ModalBody pb={6}>
            <VStack spacing={4} align="stretch">
              {templates.map((template) => (
                <Card key={template.id} variant="outline">
                  <CardBody>
                    <HStack justify="space-between" mb={2}>
                      <Heading size="sm">{template.name}</Heading>
                      <Badge colorScheme="blue">{template.category}</Badge>
                    </HStack>
                    <Text fontSize="sm" color="gray.600" mb={3}>
                      {template.description}
                    </Text>
                    <HStack spacing={2}>
                      <Button
                        size="sm"
                        leftIcon={<FiPlus />}
                        onClick={() => handleApplyTemplate(template)}
                      >
                        应用模板
                      </Button>
                      <Button size="sm" variant="outline" leftIcon={<FiEye />}>
                        查看详情
                      </Button>
                    </HStack>
                  </CardBody>
                </Card>
              ))}
            </VStack>
          </ModalBody>
        </ModalContent>
      </Modal>
    </Container>
  );
};

export default WAFRules;

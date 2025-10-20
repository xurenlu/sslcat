import React, { useState } from 'react'
import { PathPrefixRule, ProxyBackend } from '../types/config'
import {
  Box,
  Heading,
  FormControl,
  FormLabel,
  Input,
  Switch,
  Select,
  Button,
  VStack,
  HStack,
  Icon,
  Text,
  Divider,
  SimpleGrid,
  Card,
  CardBody,
  Badge,
  IconButton,
  Alert,
  AlertIcon,
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  NumberIncrementStepper,
  NumberDecrementStepper,
  Textarea,
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
  useDisclosure,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
} from '@chakra-ui/react'
import { 
  FiPlus, 
  FiTrash2, 
  FiServer, 
  FiActivity, 
  FiSettings,
  FiShield,
  FiClock,
  FiEdit,
  FiChevronDown,
  FiChevronUp
} from 'react-icons/fi'


interface PathPrefixRulesConfigProps {
  pathPrefixRules: PathPrefixRule[]
  onChange: (rules: PathPrefixRule[]) => void
}

const PathPrefixRulesConfig: React.FC<PathPrefixRulesConfigProps> = ({
  pathPrefixRules,
  onChange
}) => {
  const [editingRule, setEditingRule] = useState<PathPrefixRule | null>(null)
  const [editingIndex, setEditingIndex] = useState<number>(-1)
  const { isOpen, onOpen, onClose } = useDisclosure()

  // 添加新规则
  const addRule = () => {
    const newRule: PathPrefixRule = {
      name: '',
      description: '',
      enabled: true,
      prefixes: [''],
      exact: false,
      backends: [
        {
          id: `backend_${Date.now()}`,
          host: '',
          port: 8080,
          weight: 1,
          priority: 0,
          enabled: true,
          health_check_enabled: false,
          health_check_path: '/health',
          health_check_interval: 30,
          health_check_timeout: 5,
          health_check_method: 'GET',
          expected_status_code: 200,
          max_retries: 3,
          retry_interval: 1,
          failure_threshold: 3,
          recovery_threshold: 2,
          connect_timeout: 30,
          read_timeout: 30,
          write_timeout: 30,
          keep_alive_timeout: 30,
          max_connections: 100,
          tls_enabled: false,
          tls_insecure: false
        }
      ],
      load_balancer_algorithm: 'round_robin',
      session_affinity_enabled: false,
      session_affinity_method: 'ip',
      session_affinity_cookie: '',
      session_affinity_header: '',
      session_affinity_ttl: 3600,
      health_check_enabled: false,
      health_check_path: '/health',
      health_check_interval: 30,
      health_check_timeout: 5,
      health_check_method: 'GET',
      expected_status_code: 200,
      failover_enabled: true,
      max_retries: 3,
      retry_interval: 1,
      failure_threshold: 3,
      recovery_threshold: 2
    }
    
    setEditingRule(newRule)
    setEditingIndex(-1)
    onOpen()
  }

  // 编辑规则
  const editRule = (index: number) => {
    setEditingRule({ ...pathPrefixRules[index] })
    setEditingIndex(index)
    onOpen()
  }

  // 删除规则
  const deleteRule = (index: number) => {
    const newRules = pathPrefixRules.filter((_, i) => i !== index)
    onChange(newRules)
  }

  // 保存规则
  const saveRule = () => {
    if (!editingRule) return

    const newRules = [...pathPrefixRules]
    if (editingIndex === -1) {
      // 添加新规则
      newRules.push(editingRule)
    } else {
      // 更新现有规则
      newRules[editingIndex] = editingRule
    }
    
    onChange(newRules)
    onClose()
  }

  // 更新规则字段
  const updateRuleField = (field: keyof PathPrefixRule, value: any) => {
    if (!editingRule) return
    setEditingRule({ ...editingRule, [field]: value })
  }

  // 更新前缀列表
  const updatePrefixes = (index: number, value: string) => {
    if (!editingRule) return
    const newPrefixes = [...editingRule.prefixes]
    newPrefixes[index] = value
    setEditingRule({ ...editingRule, prefixes: newPrefixes })
  }

  // 添加前缀
  const addPrefix = () => {
    if (!editingRule) return
    setEditingRule({ ...editingRule, prefixes: [...editingRule.prefixes, ''] })
  }

  // 删除前缀
  const removePrefix = (index: number) => {
    if (!editingRule || editingRule.prefixes.length <= 1) return
    const newPrefixes = editingRule.prefixes.filter((_, i) => i !== index)
    setEditingRule({ ...editingRule, prefixes: newPrefixes })
  }

  // 更新后端服务器
  const updateBackend = (index: number, field: keyof ProxyBackend, value: any) => {
    if (!editingRule) return
    const newBackends = [...editingRule.backends]
    newBackends[index] = { ...newBackends[index], [field]: value }
    setEditingRule({ ...editingRule, backends: newBackends })
  }

  // 添加后端服务器
  const addBackend = () => {
    if (!editingRule) return
    const newBackend: ProxyBackend = {
      id: `backend_${Date.now()}`,
      host: '',
      port: 8080,
      weight: 1,
      priority: 0,
      enabled: true,
      health_check_enabled: false,
      health_check_path: '/health',
      health_check_interval: 30,
      health_check_timeout: 5,
      health_check_method: 'GET',
      expected_status_code: 200,
      max_retries: 3,
      retry_interval: 1,
      failure_threshold: 3,
      recovery_threshold: 2,
      connect_timeout: 30,
      read_timeout: 30,
      write_timeout: 30,
      keep_alive_timeout: 30,
      max_connections: 100,
      tls_enabled: false,
      tls_insecure: false
    }
    setEditingRule({ ...editingRule, backends: [...editingRule.backends, newBackend] })
  }

  // 删除后端服务器
  const removeBackend = (index: number) => {
    if (!editingRule || editingRule.backends.length <= 1) return
    const newBackends = editingRule.backends.filter((_, i) => i !== index)
    setEditingRule({ ...editingRule, backends: newBackends })
  }

  return (
    <Box>
      <HStack justify="space-between" align="center" mb={4}>
        <Heading size="md" color="gray.700">
          <Icon as={FiServer} mr={2} />
          路径前缀规则配置
        </Heading>
        <Button
          leftIcon={<Icon as={FiPlus} />}
          colorScheme="blue"
          size="sm"
          onClick={addRule}
        >
          添加规则
        </Button>
      </HStack>

      {pathPrefixRules.length === 0 ? (
        <Alert status="info">
          <AlertIcon />
          暂无路径前缀规则，点击"添加规则"开始配置
        </Alert>
      ) : (
        <VStack spacing={4} align="stretch">
          {pathPrefixRules.map((rule, index) => (
            <Card key={index}>
              <CardBody>
                <HStack justify="space-between" align="start" mb={3}>
                  <VStack align="start" spacing={1}>
                    <HStack>
                      <Text fontWeight="bold" fontSize="lg">{rule.name}</Text>
                      <Badge colorScheme={rule.enabled ? 'green' : 'gray'}>
                        {rule.enabled ? '启用' : '禁用'}
                      </Badge>
                    </HStack>
                    {rule.description && (
                      <Text fontSize="sm" color="gray.600">{rule.description}</Text>
                    )}
                  </VStack>
                  <HStack>
                    <IconButton
                      aria-label="编辑规则"
                      icon={<Icon as={FiEdit} />}
                      size="sm"
                      variant="outline"
                      onClick={() => editRule(index)}
                    />
                    <IconButton
                      aria-label="删除规则"
                      icon={<Icon as={FiTrash2} />}
                      size="sm"
                      variant="outline"
                      colorScheme="red"
                      onClick={() => deleteRule(index)}
                    />
                  </HStack>
                </HStack>

                <SimpleGrid columns={2} spacing={4} mb={3}>
                  <Box>
                    <Text fontSize="sm" fontWeight="medium" mb={1}>路径前缀</Text>
                    <VStack spacing={1} align="stretch">
                      {rule.prefixes.map((prefix, prefixIndex) => (
                        <HStack key={prefixIndex}>
                          <Text fontSize="sm" color="blue.600" fontFamily="mono">
                            {prefix}
                          </Text>
                        </HStack>
                      ))}
                    </VStack>
                  </Box>
                  <Box>
                    <Text fontSize="sm" fontWeight="medium" mb={1}>后端服务器</Text>
                    <VStack spacing={1} align="stretch">
                      {rule.backends.map((backend, backendIndex) => (
                        <HStack key={backendIndex}>
                          <Text fontSize="sm" color="green.600">
                            {backend.host}:{backend.port}
                          </Text>
                          <Badge size="sm" colorScheme="blue">
                            权重: {backend.weight}
                          </Badge>
                        </HStack>
                      ))}
                    </VStack>
                  </Box>
                </SimpleGrid>

                <HStack spacing={4} fontSize="sm" color="gray.600">
                  <HStack>
                    <Icon as={FiActivity} />
                    <Text>算法: {rule.load_balancer_algorithm}</Text>
                  </HStack>
                  {rule.session_affinity_enabled && (
                    <HStack>
                      <Icon as={FiShield} />
                      <Text>会话保持: {rule.session_affinity_method}</Text>
                    </HStack>
                  )}
                  {rule.health_check_enabled && (
                    <HStack>
                      <Icon as={FiClock} />
                      <Text>健康检查: {rule.health_check_path}</Text>
                    </HStack>
                  )}
                </HStack>
              </CardBody>
            </Card>
          ))}
        </VStack>
      )}

      {/* 编辑规则模态框 */}
      <Modal isOpen={isOpen} onClose={onClose} size="xl">
        <ModalOverlay />
        <ModalContent maxH="90vh" overflowY="auto">
          <ModalHeader>
            {editingIndex === -1 ? '添加路径前缀规则' : '编辑路径前缀规则'}
          </ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            {editingRule && (
              <VStack spacing={6} align="stretch">
                {/* 基本信息 */}
                <Box>
                  <Heading size="sm" mb={3} color="gray.700">基本信息</Heading>
                  <SimpleGrid columns={2} spacing={4}>
                    <FormControl>
                      <FormLabel>规则名称</FormLabel>
                      <Input
                        value={editingRule.name}
                        onChange={(e) => updateRuleField('name', e.target.value)}
                        placeholder="API v1 规则"
                      />
                    </FormControl>
                    <FormControl>
                      <FormLabel>描述</FormLabel>
                      <Input
                        value={editingRule.description}
                        onChange={(e) => updateRuleField('description', e.target.value)}
                        placeholder="API v1 路径前缀规则"
                      />
                    </FormControl>
                  </SimpleGrid>
                  <HStack mt={3}>
                    <Switch
                      isChecked={editingRule.enabled}
                      onChange={(e) => updateRuleField('enabled', e.target.checked)}
                    />
                    <Text>启用此规则</Text>
                  </HStack>
                </Box>

                <Divider />

                {/* 路径前缀配置 */}
                <Box>
                  <Heading size="sm" mb={3} color="gray.700">路径前缀配置</Heading>
                  <VStack spacing={3} align="stretch">
                    {editingRule.prefixes.map((prefix, index) => (
                      <HStack key={index}>
                        <Input
                          value={prefix}
                          onChange={(e) => updatePrefixes(index, e.target.value)}
                          placeholder="/api/v1/"
                          size="sm"
                        />
                        {editingRule.prefixes.length > 1 && (
                          <IconButton
                            aria-label="删除前缀"
                            icon={<Icon as={FiTrash2} />}
                            size="sm"
                            variant="outline"
                            colorScheme="red"
                            onClick={() => removePrefix(index)}
                          />
                        )}
                      </HStack>
                    ))}
                    <Button
                      leftIcon={<Icon as={FiPlus} />}
                      size="sm"
                      variant="outline"
                      onClick={addPrefix}
                    >
                      添加前缀
                    </Button>
                  </VStack>
                  <HStack mt={3}>
                    <Switch
                      isChecked={editingRule.exact}
                      onChange={(e) => updateRuleField('exact', e.target.checked)}
                    />
                    <Text>精确匹配路径前缀</Text>
                  </HStack>
                </Box>

                <Divider />

                {/* 后端服务器配置 */}
                <Box>
                  <Heading size="sm" mb={3} color="gray.700">后端服务器配置</Heading>
                  <VStack spacing={4} align="stretch">
                    {editingRule.backends.map((backend, index) => (
                      <Card key={index}>
                        <CardBody>
                          <HStack justify="space-between" align="center" mb={3}>
                            <Text fontWeight="medium">后端服务器 {index + 1}</Text>
                            {editingRule.backends.length > 1 && (
                              <IconButton
                                aria-label="删除后端"
                                icon={<Icon as={FiTrash2} />}
                                size="sm"
                                variant="outline"
                                colorScheme="red"
                                onClick={() => removeBackend(index)}
                              />
                            )}
                          </HStack>
                          <SimpleGrid columns={2} spacing={3}>
                            <FormControl>
                              <FormLabel>主机地址</FormLabel>
                              <Input
                                value={backend.host}
                                onChange={(e) => updateBackend(index, 'host', e.target.value)}
                                placeholder="api-server.example.com"
                                size="sm"
                              />
                            </FormControl>
                            <FormControl>
                              <FormLabel>端口</FormLabel>
                              <NumberInput
                                value={backend.port}
                                onChange={(_, value) => updateBackend(index, 'port', value)}
                                min={1}
                                max={65535}
                                size="sm"
                              >
                                <NumberInputField />
                                <NumberInputStepper>
                                  <NumberIncrementStepper />
                                  <NumberDecrementStepper />
                                </NumberInputStepper>
                              </NumberInput>
                            </FormControl>
                            <FormControl>
                              <FormLabel>权重</FormLabel>
                              <NumberInput
                                value={backend.weight}
                                onChange={(_, value) => updateBackend(index, 'weight', value)}
                                min={1}
                                max={100}
                                size="sm"
                              >
                                <NumberInputField />
                                <NumberInputStepper>
                                  <NumberIncrementStepper />
                                  <NumberDecrementStepper />
                                </NumberInputStepper>
                              </NumberInput>
                            </FormControl>
                            <FormControl>
                              <FormLabel>优先级</FormLabel>
                              <NumberInput
                                value={backend.priority}
                                onChange={(_, value) => updateBackend(index, 'priority', value)}
                                min={0}
                                max={100}
                                size="sm"
                              >
                                <NumberInputField />
                                <NumberInputStepper>
                                  <NumberIncrementStepper />
                                  <NumberDecrementStepper />
                                </NumberInputStepper>
                              </NumberInput>
                            </FormControl>
                          </SimpleGrid>
                          <HStack mt={3}>
                            <Switch
                              isChecked={backend.enabled}
                              onChange={(e) => updateBackend(index, 'enabled', e.target.checked)}
                            />
                            <Text>启用此后端</Text>
                          </HStack>
                        </CardBody>
                      </Card>
                    ))}
                    <Button
                      leftIcon={<Icon as={FiPlus} />}
                      size="sm"
                      variant="outline"
                      onClick={addBackend}
                    >
                      添加后端服务器
                    </Button>
                  </VStack>
                </Box>

                <Divider />

                {/* 负载均衡配置 */}
                <Box>
                  <Heading size="sm" mb={3} color="gray.700">负载均衡配置</Heading>
                  <SimpleGrid columns={2} spacing={4}>
                    <FormControl>
                      <FormLabel>负载均衡算法</FormLabel>
                      <Select
                        value={editingRule.load_balancer_algorithm}
                        onChange={(e) => updateRuleField('load_balancer_algorithm', e.target.value)}
                        size="sm"
                      >
                        <option value="round_robin">轮询</option>
                        <option value="weighted_round_robin">加权轮询</option>
                        <option value="least_conn">最少连接</option>
                        <option value="ip_hash">IP哈希</option>
                        <option value="random">随机</option>
                        <option value="consistent_hash">一致性哈希</option>
                      </Select>
                    </FormControl>
                    <FormControl>
                      <FormLabel>会话保持方法</FormLabel>
                      <Select
                        value={editingRule.session_affinity_method}
                        onChange={(e) => updateRuleField('session_affinity_method', e.target.value)}
                        size="sm"
                      >
                        <option value="ip">IP地址</option>
                        <option value="cookie">Cookie</option>
                        <option value="header">Header</option>
                      </Select>
                    </FormControl>
                  </SimpleGrid>
                  <HStack mt={3}>
                    <Switch
                      isChecked={editingRule.session_affinity_enabled}
                      onChange={(e) => updateRuleField('session_affinity_enabled', e.target.checked)}
                    />
                    <Text>启用会话保持</Text>
                  </HStack>
                </Box>
              </VStack>
            )}
          </ModalBody>
          <ModalFooter>
            <Button variant="outline" mr={3} onClick={onClose}>
              取消
            </Button>
            <Button colorScheme="blue" onClick={saveRule}>
              保存
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default PathPrefixRulesConfig

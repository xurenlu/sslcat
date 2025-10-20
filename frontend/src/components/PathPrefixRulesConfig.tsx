import React, { useState } from 'react'
import { PathPrefixRule, ProxyBackend } from '../types/config'
import { useTranslation } from '../hooks/useLanguage'
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
  const t = useTranslation()
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
          {t.pathPrefixRules.title}
        </Heading>
        <Button
          leftIcon={<Icon as={FiPlus} />}
          colorScheme="blue"
          size="sm"
          onClick={addRule}
        >
          {t.pathPrefixRules.addRule}
        </Button>
      </HStack>

      {pathPrefixRules.length === 0 ? (
        <Alert status="info">
          <AlertIcon />
          {t.pathPrefixRules.noRulesMessage}
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
                        {rule.enabled ? t.pathPrefixRules.enabled : t.pathPrefixRules.disabled}
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
                    <Text fontSize="sm" fontWeight="medium" mb={1}>{t.pathPrefixRules.pathPrefix}</Text>
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
                    <Text fontSize="sm" fontWeight="medium" mb={1}>{t.pathPrefixRules.backendServer}</Text>
                    <VStack spacing={1} align="stretch">
                      {rule.backends.map((backend, backendIndex) => (
                        <HStack key={backendIndex}>
                          <Text fontSize="sm" color="green.600">
                            {backend.host}:{backend.port}
                          </Text>
                          <Badge size="sm" colorScheme="blue">
                            {t.pathPrefixRules.weightLabel}: {backend.weight}
                          </Badge>
                        </HStack>
                      ))}
                    </VStack>
                  </Box>
                </SimpleGrid>

                <HStack spacing={4} fontSize="sm" color="gray.600">
                  <HStack>
                    <Icon as={FiActivity} />
                    <Text>{t.pathPrefixRules.algorithm}: {rule.load_balancer_algorithm}</Text>
                  </HStack>
                  {rule.session_affinity_enabled && (
                    <HStack>
                      <Icon as={FiShield} />
                      <Text>{t.pathPrefixRules.sessionAffinity}: {rule.session_affinity_method}</Text>
                    </HStack>
                  )}
                  {rule.health_check_enabled && (
                    <HStack>
                      <Icon as={FiClock} />
                      <Text>{t.pathPrefixRules.healthCheck}: {rule.health_check_path}</Text>
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
            {editingIndex === -1 ? t.pathPrefixRules.addRule : t.pathPrefixRules.editRule}
          </ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            {editingRule && (
              <VStack spacing={6} align="stretch">
                {/* 基本信息 */}
                <Box>
                  <Heading size="sm" mb={3} color="gray.700">{t.pathPrefixRules.basicInfo}</Heading>
                  <SimpleGrid columns={2} spacing={4}>
                    <FormControl>
                      <FormLabel>{t.pathPrefixRules.ruleName}</FormLabel>
                      <Input
                        value={editingRule.name}
                        onChange={(e) => updateRuleField('name', e.target.value)}
                        placeholder={t.pathPrefixRules.ruleNamePlaceholder}
                      />
                    </FormControl>
                    <FormControl>
                      <FormLabel>{t.pathPrefixRules.description}</FormLabel>
                      <Input
                        value={editingRule.description}
                        onChange={(e) => updateRuleField('description', e.target.value)}
                        placeholder={t.pathPrefixRules.descriptionPlaceholder}
                      />
                    </FormControl>
                  </SimpleGrid>
                  <HStack mt={3}>
                    <Switch
                      isChecked={editingRule.enabled}
                      onChange={(e) => updateRuleField('enabled', e.target.checked)}
                    />
                    <Text>{t.pathPrefixRules.enableRule}</Text>
                  </HStack>
                </Box>

                <Divider />

                {/* 路径前缀配置 */}
                <Box>
                  <Heading size="sm" mb={3} color="gray.700">{t.pathPrefixRules.pathPrefixConfig}</Heading>
                  <VStack spacing={3} align="stretch">
                    {editingRule.prefixes.map((prefix, index) => (
                      <HStack key={index}>
                        <Input
                          value={prefix}
                          onChange={(e) => updatePrefixes(index, e.target.value)}
                          placeholder={t.pathPrefixRules.pathPrefixPlaceholder}
                          size="sm"
                        />
                        {editingRule.prefixes.length > 1 && (
                          <IconButton
                            aria-label={t.pathPrefixRules.deleteRule}
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
                      {t.pathPrefixRules.addPrefix}
                    </Button>
                  </VStack>
                  <HStack mt={3}>
                    <Switch
                      isChecked={editingRule.exact}
                      onChange={(e) => updateRuleField('exact', e.target.checked)}
                    />
                    <Text>{t.pathPrefixRules.exactMatch}</Text>
                  </HStack>
                </Box>

                <Divider />

                {/* 后端服务器配置 */}
                <Box>
                  <Heading size="sm" mb={3} color="gray.700">{t.pathPrefixRules.backendConfig}</Heading>
                  <VStack spacing={4} align="stretch">
                    {editingRule.backends.map((backend, index) => (
                      <Card key={index}>
                        <CardBody>
                          <HStack justify="space-between" align="center" mb={3}>
                            <Text fontWeight="medium">{t.pathPrefixRules.backendServerNumber.replace('{number}', (index + 1).toString())}</Text>
                            {editingRule.backends.length > 1 && (
                              <IconButton
                                aria-label={t.pathPrefixRules.deleteRule}
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
                              <FormLabel>{t.pathPrefixRules.hostAddress}</FormLabel>
                              <Input
                                value={backend.host}
                                onChange={(e) => updateBackend(index, 'host', e.target.value)}
                                placeholder={t.pathPrefixRules.hostAddressPlaceholder}
                                size="sm"
                              />
                            </FormControl>
                            <FormControl>
                              <FormLabel>{t.pathPrefixRules.port}</FormLabel>
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
                              <FormLabel>{t.pathPrefixRules.weight}</FormLabel>
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
                              <FormLabel>{t.pathPrefixRules.priority}</FormLabel>
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
                            <Text>{t.pathPrefixRules.enableBackend}</Text>
                          </HStack>

                          {/* 后端级 健康检查配置 */}
                          <Divider mt={4} mb={3} />
                          <Heading size="xs" mb={2} color="gray.700">{t.pathPrefixRules.backendHealthCheck}</Heading>
                          <VStack spacing={3} align="stretch">
                            <FormControl display="flex" alignItems="center">
                              <FormLabel htmlFor={`backend-health-enabled-${index}`} mb="0">{t.pathPrefixRules.enableHealthCheck}</FormLabel>
                              <Switch
                                id={`backend-health-enabled-${index}`}
                                isChecked={backend.health_check_enabled}
                                onChange={(e) => updateBackend(index, 'health_check_enabled', e.target.checked)}
                              />
                            </FormControl>

                            {backend.health_check_enabled && (
                              <SimpleGrid columns={2} spacing={3}>
                                <FormControl>
                                  <FormLabel>{t.pathPrefixRules.checkPath}</FormLabel>
                                  <Input
                                    value={backend.health_check_path}
                                    onChange={(e) => updateBackend(index, 'health_check_path', e.target.value)}
                                    placeholder={t.pathPrefixRules.checkPathPlaceholder}
                                    size="sm"
                                  />
                                </FormControl>

                                <FormControl>
                                  <FormLabel>{t.pathPrefixRules.checkMethod}</FormLabel>
                                  <Select
                                    value={backend.health_check_method}
                                    onChange={(e) => updateBackend(index, 'health_check_method', e.target.value as any)}
                                    size="sm"
                                  >
                                    <option value="GET">{t.pathPrefixRules.get}</option>
                                    <option value="HEAD">{t.pathPrefixRules.head}</option>
                                    <option value="POST">{t.pathPrefixRules.post}</option>
                                  </Select>
                                </FormControl>

                                <FormControl>
                                  <FormLabel>{t.pathPrefixRules.checkInterval}</FormLabel>
                                  <NumberInput
                                    value={backend.health_check_interval}
                                    onChange={(_, value) => updateBackend(index, 'health_check_interval', value)}
                                    min={5}
                                    max={300}
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
                                  <FormLabel>{t.pathPrefixRules.timeout}</FormLabel>
                                  <NumberInput
                                    value={backend.health_check_timeout}
                                    onChange={(_, value) => updateBackend(index, 'health_check_timeout', value)}
                                    min={1}
                                    max={30}
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
                                  <FormLabel>{t.pathPrefixRules.expectedStatusCode}</FormLabel>
                                  <NumberInput
                                    value={backend.expected_status_code}
                                    onChange={(_, value) => updateBackend(index, 'expected_status_code', value)}
                                    min={200}
                                    max={599}
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
                            )}
                          </VStack>
                        </CardBody>
                      </Card>
                    ))}
                    <Button
                      leftIcon={<Icon as={FiPlus} />}
                      size="sm"
                      variant="outline"
                      onClick={addBackend}
                    >
                      {t.pathPrefixRules.addBackendServer}
                    </Button>
                  </VStack>
                </Box>

                <Divider />

                {/* 负载均衡配置 */}
                <Box>
                  <Heading size="sm" mb={3} color="gray.700">{t.pathPrefixRules.loadBalancerConfig}</Heading>
                  <SimpleGrid columns={2} spacing={4}>
                    <FormControl>
                      <FormLabel>{t.pathPrefixRules.loadBalancerAlgorithm}</FormLabel>
                      <Select
                        value={editingRule.load_balancer_algorithm}
                        onChange={(e) => updateRuleField('load_balancer_algorithm', e.target.value)}
                        size="sm"
                      >
                        <option value="round_robin">{t.pathPrefixRules.roundRobin}</option>
                        <option value="weighted_round_robin">{t.pathPrefixRules.weightedRoundRobin}</option>
                        <option value="least_conn">{t.pathPrefixRules.leastConn}</option>
                        <option value="ip_hash">{t.pathPrefixRules.ipHash}</option>
                        <option value="random">{t.pathPrefixRules.random}</option>
                        <option value="consistent_hash">{t.pathPrefixRules.consistentHash}</option>
                      </Select>
                    </FormControl>
                    <FormControl>
                      <FormLabel>{t.pathPrefixRules.sessionAffinityMethod}</FormLabel>
                      <Select
                        value={editingRule.session_affinity_method}
                        onChange={(e) => updateRuleField('session_affinity_method', e.target.value)}
                        size="sm"
                      >
                        <option value="ip">{t.pathPrefixRules.ipAddress}</option>
                        <option value="cookie">{t.pathPrefixRules.cookie}</option>
                        <option value="header">{t.pathPrefixRules.header}</option>
                      </Select>
                    </FormControl>
                  </SimpleGrid>
                  <HStack mt={3}>
                    <Switch
                      isChecked={editingRule.session_affinity_enabled}
                      onChange={(e) => updateRuleField('session_affinity_enabled', e.target.checked)}
                    />
                    <Text>{t.pathPrefixRules.enableSessionAffinity}</Text>
                  </HStack>
                </Box>

                <Divider />

                {/* 规则级 健康检查配置 */}
                <Box>
                  <Heading size="sm" mb={3} color="gray.700">{t.pathPrefixRules.ruleHealthCheckTitle}</Heading>
                  <VStack spacing={4} align="stretch">
                    <FormControl display="flex" alignItems="center">
                      <FormLabel htmlFor="rule-health-check" mb="0">{t.pathPrefixRules.enableHealthCheck}</FormLabel>
                      <Switch
                        id="rule-health-check"
                        isChecked={editingRule.health_check_enabled}
                        onChange={(e) => updateRuleField('health_check_enabled', e.target.checked)}
                      />
                    </FormControl>

                    {editingRule.health_check_enabled && (
                      <SimpleGrid columns={2} spacing={4}>
                        <FormControl>
                          <FormLabel>{t.pathPrefixRules.checkPath}</FormLabel>
                          <Input
                            value={editingRule.health_check_path}
                            onChange={(e) => updateRuleField('health_check_path', e.target.value)}
                            placeholder={t.pathPrefixRules.checkPathPlaceholder}
                            size="sm"
                          />
                        </FormControl>

                        <FormControl>
                          <FormLabel>{t.pathPrefixRules.checkMethod}</FormLabel>
                          <Select
                            value={editingRule.health_check_method}
                            onChange={(e) => updateRuleField('health_check_method', e.target.value)}
                            size="sm"
                          >
                            <option value="GET">{t.pathPrefixRules.get}</option>
                            <option value="HEAD">{t.pathPrefixRules.head}</option>
                            <option value="POST">{t.pathPrefixRules.post}</option>
                          </Select>
                        </FormControl>

                        <FormControl>
                          <FormLabel>{t.pathPrefixRules.checkInterval}</FormLabel>
                          <NumberInput
                            value={editingRule.health_check_interval}
                            onChange={(_, value) => updateRuleField('health_check_interval', value)}
                            min={5}
                            max={300}
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
                          <FormLabel>{t.pathPrefixRules.timeout}</FormLabel>
                          <NumberInput
                            value={editingRule.health_check_timeout}
                            onChange={(_, value) => updateRuleField('health_check_timeout', value)}
                            min={1}
                            max={30}
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
                          <FormLabel>{t.pathPrefixRules.expectedStatusCode}</FormLabel>
                          <NumberInput
                            value={editingRule.expected_status_code}
                            onChange={(_, value) => updateRuleField('expected_status_code', value)}
                            min={200}
                            max={599}
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
                    )}
                  </VStack>
                </Box>
              </VStack>
            )}
          </ModalBody>
          <ModalFooter>
            <Button variant="outline" mr={3} onClick={onClose}>
              {t.common.cancel}
            </Button>
            <Button colorScheme="blue" onClick={saveRule}>
              {t.common.save}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default PathPrefixRulesConfig

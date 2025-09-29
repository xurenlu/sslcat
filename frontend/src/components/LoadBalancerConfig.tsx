import React from 'react'
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
} from '@chakra-ui/react'
import { 
  FiPlus, 
  FiTrash2, 
  FiServer, 
  FiActivity, 
  FiSettings,
  FiShield,
  FiClock
} from 'react-icons/fi'

interface ProxyBackend {
  id: string
  host: string
  port: number
  weight: number
  enabled: boolean
  health_check_enabled: boolean
  health_check_path: string
  health_check_method: string
  expected_status_code: number
  max_connections: number
  tls_enabled: boolean
  tls_insecure: boolean
}

interface LoadBalancerConfigProps {
  // 负载均衡配置
  load_balancer_enabled: boolean
  load_balancer_algorithm: string
  load_balancer_backends: ProxyBackend[]
  
  // 会话保持配置
  session_affinity_enabled: boolean
  session_affinity_method: string
  session_affinity_cookie: string
  session_affinity_header: string
  session_affinity_ttl: number
  
  // 健康检查配置
  health_check_enabled: boolean
  health_check_path: string
  health_check_interval: number
  health_check_timeout: number
  health_check_method: string
  expected_status_code: number
  
  // 故障转移配置
  failover_enabled: boolean
  max_retries: number
  retry_interval: number
  failure_threshold: number
  recovery_threshold: number
  
  // 事件处理函数
  onFieldChange: (field: string, value: any) => void
  onBackendChange: (index: number, field: string, value: any) => void
  onAddBackend: () => void
  onRemoveBackend: (index: number) => void
}

const LoadBalancerConfig: React.FC<LoadBalancerConfigProps> = ({
  load_balancer_enabled,
  load_balancer_algorithm,
  load_balancer_backends,
  session_affinity_enabled,
  session_affinity_method,
  session_affinity_cookie,
  session_affinity_header,
  session_affinity_ttl,
  health_check_enabled,
  health_check_path,
  health_check_interval,
  health_check_timeout,
  health_check_method,
  expected_status_code,
  failover_enabled,
  max_retries,
  retry_interval,
  failure_threshold,
  recovery_threshold,
  onFieldChange,
  onBackendChange,
  onAddBackend,
  onRemoveBackend
}) => {
  const algorithmOptions = [
    { value: 'round_robin', label: '轮询 (Round Robin)' },
    { value: 'weighted_round_robin', label: '加权轮询 (Weighted Round Robin)' },
    { value: 'least_conn', label: '最少连接 (Least Connections)' },
    { value: 'ip_hash', label: 'IP哈希 (IP Hash)' },
    { value: 'random', label: '随机 (Random)' },
    { value: 'consistent_hash', label: '一致性哈希 (Consistent Hash)' }
  ]

  const methodOptions = [
    { value: 'GET', label: 'GET' },
    { value: 'HEAD', label: 'HEAD' },
    { value: 'POST', label: 'POST' }
  ]

  const affinityMethods = [
    { value: 'ip', label: 'IP地址' },
    { value: 'cookie', label: 'Cookie' },
    { value: 'header', label: 'HTTP头部' }
  ]

  return (
    <Box>
      {/* 负载均衡开关 */}
      <Box mb={6}>
        <Heading size="md" mb={4} display="flex" alignItems="center">
          <Icon as={FiServer} mr={2} />
          负载均衡配置
        </Heading>
        
        <FormControl display="flex" alignItems="center">
          <FormLabel htmlFor="load-balancer-switch" mb="0">
            启用负载均衡
          </FormLabel>
          <Switch
            id="load-balancer-switch"
            isChecked={load_balancer_enabled}
            onChange={(e) => onFieldChange('load_balancer_enabled', e.target.checked)}
          />
        </FormControl>
        
        <Text fontSize="sm" color="gray.500" mt={2}>
          启用后可以将请求分发到多个后端服务器，提高可用性和性能
        </Text>
        <Text fontSize="sm" color="blue.500" mt={1} fontWeight="medium">
          ⚠️ 启用负载均衡后，上方的"目标地址"字段将被忽略，系统将使用下方配置的后端服务器列表
        </Text>
      </Box>

      {load_balancer_enabled && (
        <VStack spacing={6} align="stretch">
          {/* 负载均衡算法 */}
          <FormControl>
            <FormLabel>负载均衡算法</FormLabel>
            <Select
              value={load_balancer_algorithm}
              onChange={(e) => onFieldChange('load_balancer_algorithm', e.target.value)}
            >
              {algorithmOptions.map(option => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </Select>
            <Text fontSize="sm" color="gray.500" mt={1}>
              选择请求分发算法，不同算法适用于不同场景
            </Text>
          </FormControl>

          {/* 后端服务器列表 */}
          <Box>
            <HStack justify="space-between" mb={4}>
              <Heading size="sm" display="flex" alignItems="center">
                <Icon as={FiServer} mr={2} />
                后端服务器 ({load_balancer_backends.length})
              </Heading>
              <Button
                leftIcon={<Icon as={FiPlus} />}
                colorScheme="blue"
                size="sm"
                onClick={onAddBackend}
              >
                添加服务器
              </Button>
            </HStack>

            {load_balancer_backends.length === 0 ? (
              <Alert status="info">
                <AlertIcon />
                请添加至少一个后端服务器
              </Alert>
            ) : (
              <VStack spacing={4} align="stretch">
                {load_balancer_backends.map((backend, index) => (
                  <Card key={backend.id} variant="outline">
                    <CardBody>
                      <VStack spacing={4} align="stretch">
                        <HStack justify="space-between">
                          <HStack>
                            <Badge colorScheme={backend.enabled ? 'green' : 'gray'}>
                              {backend.enabled ? '启用' : '禁用'}
                            </Badge>
                            <Text fontWeight="medium">服务器 {index + 1}</Text>
                          </HStack>
                          <IconButton
                            aria-label="删除服务器"
                            icon={<Icon as={FiTrash2} />}
                            size="sm"
                            colorScheme="red"
                            variant="ghost"
                            onClick={() => onRemoveBackend(index)}
                            isDisabled={load_balancer_backends.length <= 1}
                          />
                        </HStack>

                        <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                          <FormControl isRequired>
                            <FormLabel>主机地址</FormLabel>
                            <Input
                              value={backend.host}
                              onChange={(e) => onBackendChange(index, 'host', e.target.value)}
                              placeholder="192.168.1.10"
                            />
                          </FormControl>

                          <FormControl isRequired>
                            <FormLabel>端口</FormLabel>
                            <NumberInput
                              value={backend.port}
                              onChange={(_, value) => onBackendChange(index, 'port', value || 8080)}
                              min={1}
                              max={65535}
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
                              onChange={(_, value) => onBackendChange(index, 'weight', value || 1)}
                              min={1}
                              max={100}
                            >
                              <NumberInputField />
                              <NumberInputStepper>
                                <NumberIncrementStepper />
                                <NumberDecrementStepper />
                              </NumberInputStepper>
                            </NumberInput>
                          </FormControl>

                          <FormControl>
                            <FormLabel>最大连接数</FormLabel>
                            <NumberInput
                              value={backend.max_connections}
                              onChange={(_, value) => onBackendChange(index, 'max_connections', value || 100)}
                              min={0}
                            >
                              <NumberInputField />
                              <NumberInputStepper>
                                <NumberIncrementStepper />
                                <NumberDecrementStepper />
                              </NumberInputStepper>
                            </NumberInput>
                          </FormControl>
                        </SimpleGrid>

                        <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                          <FormControl display="flex" alignItems="center">
                            <FormLabel mb="0">启用此服务器</FormLabel>
                            <Switch
                              isChecked={backend.enabled}
                              onChange={(e) => onBackendChange(index, 'enabled', e.target.checked)}
                            />
                          </FormControl>

                          <FormControl display="flex" alignItems="center">
                            <FormLabel mb="0">启用TLS</FormLabel>
                            <Switch
                              isChecked={backend.tls_enabled}
                              onChange={(e) => onBackendChange(index, 'tls_enabled', e.target.checked)}
                            />
                          </FormControl>

                          <FormControl display="flex" alignItems="center">
                            <FormLabel mb="0">跳过TLS验证</FormLabel>
                            <Switch
                              isChecked={backend.tls_insecure}
                              onChange={(e) => onBackendChange(index, 'tls_insecure', e.target.checked)}
                              isDisabled={!backend.tls_enabled}
                            />
                          </FormControl>

                          <FormControl display="flex" alignItems="center">
                            <FormLabel mb="0">健康检查</FormLabel>
                            <Switch
                              isChecked={backend.health_check_enabled}
                              onChange={(e) => onBackendChange(index, 'health_check_enabled', e.target.checked)}
                            />
                          </FormControl>
                        </SimpleGrid>

                        {backend.health_check_enabled && (
                          <SimpleGrid columns={{ base: 1, md: 3 }} spacing={4}>
                            <FormControl>
                              <FormLabel>健康检查路径</FormLabel>
                              <Input
                                value={backend.health_check_path}
                                onChange={(e) => onBackendChange(index, 'health_check_path', e.target.value)}
                                placeholder="/health"
                              />
                            </FormControl>

                            <FormControl>
                              <FormLabel>检查方法</FormLabel>
                              <Select
                                value={backend.health_check_method}
                                onChange={(e) => onBackendChange(index, 'health_check_method', e.target.value)}
                              >
                                {methodOptions.map(option => (
                                  <option key={option.value} value={option.value}>
                                    {option.label}
                                  </option>
                                ))}
                              </Select>
                            </FormControl>

                            <FormControl>
                              <FormLabel>期望状态码</FormLabel>
                              <NumberInput
                                value={backend.expected_status_code}
                                onChange={(_, value) => onBackendChange(index, 'expected_status_code', value || 200)}
                                min={100}
                                max={599}
                              >
                                <NumberInputField />
                              </NumberInput>
                            </FormControl>
                          </SimpleGrid>
                        )}
                      </VStack>
                    </CardBody>
                  </Card>
                ))}
              </VStack>
            )}
          </Box>

          <Divider />

          {/* 健康检查配置 */}
          <Box>
            <Heading size="sm" mb={4} display="flex" alignItems="center">
              <Icon as={FiActivity} mr={2} />
              全局健康检查配置
            </Heading>
            
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">启用健康检查</FormLabel>
                <Switch
                  isChecked={health_check_enabled}
                  onChange={(e) => onFieldChange('health_check_enabled', e.target.checked)}
                />
              </FormControl>

              {health_check_enabled && (
                <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={4}>
                  <FormControl>
                    <FormLabel>检查路径</FormLabel>
                    <Input
                      value={health_check_path}
                      onChange={(e) => onFieldChange('health_check_path', e.target.value)}
                      placeholder="/health"
                    />
                  </FormControl>

                  <FormControl>
                    <FormLabel>检查间隔 (秒)</FormLabel>
                    <NumberInput
                      value={health_check_interval}
                      onChange={(_, value) => onFieldChange('health_check_interval', value || 30)}
                      min={5}
                      max={300}
                    >
                      <NumberInputField />
                    </NumberInput>
                  </FormControl>

                  <FormControl>
                    <FormLabel>检查超时 (秒)</FormLabel>
                    <NumberInput
                      value={health_check_timeout}
                      onChange={(_, value) => onFieldChange('health_check_timeout', value || 5)}
                      min={1}
                      max={60}
                    >
                      <NumberInputField />
                    </NumberInput>
                  </FormControl>

                  <FormControl>
                    <FormLabel>HTTP方法</FormLabel>
                    <Select
                      value={health_check_method}
                      onChange={(e) => onFieldChange('health_check_method', e.target.value)}
                    >
                      {methodOptions.map(option => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </Select>
                  </FormControl>
                </SimpleGrid>
              )}
            </VStack>
          </Box>

          <Divider />

          {/* 会话保持配置 */}
          <Box>
            <Heading size="sm" mb={4} display="flex" alignItems="center">
              <Icon as={FiSettings} mr={2} />
              会话保持配置
            </Heading>
            
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">启用会话保持</FormLabel>
                <Switch
                  isChecked={session_affinity_enabled}
                  onChange={(e) => onFieldChange('session_affinity_enabled', e.target.checked)}
                />
              </FormControl>

              {session_affinity_enabled && (
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                  <FormControl>
                    <FormLabel>会话保持方法</FormLabel>
                    <Select
                      value={session_affinity_method}
                      onChange={(e) => onFieldChange('session_affinity_method', e.target.value)}
                    >
                      {affinityMethods.map(option => (
                        <option key={option.value} value={option.value}>
                          {option.label}
                        </option>
                      ))}
                    </Select>
                  </FormControl>

                  <FormControl>
                    <FormLabel>会话TTL (秒)</FormLabel>
                    <NumberInput
                      value={session_affinity_ttl}
                      onChange={(_, value) => onFieldChange('session_affinity_ttl', value || 3600)}
                      min={60}
                      max={86400}
                    >
                      <NumberInputField />
                    </NumberInput>
                  </FormControl>

                  {session_affinity_method === 'cookie' && (
                    <FormControl>
                      <FormLabel>Cookie名称</FormLabel>
                      <Input
                        value={session_affinity_cookie}
                        onChange={(e) => onFieldChange('session_affinity_cookie', e.target.value)}
                        placeholder="JSESSIONID"
                      />
                    </FormControl>
                  )}

                  {session_affinity_method === 'header' && (
                    <FormControl>
                      <FormLabel>Header名称</FormLabel>
                      <Input
                        value={session_affinity_header}
                        onChange={(e) => onFieldChange('session_affinity_header', e.target.value)}
                        placeholder="X-Session-ID"
                      />
                    </FormControl>
                  )}
                </SimpleGrid>
              )}
            </VStack>
          </Box>

          <Divider />

          {/* 故障转移配置 */}
          <Box>
            <Heading size="sm" mb={4} display="flex" alignItems="center">
              <Icon as={FiShield} mr={2} />
              故障转移配置
            </Heading>
            
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">启用故障转移</FormLabel>
                <Switch
                  isChecked={failover_enabled}
                  onChange={(e) => onFieldChange('failover_enabled', e.target.checked)}
                />
              </FormControl>

              {failover_enabled && (
                <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={4}>
                  <FormControl>
                    <FormLabel>最大重试次数</FormLabel>
                    <NumberInput
                      value={max_retries}
                      onChange={(_, value) => onFieldChange('max_retries', value || 3)}
                      min={1}
                      max={10}
                    >
                      <NumberInputField />
                    </NumberInput>
                  </FormControl>

                  <FormControl>
                    <FormLabel>重试间隔 (秒)</FormLabel>
                    <NumberInput
                      value={retry_interval}
                      onChange={(_, value) => onFieldChange('retry_interval', value || 1)}
                      min={1}
                      max={60}
                    >
                      <NumberInputField />
                    </NumberInput>
                  </FormControl>

                  <FormControl>
                    <FormLabel>故障阈值</FormLabel>
                    <NumberInput
                      value={failure_threshold}
                      onChange={(_, value) => onFieldChange('failure_threshold', value || 3)}
                      min={1}
                      max={10}
                    >
                      <NumberInputField />
                    </NumberInput>
                  </FormControl>

                  <FormControl>
                    <FormLabel>恢复阈值</FormLabel>
                    <NumberInput
                      value={recovery_threshold}
                      onChange={(_, value) => onFieldChange('recovery_threshold', value || 2)}
                      min={1}
                      max={10}
                    >
                      <NumberInputField />
                    </NumberInput>
                  </FormControl>
                </SimpleGrid>
              )}
            </VStack>
          </Box>
        </VStack>
      )}
    </Box>
  )
}

export default LoadBalancerConfig

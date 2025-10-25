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
import { useTranslation } from '../hooks/useLanguage'

interface ProxyBackend {
  id: string
  host: string
  port: number
  weight: number
  priority: number
  enabled: boolean
  health_check_enabled: boolean
  health_check_path: string
  health_check_interval: number
  health_check_timeout: number
  health_check_method: string
  expected_status_code: number
  max_retries: number
  retry_interval: number
  failure_threshold: number
  recovery_threshold: number
  connect_timeout: number
  read_timeout: number
  write_timeout: number
  keep_alive_timeout: number
  max_connections: number
  tls_enabled: boolean
  tls_insecure: boolean
}

interface BackendConfigProps {
  // 后端服务器配置
  backends: ProxyBackend[]
  
  // 负载均衡配置（自动启用）
  load_balancer_algorithm: string
  
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

const BackendConfig: React.FC<BackendConfigProps> = ({
  backends,
  load_balancer_algorithm,
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
  const t = useTranslation()
  
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

  const getBackendStatus = (backendCount: number) => {
    if (backendCount === 0) {
      return { text: t.backend.at_least_one_server, color: "red.500" }
    } else if (backendCount === 1) {
      return { text: t.backend.single_server_proxy, color: "green.500" }
    } else {
      return { text: `🔵 负载均衡代理 (${backendCount}个服务器)`, color: "blue.500" }
    }
  }

  const status = getBackendStatus(backends.length)

  return (
    <Box>
      {/* 后端服务器配置 */}
      <Box mb={6}>
        <Heading size="md" mb={4} display="flex" alignItems="center">
          <Icon as={FiServer} mr={2} />
          后端服务器配置
        </Heading>
        
        <Alert status="info" mb={4}>
          <AlertIcon />
          <Box>
            <Text fontWeight="medium">统一后端配置</Text>
            <Text fontSize="sm">
              所有代理规则都使用统一的后端配置。单后端时自动使用直接代理，多后端时自动启用负载均衡。
            </Text>
          </Box>
        </Alert>

        <Text fontSize="sm" color={status.color} fontWeight="medium" mb={4}>
          {status.text}
        </Text>

        {/* 后端服务器列表 */}
        <VStack spacing={4} align="stretch">
          {backends.map((backend, index) => (
            <Card key={index} variant="outline">
              <CardBody>
                <VStack spacing={4} align="stretch">
                  <HStack justify="space-between">
                    <HStack>
                      <Icon as={FiServer} />
                      <Text fontWeight="medium">后端服务器 {index + 1}</Text>
                      {backend.enabled ? (
                        <Badge colorScheme="green">启用</Badge>
                      ) : (
                        <Badge colorScheme="gray">禁用</Badge>
                      )}
                    </HStack>
                    {backends.length > 1 && (
                      <IconButton
                        aria-label={t.backend.delete_backend}
                        icon={<FiTrash2 />}
                        size="sm"
                        colorScheme="red"
                        variant="ghost"
                        onClick={() => onRemoveBackend(index)}
                      />
                    )}
                  </HStack>

                  <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                    <FormControl isRequired>
                      <FormLabel>服务器地址</FormLabel>
                      <Input
                        value={backend.host}
                        onChange={(e) => onBackendChange(index, 'host', e.target.value)}
                        placeholder={t.backend.server_placeholder}
                      />
                    </FormControl>

                    <FormControl isRequired>
                      <FormLabel>端口</FormLabel>
                      <NumberInput
                        value={backend.port}
                        onChange={(_, value) => onBackendChange(index, 'port', value)}
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
                        onChange={(_, value) => onBackendChange(index, 'weight', value)}
                        min={1}
                        max={100}
                      >
                        <NumberInputField />
                        <NumberInputStepper>
                          <NumberIncrementStepper />
                          <NumberDecrementStepper />
                        </NumberInputStepper>
                      </NumberInput>
                      <Text fontSize="sm" color="gray.500" mt={1}>
                        权重越高，分配的请求越多
                      </Text>
                    </FormControl>

                    <FormControl>
                      <FormLabel>优先级</FormLabel>
                      <NumberInput
                        value={backend.priority}
                        onChange={(_, value) => onBackendChange(index, 'priority', value)}
                        min={0}
                        max={100}
                      >
                        <NumberInputField />
                        <NumberInputStepper>
                          <NumberIncrementStepper />
                          <NumberDecrementStepper />
                        </NumberInputStepper>
                      </NumberInput>
                      <Text fontSize="sm" color="gray.500" mt={1}>
                        数字越小优先级越高
                      </Text>
                    </FormControl>
                  </SimpleGrid>

                  <FormControl display="flex" alignItems="center">
                    <FormLabel htmlFor={`backend-enabled-${index}`} mb="0">
                      启用此后端服务器
                    </FormLabel>
                    <Switch
                      id={`backend-enabled-${index}`}
                      isChecked={backend.enabled}
                      onChange={(e) => onBackendChange(index, 'enabled', e.target.checked)}
                    />
                  </FormControl>
                </VStack>
              </CardBody>
            </Card>
          ))}

          <Button
            leftIcon={<FiPlus />}
            variant="outline"
            onClick={onAddBackend}
            size="lg"
          >
            添加后端服务器
          </Button>
        </VStack>
      </Box>

      {/* 负载均衡配置（多后端时显示） */}
      {backends.length > 1 && (
        <Box mb={6}>
          <Heading size="md" mb={4} display="flex" alignItems="center">
            <Icon as={FiSettings} mr={2} />
            负载均衡配置
          </Heading>
          
          <Alert status="success" mb={4}>
            <AlertIcon />
            <Text>检测到多个后端服务器，已自动启用负载均衡</Text>
          </Alert>

          <VStack spacing={4} align="stretch">
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
                选择请求分发到后端服务器的方式
              </Text>
            </FormControl>

            {/* 会话保持配置 */}
            <Box>
              <Heading size="sm" mb={3} display="flex" alignItems="center">
                <Icon as={FiShield} mr={2} />
                会话保持
              </Heading>
              
              <VStack spacing={4} align="stretch">
                <FormControl display="flex" alignItems="center">
                  <FormLabel htmlFor="session-affinity" mb="0">
                    启用会话保持
                  </FormLabel>
                  <Switch
                    id="session-affinity"
                    isChecked={session_affinity_enabled}
                    onChange={(e) => onFieldChange('session_affinity_enabled', e.target.checked)}
                  />
                </FormControl>

                {session_affinity_enabled && (
                  <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                    <FormControl>
                      <FormLabel>保持方法</FormLabel>
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
                      <FormLabel>会话超时时间（秒）</FormLabel>
                      <NumberInput
                        value={session_affinity_ttl}
                        onChange={(_, value) => onFieldChange('session_affinity_ttl', value)}
                        min={60}
                        max={86400}
                      >
                        <NumberInputField />
                        <NumberInputStepper>
                          <NumberIncrementStepper />
                          <NumberDecrementStepper />
                        </NumberInputStepper>
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

            {/* 健康检查配置 */}
            <Box>
              <Heading size="sm" mb={3} display="flex" alignItems="center">
                <Icon as={FiActivity} mr={2} />
                健康检查
              </Heading>
              
              <VStack spacing={4} align="stretch">
                <FormControl display="flex" alignItems="center">
                  <FormLabel htmlFor="health-check" mb="0">
                    启用健康检查
                  </FormLabel>
                  <Switch
                    id="health-check"
                    isChecked={health_check_enabled}
                    onChange={(e) => onFieldChange('health_check_enabled', e.target.checked)}
                  />
                </FormControl>

                {health_check_enabled && (
                  <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                    <FormControl>
                      <FormLabel>检查路径</FormLabel>
                      <Input
                        value={health_check_path}
                        onChange={(e) => onFieldChange('health_check_path', e.target.value)}
                        placeholder="/health"
                      />
                    </FormControl>

                    <FormControl>
                      <FormLabel>检查方法</FormLabel>
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

                    <FormControl>
                      <FormLabel>检查间隔（秒）</FormLabel>
                      <NumberInput
                        value={health_check_interval}
                        onChange={(_, value) => onFieldChange('health_check_interval', value)}
                        min={5}
                        max={300}
                      >
                        <NumberInputField />
                        <NumberInputStepper>
                          <NumberIncrementStepper />
                          <NumberDecrementStepper />
                        </NumberInputStepper>
                      </NumberInput>
                    </FormControl>

                    <FormControl>
                      <FormLabel>超时时间（秒）</FormLabel>
                      <NumberInput
                        value={health_check_timeout}
                        onChange={(_, value) => onFieldChange('health_check_timeout', value)}
                        min={1}
                        max={30}
                      >
                        <NumberInputField />
                        <NumberInputStepper>
                          <NumberIncrementStepper />
                          <NumberDecrementStepper />
                        </NumberInputStepper>
                      </NumberInput>
                    </FormControl>

                    <FormControl>
                      <FormLabel>期望状态码</FormLabel>
                      <NumberInput
                        value={expected_status_code}
                        onChange={(_, value) => onFieldChange('expected_status_code', value)}
                        min={200}
                        max={599}
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

            {/* 故障转移配置 */}
            <Box>
              <Heading size="sm" mb={3} display="flex" alignItems="center">
                <Icon as={FiClock} mr={2} />
                故障转移
              </Heading>
              
              <VStack spacing={4} align="stretch">
                <FormControl display="flex" alignItems="center">
                  <FormLabel htmlFor="failover" mb="0">
                    启用故障转移
                  </FormLabel>
                  <Switch
                    id="failover"
                    isChecked={failover_enabled}
                    onChange={(e) => onFieldChange('failover_enabled', e.target.checked)}
                  />
                </FormControl>

                {failover_enabled && (
                  <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                    <FormControl>
                      <FormLabel>最大重试次数</FormLabel>
                      <NumberInput
                        value={max_retries}
                        onChange={(_, value) => onFieldChange('max_retries', value)}
                        min={1}
                        max={10}
                      >
                        <NumberInputField />
                        <NumberInputStepper>
                          <NumberIncrementStepper />
                          <NumberDecrementStepper />
                        </NumberInputStepper>
                      </NumberInput>
                    </FormControl>

                    <FormControl>
                      <FormLabel>重试间隔（秒）</FormLabel>
                      <NumberInput
                        value={retry_interval}
                        onChange={(_, value) => onFieldChange('retry_interval', value)}
                        min={1}
                        max={60}
                      >
                        <NumberInputField />
                        <NumberInputStepper>
                          <NumberIncrementStepper />
                          <NumberDecrementStepper />
                        </NumberInputStepper>
                      </NumberInput>
                    </FormControl>

                    <FormControl>
                      <FormLabel>故障阈值</FormLabel>
                      <NumberInput
                        value={failure_threshold}
                        onChange={(_, value) => onFieldChange('failure_threshold', value)}
                        min={1}
                        max={10}
                      >
                        <NumberInputField />
                        <NumberInputStepper>
                          <NumberIncrementStepper />
                          <NumberDecrementStepper />
                        </NumberInputStepper>
                      </NumberInput>
                    </FormControl>

                    <FormControl>
                      <FormLabel>恢复阈值</FormLabel>
                      <NumberInput
                        value={recovery_threshold}
                        onChange={(_, value) => onFieldChange('recovery_threshold', value)}
                        min={1}
                        max={10}
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
        </Box>
      )}
    </Box>
  )
}

export default BackendConfig

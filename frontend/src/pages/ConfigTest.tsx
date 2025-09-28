import React, { useState } from 'react'
import {
  Box,
  Heading,
  Button,
  Card,
  CardBody,
  CardHeader,
  VStack,
  HStack,
  Icon,
  useToast,
  Text,
  Alert,
  AlertIcon,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  SimpleGrid,
  Badge,
  Divider,
  Code,
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
  List,
  ListItem,
  ListIcon,
} from '@chakra-ui/react'
import { 
  FiCheckCircle, 
  FiXCircle, 
  FiAlertTriangle,
  FiInfo,
  FiRefreshCw,
  FiSettings,
  FiFileText,
  FiServer,
  FiShield,
  FiZap
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'

interface ValidationError {
  field: string
  message: string
  value: string
}

interface ValidationWarning {
  field: string
  message: string
  value: string
}

interface ValidationInfo {
  field: string
  message: string
  value: string
}

interface ValidationSummary {
  total_rules: number
  load_balancer_rules: number
  single_backend_rules: number
  total_backends: number
  health_check_enabled: number
  compression_enabled: boolean
  cdn_cache_enabled: boolean
  ssl_email: string
  admin_prefix: string
}

interface ValidationResult {
  valid: boolean
  errors: ValidationError[]
  warnings: ValidationWarning[]
  info: ValidationInfo[]
  summary: ValidationSummary
}

const ConfigTest: React.FC = () => {
  const { adminPrefix } = useConfig()
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<ValidationResult | null>(null)
  const toast = useToast()

  const validateConfig = async () => {
    setLoading(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/config/validate'), {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const data = await response.json()
      
      if (response.ok && data.valid !== undefined) {
        setResult(data)
        
        if (data.valid) {
          toast({
            title: '配置验证通过',
            description: '配置文件语法正确，所有必要设置已配置',
            status: 'success',
            duration: 3000,
            isClosable: true,
          })
        } else {
          toast({
            title: '配置验证失败',
            description: `发现 ${data.errors?.length || 0} 个错误`,
            status: 'error',
            duration: 5000,
            isClosable: true,
          })
        }
      } else {
        throw new Error(data.error || '验证请求失败')
      }
    } catch (error) {
      console.error('Config validation error:', error)
      toast({
        title: '验证失败',
        description: '无法验证配置文件，请稍后重试',
        status: 'error',
        duration: 5000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  const reloadConfig = async () => {
    setLoading(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/config/reload'), {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const data = await response.json()
      
      if (response.ok && data.success) {
        toast({
          title: '配置重载成功',
          description: `配置已更新，耗时 ${data.duration}`,
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        
        // 重新验证配置
        setTimeout(() => {
          validateConfig()
        }, 1000)
      } else {
        throw new Error(data.error || '重载失败')
      }
    } catch (error) {
      console.error('Config reload error:', error)
      toast({
        title: '重载失败',
        description: '无法重载配置，请检查配置文件',
        status: 'error',
        duration: 5000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <Box>
      {/* 页面头部 */}
      <HStack justify="space-between" align="center" mb={6}>
        <HStack>
          <Icon as={FiSettings} boxSize={6} />
          <Heading size="lg">配置测试与验证</Heading>
        </HStack>
        
        <HStack>
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            onClick={validateConfig}
            isLoading={loading}
            loadingText="验证中..."
          >
            验证配置
          </Button>
          
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            colorScheme="blue"
            onClick={reloadConfig}
            isLoading={loading}
            loadingText="重载中..."
          >
            重载配置
          </Button>
        </HStack>
      </HStack>

      {/* 验证状态 */}
      {result && (
        <Alert status={result.valid ? 'success' : 'error'} mb={6}>
          <AlertIcon />
          <VStack align="start" spacing={1}>
            <Text fontWeight="medium">
              {result.valid ? '✅ 配置验证通过' : '❌ 配置验证失败'}
            </Text>
            <Text fontSize="sm">
              {result.valid 
                ? '配置文件语法正确，所有必要设置已配置'
                : `发现 ${result.errors.length} 个错误，${result.warnings.length} 个警告`
              }
            </Text>
          </VStack>
        </Alert>
      )}

      {/* 配置摘要 */}
      {result?.summary && (
        <Card mb={6}>
          <CardHeader>
            <Heading size="md" display="flex" alignItems="center">
              <Icon as={FiFileText} mr={2} />
              配置摘要
            </Heading>
          </CardHeader>
          <CardBody>
            <SimpleGrid columns={{ base: 2, md: 4 }} spacing={4}>
              <Stat>
                <StatLabel>代理规则</StatLabel>
                <StatNumber>{result.summary.total_rules}</StatNumber>
                <StatHelpText>
                  负载均衡: {result.summary.load_balancer_rules} | 
                  单后端: {result.summary.single_backend_rules}
                </StatHelpText>
              </Stat>

              <Stat>
                <StatLabel>后端服务器</StatLabel>
                <StatNumber>{result.summary.total_backends}</StatNumber>
                <StatHelpText>
                  健康检查: {result.summary.health_check_enabled}
                </StatHelpText>
              </Stat>

              <Stat>
                <StatLabel>压缩功能</StatLabel>
                <StatNumber>
                  <Badge colorScheme={result.summary.compression_enabled ? 'green' : 'gray'}>
                    {result.summary.compression_enabled ? '已启用' : '已禁用'}
                  </Badge>
                </StatNumber>
                <StatHelpText>Brotli + Gzip</StatHelpText>
              </Stat>

              <Stat>
                <StatLabel>CDN缓存</StatLabel>
                <StatNumber>
                  <Badge colorScheme={result.summary.cdn_cache_enabled ? 'green' : 'gray'}>
                    {result.summary.cdn_cache_enabled ? '已启用' : '已禁用'}
                  </Badge>
                </StatNumber>
                <StatHelpText>静态文件缓存</StatHelpText>
              </Stat>
            </SimpleGrid>
            
            <Divider my={4} />
            
            <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
              <Box>
                <Text fontSize="sm" color="gray.600">SSL邮箱</Text>
                <Text fontWeight="medium">{result.summary.ssl_email}</Text>
              </Box>
              
              <Box>
                <Text fontSize="sm" color="gray.600">管理面板前缀</Text>
                <Code>{result.summary.admin_prefix}</Code>
              </Box>
            </SimpleGrid>
          </CardBody>
        </Card>
      )}

      {/* 验证详情 */}
      {result && (result.errors.length > 0 || result.warnings.length > 0 || result.info.length > 0) && (
        <Card>
          <CardHeader>
            <Heading size="md">验证详情</Heading>
          </CardHeader>
          <CardBody>
            <Accordion allowMultiple>
              {/* 错误 */}
              {result.errors.length > 0 && (
                <AccordionItem>
                  <AccordionButton>
                    <Box flex="1" textAlign="left">
                      <HStack>
                        <Icon as={FiXCircle} color="red.500" />
                        <Text fontWeight="medium">错误 ({result.errors.length})</Text>
                      </HStack>
                    </Box>
                    <AccordionIcon />
                  </AccordionButton>
                  <AccordionPanel pb={4}>
                    <List spacing={2}>
                      {result.errors.map((error, index) => (
                        <ListItem key={index}>
                          <ListIcon as={FiXCircle} color="red.500" />
                          <Text as="span" fontWeight="medium">{error.field}:</Text>{' '}
                          {error.message}
                          {error.value && (
                            <Code ml={2} fontSize="sm" colorScheme="red">
                              {error.value}
                            </Code>
                          )}
                        </ListItem>
                      ))}
                    </List>
                  </AccordionPanel>
                </AccordionItem>
              )}

              {/* 警告 */}
              {result.warnings.length > 0 && (
                <AccordionItem>
                  <AccordionButton>
                    <Box flex="1" textAlign="left">
                      <HStack>
                        <Icon as={FiAlertTriangle} color="yellow.500" />
                        <Text fontWeight="medium">警告 ({result.warnings.length})</Text>
                      </HStack>
                    </Box>
                    <AccordionIcon />
                  </AccordionButton>
                  <AccordionPanel pb={4}>
                    <List spacing={2}>
                      {result.warnings.map((warning, index) => (
                        <ListItem key={index}>
                          <ListIcon as={FiAlertTriangle} color="yellow.500" />
                          <Text as="span" fontWeight="medium">{warning.field}:</Text>{' '}
                          {warning.message}
                          {warning.value && (
                            <Code ml={2} fontSize="sm" colorScheme="yellow">
                              {warning.value}
                            </Code>
                          )}
                        </ListItem>
                      ))}
                    </List>
                  </AccordionPanel>
                </AccordionItem>
              )}

              {/* 信息 */}
              {result.info.length > 0 && (
                <AccordionItem>
                  <AccordionButton>
                    <Box flex="1" textAlign="left">
                      <HStack>
                        <Icon as={FiInfo} color="blue.500" />
                        <Text fontWeight="medium">信息 ({result.info.length})</Text>
                      </HStack>
                    </Box>
                    <AccordionIcon />
                  </AccordionButton>
                  <AccordionPanel pb={4}>
                    <List spacing={2}>
                      {result.info.map((info, index) => (
                        <ListItem key={index}>
                          <ListIcon as={FiInfo} color="blue.500" />
                          <Text as="span" fontWeight="medium">{info.field}:</Text>{' '}
                          {info.message}
                          {info.value && (
                            <Code ml={2} fontSize="sm" colorScheme="blue">
                              {info.value}
                            </Code>
                          )}
                        </ListItem>
                      ))}
                    </List>
                  </AccordionPanel>
                </AccordionItem>
              )}
            </Accordion>
          </CardBody>
        </Card>
      )}

      {/* 使用说明 */}
      {!result && (
        <Card>
          <CardHeader>
            <Heading size="md" display="flex" alignItems="center">
              <Icon as={FiInfo} mr={2} />
              配置验证说明
            </Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <Alert status="info">
                <AlertIcon />
                <VStack align="start" spacing={1}>
                  <Text fontWeight="medium">配置验证功能</Text>
                  <Text fontSize="sm">
                    验证当前配置文件的语法正确性和参数完整性，确保服务能够正常启动和运行。
                  </Text>
                </VStack>
              </Alert>
              
              <Box>
                <Text fontWeight="medium" mb={2}>验证内容包括：</Text>
                <List spacing={1}>
                  <ListItem>
                    <ListIcon as={FiServer} color="blue.500" />
                    服务器配置：端口、主机地址、超时参数
                  </ListItem>
                  <ListItem>
                    <ListIcon as={FiShield} color="green.500" />
                    SSL配置：邮箱、证书目录、验证方式
                  </ListItem>
                  <ListItem>
                    <ListIcon as={FiSettings} color="purple.500" />
                    代理配置：域名、后端服务器、负载均衡
                  </ListItem>
                  <ListItem>
                    <ListIcon as={FiZap} color="orange.500" />
                    压缩配置：算法、级别、文件类型
                  </ListItem>
                </List>
              </Box>

              <Alert status="warning">
                <AlertIcon />
                <VStack align="start" spacing={1}>
                  <Text fontWeight="medium">配置热重载</Text>
                  <Text fontSize="sm">
                    验证通过后可以使用"重载配置"功能在不重启服务的情况下应用新配置。
                  </Text>
                </VStack>
              </Alert>
            </VStack>
          </CardBody>
        </Card>
      )}
    </Box>
  )
}

export default ConfigTest

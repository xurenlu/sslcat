import React, { useState } from 'react'
import {
  Box,
  Heading,
  Button,
  Card,
  CardBody,
  FormControl,
  FormLabel,
  Input,
  Switch,
  HStack,
  VStack,
  Icon,
  useToast,
  Text,
  Divider,
  Alert,
  AlertIcon,
  Flex,
} from '@chakra-ui/react'
import { FiArrowLeft, FiZap, FiGlobe, FiShield } from 'react-icons/fi'
import { useNavigate } from 'react-router-dom'

interface ProxyRuleForm {
  domain: string
  target: string
  port: string
  enabled: boolean
  ssl_only: boolean
  cdn_enabled: boolean
  cdn_preset: string
  cdn_ttl_seconds: number
}

const ProxyAdd: React.FC = () => {
  const navigate = useNavigate()
  const toast = useToast()
  const [loading, setLoading] = useState(false)
  const [formData, setFormData] = useState<ProxyRuleForm>({
    domain: '',
    target: '',
    port: '',
    enabled: true,
    ssl_only: true,
    cdn_enabled: false,
    cdn_preset: '',
    cdn_ttl_seconds: 3600,
  })

  const handleInputChange = (field: keyof ProxyRuleForm, value: string | boolean | number) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }))
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)

    try {
      // TODO: 实际的 API 调用
      await new Promise(resolve => setTimeout(resolve, 1000))
      
      toast({
        title: '代理规则创建成功',
        description: '新的代理规则已添加到系统中',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      
      navigate('/proxy')
    } catch (error) {
      toast({
        title: '创建失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  const handleCancel = () => {
    navigate('/proxy')
  }

  return (
    <Box>
      {/* 页面头部 */}
      <Flex justify="space-between" align="center" mb={6}>
        <HStack>
          <Button
            leftIcon={<Icon as={FiArrowLeft} />}
            variant="ghost"
            onClick={handleCancel}
          >
            返回
          </Button>
          <Divider orientation="vertical" height="24px" />
          <Icon as={FiZap} boxSize={6} />
          <Heading size="lg">添加代理规则</Heading>
        </HStack>
      </Flex>

      {/* 表单内容 */}
      <Card>
        <CardBody>
          <form onSubmit={handleSubmit}>
            <VStack spacing={6} align="stretch">
              {/* 基本信息 */}
              <Box>
                <Heading size="md" mb={4} color="gray.700">
                  <Icon as={FiGlobe} mr={2} />
                  基本信息
                </Heading>
                
                <VStack spacing={4}>
                  <FormControl isRequired>
                    <FormLabel>域名</FormLabel>
                    <Input
                      value={formData.domain}
                      onChange={(e) => handleInputChange('domain', e.target.value)}
                      placeholder="example.com"
                      size="lg"
                    />
                    <Text fontSize="sm" color="gray.500" mt={1}>
                      输入要代理的域名，支持通配符如 *.example.com
                    </Text>
                  </FormControl>

                  <FormControl isRequired>
                    <FormLabel>目标地址</FormLabel>
                    <Input
                      value={formData.target}
                      onChange={(e) => handleInputChange('target', e.target.value)}
                      placeholder="http://localhost:3000"
                      size="lg"
                    />
                    <Text fontSize="sm" color="gray.500" mt={1}>
                      代理转发的目标地址，支持 HTTP/HTTPS 协议
                    </Text>
                  </FormControl>

                  <FormControl>
                    <FormLabel>端口（可选）</FormLabel>
                    <Input
                      value={formData.port}
                      onChange={(e) => handleInputChange('port', e.target.value)}
                      placeholder="8080"
                      size="lg"
                    />
                    <Text fontSize="sm" color="gray.500" mt={1}>
                      如果目标地址已包含端口，此字段可留空
                    </Text>
                  </FormControl>
                </VStack>
              </Box>

              <Divider />

              {/* 安全设置 */}
              <Box>
                <Heading size="md" mb={4} color="gray.700">
                  <Icon as={FiShield} mr={2} />
                  安全设置
                </Heading>
                
                <VStack spacing={4}>
                  <FormControl>
                    <HStack justify="space-between">
                      <Box>
                        <FormLabel mb={1}>启用规则</FormLabel>
                        <Text fontSize="sm" color="gray.500">
                          规则创建后是否立即启用
                        </Text>
                      </Box>
                      <Switch
                        isChecked={formData.enabled}
                        onChange={(e) => handleInputChange('enabled', e.target.checked)}
                        size="lg"
                      />
                    </HStack>
                  </FormControl>

                  <FormControl>
                    <HStack justify="space-between">
                      <Box>
                        <FormLabel mb={1}>仅 HTTPS</FormLabel>
                        <Text fontSize="sm" color="gray.500">
                          只允许 HTTPS 连接，自动重定向 HTTP 到 HTTPS
                        </Text>
                      </Box>
                      <Switch
                        isChecked={formData.ssl_only}
                        onChange={(e) => handleInputChange('ssl_only', e.target.checked)}
                        size="lg"
                      />
                    </HStack>
                  </FormControl>
                </VStack>
              </Box>

              <Divider />

              {/* CDN 设置 */}
              <Box>
                <Heading size="md" mb={4} color="gray.700">
                  CDN 缓存设置
                </Heading>
                
                <VStack spacing={4}>
                  <FormControl>
                    <HStack justify="space-between">
                      <Box>
                        <FormLabel mb={1}>启用 CDN 缓存</FormLabel>
                        <Text fontSize="sm" color="gray.500">
                          启用静态资源缓存以提升性能
                        </Text>
                      </Box>
                      <Switch
                        isChecked={formData.cdn_enabled}
                        onChange={(e) => handleInputChange('cdn_enabled', e.target.checked)}
                        size="lg"
                      />
                    </HStack>
                  </FormControl>

                  {formData.cdn_enabled && (
                    <>
                      <FormControl>
                        <FormLabel>缓存预设</FormLabel>
                        <Input
                          value={formData.cdn_preset}
                          onChange={(e) => handleInputChange('cdn_preset', e.target.value)}
                          placeholder="default"
                          size="lg"
                        />
                        <Text fontSize="sm" color="gray.500" mt={1}>
                          缓存策略预设名称
                        </Text>
                      </FormControl>

                      <FormControl>
                        <FormLabel>缓存时间（秒）</FormLabel>
                        <Input
                          type="number"
                          value={formData.cdn_ttl_seconds}
                          onChange={(e) => handleInputChange('cdn_ttl_seconds', parseInt(e.target.value) || 0)}
                          placeholder="3600"
                          size="lg"
                        />
                        <Text fontSize="sm" color="gray.500" mt={1}>
                          静态资源缓存时间，默认 1 小时
                        </Text>
                      </FormControl>
                    </>
                  )}
                </VStack>
              </Box>

              {/* 提示信息 */}
              <Alert status="info">
                <AlertIcon />
                <Box>
                  <Text fontWeight="bold">提示：</Text>
                  <Text fontSize="sm">
                    创建代理规则后，系统会自动为域名申请 SSL 证书（如果启用 HTTPS）。
                    请确保域名已正确解析到当前服务器。
                  </Text>
                </Box>
              </Alert>

              {/* 操作按钮 */}
              <HStack justify="flex-end" spacing={4} pt={4}>
                <Button
                  onClick={handleCancel}
                  variant="outline"
                  size="lg"
                >
                  取消
                </Button>
                <Button
                  type="submit"
                  colorScheme="blue"
                  size="lg"
                  isLoading={loading}
                  loadingText="创建中..."
                >
                  创建规则
                </Button>
              </HStack>
            </VStack>
          </form>
        </CardBody>
      </Card>
    </Box>
  )
}

export default ProxyAdd

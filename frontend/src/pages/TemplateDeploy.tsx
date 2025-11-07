import React, { useState, useEffect } from 'react'
import {
  Box,
  VStack,
  HStack,
  FormControl,
  FormLabel,
  Input,
  Button,
  Select,
  Textarea,
  Heading,
  Text,
  useToast,
  Spinner,
  Center,
  Card,
  CardBody,
  Checkbox,
  Divider,
  Alert,
  AlertIcon,
} from '@chakra-ui/react'
import { useParams, useNavigate } from 'react-router-dom'
import api from '../utils/api'
import { useConfig, buildPath } from '../contexts/ConfigContext'

interface TemplateVariable {
  name: string
  type: string
  title?: string
  description?: string
  default?: any
  options?: any[]
  required?: boolean
  min?: number
  max?: number
}

interface Template {
  id: string
  name: string
  description: string
  variables?: TemplateVariable[]
  services?: any[]
}

const TemplateDeploy: React.FC = () => {
  const { templateId } = useParams<{ templateId: string }>()
  const [template, setTemplate] = useState<Template | null>(null)
  const [loading, setLoading] = useState(true)
  const [deploying, setDeploying] = useState(false)
  const [formData, setFormData] = useState<any>({})
  const navigate = useNavigate()
  const toast = useToast()
  const { adminPrefix } = useConfig()

  useEffect(() => {
    if (templateId) {
      loadTemplate()
    }
  }, [templateId])

  const loadTemplate = async () => {
    try {
      setLoading(true)
      const response: any = await api.get(`/git-server/templates/${templateId}`)
      if (response && response.meta) {
        setTemplate({
          id: response.meta.id,
          name: response.meta.name,
          description: response.meta.description,
          variables: response.meta.variables || [],
          services: response.meta.services || [],
        })

        // 初始化表单数据
        const initialData: any = {
          app_name: '',
          primary_domain: '',
          auto_ssl: true,
        }
        if (response.meta.variables) {
          response.meta.variables.forEach((v: TemplateVariable) => {
            initialData[v.name] = v.default !== undefined ? v.default : ''
          })
        }
        setFormData(initialData)
      }
    } catch (error: any) {
      toast({
        title: '加载模板失败',
        description: error.message || '无法加载模板详情',
        status: 'error',
        duration: 3000,
      })
      navigate(buildPath(adminPrefix, '/templates'))
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!formData.app_name) {
      toast({
        title: '验证失败',
        description: '应用名称不能为空',
        status: 'error',
        duration: 3000,
      })
      return
    }

    try {
      setDeploying(true)
      const variables: any = {}
      template?.variables?.forEach((v) => {
        if (formData[v.name] !== undefined) {
          variables[v.name] = formData[v.name]
        }
      })

      const response: any = await api.post('/git-server/templates/deploy', {
        app_name: formData.app_name,
        template_id: templateId,
        primary_domain: formData.primary_domain || '',
        domains: [],
        variables,
        auto_ssl: formData.auto_ssl || false,
      })

      if (response && response.success) {
        toast({
          title: '部署已启动',
          description: response.message || `应用 ${formData.app_name} 正在后台部署中，请稍候查看状态`,
          status: 'info',
          duration: 5000,
        })
        // 跳转到应用列表页面，用户可以查看部署状态
        navigate(buildPath(adminPrefix, '/git-server'))
      }
    } catch (error: any) {
      toast({
        title: '部署失败',
        description: error.message || '部署过程中出现错误',
        status: 'error',
        duration: 5000,
      })
    } finally {
      setDeploying(false)
    }
  }

  const handleChange = (name: string, value: any) => {
    setFormData((prev: any) => ({
      ...prev,
      [name]: value,
    }))
  }

  if (loading) {
    return (
      <Center h="400px">
        <Spinner size="xl" />
      </Center>
    )
  }

  if (!template) {
    return (
      <Box p={6}>
        <Alert status="error">
          <AlertIcon />
          模板不存在
        </Alert>
      </Box>
    )
  }

  return (
    <Box p={6}>
      <VStack spacing={6} align="stretch" maxW="800px" mx="auto">
        <Heading size="lg">部署模板: {template.name}</Heading>
        <Text color="gray.600">{template.description}</Text>

        <Card>
          <CardBody>
            <form onSubmit={handleSubmit}>
              <VStack spacing={6} align="stretch">
                {/* 基本信息 */}
                <VStack spacing={4} align="stretch">
                  <Heading size="md">基本信息</Heading>
                  <FormControl isRequired>
                    <FormLabel>应用名称</FormLabel>
                    <Input
                      value={formData.app_name || ''}
                      onChange={(e) => handleChange('app_name', e.target.value)}
                      placeholder="my-app"
                      pattern="[a-z0-9-]+"
                    />
                    <Text fontSize="sm" color="gray.500" mt={1}>
                      只能包含小写字母、数字和连字符
                    </Text>
                  </FormControl>

                  <FormControl>
                    <FormLabel>主域名（可选）</FormLabel>
                    <Input
                      value={formData.primary_domain || ''}
                      onChange={(e) => handleChange('primary_domain', e.target.value)}
                      placeholder="example.com"
                    />
                    <Text fontSize="sm" color="gray.500" mt={1}>
                      如果不填写，将使用默认域名
                    </Text>
                  </FormControl>

                  <FormControl>
                    <Checkbox
                      isChecked={formData.auto_ssl !== false}
                      onChange={(e) => handleChange('auto_ssl', e.target.checked)}
                    >
                      自动申请 SSL 证书
                    </Checkbox>
                  </FormControl>
                </VStack>

                <Divider />

                {/* 模板变量 */}
                {template.variables && template.variables.length > 0 && (
                  <VStack spacing={4} align="stretch">
                    <Heading size="md">配置选项</Heading>
                    {template.variables.map((variable) => (
                      <FormControl
                        key={variable.name}
                        isRequired={variable.required}
                      >
                        <FormLabel>
                          {variable.title || variable.name}
                          {variable.description && (
                            <Text fontSize="sm" color="gray.500" fontWeight="normal">
                              {variable.description}
                            </Text>
                          )}
                        </FormLabel>
                        {variable.type === 'select' && variable.options ? (
                          <Select
                            value={formData[variable.name] || variable.default || ''}
                            onChange={(e) => handleChange(variable.name, e.target.value)}
                          >
                            {variable.options.map((opt: any) => (
                              <option key={opt} value={opt}>
                                {opt}
                              </option>
                            ))}
                          </Select>
                        ) : variable.type === 'bool' ? (
                          <Checkbox
                            isChecked={formData[variable.name] ?? variable.default ?? false}
                            onChange={(e) => handleChange(variable.name, e.target.checked)}
                          >
                            {variable.title || variable.name}
                          </Checkbox>
                        ) : variable.type === 'number' ? (
                          <Input
                            type="number"
                            value={formData[variable.name] || variable.default || ''}
                            onChange={(e) => handleChange(variable.name, Number(e.target.value))}
                            min={variable.min}
                            max={variable.max}
                          />
                        ) : (
                          <Input
                            value={formData[variable.name] || variable.default || ''}
                            onChange={(e) => handleChange(variable.name, e.target.value)}
                            placeholder={variable.description}
                          />
                        )}
                      </FormControl>
                    ))}
                  </VStack>
                )}

                {/* 服务信息 */}
                {template.services && template.services.length > 0 && (
                  <VStack spacing={4} align="stretch">
                    <Heading size="md">服务信息</Heading>
                    {template.services.map((service: any) => (
                      <Box key={service.name} p={3} bg="gray.50" borderRadius="md">
                        <Text fontWeight="bold">{service.name}</Text>
                        {service.description && (
                          <Text fontSize="sm" color="gray.600">
                            {service.description}
                          </Text>
                        )}
                      </Box>
                    ))}
                  </VStack>
                )}

                <Divider />

                <HStack justify="flex-end" spacing={4}>
                  <Button onClick={() => navigate('/templates')}>
                    取消
                  </Button>
                  <Button
                    type="submit"
                    colorScheme="blue"
                    isLoading={deploying}
                    loadingText="部署中..."
                  >
                    开始部署
                  </Button>
                </HStack>
              </VStack>
            </form>
          </CardBody>
        </Card>
      </VStack>
    </Box>
  )
}

export default TemplateDeploy


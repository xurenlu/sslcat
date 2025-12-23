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
  gpu_required?: boolean
  requires_ghcr_token?: boolean
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
          gpu_required: response.meta.gpu_required || false,
          requires_ghcr_token: response.meta.requires_ghcr_token || false,
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

    // 验证应用名称格式：只能包含小写字母、数字和连字符
    const appNamePattern = /^[a-z0-9-]+$/
    if (!appNamePattern.test(formData.app_name)) {
      toast({
        title: '验证失败',
        description: '应用名称只能包含小写字母、数字和连字符',
        status: 'error',
        duration: 3000,
      })
      return
    }

    // 验证应用名称不能以连字符开头或结尾
    if (formData.app_name.startsWith('-') || formData.app_name.endsWith('-')) {
      toast({
        title: '验证失败',
        description: '应用名称不能以连字符开头或结尾',
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

      // 验证 GitHub token（如果需要）
      if (template?.requires_ghcr_token && !formData.github_token) {
        toast({
          title: '验证失败',
          description: '此模板使用 ghcr.io 镜像，需要提供 GitHub Personal Access Token',
          status: 'error',
          duration: 3000,
        })
        return
      }

      const response: any = await api.post('/git-server/templates/deploy', {
        app_name: formData.app_name,
        template_id: templateId,
        primary_domain: formData.primary_domain || '',
        domains: [],
        variables,
        auto_ssl: formData.auto_ssl || false,
        github_token: formData.github_token || '',
      })

      // 检查响应中的 success 字段
      if (!response) {
        toast({
          title: '部署失败',
          description: '服务器未返回有效响应',
          status: 'error',
          duration: 5000,
        })
        return
      }

      if (response.success === false) {
        // 如果 success 为 false，显示错误消息
        const errorMessage = response.error || response.message || '部署失败，请查看日志了解详情'
        toast({
          title: '部署失败',
          description: errorMessage,
          status: 'error',
          duration: 5000,
        })
        return
      }

      if (response.success) {
        toast({
          title: '部署已启动',
          description: response.message || `应用 ${formData.app_name} 正在后台部署中，请稍候查看状态`,
          status: 'info',
          duration: 5000,
        })
        // 跳转到应用列表页面，用户可以查看部署状态
        navigate(buildPath(adminPrefix, '/git-server'))
      } else {
        // 如果 success 字段不存在或为其他值，也显示错误
        toast({
          title: '部署失败',
          description: response.message || response.error || '部署过程中出现未知错误',
          status: 'error',
          duration: 5000,
        })
      }
    } catch (error: any) {
      // 处理网络错误或其他异常
      const errorMessage = error.message || error.data?.error || error.data?.message || '部署过程中出现错误'
      toast({
        title: '部署失败',
        description: errorMessage,
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

        {/* GPU 需求提示 */}
        {template.gpu_required && (
          <Alert status="warning">
            <AlertIcon />
            <Box>
              <Text fontWeight="bold">此模板需要 GPU 支持</Text>
              <Text fontSize="sm" mt={1}>
                请确保您的服务器已安装 NVIDIA 驱动和 nvidia-container-toolkit。如果当前系统没有 GPU，此模板将无法运行。
              </Text>
            </Box>
          </Alert>
        )}

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

                  {/* GitHub Token 输入（如果需要） */}
                  {template.requires_ghcr_token && (
                    <FormControl isRequired>
                      <FormLabel>GitHub Personal Access Token</FormLabel>
                      <Input
                        type="password"
                        value={formData.github_token || ''}
                        onChange={(e) => handleChange('github_token', e.target.value)}
                        placeholder="ghp_xxxxxxxxxxxxxxxxxxxx"
                      />
                      <Text fontSize="sm" color="gray.500" mt={1}>
                        此模板使用 ghcr.io 镜像，需要 GitHub Personal Access Token 才能拉取镜像。
                        请在 GitHub Settings → Developer settings → Personal access tokens 中创建 token，需要 read:packages 权限。
                      </Text>
                    </FormControl>
                  )}
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


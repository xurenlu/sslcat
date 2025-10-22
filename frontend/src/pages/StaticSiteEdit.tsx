import React, { useState, useEffect } from 'react'
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
  SimpleGrid,
} from '@chakra-ui/react'
import { FiArrowLeft, FiGlobe, FiSave, FiFolder } from 'react-icons/fi'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useConfig, buildPath, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'
import HeaderEditor from '../components/HeaderEditor'
import PathPrefixRulesConfig from '../components/PathPrefixRulesConfig'
import { PathPrefixRule } from '../types/config'
import { CORS_PRESET } from '../constants/cors'

interface StaticSiteForm {
  domain: string
  root: string
  index: string
  enabled: boolean
  headers: Record<string, string>
  path_prefix_rules: PathPrefixRule[]
}

const StaticSiteEdit: React.FC = () => {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const toast = useToast()
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  
  const domain = searchParams.get('domain') || ''
  
  const [formData, setFormData] = useState<StaticSiteForm>({
    domain: '',
    root: '',
    index: 'index.html',
    enabled: true,
    headers: {},
    path_prefix_rules: [],
  })
  
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)

  // 加载站点数据
  useEffect(() => {
    if (!domain) return
    
    const loadSiteData = async () => {
      setLoading(true)
      try {
        const response = await fetch(buildApiPath(adminPrefix, '/api/static-sites'), {
          credentials: 'include',
        })
        
        if (!response.ok) {
          throw new Error('Failed to load sites')
        }
        
        const data = await response.json()
        const site = data.sites.find((s: any) => s.domain === domain)
        
        if (site) {
          setFormData({
            domain: site.domain || '',
            root: site.root || '',
            index: site.index || 'index.html',
            enabled: site.enabled ?? true,
            headers: site.response_headers || {},
            path_prefix_rules: site.path_prefix_rules || [],
          })
        }
      } catch (error) {
        console.error('Error loading site data:', error)
        toast({
          title: '加载失败',
          description: '无法加载站点数据',
          status: 'error',
          duration: 3000,
          isClosable: true,
        })
      } finally {
        setLoading(false)
      }
    }
    
    loadSiteData()
  }, [domain, adminPrefix, toast])

  const handleInputChange = (field: keyof StaticSiteForm, value: any) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }))
  }

  const applyCorsPreset = () => {
    setFormData(prev => ({
      ...prev,
      headers: {
        ...prev.headers,
        ...CORS_PRESET.response,
      },
    }))
  }

  const handleSave = async () => {
    if (!formData.domain || !formData.root) {
      toast({
        title: '验证失败',
        description: '域名和根目录路径是必填项',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    setSaving(true)
    try {
      // 如果没有 domain 参数，说明是新增站点，使用 POST；否则使用 PUT 更新
      const isNewSite = !domain
      const response = await fetch(buildApiPath(adminPrefix, '/api/static-sites'), {
        method: isNewSite ? 'POST' : 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          domain: formData.domain,
          root: formData.root,
          index: formData.index,
          enabled: formData.enabled,
          headers: formData.headers,
          path_prefix_rules: formData.path_prefix_rules,
        }),
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || '保存失败')
      }

      toast({
        title: '保存成功',
        description: isNewSite ? '静态站点已创建' : '静态站点配置已更新',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })

      navigate(buildPath(adminPrefix, '/sites'))
    } catch (error) {
      console.error('Error saving site:', error)
      toast({
        title: '保存失败',
        description: error instanceof Error ? error.message : '保存站点配置时出错',
        status: 'error',
        duration: 5000,
        isClosable: true,
      })
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <Box p={6}>
        <Text>加载中...</Text>
      </Box>
    )
  }

  return (
    <Box p={6}>
      <Flex align="center" mb={6}>
        <Button
          variant="ghost"
          leftIcon={<Icon as={FiArrowLeft} />}
          onClick={() => navigate(buildPath(adminPrefix, '/sites'))}
          mr={4}
        >
          返回站点管理
        </Button>
        <Heading size="lg">{domain ? '编辑静态站点' : '添加静态站点'}</Heading>
      </Flex>

      <VStack spacing={6} align="stretch">
        {/* 基本信息 */}
        <Card>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <Heading size="md" display="flex" alignItems="center">
                <Icon as={FiGlobe} mr={2} />
                基本信息
              </Heading>
              
              <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                <FormControl isRequired>
                  <FormLabel>域名</FormLabel>
                  <Input
                    value={formData.domain}
                    onChange={(e) => handleInputChange('domain', e.target.value)}
                    placeholder="example.com"
                  />
                </FormControl>

                <FormControl isRequired>
                  <FormLabel>根目录路径</FormLabel>
                  <Input
                    value={formData.root}
                    onChange={(e) => handleInputChange('root', e.target.value)}
                    placeholder="/var/www/example.com"
                  />
                </FormControl>

                <FormControl>
                  <FormLabel>默认文件</FormLabel>
                  <Input
                    value={formData.index}
                    onChange={(e) => handleInputChange('index', e.target.value)}
                    placeholder="index.html"
                  />
                </FormControl>

                <FormControl>
                  <FormLabel>启用状态</FormLabel>
                  <HStack>
                    <Switch
                      isChecked={formData.enabled}
                      onChange={(e) => handleInputChange('enabled', e.target.checked)}
                    />
                    <Text>{formData.enabled ? '已启用' : '已禁用'}</Text>
                  </HStack>
                </FormControl>
              </SimpleGrid>
            </VStack>
          </CardBody>
        </Card>

        {/* 路径前缀规则配置 */}
        <Card>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <Heading size="md" display="flex" alignItems="center">
                <Icon as={FiFolder} mr={2} />
                路径前缀规则配置
              </Heading>
              <Text fontSize="sm" color="gray.500">
                配置特定路径前缀的负载均衡转发规则
              </Text>
              <PathPrefixRulesConfig
                pathPrefixRules={formData.path_prefix_rules}
                onChange={(rules) => handleInputChange('path_prefix_rules', rules)}
              />
            </VStack>
          </CardBody>
        </Card>

        {/* 响应头配置 */}
        <Card>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <Flex justify="space-between" align="center">
                <Heading size="md">响应头配置</Heading>
                <Button size="sm" variant="outline" onClick={applyCorsPreset}>
                  一键填充 CORS 预设
                </Button>
              </Flex>
              <HeaderEditor
                value={formData.headers}
                onChange={(headers) => handleInputChange('headers', headers)}
                placeholderKey="Access-Control-Allow-Origin"
                placeholderValue="*"
              />
            </VStack>
          </CardBody>
        </Card>

        {/* 保存按钮 */}
        <Card>
          <CardBody>
            <HStack justify="space-between">
              <Alert status="info" variant="left-accent">
                <AlertIcon />
                <Text fontSize="sm">
                  配置保存后将立即生效，请确保路径前缀规则配置正确。
                </Text>
              </Alert>
              <Button
                colorScheme="blue"
                leftIcon={<Icon as={FiSave} />}
                onClick={handleSave}
                isLoading={saving}
                loadingText="保存中..."
              >
                保存配置
              </Button>
            </HStack>
          </CardBody>
        </Card>
      </VStack>
    </Box>
  )
}

export default StaticSiteEdit

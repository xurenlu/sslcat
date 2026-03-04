import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  Button,
  Card,
  CardBody,
  FormControl,
  FormLabel,
  FormHelperText,
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
import { FiArrowLeft, FiGlobe, FiSave, FiFolder, FiShield } from 'react-icons/fi'
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
  try_files: boolean
  headers: Record<string, string>
  path_prefix_rules: PathPrefixRule[]
  waf_enabled?: boolean | null
  access_log_enabled: boolean | null
  access_log_path: string
  error_log_enabled: boolean | null
  error_log_path: string
  http2_enabled: boolean | null
  http3_enabled: boolean | null
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
    try_files: false,
    headers: {},
    path_prefix_rules: [],
    waf_enabled: null,
    access_log_enabled: null,
    access_log_path: '',
    error_log_enabled: null,
    error_log_path: '',
    http2_enabled: null,
    http3_enabled: null,
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
            try_files: site.try_files ?? false,
            headers: site.response_headers || {},
            path_prefix_rules: site.path_prefix_rules || [],
            waf_enabled: site.waf_enabled ?? null,
            access_log_enabled: site.access_log_enabled ?? null,
            access_log_path: site.access_log_path || '',
            error_log_enabled: site.error_log_enabled ?? null,
            error_log_path: site.error_log_path || '',
            http2_enabled: site.http2_enabled ?? null,
            http3_enabled: site.http3_enabled ?? null,
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
          try_files: formData.try_files,
          headers: formData.headers,
          path_prefix_rules: formData.path_prefix_rules,
          waf_enabled: formData.waf_enabled,
          access_log_enabled: formData.access_log_enabled,
          access_log_path: formData.access_log_path || undefined,
          error_log_enabled: formData.error_log_enabled,
          error_log_path: formData.error_log_path || undefined,
          http2_enabled: formData.http2_enabled,
          http3_enabled: formData.http3_enabled,
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
                  <FormLabel>{t.sites.tryFiles ?? 'Try Files (SPA)'}</FormLabel>
                  <VStack align="stretch" spacing={1}>
                    <HStack>
                      <Switch
                        isChecked={formData.try_files}
                        onChange={(e) => handleInputChange('try_files', e.target.checked)}
                      />
                      <Text>{formData.try_files ? (t.sites.tryFilesEnabled ?? '已启用') : (t.sites.tryFilesDisabled ?? '已禁用')}</Text>
                    </HStack>
                    <FormHelperText fontSize="xs">
                      {t.sites.tryFilesHelp ?? '启用后，请求路径不存在时回退到默认文件，用于 Vue/React Router 等 SPA 前端路由'}
                    </FormHelperText>
                  </VStack>
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

                <FormControl>
                  <FormLabel>
                    <HStack>
                      <Icon as={FiShield} />
                      <Text>WAF 防护</Text>
                    </HStack>
                  </FormLabel>
                  <VStack align="stretch" spacing={2}>
                    <Text fontSize="sm" color="gray.500">
                      {formData.waf_enabled === null 
                        ? '使用全局 WAF 配置（默认）' 
                        : formData.waf_enabled 
                          ? '已为此站点启用 WAF' 
                          : '已为此站点禁用 WAF'}
                    </Text>
                    <HStack>
                      <Button
                        size="sm"
                        variant={formData.waf_enabled === null ? 'solid' : 'outline'}
                        colorScheme={formData.waf_enabled === null ? 'blue' : 'gray'}
                        onClick={() => handleInputChange('waf_enabled', null)}
                      >
                        全局
                      </Button>
                      <Button
                        size="sm"
                        variant={formData.waf_enabled === true ? 'solid' : 'outline'}
                        colorScheme={formData.waf_enabled === true ? 'green' : 'gray'}
                        onClick={() => handleInputChange('waf_enabled', true)}
                      >
                        启用
                      </Button>
                      <Button
                        size="sm"
                        variant={formData.waf_enabled === false ? 'solid' : 'outline'}
                        colorScheme={formData.waf_enabled === false ? 'red' : 'gray'}
                        onClick={() => handleInputChange('waf_enabled', false)}
                      >
                        禁用
                      </Button>
                    </HStack>
                  </VStack>
                </FormControl>

                <Box gridColumn={{ base: '1', md: '1 / -1' }}>
                  <FormLabel mb={2}>访问日志覆盖</FormLabel>
                  <Text fontSize="sm" color="gray.500" mb={2}>
                    可在此站点关闭访问日志或指定单独日志路径，留空则使用系统设置中的全局配置
                  </Text>
                  <VStack spacing={3} align="stretch">
                    <FormControl display="flex" alignItems="center">
                      <Switch
                        id="static-access-log-off"
                        isChecked={formData.access_log_enabled === false}
                        onChange={(e) => handleInputChange('access_log_enabled', e.target.checked ? false : null)}
                      />
                      <FormLabel htmlFor="static-access-log-off" mb="0" ml={2}>
                        关闭此站点访问日志
                      </FormLabel>
                    </FormControl>
                    <FormControl>
                      <FormLabel fontSize="sm">自定义访问日志路径（留空使用全局）</FormLabel>
                      <Input
                        value={formData.access_log_path}
                        onChange={(e) => handleInputChange('access_log_path', e.target.value)}
                        placeholder="./data/access-{yyyy}-{mm}-{dd}.log"
                        size="sm"
                      />
                      <FormHelperText fontSize="xs">支持日期占位符: {'{yyyy}'}, {'{mm}'}, {'{dd}'}, {'{HH}'}, {'{MM}'}, {'{SS}'} 等</FormHelperText>
                    </FormControl>
                  </VStack>
                </Box>

                <Box gridColumn={{ base: '1', md: '1 / -1' }}>
                  <FormLabel mb={2}>错误日志覆盖</FormLabel>
                  <Text fontSize="sm" color="gray.500" mb={2}>
                    可在此站点关闭错误日志或指定单独日志路径，留空则使用系统设置中的全局配置
                  </Text>
                  <VStack spacing={3} align="stretch">
                    <FormControl display="flex" alignItems="center">
                      <Switch
                        id="static-error-log-off"
                        isChecked={formData.error_log_enabled === false}
                        onChange={(e) => handleInputChange('error_log_enabled', e.target.checked ? false : null)}
                      />
                      <FormLabel htmlFor="static-error-log-off" mb="0" ml={2}>
                        关闭此站点错误日志
                      </FormLabel>
                    </FormControl>
                    <FormControl>
                      <FormLabel fontSize="sm">自定义错误日志路径（留空使用全局）</FormLabel>
                      <Input
                        value={formData.error_log_path}
                        onChange={(e) => handleInputChange('error_log_path', e.target.value)}
                        placeholder="./data/error-{yyyy}-{mm}-{dd}.log"
                        size="sm"
                      />
                      <FormHelperText fontSize="xs">支持日期占位符: {'{yyyy}'}, {'{mm}'}, {'{dd}'}, {'{HH}'}, {'{MM}'}, {'{SS}'} 等</FormHelperText>
                    </FormControl>
                  </VStack>
                </Box>

                <Box gridColumn={{ base: '1', md: '1 / -1' }}>
                  <FormLabel mb={2}>HTTP/2 覆盖</FormLabel>
                  <Text fontSize="sm" color="gray.500" mb={2}>
                    可在此站点覆盖全局 HTTP/2 设置，留空则使用系统设置中的全局配置
                  </Text>
                  <HStack>
                    <Button
                      size="sm"
                      variant={formData.http2_enabled === null ? 'solid' : 'outline'}
                      colorScheme={formData.http2_enabled === null ? 'blue' : 'gray'}
                      onClick={() => handleInputChange('http2_enabled', null)}
                    >
                      全局
                    </Button>
                    <Button
                      size="sm"
                      variant={formData.http2_enabled === true ? 'solid' : 'outline'}
                      colorScheme={formData.http2_enabled === true ? 'green' : 'gray'}
                      onClick={() => handleInputChange('http2_enabled', true)}
                    >
                      启用
                    </Button>
                    <Button
                      size="sm"
                      variant={formData.http2_enabled === false ? 'solid' : 'outline'}
                      colorScheme={formData.http2_enabled === false ? 'red' : 'gray'}
                      onClick={() => handleInputChange('http2_enabled', false)}
                    >
                      禁用
                    </Button>
                  </HStack>
                </Box>

                <Box gridColumn={{ base: '1', md: '1 / -1' }}>
                  <FormLabel mb={2}>HTTP/3 覆盖</FormLabel>
                  <Text fontSize="sm" color="gray.500" mb={2}>
                    可在此站点覆盖全局 HTTP/3 设置，留空则使用系统设置中的全局配置
                  </Text>
                  <HStack>
                    <Button
                      size="sm"
                      variant={formData.http3_enabled === null ? 'solid' : 'outline'}
                      colorScheme={formData.http3_enabled === null ? 'blue' : 'gray'}
                      onClick={() => handleInputChange('http3_enabled', null)}
                    >
                      全局
                    </Button>
                    <Button
                      size="sm"
                      variant={formData.http3_enabled === true ? 'solid' : 'outline'}
                      colorScheme={formData.http3_enabled === true ? 'green' : 'gray'}
                      onClick={() => handleInputChange('http3_enabled', true)}
                    >
                      启用
                    </Button>
                    <Button
                      size="sm"
                      variant={formData.http3_enabled === false ? 'solid' : 'outline'}
                      colorScheme={formData.http3_enabled === false ? 'red' : 'gray'}
                      onClick={() => handleInputChange('http3_enabled', false)}
                    >
                      禁用
                    </Button>
                  </HStack>
                </Box>
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
                loadingText={t.common.saving}
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

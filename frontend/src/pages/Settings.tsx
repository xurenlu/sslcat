import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  Card,
  CardBody,
  CardHeader,
  VStack,
  HStack,
  FormControl,
  FormLabel,
  Input,
  Switch,
  Button,
  Icon,
  useToast,
  SimpleGrid,
  Text,
  Select,
} from '@chakra-ui/react'
import {
  FiSettings,
  FiSave,
  FiRefreshCw,
} from 'react-icons/fi'
import { useConfig } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

const Settings: React.FC = () => {
  const { adminPrefix, refreshConfig } = useConfig()
  const t = useTranslation()
  const [settings, setSettings] = useState({
    // 基础设置
    adminPrefix: adminPrefix,
    httpPort: '80',
    httpsPort: '443',
    
    // SSL设置
    autoSSL: true,
    letsEncryptEmail: 'admin@example.com',
    sslProvider: 'letsencrypt',
    
    // 安全设置
    enableDDoSProtection: true,
    maxRequestsPerMinute: '1000',
    enableRateLimit: true,
    
    // 日志设置
    enableAccessLog: false,
    enableErrorLog: true,
    logLevel: 'info',
    
    // 压缩设置
    compressionEnabled: true,
    compressionAlgorithms: ['br', 'gzip'],
    compressionMinSize: 1024,
    compressionGzipLevel: 6,
    compressionBrotliLevel: 6,
    
    // 上游缓存设置
    upstreamCacheEnabled: true,
    upstreamCacheDir: './data/upstream-cache',
    upstreamCacheMaxSize: 1024,
    upstreamCacheDefaultTTL: 3600,
    upstreamCacheRespectUpstream: true,
    
    // 通知设置
    enableNotifications: true,
    notificationChannels: 'email,webhook',
    // 邮件通知配置
    smtpHost: '',
    smtpPort: '587',
    smtpUsername: '',
    smtpPassword: '',
    smtpFrom: '',
    smtpTo: '',
    smtpUseTLS: true,
    // Slack配置
    slackWebhook: '',
    // 其他Webhook配置
    webhookUrl: '',
  })
  
  const [loading, setLoading] = useState(false)
  const toast = useToast()

  // 当adminPrefix变化时更新设置
  useEffect(() => {
    setSettings(prev => ({
      ...prev,
      adminPrefix: adminPrefix,
    }))
  }, [adminPrefix])

  // 加载通知配置
  useEffect(() => {
    const loadNotificationConfig = async () => {
      try {
        const response = await fetch(`${adminPrefix}/api/notifications/config`, {
          method: 'GET',
          credentials: 'include',
        })
        
        if (response.ok) {
          const data = await response.json()
          if (data.success && data.config) {
            const config = data.config
            setSettings(prev => ({
              ...prev,
              enableNotifications: config.enabled || false,
              smtpHost: config.channels?.email?.smtp_host || '',
              smtpPort: config.channels?.email?.smtp_port?.toString() || '587',
              smtpUsername: config.channels?.email?.username || '',
              smtpPassword: config.channels?.email?.password || '',
              smtpFrom: config.channels?.email?.from || '',
              smtpTo: config.channels?.email?.to?.join(',') || '',
              smtpUseTLS: config.channels?.email?.use_tls || true,
              slackWebhook: config.channels?.webhook?.url || '',
              webhookUrl: config.channels?.webhook?.url || '',
            }))
          }
        }
      } catch (error) {
        console.error('加载通知配置失败:', error)
      }
    }

    loadNotificationConfig()
  }, [adminPrefix])

  const handleInputChange = (field: string, value: string | boolean | number) => {
    setSettings(prev => ({
      ...prev,
      [field]: value,
    }))
  }

  const saveSettings = async () => {
    setLoading(true)
    try {
      const response = await fetch(`${adminPrefix}/api/settings/basic`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          adminPrefix: settings.adminPrefix,
          httpPort: settings.httpPort,
          httpsPort: settings.httpsPort,
          autoSSL: settings.autoSSL,
          letsEncryptEmail: settings.letsEncryptEmail,
          sslProvider: settings.sslProvider,
          enableDDoSProtection: settings.enableDDoSProtection,
          maxRequestsPerMinute: settings.maxRequestsPerMinute,
          enableRateLimit: settings.enableRateLimit,
          enableAccessLog: settings.enableAccessLog,
          enableErrorLog: settings.enableErrorLog,
          logLevel: settings.logLevel,
        }),
      })

      if (response.ok) {
        toast({
          title: t.settings.settingsSaved,
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        
        // 如果adminPrefix发生变化，刷新配置并重定向到新的前缀
        if (settings.adminPrefix !== adminPrefix) {
          // 先刷新配置
          await refreshConfig()
          // 然后重定向到新的URL
          setTimeout(() => {
            const newUrl = `${settings.adminPrefix}/settings`
            console.log('Redirecting to new admin prefix:', newUrl)
            window.location.href = newUrl
          }, 1000)
        }
      } else {
        const errorData = await response.json()
        throw new Error(errorData.message || '保存失败')
      }
    } catch (error) {
      toast({
        title: '保存失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  const saveNotificationSettings = async () => {
    setLoading(true)
    try {
      const notificationConfig = {
        enabled: settings.enableNotifications,
        channels: {
          email: {
            enabled: settings.smtpHost && settings.smtpUsername && settings.smtpPassword,
            smtp_host: settings.smtpHost,
            smtp_port: parseInt(settings.smtpPort) || 587,
            username: settings.smtpUsername,
            password: settings.smtpPassword,
            from: settings.smtpFrom,
            to: settings.smtpTo ? settings.smtpTo.split(',').map(email => email.trim()) : [],
            use_tls: settings.smtpUseTLS,
          },
          webhook: {
            enabled: settings.slackWebhook || settings.webhookUrl,
            url: settings.slackWebhook || settings.webhookUrl,
            headers: settings.slackWebhook ? { 'Content-Type': 'application/json' } : {},
            timeout: 10,
          },
        },
      }

      const response = await fetch(`${adminPrefix}/api/notifications/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(notificationConfig),
      })

      if (response.ok) {
        toast({
          title: '通知配置保存成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
      } else {
        throw new Error('保存失败')
      }
    } catch (error) {
      toast({
        title: '保存失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  const resetSettings = () => {
    // 重置为默认值
    setSettings({
      adminPrefix: adminPrefix,
      httpPort: '80',
      httpsPort: '443',
      autoSSL: true,
      letsEncryptEmail: 'admin@example.com',
      sslProvider: 'letsencrypt',
      enableDDoSProtection: true,
      maxRequestsPerMinute: '1000',
      enableRateLimit: true,
      enableAccessLog: false,
      enableErrorLog: true,
      logLevel: 'info',
      // 压缩设置
      compressionEnabled: true,
      compressionAlgorithms: ['br', 'gzip'],
      compressionMinSize: 1024,
      compressionGzipLevel: 6,
      compressionBrotliLevel: 6,
      // 上游缓存设置
      upstreamCacheEnabled: true,
      upstreamCacheDir: './data/upstream-cache',
      upstreamCacheMaxSize: 1024,
      upstreamCacheDefaultTTL: 3600,
      upstreamCacheRespectUpstream: true,
      enableNotifications: true,
      notificationChannels: 'email,webhook',
      // 邮件通知配置
      smtpHost: '',
      smtpPort: '587',
      smtpUsername: '',
      smtpPassword: '',
      smtpFrom: '',
      smtpTo: '',
      smtpUseTLS: true,
      // Slack配置
      slackWebhook: '',
      // 其他Webhook配置
      webhookUrl: '',
    })
    
    toast({
      title: '设置已重置',
      status: 'info',
      duration: 3000,
      isClosable: true,
    })
  }

  return (
    <Box>
      <HStack justify="space-between" align="center" mb={6}>
        <HStack>
          <Icon as={FiSettings} boxSize={6} />
          <Heading size="lg">{t.settings.title}</Heading>
        </HStack>
        <HStack>
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            onClick={resetSettings}
            variant="outline"
          >
            {t.settings.resetSettings}
          </Button>
          <Button
            leftIcon={<Icon as={FiSave} />}
            onClick={saveSettings}
            isLoading={loading}
            colorScheme="blue"
          >
            {t.settings.saveSettings}
          </Button>
        </HStack>
      </HStack>

      <SimpleGrid columns={{ base: 1, lg: 2 }} spacing={6}>
        {/* 基础设置 */}
        <Card>
          <CardHeader>
            <Heading size="md">{t.settings.basicSettings}</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl>
                <FormLabel>{t.settings.adminPrefix}</FormLabel>
                <Input
                  value={settings.adminPrefix}
                  onChange={(e) => handleInputChange('adminPrefix', e.target.value)}
                  placeholder="/admin"
                />
              </FormControl>
              
              <FormControl>
                <FormLabel>{t.settings.httpPort}</FormLabel>
                <Input
                  value={settings.httpPort}
                  onChange={(e) => handleInputChange('httpPort', e.target.value)}
                  placeholder="80"
                  type="number"
                />
              </FormControl>
              
              <FormControl>
                <FormLabel>{t.settings.httpsPort}</FormLabel>
                <Input
                  value={settings.httpsPort}
                  onChange={(e) => handleInputChange('httpsPort', e.target.value)}
                  placeholder="443"
                  type="number"
                />
              </FormControl>
            </VStack>
          </CardBody>
        </Card>

        {/* SSL设置 */}
        <Card>
          <CardHeader>
            <Heading size="md">{t.settings.sslSettings}</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">{t.settings.autoSSL}</FormLabel>
                <Switch
                  isChecked={settings.autoSSL}
                  onChange={(e) => handleInputChange('autoSSL', e.target.checked)}
                />
              </FormControl>
              
              <FormControl>
                <FormLabel>{t.settings.letsEncryptEmail}</FormLabel>
                <Input
                  value={settings.letsEncryptEmail}
                  onChange={(e) => handleInputChange('letsEncryptEmail', e.target.value)}
                  placeholder="admin@example.com"
                  type="email"
                />
              </FormControl>
              
            </VStack>
          </CardBody>
        </Card>

        {/* 安全设置 */}
        <Card>
          <CardHeader>
            <Heading size="md">{t.settings.securitySettings}</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">{t.settings.enableDDoSProtection}</FormLabel>
                <Switch
                  isChecked={settings.enableDDoSProtection}
                  onChange={(e) => handleInputChange('enableDDoSProtection', e.target.checked)}
                />
              </FormControl>
              
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">{t.settings.enableRateLimit}</FormLabel>
                <Switch
                  isChecked={settings.enableRateLimit}
                  onChange={(e) => handleInputChange('enableRateLimit', e.target.checked)}
                />
              </FormControl>
              
              <FormControl>
                <FormLabel>{t.settings.maxRequestsPerMinute}</FormLabel>
                <Input
                  value={settings.maxRequestsPerMinute}
                  onChange={(e) => handleInputChange('maxRequestsPerMinute', e.target.value)}
                  placeholder="1000"
                  type="number"
                />
              </FormControl>
            </VStack>
          </CardBody>
        </Card>

        {/* 日志设置 */}
        <Card>
          <CardHeader>
            <Heading size="md">{t.settings.logSettings}</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">{t.settings.enableAccessLog}</FormLabel>
                <Switch
                  isChecked={settings.enableAccessLog}
                  onChange={(e) => handleInputChange('enableAccessLog', e.target.checked)}
                />
              </FormControl>
              
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">{t.settings.enableErrorLog}</FormLabel>
                <Switch
                  isChecked={settings.enableErrorLog}
                  onChange={(e) => handleInputChange('enableErrorLog', e.target.checked)}
                />
              </FormControl>
              
              <FormControl>
                <FormLabel>{t.settings.logLevel}</FormLabel>
                <Select
                  value={settings.logLevel}
                  onChange={(e) => handleInputChange('logLevel', e.target.value)}
                >
                  <option value="debug">{t.settings.debug}</option>
                  <option value="info">{t.settings.info}</option>
                  <option value="warn">{t.settings.warn}</option>
                  <option value="error">{t.settings.error}</option>
                </Select>
              </FormControl>
            </VStack>
          </CardBody>
        </Card>
      </SimpleGrid>

      {/* 压缩设置 */}
      <Card mt={6}>
        <CardHeader>
          <Heading size="md">内容压缩设置</Heading>
        </CardHeader>
        <CardBody>
          <VStack spacing={4} align="stretch">
            <FormControl display="flex" alignItems="center">
              <FormLabel mb="0">启用内容压缩</FormLabel>
              <Switch
                isChecked={settings.compressionEnabled}
                onChange={(e) => handleInputChange('compressionEnabled', e.target.checked)}
              />
            </FormControl>
            
            {settings.compressionEnabled && (
              <>
                <SimpleGrid columns={{ base: 1, md: 3 }} spacing={4}>
                  <FormControl>
                    <FormLabel>最小文件大小 (字节)</FormLabel>
                    <Input
                      type="number"
                      value={settings.compressionMinSize}
                      onChange={(e) => handleInputChange('compressionMinSize', parseInt(e.target.value) || 1024)}
                      min="100"
                      max="10240"
                    />
                  </FormControl>
                  
                  <FormControl>
                    <FormLabel>Gzip压缩级别</FormLabel>
                    <Input
                      type="number"
                      value={settings.compressionGzipLevel}
                      onChange={(e) => handleInputChange('compressionGzipLevel', parseInt(e.target.value) || 6)}
                      min="1"
                      max="9"
                    />
                  </FormControl>
                  
                  <FormControl>
                    <FormLabel>Brotli压缩级别</FormLabel>
                    <Input
                      type="number"
                      value={settings.compressionBrotliLevel}
                      onChange={(e) => handleInputChange('compressionBrotliLevel', parseInt(e.target.value) || 6)}
                      min="0"
                      max="11"
                    />
                  </FormControl>
                </SimpleGrid>
                
                <Text fontSize="sm" color="gray.500">
                  💡 Brotli压缩效果更好但CPU消耗稍高，Gzip兼容性更好。建议同时启用以获得最佳效果。
                </Text>
              </>
            )}
          </VStack>
        </CardBody>
      </Card>

      {/* 上游缓存设置 */}
      <Card mt={6}>
        <CardHeader>
          <Heading size="md">上游缓存设置</Heading>
        </CardHeader>
        <CardBody>
          <VStack spacing={4} align="stretch">
            <FormControl display="flex" alignItems="center">
              <FormLabel mb="0">启用上游缓存</FormLabel>
              <Switch
                isChecked={settings.upstreamCacheEnabled}
                onChange={(e) => handleInputChange('upstreamCacheEnabled', e.target.checked)}
              />
            </FormControl>
            
            {settings.upstreamCacheEnabled && (
              <>
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                  <FormControl>
                    <FormLabel>缓存目录</FormLabel>
                    <Input
                      value={settings.upstreamCacheDir}
                      onChange={(e) => handleInputChange('upstreamCacheDir', e.target.value)}
                      placeholder="./data/upstream-cache"
                    />
                  </FormControl>
                  
                  <FormControl>
                    <FormLabel>最大缓存大小 (MB)</FormLabel>
                    <Input
                      type="number"
                      value={settings.upstreamCacheMaxSize}
                      onChange={(e) => handleInputChange('upstreamCacheMaxSize', parseInt(e.target.value) || 1024)}
                      min="100"
                      max="10240"
                    />
                  </FormControl>
                  
                  <FormControl>
                    <FormLabel>默认TTL (秒)</FormLabel>
                    <Input
                      type="number"
                      value={settings.upstreamCacheDefaultTTL}
                      onChange={(e) => handleInputChange('upstreamCacheDefaultTTL', parseInt(e.target.value) || 3600)}
                      min="60"
                      max="86400"
                    />
                  </FormControl>
                  
                  <FormControl display="flex" alignItems="center">
                    <FormLabel mb="0">遵循上游Cache-Control</FormLabel>
                    <Switch
                      isChecked={settings.upstreamCacheRespectUpstream}
                      onChange={(e) => handleInputChange('upstreamCacheRespectUpstream', e.target.checked)}
                    />
                  </FormControl>
                </SimpleGrid>
                
                <Text fontSize="sm" color="gray.500">
                  💡 上游缓存会自动缓存静态文件（CSS、JS、图片等），遵循Cache-Control策略，显著提升访问速度。
                </Text>
              </>
            )}
          </VStack>
        </CardBody>
      </Card>

      {/* 通知设置 */}
      <Card mt={6}>
        <CardHeader>
          <Heading size="md">{t.settings.notificationSettings}</Heading>
        </CardHeader>
        <CardBody>
          <VStack spacing={6} align="stretch">
            <FormControl display="flex" alignItems="center">
              <FormLabel mb="0">{t.settings.enableNotifications}</FormLabel>
              <Switch
                isChecked={settings.enableNotifications}
                onChange={(e) => handleInputChange('enableNotifications', e.target.checked)}
              />
            </FormControl>
            
            {/* 邮件通知配置 */}
            <Box border="1px" borderColor="gray.200" borderRadius="md" p={4}>
              <Heading size="sm" mb={4}>{t.settings.emailNotification}</Heading>
              <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                <FormControl>
                  <FormLabel>{t.settings.smtpServer}</FormLabel>
                  <Input
                    value={settings.smtpHost || ''}
                    onChange={(e) => handleInputChange('smtpHost', e.target.value)}
                    placeholder="smtp.gmail.com"
                  />
                </FormControl>
                <FormControl>
                  <FormLabel>{t.settings.port}</FormLabel>
                  <Input
                    value={settings.smtpPort || ''}
                    onChange={(e) => handleInputChange('smtpPort', e.target.value)}
                    placeholder="587"
                    type="number"
                  />
                </FormControl>
                <FormControl>
                  <FormLabel>{t.settings.username}</FormLabel>
                  <Input
                    value={settings.smtpUsername || ''}
                    onChange={(e) => handleInputChange('smtpUsername', e.target.value)}
                    placeholder="your-email@gmail.com"
                  />
                </FormControl>
                <FormControl>
                  <FormLabel>{t.settings.password}</FormLabel>
                  <Input
                    value={settings.smtpPassword || ''}
                    onChange={(e) => handleInputChange('smtpPassword', e.target.value)}
                    placeholder="your-app-password"
                    type="password"
                  />
                </FormControl>
                <FormControl>
                  <FormLabel>{t.settings.sender}</FormLabel>
                  <Input
                    value={settings.smtpFrom || ''}
                    onChange={(e) => handleInputChange('smtpFrom', e.target.value)}
                    placeholder="your-email@gmail.com"
                  />
                </FormControl>
                <FormControl>
                  <FormLabel>{t.settings.recipient}</FormLabel>
                  <Input
                    value={settings.smtpTo || ''}
                    onChange={(e) => handleInputChange('smtpTo', e.target.value)}
                    placeholder="admin@example.com,support@example.com"
                  />
                </FormControl>
              </SimpleGrid>
              <FormControl display="flex" alignItems="center" mt={4}>
                <FormLabel mb="0">{t.settings.enableTLS}</FormLabel>
                <Switch
                  isChecked={settings.smtpUseTLS || false}
                  onChange={(e) => handleInputChange('smtpUseTLS', e.target.checked)}
                />
              </FormControl>
            </Box>

            {/* Slack通知配置 */}
            <Box border="1px" borderColor="gray.200" borderRadius="md" p={4}>
              <Heading size="sm" mb={4}>{t.settings.slackNotification}</Heading>
              <FormControl>
                <FormLabel>{t.settings.webhookUrl}</FormLabel>
                <Input
                  value={settings.slackWebhook || ''}
                  onChange={(e) => handleInputChange('slackWebhook', e.target.value)}
                  placeholder="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
                />
                <Text fontSize="sm" color="gray.500" mt={1}>
                  {t.settings.createSlackWebhook}
                </Text>
              </FormControl>
            </Box>

            {/* 其他通知渠道 */}
            <Box border="1px" borderColor="gray.200" borderRadius="md" p={4}>
              <Heading size="sm" mb={4}>其他通知渠道 (Webhook)</Heading>
              <FormControl>
                <FormLabel>Webhook URL</FormLabel>
                <Input
                  value={settings.webhookUrl || ''}
                  onChange={(e) => handleInputChange('webhookUrl', e.target.value)}
                  placeholder="https://your-webhook-endpoint.com/notify"
                />
                <Text fontSize="sm" color="gray.500" mt={1}>
                  支持自动格式适配的平台：
                </Text>
                <VStack align="start" spacing={1} mt={2}>
                  <Text fontSize="xs" color="blue.600">
                    • 企业微信: qyapi.weixin.qq.com
                  </Text>
                  <Text fontSize="xs" color="blue.600">
                    • 飞书: open.feishu.cn
                  </Text>
                  <Text fontSize="xs" color="blue.600">
                    • 钉钉: oapi.dingtalk.com
                  </Text>
                  <Text fontSize="xs" color="blue.600">
                    • Slack: hooks.slack.com
                  </Text>
                  <Text fontSize="xs" color="blue.600">
                    • Discord: discord.com
                  </Text>
                  <Text fontSize="xs" color="blue.600">
                    • Telegram: api.telegram.org
                  </Text>
                  <Text fontSize="xs" color="gray.500">
                    • 其他: 通用JSON格式
                  </Text>
                </VStack>
              </FormControl>
            </Box>
            
            {/* 保存按钮 */}
            <Button 
              colorScheme="blue" 
              onClick={saveNotificationSettings}
              isLoading={loading}
              loadingText={t.settings.saving}
            >
              {t.settings.saveNotificationSettings}
            </Button>
          </VStack>
        </CardBody>
      </Card>
    </Box>
  )
}

export default Settings

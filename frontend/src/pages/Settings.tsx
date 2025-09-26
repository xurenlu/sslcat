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

const Settings: React.FC = () => {
  const { adminPrefix } = useConfig()
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

  const handleInputChange = (field: string, value: string | boolean) => {
    setSettings(prev => ({
      ...prev,
      [field]: value,
    }))
  }

  const saveSettings = async () => {
    setLoading(true)
    try {
      // TODO: 实际的 API 调用
      // const response = await fetch('/api/settings', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify(settings),
      // })
      
      setTimeout(() => {
        toast({
          title: '设置保存成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        setLoading(false)
      }, 1000)
    } catch (error) {
      toast({
        title: '保存失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
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
          <Heading size="lg">系统设置</Heading>
        </HStack>
        <HStack>
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            onClick={resetSettings}
            variant="outline"
          >
            重置
          </Button>
          <Button
            leftIcon={<Icon as={FiSave} />}
            onClick={saveSettings}
            isLoading={loading}
            colorScheme="blue"
          >
            保存设置
          </Button>
        </HStack>
      </HStack>

      <SimpleGrid columns={{ base: 1, lg: 2 }} spacing={6}>
        {/* 基础设置 */}
        <Card>
          <CardHeader>
            <Heading size="md">基础设置</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl>
                <FormLabel>管理界面前缀</FormLabel>
                <Input
                  value={settings.adminPrefix}
                  onChange={(e) => handleInputChange('adminPrefix', e.target.value)}
                  placeholder="/admin"
                />
              </FormControl>
              
              <FormControl>
                <FormLabel>HTTP端口</FormLabel>
                <Input
                  value={settings.httpPort}
                  onChange={(e) => handleInputChange('httpPort', e.target.value)}
                  placeholder="80"
                  type="number"
                />
              </FormControl>
              
              <FormControl>
                <FormLabel>HTTPS端口</FormLabel>
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
            <Heading size="md">SSL设置</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">自动SSL证书</FormLabel>
                <Switch
                  isChecked={settings.autoSSL}
                  onChange={(e) => handleInputChange('autoSSL', e.target.checked)}
                />
              </FormControl>
              
              <FormControl>
                <FormLabel>Let's Encrypt 邮箱</FormLabel>
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
            <Heading size="md">安全设置</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">启用DDoS防护</FormLabel>
                <Switch
                  isChecked={settings.enableDDoSProtection}
                  onChange={(e) => handleInputChange('enableDDoSProtection', e.target.checked)}
                />
              </FormControl>
              
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">启用访问限制</FormLabel>
                <Switch
                  isChecked={settings.enableRateLimit}
                  onChange={(e) => handleInputChange('enableRateLimit', e.target.checked)}
                />
              </FormControl>
              
              <FormControl>
                <FormLabel>每分钟最大请求数</FormLabel>
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
            <Heading size="md">日志设置</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">启用访问日志</FormLabel>
                <Switch
                  isChecked={settings.enableAccessLog}
                  onChange={(e) => handleInputChange('enableAccessLog', e.target.checked)}
                />
              </FormControl>
              
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">启用错误日志</FormLabel>
                <Switch
                  isChecked={settings.enableErrorLog}
                  onChange={(e) => handleInputChange('enableErrorLog', e.target.checked)}
                />
              </FormControl>
              
              <FormControl>
                <FormLabel>日志级别</FormLabel>
                <Select
                  value={settings.logLevel}
                  onChange={(e) => handleInputChange('logLevel', e.target.value)}
                >
                  <option value="debug">调试 (Debug)</option>
                  <option value="info">信息 (Info)</option>
                  <option value="warn">警告 (Warning)</option>
                  <option value="error">错误 (Error)</option>
                </Select>
              </FormControl>
            </VStack>
          </CardBody>
        </Card>
      </SimpleGrid>

      {/* 通知设置 */}
      <Card mt={6}>
        <CardHeader>
          <Heading size="md">通知设置</Heading>
        </CardHeader>
        <CardBody>
          <VStack spacing={6} align="stretch">
            <FormControl display="flex" alignItems="center">
              <FormLabel mb="0">启用通知</FormLabel>
              <Switch
                isChecked={settings.enableNotifications}
                onChange={(e) => handleInputChange('enableNotifications', e.target.checked)}
              />
            </FormControl>
            
            {/* 邮件通知配置 */}
            <Box border="1px" borderColor="gray.200" borderRadius="md" p={4}>
              <Heading size="sm" mb={4}>邮件通知 (SMTP)</Heading>
              <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                <FormControl>
                  <FormLabel>SMTP服务器</FormLabel>
                  <Input
                    value={settings.smtpHost || ''}
                    onChange={(e) => handleInputChange('smtpHost', e.target.value)}
                    placeholder="smtp.gmail.com"
                  />
                </FormControl>
                <FormControl>
                  <FormLabel>端口</FormLabel>
                  <Input
                    value={settings.smtpPort || ''}
                    onChange={(e) => handleInputChange('smtpPort', e.target.value)}
                    placeholder="587"
                    type="number"
                  />
                </FormControl>
                <FormControl>
                  <FormLabel>用户名</FormLabel>
                  <Input
                    value={settings.smtpUsername || ''}
                    onChange={(e) => handleInputChange('smtpUsername', e.target.value)}
                    placeholder="your-email@gmail.com"
                  />
                </FormControl>
                <FormControl>
                  <FormLabel>密码</FormLabel>
                  <Input
                    value={settings.smtpPassword || ''}
                    onChange={(e) => handleInputChange('smtpPassword', e.target.value)}
                    placeholder="your-app-password"
                    type="password"
                  />
                </FormControl>
                <FormControl>
                  <FormLabel>发件人</FormLabel>
                  <Input
                    value={settings.smtpFrom || ''}
                    onChange={(e) => handleInputChange('smtpFrom', e.target.value)}
                    placeholder="your-email@gmail.com"
                  />
                </FormControl>
                <FormControl>
                  <FormLabel>收件人</FormLabel>
                  <Input
                    value={settings.smtpTo || ''}
                    onChange={(e) => handleInputChange('smtpTo', e.target.value)}
                    placeholder="admin@example.com,support@example.com"
                  />
                </FormControl>
              </SimpleGrid>
              <FormControl display="flex" alignItems="center" mt={4}>
                <FormLabel mb="0">启用TLS</FormLabel>
                <Switch
                  isChecked={settings.smtpUseTLS || false}
                  onChange={(e) => handleInputChange('smtpUseTLS', e.target.checked)}
                />
              </FormControl>
            </Box>

            {/* Slack通知配置 */}
            <Box border="1px" borderColor="gray.200" borderRadius="md" p={4}>
              <Heading size="sm" mb={4}>Slack通知</Heading>
              <FormControl>
                <FormLabel>Webhook URL</FormLabel>
                <Input
                  value={settings.slackWebhook || ''}
                  onChange={(e) => handleInputChange('slackWebhook', e.target.value)}
                  placeholder="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
                />
                <Text fontSize="sm" color="gray.500" mt={1}>
                  在Slack中创建Incoming Webhook获取URL
                </Text>
              </FormControl>
            </Box>

            {/* 其他通知渠道 */}
            <Box border="1px" borderColor="gray.200" borderRadius="md" p={4}>
              <Heading size="sm" mb={4}>其他通知渠道</Heading>
              <FormControl>
                <FormLabel>通用Webhook URL</FormLabel>
                <Input
                  value={settings.webhookUrl || ''}
                  onChange={(e) => handleInputChange('webhookUrl', e.target.value)}
                  placeholder="https://your-webhook-endpoint.com/notify"
                />
                <Text fontSize="sm" color="gray.500" mt={1}>
                  支持钉钉、企业微信等Webhook通知
                </Text>
              </FormControl>
            </Box>
            
            {/* 保存按钮 */}
            <Button 
              colorScheme="blue" 
              onClick={saveNotificationSettings}
              isLoading={loading}
              loadingText="保存中..."
            >
              保存通知设置
            </Button>
          </VStack>
        </CardBody>
      </Card>
    </Box>
  )
}

export default Settings

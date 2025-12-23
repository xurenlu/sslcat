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
  RadioGroup,
  Radio,
  Badge,
  Alert,
  AlertIcon,
  AlertDescription,
} from '@chakra-ui/react'
import {
  FiSettings,
  FiSave,
  FiRefreshCw,
} from 'react-icons/fi'
import { useConfig } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'
import { TOAST_DURATION } from '../constants'

const Settings: React.FC = () => {
  const { adminPrefix, refreshConfig, changeAdminPrefix } = useConfig()
  const t = useTranslation()
  const [settings, setSettings] = useState({
    // 基础设置
    adminPrefix: adminPrefix,
    // 新的端口配置
    portMode: 'standard', // 'standard' | 'custom'
    customPort: 8080,
    enableHttps: true,
    
    // SSL设置
    autoSSL: true,
    letsEncryptEmail: 'admin@example.com',
    sslProvider: 'letsencrypt',
    sslStaging: false, // 是否使用 staging 环境
    
    // 安全设置
    enableDDoSProtection: true,
    maxRequestsPerMinute: '1000',
    enableRateLimit: true,
    
    // 日志设置
    enableAccessLog: false,
    enableErrorLog: true,
    logLevel: 'info',

    // 缓存 & 内存设置
    sharedCacheMaxSizeMB: 64,
    memoryMaxUsagePercent: 20,
    memoryReleaseCooldownSec: 300,
    
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
    notificationChannels: 'email,webhook',
    minNotificationLevel: 'info', // 最小通知级别
    // 渠道启用状态
    emailEnabled: false, // 邮箱通知是否启用
    webhookEnabled: false, // Webhook通知是否启用
    // 邮件通知配置
    emailMethod: 'smtp', // 'smtp' | 'sendmail' | 'resend' | 'mailgun' | 'sendgrid'
    smtpHost: '',
    smtpPort: '587',
    smtpUsername: '',
    smtpPassword: '',
    smtpFrom: '',
    smtpTo: '',
    smtpUseTLS: true,
    // Sendmail 配置
    sendmailCommand: '/usr/sbin/sendmail',
    sendmailArgs: '-t',
    // Resend 配置
    resendApiKey: '',
    resendFrom: '',
    resendTo: '',
    // Mailgun 配置
    mailgunApiKey: '',
    mailgunDomain: '',
    mailgunFrom: '',
    mailgunTo: '',
    // SendGrid 配置
    sendgridApiKey: '',
    sendgridFrom: '',
    sendgridTo: '',
    // Webhook配置（包括Slack、企业微信、飞书等）
    webhookUrls: [''],
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

  // 加载基础配置（提取为独立方法）
  const loadBasicConfig = async () => {
    try {
      const response = await fetch(`${adminPrefix}/api/settings`, {
        method: 'GET',
          credentials: 'include',
        })
        
        if (response.ok) {
          const data = await response.json()
          if (data.success && data.data) {
            const config = data.data
            setSettings(prev => ({
              ...prev,
              // 基础设置
              portMode: config.server?.port_mode || 'standard',
              customPort: config.server?.custom_port || 8080,
              enableHttps: config.server?.enable_https !== false,
              
              // SSL设置
              autoSSL: !config.ssl?.disable_self_signed || true,
              letsEncryptEmail: config.ssl?.email || '',
              sslStaging: config.ssl?.staging || false,
              
              // 安全设置
              enableDDoSProtection: config.security?.enable_ddos || false,
              maxRequestsPerMinute: config.security?.max_attempts_5min?.toString() || '1000',
              enableRateLimit: config.security?.enable_ua_filter || false,
              
              // 日志设置
              enableAccessLog: config.server?.access_log_enabled || false,
              logLevel: config.server?.log_level || 'info',

              // 缓存 & 内存
              sharedCacheMaxSizeMB: config.server?.shared_cache_max_size_mb || 64,
              memoryMaxUsagePercent: config.monitoring?.memory_max_usage_percent || 20,
              memoryReleaseCooldownSec: config.monitoring?.memory_release_cooldown_sec || 300,
            }))
          }
        }
      } catch (error) {
        console.error(t.settings.basic_config_load_failed, error)
      }
  }

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
            minNotificationLevel: config.min_notification_level || 'info', // 加载最小通知级别
            emailEnabled: config.channels?.email?.enabled || false, // 加载邮箱启用状态
            webhookEnabled: config.channels?.webhook?.enabled || false, // 加载webhook启用状态
            emailMethod: config.channels?.email?.method || 'smtp', // 加载邮件发送方式
            // SMTP 配置
            smtpHost: config.channels?.email?.smtp_host || '',
            smtpPort: config.channels?.email?.smtp_port?.toString() || '587',
            smtpUsername: config.channels?.email?.username || '',
            smtpPassword: config.channels?.email?.password || '',
            smtpFrom: config.channels?.email?.from || '',
            smtpTo: config.channels?.email?.to?.join(',') || '',
            smtpUseTLS: config.channels?.email?.use_tls || true,
            // Sendmail 配置
            sendmailCommand: config.channels?.email?.sendmail_command || '/usr/sbin/sendmail',
            sendmailArgs: config.channels?.email?.sendmail_args || '-t',
            // Resend 配置
            resendApiKey: config.channels?.email?.resend_api_key || '',
            resendFrom: config.channels?.email?.resend_from || '',
            resendTo: config.channels?.email?.resend_to || '',
            // Mailgun 配置
            mailgunApiKey: config.channels?.email?.mailgun_api_key || '',
            mailgunDomain: config.channels?.email?.mailgun_domain || '',
            mailgunFrom: config.channels?.email?.mailgun_from || '',
            mailgunTo: config.channels?.email?.mailgun_to || '',
            // SendGrid 配置
            sendgridApiKey: config.channels?.email?.sendgrid_api_key || '',
            sendgridFrom: config.channels?.email?.sendgrid_from || '',
            sendgridTo: config.channels?.email?.sendgrid_to || '',
            webhookUrls: config.channels?.webhook?.urls || [config.channels?.webhook?.url || ''].filter(url => url !== ''),
          }))
        }
      }
    } catch (error) {
      console.error(t.settings.notification_config_load_failed, error)
    }
  }

  // 页面加载时或 adminPrefix 变化时重新加载配置
  useEffect(() => {
    if (adminPrefix) {
      // 并行加载配置
      Promise.all([
        loadBasicConfig(),
        loadNotificationConfig()
      ])
    }
  }, [adminPrefix])

  const handleInputChange = (field: string, value: string | boolean | number) => {
    setSettings(prev => ({
      ...prev,
      [field]: value,
    }))
  }

  const saveAllSettings = async () => {
    setLoading(true)
    try {
      // 并行保存基础设置和通知设置
      const [basicResponse, notificationResponse] = await Promise.all([
        // 保存基础设置
        fetch(`${adminPrefix}/api/settings/basic`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            adminPrefix: settings.adminPrefix,
            // 新的端口配置
            portMode: settings.portMode,
            customPort: settings.customPort,
            enableHttps: settings.enableHttps,
            autoSSL: settings.autoSSL,
            letsEncryptEmail: settings.letsEncryptEmail,
            sslProvider: settings.sslProvider,
            sslStaging: settings.sslStaging,
            enableDDoSProtection: settings.enableDDoSProtection,
            maxRequestsPerMinute: settings.maxRequestsPerMinute,
            enableRateLimit: settings.enableRateLimit,
            enableAccessLog: settings.enableAccessLog,
            enableErrorLog: settings.enableErrorLog,
            logLevel: settings.logLevel,
            // 压缩设置
            compressionEnabled: settings.compressionEnabled,
            compressionAlgorithms: settings.compressionAlgorithms,
            compressionMinSize: settings.compressionMinSize,
            compressionGzipLevel: settings.compressionGzipLevel,
            compressionBrotliLevel: settings.compressionBrotliLevel,
            // 上游缓存设置
            upstreamCacheEnabled: settings.upstreamCacheEnabled,
            upstreamCacheDir: settings.upstreamCacheDir,
            upstreamCacheMaxSize: settings.upstreamCacheMaxSize,
            upstreamCacheDefaultTTL: settings.upstreamCacheDefaultTTL,
            upstreamCacheRespectUpstream: settings.upstreamCacheRespectUpstream,
            sharedCacheMaxSizeMB: settings.sharedCacheMaxSizeMB,
            memoryMaxUsagePercent: settings.memoryMaxUsagePercent,
            memoryReleaseCooldownSec: settings.memoryReleaseCooldownSec,
          }),
        }),
        // 保存通知设置
        fetch(`${adminPrefix}/api/notifications/config`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            min_notification_level: settings.minNotificationLevel,
            channels: {
              email: {
                enabled: settings.emailEnabled, // 使用开关状态
                method: settings.emailMethod || 'smtp', // 邮件发送方式
                // SMTP 配置
                smtp_host: settings.smtpHost,
                smtp_port: parseInt(settings.smtpPort) || 587,
                username: settings.smtpUsername,
                password: settings.smtpPassword,
                from: settings.smtpFrom,
                to: settings.smtpTo ? settings.smtpTo.split(',').map(email => email.trim()) : [],
                use_tls: settings.smtpUseTLS,
                // Sendmail 配置
                sendmail_command: settings.sendmailCommand,
                sendmail_args: settings.sendmailArgs,
                // Resend 配置
                resend_api_key: settings.resendApiKey,
                resend_from: settings.resendFrom,
                resend_to: settings.resendTo,
                // Mailgun 配置
                mailgun_api_key: settings.mailgunApiKey,
                mailgun_domain: settings.mailgunDomain,
                mailgun_from: settings.mailgunFrom,
                mailgun_to: settings.mailgunTo,
                // SendGrid 配置
                sendgrid_api_key: settings.sendgridApiKey,
                sendgrid_from: settings.sendgridFrom,
                sendgrid_to: settings.sendgridTo,
              },
              webhook: {
                enabled: settings.webhookEnabled, // 使用开关状态
                urls: settings.webhookUrls.filter(url => url.trim() !== ''),
                headers: { 'Content-Type': 'application/json' },
                timeout: 10,
              },
            },
          }),
        })
      ])

      // 检查基础设置保存结果
      if (!basicResponse.ok) {
        const errorData = await basicResponse.json()
        throw new Error(errorData.message || t.settings.basic_config_save_failed)
      }

      // 检查通知设置保存结果
      if (!notificationResponse.ok) {
        const errorData = await notificationResponse.json()
        throw new Error(errorData.message || t.settings.notification_config_save_failed)
      }

      toast({
        title: t.settings.save_success,
        status: 'success',
        duration: TOAST_DURATION.SHORT,
        isClosable: true,
      })
      
      // 重新加载配置以显示最新保存的值
      await Promise.all([
        loadBasicConfig(),
        loadNotificationConfig()
      ])
      
      // 如果adminPrefix发生变化，使用新的changeAdminPrefix函数
      if (settings.adminPrefix !== adminPrefix) {
        await changeAdminPrefix(
          settings.adminPrefix,
          (newPrefix) => {
            // 成功回调
            toast({
              title: t.settings.admin_prefix_change_success,
              description: `${t.settings.admin_prefix_changed}: ${newPrefix}，${t.settings.notification_sent}`,
              status: 'success',
              duration: TOAST_DURATION.MEDIUM,
              isClosable: true,
            })
          },
          (error) => {
            // 错误回调
            toast({
              title: t.settings.admin_prefix_change_failed,
              description: error.message,
              status: 'error',
              duration: TOAST_DURATION.MEDIUM,
              isClosable: true,
            })
          }
        )
      }
    } catch (error) {
      toast({
        title: t.settings.save_failed,
        description: error instanceof Error ? error.message : t.common.unknownError,
        status: 'error',
        duration: TOAST_DURATION.SHORT,
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
      // 新的端口配置
      portMode: 'standard',
      customPort: 8080,
      enableHttps: true,
      autoSSL: true,
      letsEncryptEmail: 'admin@example.com',
      sslProvider: 'letsencrypt',
      sslStaging: false,
      enableDDoSProtection: true,
      maxRequestsPerMinute: '1000',
      enableRateLimit: true,
      enableAccessLog: false,
      enableErrorLog: true,
      logLevel: 'info',
      // 缓存 & 内存设置
      sharedCacheMaxSizeMB: 64,
      memoryMaxUsagePercent: 20,
      memoryReleaseCooldownSec: 300,
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
      notificationChannels: 'email,webhook',
      minNotificationLevel: 'info', // 最小通知级别
      // 渠道启用状态
      emailEnabled: false,
      webhookEnabled: false,
      // 邮件通知配置
      emailMethod: 'smtp',
      smtpHost: '',
      smtpPort: '587',
      smtpUsername: '',
      smtpPassword: '',
      smtpFrom: '',
      smtpTo: '',
      smtpUseTLS: true,
      // Sendmail 配置
      sendmailCommand: '/usr/sbin/sendmail',
      sendmailArgs: '-t',
      // Resend 配置
      resendApiKey: '',
      resendFrom: '',
      resendTo: '',
      // Mailgun 配置
      mailgunApiKey: '',
      mailgunDomain: '',
      mailgunFrom: '',
      mailgunTo: '',
      // SendGrid 配置
      sendgridApiKey: '',
      sendgridFrom: '',
      sendgridTo: '',
      // Webhook配置（包括Slack、企业微信、飞书等）
      webhookUrls: [''],
    })
    
    toast({
      title: t.settings.reset_success,
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
              
              {/* 端口模式选择 */}
              <FormControl>
                <FormLabel>{t.settings.portMode}</FormLabel>
                <RadioGroup 
                  value={settings.portMode} 
                  onChange={(value) => handleInputChange('portMode', value)}
                >
                  <VStack align="start" spacing={3}>
                    <Radio value="standard">
                      <VStack align="start" spacing={1}>
                        <Text fontWeight="bold">{t.settings.standardMode}</Text>
                        <Text fontSize="sm" color="gray.600">
                          {t.settings.standardModeDesc}
                        </Text>
                        <Text fontSize="sm" color="green.600">
                          <div dangerouslySetInnerHTML={{ __html: t.settings.standardModeFeatures }} />
                        </Text>
                      </VStack>
                    </Radio>
                    <Radio value="custom">
                      <VStack align="start" spacing={1}>
                        <Text fontWeight="bold">{t.settings.customMode}</Text>
                        <Text fontSize="sm" color="gray.600">
                          {t.settings.customModeDesc}
                        </Text>
                        <Text fontSize="sm" color="orange.600">
                          <div dangerouslySetInnerHTML={{ __html: t.settings.customModeFeatures }} />
                        </Text>
                      </VStack>
                    </Radio>
                  </VStack>
                </RadioGroup>
              </FormControl>

              {/* 标准模式配置 */}
              {settings.portMode === 'standard' && (
                <Box p={4} bg="green.50" borderRadius="md">
                  <VStack spacing={3} align="stretch">
                    <Text fontWeight="bold" color="green.700">
                      {t.settings.standardModeConfig}
                    </Text>
                    <HStack>
                      <Text>{t.settings.httpPortLabel}</Text>
                      <Badge colorScheme="blue">80</Badge>
                    </HStack>
                    <HStack>
                      <Text>{t.settings.httpsPortLabel}</Text>
                      <Badge colorScheme="green">443</Badge>
                    </HStack>
                    <FormControl>
                      <FormLabel>{t.settings.enableHttps}</FormLabel>
                      <Switch
                        isChecked={settings.enableHttps}
                        onChange={(e) => handleInputChange('enableHttps', e.target.checked)}
                      />
                      <Text fontSize="sm" color="gray.600">
                        启用后会自动申请和管理 SSL 证书
                      </Text>
                    </FormControl>
                  </VStack>
                </Box>
              )}

              {/* 自定义模式配置 */}
              {settings.portMode === 'custom' && (
                <Box p={4} bg="orange.50" borderRadius="md">
                  <VStack spacing={3} align="stretch">
                    <Text fontWeight="bold" color="orange.700">
                      自定义端口配置
                    </Text>
                    <Alert status="warning" borderRadius="md">
                      <AlertIcon />
                      <AlertDescription>
                        自定义端口模式下，SSLcat 将仅监听指定端口，不支持 HTTPS 功能。
                        如需 HTTPS，请使用标准模式或配置反向代理。
                      </AlertDescription>
                    </Alert>
                    <FormControl>
                      <FormLabel>监听端口</FormLabel>
                      <Input
                        type="number"
                        value={settings.customPort}
                        onChange={(e) => handleInputChange('customPort', parseInt(e.target.value))}
                        placeholder="8080"
                        min="1024"
                        max="65535"
                      />
                      <Text fontSize="sm" color="gray.600">
                        建议使用 8080、3000、8000 等非特权端口
                      </Text>
                    </FormControl>
                  </VStack>
                </Box>
              )}
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

              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">使用 Staging 环境（测试）</FormLabel>
                <Switch
                  isChecked={settings.sslStaging}
                  onChange={(e) => handleInputChange('sslStaging', e.target.checked)}
                />
              </FormControl>
              <Text fontSize="sm" color="orange.600">
                ⚠️ Staging 环境签发的证书不被浏览器信任，仅用于测试。正式使用请关闭此选项。
              </Text>
              
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

      {/* 内存与缓存设置 */}
      <Card mt={6}>
        <CardHeader>
          <Heading size="md">内存与缓存设置</Heading>
        </CardHeader>
        <CardBody>
          <VStack spacing={4} align="stretch">
            <FormControl>
              <FormLabel>共享缓存最大容量 (MB)</FormLabel>
              <Input
                type="number"
                min={8}
                max={4096}
                value={settings.sharedCacheMaxSizeMB}
                onChange={(e) =>
                  handleInputChange(
                    'sharedCacheMaxSizeMB',
                    parseInt(e.target.value) || settings.sharedCacheMaxSizeMB
                  )
                }
              />
              <Text fontSize="sm" color="gray.500">
                建议不低于 8 MB，根据实际业务流量可适当增大。
              </Text>
            </FormControl>

            <FormControl>
              <FormLabel>内存释放阈值 (占系统内存百分比)</FormLabel>
              <Input
                type="number"
                min={5}
                max={90}
                step={1}
                value={settings.memoryMaxUsagePercent}
                onChange={(e) =>
                  handleInputChange(
                    'memoryMaxUsagePercent',
                    parseFloat(e.target.value) || settings.memoryMaxUsagePercent
                  )
                }
              />
              <Text fontSize="sm" color="gray.500">
                达到该占用比例时会执行 GC 并归还内存给操作系统，范围 5% ~ 90%。
              </Text>
            </FormControl>

            <FormControl>
              <FormLabel>内存释放冷却时间 (秒)</FormLabel>
              <Input
                type="number"
                min={60}
                value={settings.memoryReleaseCooldownSec}
                onChange={(e) =>
                  handleInputChange(
                    'memoryReleaseCooldownSec',
                    parseInt(e.target.value) || settings.memoryReleaseCooldownSec
                  )
                }
              />
              <Text fontSize="sm" color="gray.500">
                最小 60 秒，避免内存释放过于频繁导致性能抖动。
              </Text>
            </FormControl>
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
            {/* 最小通知级别设置 */}
            <FormControl>
              <FormLabel>最小通知级别</FormLabel>
              <Select
                value={settings.minNotificationLevel}
                onChange={(e) => handleInputChange('minNotificationLevel', e.target.value)}
                placeholder={t.settings.select_min_notification_level}
              >
                <option value="info">信息 (info) - 所有通知</option>
                <option value="warning">警告 (warning) - 警告及以上</option>
                <option value="error">错误 (error) - 错误及以上</option>
                <option value="critical">严重 (critical) - 仅严重通知</option>
              </Select>
              <Text fontSize="sm" color="gray.600" mt={1}>
                设置最小通知级别，低于此级别的通知将不会发送邮件或推送
              </Text>
            </FormControl>
            
            {/* 邮件通知配置 */}
            <Box border="1px" borderColor="gray.200" borderRadius="md" p={4}>
              <HStack justify="space-between" mb={4}>
                <Heading size="sm">{t.settings.emailNotification}</Heading>
                <FormControl display="flex" alignItems="center" width="auto">
                  <FormLabel mb="0" mr={2}>启用邮箱通知</FormLabel>
                  <Switch
                    isChecked={settings.emailEnabled}
                    onChange={(e) => handleInputChange('emailEnabled', e.target.checked)}
                  />
                </FormControl>
              </HStack>
              
              {/* 邮件发送方式选择 */}
              <FormControl mb={4}>
                <FormLabel>{t.settings.emailMethod}</FormLabel>
                <Select
                  value={settings.emailMethod || 'smtp'}
                  onChange={(e) => handleInputChange('emailMethod', e.target.value)}
                >
                  <option value="smtp">SMTP 服务器</option>
                  <option value="sendmail">系统 Sendmail</option>
                  <option value="resend">Resend 服务</option>
                  <option value="mailgun">Mailgun 服务</option>
                  <option value="sendgrid">SendGrid 服务</option>
                </Select>
              </FormControl>

              {/* SMTP 配置 */}
              {settings.emailMethod === 'smtp' && (
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
                  <FormControl display="flex" alignItems="center" mt={4}>
                    <FormLabel mb="0">{t.settings.enableTLS}</FormLabel>
                    <Switch
                      isChecked={settings.smtpUseTLS || false}
                      onChange={(e) => handleInputChange('smtpUseTLS', e.target.checked)}
                    />
                  </FormControl>
                </SimpleGrid>
              )}

              {/* Sendmail 配置 */}
              {settings.emailMethod === 'sendmail' && (
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                  <FormControl>
                    <FormLabel>Sendmail 命令</FormLabel>
                    <Input
                      value={settings.sendmailCommand || ''}
                      onChange={(e) => handleInputChange('sendmailCommand', e.target.value)}
                      placeholder="/usr/sbin/sendmail"
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel>命令参数</FormLabel>
                    <Input
                      value={settings.sendmailArgs || ''}
                      onChange={(e) => handleInputChange('sendmailArgs', e.target.value)}
                      placeholder="-t"
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel>发件人</FormLabel>
                    <Input
                      value={settings.smtpFrom || ''}
                      onChange={(e) => handleInputChange('smtpFrom', e.target.value)}
                      placeholder="noreply@example.com"
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
              )}

              {/* Resend 配置 */}
              {settings.emailMethod === 'resend' && (
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                  <FormControl>
                    <FormLabel>Resend API Key</FormLabel>
                    <Input
                      value={settings.resendApiKey || ''}
                      onChange={(e) => handleInputChange('resendApiKey', e.target.value)}
                      placeholder="re_xxxxxxxxxx"
                      type="password"
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel>发件人</FormLabel>
                    <Input
                      value={settings.resendFrom || ''}
                      onChange={(e) => handleInputChange('resendFrom', e.target.value)}
                      placeholder="noreply@example.com"
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel>收件人</FormLabel>
                    <Input
                      value={settings.resendTo || ''}
                      onChange={(e) => handleInputChange('resendTo', e.target.value)}
                      placeholder="admin@example.com,support@example.com"
                    />
                  </FormControl>
                </SimpleGrid>
              )}

              {/* Mailgun 配置 */}
              {settings.emailMethod === 'mailgun' && (
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                  <FormControl>
                    <FormLabel>Mailgun API Key</FormLabel>
                    <Input
                      value={settings.mailgunApiKey || ''}
                      onChange={(e) => handleInputChange('mailgunApiKey', e.target.value)}
                      placeholder="key-xxxxxxxxxx"
                      type="password"
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel>Mailgun Domain</FormLabel>
                    <Input
                      value={settings.mailgunDomain || ''}
                      onChange={(e) => handleInputChange('mailgunDomain', e.target.value)}
                      placeholder="mg.example.com"
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel>发件人</FormLabel>
                    <Input
                      value={settings.mailgunFrom || ''}
                      onChange={(e) => handleInputChange('mailgunFrom', e.target.value)}
                      placeholder="noreply@example.com"
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel>收件人</FormLabel>
                    <Input
                      value={settings.mailgunTo || ''}
                      onChange={(e) => handleInputChange('mailgunTo', e.target.value)}
                      placeholder="admin@example.com,support@example.com"
                    />
                  </FormControl>
                </SimpleGrid>
              )}

              {/* SendGrid 配置 */}
              {settings.emailMethod === 'sendgrid' && (
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                  <FormControl>
                    <FormLabel>SendGrid API Key</FormLabel>
                    <Input
                      value={settings.sendgridApiKey || ''}
                      onChange={(e) => handleInputChange('sendgridApiKey', e.target.value)}
                      placeholder="SG.xxxxxxxxxx"
                      type="password"
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel>发件人</FormLabel>
                    <Input
                      value={settings.sendgridFrom || ''}
                      onChange={(e) => handleInputChange('sendgridFrom', e.target.value)}
                      placeholder="noreply@example.com"
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel>收件人</FormLabel>
                    <Input
                      value={settings.sendgridTo || ''}
                      onChange={(e) => handleInputChange('sendgridTo', e.target.value)}
                      placeholder="admin@example.com,support@example.com"
                    />
                  </FormControl>
                </SimpleGrid>
              )}
            </Box>

            {/* Webhook通知配置 */}
            <Box border="1px" borderColor="gray.200" borderRadius="md" p={4}>
              <HStack justify="space-between" mb={4}>
                <Heading size="sm">Webhook 通知渠道</Heading>
                <FormControl display="flex" alignItems="center" width="auto">
                  <FormLabel mb="0" mr={2}>启用 Webhook 通知</FormLabel>
                  <Switch
                    isChecked={settings.webhookEnabled}
                    onChange={(e) => handleInputChange('webhookEnabled', e.target.checked)}
                  />
                </FormControl>
              </HStack>
              <Text fontSize="sm" color="gray.600" mb={4}>
                支持多种平台的通知，包括 Slack、企业微信、飞书、钉钉、Discord、Telegram 等
              </Text>
              <VStack spacing={3} align="stretch">
                {settings.webhookUrls.map((url, index) => (
                  <HStack key={index}>
                    <FormControl flex={1}>
                      <FormLabel fontSize="sm" mb={1}>
                        Webhook URL {index + 1}
                        {url.includes('hooks.slack.com') && <Badge ml={2} colorScheme="purple" size="sm">Slack</Badge>}
                        {url.includes('qyapi.weixin.qq.com') && <Badge ml={2} colorScheme="green" size="sm">企业微信</Badge>}
                        {url.includes('open.feishu.cn') && <Badge ml={2} colorScheme="blue" size="sm">飞书</Badge>}
                        {url.includes('oapi.dingtalk.com') && <Badge ml={2} colorScheme="orange" size="sm">钉钉</Badge>}
                        {url.includes('discord.com') && <Badge ml={2} colorScheme="purple" size="sm">Discord</Badge>}
                        {url.includes('api.telegram.org') && <Badge ml={2} colorScheme="blue" size="sm">Telegram</Badge>}
                      </FormLabel>
                      <Input
                        value={url}
                        onChange={(e) => {
                          const newUrls = [...settings.webhookUrls]
                          newUrls[index] = e.target.value
                          setSettings(prev => ({ ...prev, webhookUrls: newUrls }))
                        }}
                        placeholder={t.settings.webhook_placeholder}
                      />
                    </FormControl>
                    {settings.webhookUrls.length > 1 && (
                      <Button
                        size="sm"
                        colorScheme="red"
                        variant="outline"
                        onClick={() => {
                          const newUrls = settings.webhookUrls.filter((_, i) => i !== index)
                          setSettings(prev => ({ ...prev, webhookUrls: newUrls }))
                        }}
                        mt={6}
                      >
                        删除
                      </Button>
                    )}
                  </HStack>
                ))}
                <Button
                  size="sm"
                  colorScheme="blue"
                  variant="outline"
                  onClick={() => {
                    setSettings(prev => ({ ...prev, webhookUrls: [...prev.webhookUrls, ''] }))
                  }}
                  alignSelf="flex-start"
                >
                  添加更多 Webhook
                </Button>
                <Text fontSize="sm" color="gray.500">
                  支持自动格式适配的平台（输入URL后会自动识别）：
                </Text>
                <VStack align="start" spacing={1}>
                  <Text fontSize="xs" color="purple.600">
                    • <strong>Slack</strong>: hooks.slack.com/services/xxx
                  </Text>
                  <Text fontSize="xs" color="green.600">
                    • <strong>企业微信</strong>: qyapi.weixin.qq.com
                  </Text>
                  <Text fontSize="xs" color="blue.600">
                    • <strong>飞书</strong>: open.feishu.cn
                  </Text>
                  <Text fontSize="xs" color="orange.600">
                    • <strong>钉钉</strong>: oapi.dingtalk.com
                  </Text>
                  <Text fontSize="xs" color="purple.600">
                    • <strong>Discord</strong>: discord.com
                  </Text>
                  <Text fontSize="xs" color="blue.600">
                    • <strong>Telegram</strong>: api.telegram.org
                  </Text>
                  <Text fontSize="xs" color="gray.500">
                    • <strong>其他</strong>: 通用JSON格式
                  </Text>
                </VStack>
              </VStack>
            </Box>
            
            {/* 保存按钮 */}
            <Button 
              colorScheme="blue" 
              onClick={saveAllSettings}
              isLoading={loading}
              loadingText={t.settings.saving}
              size="lg"
              leftIcon={<Icon as={FiSave} />}
            >
{t.settings.saveSettings}
            </Button>
          </VStack>
        </CardBody>
      </Card>
    </Box>
  )
}

export default Settings

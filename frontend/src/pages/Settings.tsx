import React, { useState } from 'react'
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

const Settings: React.FC = () => {
  const [settings, setSettings] = useState({
    // 基础设置
    adminPrefix: '/admin',
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
    enableAccessLog: true,
    enableErrorLog: true,
    logLevel: 'info',
    
    // 通知设置
    enableNotifications: true,
    notificationChannels: 'email,webhook',
  })
  
  const [loading, setLoading] = useState(false)
  const toast = useToast()

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

  const resetSettings = () => {
    // 重置为默认值
    setSettings({
      adminPrefix: '/admin',
      httpPort: '80',
      httpsPort: '443',
      autoSSL: true,
      letsEncryptEmail: 'admin@example.com',
      sslProvider: 'letsencrypt',
      enableDDoSProtection: true,
      maxRequestsPerMinute: '1000',
      enableRateLimit: true,
      enableAccessLog: true,
      enableErrorLog: true,
      logLevel: 'info',
      enableNotifications: true,
      notificationChannels: 'email,webhook',
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
              
              <FormControl>
                <FormLabel>SSL提供商</FormLabel>
                <Select
                  value={settings.sslProvider}
                  onChange={(e) => handleInputChange('sslProvider', e.target.value)}
                >
                  <option value="letsencrypt">Let's Encrypt</option>
                  <option value="self-signed">自签名证书</option>
                  <option value="custom">自定义证书</option>
                </Select>
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
          <VStack spacing={4} align="stretch">
            <FormControl display="flex" alignItems="center">
              <FormLabel mb="0">启用通知</FormLabel>
              <Switch
                isChecked={settings.enableNotifications}
                onChange={(e) => handleInputChange('enableNotifications', e.target.checked)}
              />
            </FormControl>
            
            <FormControl>
              <FormLabel>通知渠道</FormLabel>
              <Input
                value={settings.notificationChannels}
                onChange={(e) => handleInputChange('notificationChannels', e.target.value)}
                placeholder="email,webhook,slack"
              />
              <Text fontSize="sm" color="gray.500" mt={1}>
                支持的渠道: email, webhook, slack, telegram, dingtalk
              </Text>
            </FormControl>
          </VStack>
        </CardBody>
      </Card>
    </Box>
  )
}

export default Settings

import React, { useState } from 'react'
import {
  Box,
  Card,
  CardBody,
  CardHeader,
  FormControl,
  FormLabel,
  Input,
  Button,
  VStack,
  HStack,
  Heading,
  Text,
  useToast,
  Alert,
  AlertIcon,
  Step,
  StepDescription,
  StepIcon,
  StepIndicator,
  StepNumber,
  StepSeparator,
  StepStatus,
  StepTitle,
  Stepper,
  useSteps,
  FormHelperText,
  InputGroup,
  InputRightElement,
  IconButton,
} from '@chakra-ui/react'
import { FiEye, FiEyeOff, FiCheck, FiMail, FiLock } from 'react-icons/fi'
import { useNavigate } from 'react-router-dom'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'

const FirstTimeSetup: React.FC = () => {
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [adminEmail, setAdminEmail] = useState('')
  const [domain, setDomain] = useState('')
  const [target, setTarget] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  
  const { adminPrefix } = useConfig()
  const navigate = useNavigate()
  const toast = useToast()

  const { activeStep, setActiveStep } = useSteps({
    index: 0,
    count: 3,
  })

  const steps = [
    { title: '修改密码', description: '设置管理员密码' },
    { title: 'SSL 配置', description: '设置管理员邮箱' },
    { title: '代理规则', description: '可选：添加首条代理' },
  ]

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    // 验证
    if (newPassword.length < 6) {
      toast({
        title: '密码太短',
        description: '密码至少需要 6 个字符',
        status: 'error',
        duration: 3000,
      })
      return
    }

    if (newPassword !== confirmPassword) {
      toast({
        title: '密码不匹配',
        description: '两次输入的密码不一致',
        status: 'error',
        duration: 3000,
      })
      return
    }

    if (!adminEmail || !adminEmail.includes('@')) {
      toast({
        title: '邮箱无效',
        description: '请输入有效的邮箱地址',
        status: 'error',
        duration: 3000,
      })
      return
    }

    setIsLoading(true)

    try {
      const formData = new URLSearchParams()
      formData.append('new_password', newPassword)
      formData.append('confirm_password', confirmPassword)
      formData.append('admin_email', adminEmail)
      if (domain) formData.append('domain', domain)
      if (target) formData.append('target', target)

      const response = await fetch(buildApiPath(adminPrefix, '/settings/first-setup'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        credentials: 'include',
        body: formData
      })

      if (response.ok) {
        toast({
          title: '✅ 设置完成！',
          description: '正在跳转到管理面板...',
          status: 'success',
          duration: 3000,
        })
        
        // 延迟跳转
        setTimeout(() => {
          window.location.href = `${adminPrefix}/dashboard`
        }, 1500)
      } else {
        const error = await response.text()
        toast({
          title: '设置失败',
          description: error || '未知错误',
          status: 'error',
          duration: 5000,
        })
      }
    } catch (error) {
      toast({
        title: '设置失败',
        description: String(error),
        status: 'error',
        duration: 5000,
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <Box minH="100vh" bg="gray.50" py={10} px={4}>
      <Box maxW="4xl" mx="auto">
        <VStack spacing={6}>
          {/* 头部 */}
          <VStack spacing={2}>
            <Heading size="xl">🎉 欢迎使用 SSLcat</Heading>
            <Text color="gray.600">让我们完成初始设置</Text>
          </VStack>

          {/* 步骤指示器 */}
          <Card w="full">
            <CardBody>
              <Stepper index={activeStep}>
                {steps.map((step, index) => (
                  <Step key={index}>
                    <StepIndicator>
                      <StepStatus
                        complete={<StepIcon />}
                        incomplete={<StepNumber />}
                        active={<StepNumber />}
                      />
                    </StepIndicator>

                    <Box flexShrink={0}>
                      <StepTitle>{step.title}</StepTitle>
                      <StepDescription>{step.description}</StepDescription>
                    </Box>

                    <StepSeparator />
                  </Step>
                ))}
              </Stepper>
            </CardBody>
          </Card>

          {/* 表单 */}
          <form onSubmit={handleSubmit} style={{ width: '100%' }}>
            <VStack spacing={6}>
              {/* 步骤 1：密码设置 */}
              <Card w="full">
                <CardHeader bg="blue.50">
                  <HStack>
                    <FiLock />
                    <Heading size="md">步骤 1：设置管理员密码</Heading>
                  </HStack>
                </CardHeader>
                <CardBody>
                  <VStack spacing={4}>
                    <Alert status="warning">
                      <AlertIcon />
                      <Box>
                        <Text fontWeight="bold">安全提示</Text>
                        <Text fontSize="sm">
                          默认密码 admin*9527 不安全，请立即修改为强密码
                        </Text>
                      </Box>
                    </Alert>

                    <FormControl isRequired>
                      <FormLabel>新密码</FormLabel>
                      <InputGroup>
                        <Input
                          type={showPassword ? 'text' : 'password'}
                          value={newPassword}
                          onChange={(e) => setNewPassword(e.target.value)}
                          placeholder="至少 6 个字符"
                        />
                        <InputRightElement>
                          <IconButton
                            aria-label={showPassword ? '隐藏密码' : '显示密码'}
                            icon={showPassword ? <FiEyeOff /> : <FiEye />}
                            onClick={() => setShowPassword(!showPassword)}
                            variant="ghost"
                            size="sm"
                          />
                        </InputRightElement>
                      </InputGroup>
                      <FormHelperText>建议使用大小写字母、数字和特殊字符的组合</FormHelperText>
                    </FormControl>

                    <FormControl isRequired>
                      <FormLabel>确认新密码</FormLabel>
                      <InputGroup>
                        <Input
                          type={showConfirm ? 'text' : 'password'}
                          value={confirmPassword}
                          onChange={(e) => setConfirmPassword(e.target.value)}
                          placeholder="再次输入新密码"
                        />
                        <InputRightElement>
                          <IconButton
                            aria-label={showConfirm ? '隐藏密码' : '显示密码'}
                            icon={showConfirm ? <FiEyeOff /> : <FiEye />}
                            onClick={() => setShowConfirm(!showConfirm)}
                            variant="ghost"
                            size="sm"
                          />
                        </InputRightElement>
                      </InputGroup>
                      {newPassword && confirmPassword && newPassword !== confirmPassword && (
                        <Text color="red.500" fontSize="sm" mt={1}>两次密码不一致</Text>
                      )}
                    </FormControl>
                  </VStack>
                </CardBody>
              </Card>

              {/* 步骤 2：SSL 配置 */}
              <Card w="full">
                <CardHeader bg="green.50">
                  <HStack>
                    <FiMail />
                    <Heading size="md">步骤 2：SSL 配置</Heading>
                  </HStack>
                </CardHeader>
                <CardBody>
                  <VStack spacing={4}>
                    <FormControl isRequired>
                      <FormLabel>管理员邮箱</FormLabel>
                      <Input
                        type="email"
                        value={adminEmail}
                        onChange={(e) => setAdminEmail(e.target.value)}
                        placeholder="admin@example.com"
                      />
                      <FormHelperText>
                        用于 Let's Encrypt 证书申请、到期提醒和系统通知
                      </FormHelperText>
                    </FormControl>
                  </VStack>
                </CardBody>
              </Card>

              {/* 步骤 3：代理规则（可选） */}
              <Card w="full">
                <CardHeader bg="purple.50">
                  <HStack>
                    <FiCheck />
                    <Heading size="md">步骤 3：添加首条代理规则（可选）</Heading>
                  </HStack>
                </CardHeader>
                <CardBody>
                  <Alert status="info" mb={4}>
                    <AlertIcon />
                    <Text fontSize="sm">这一步可以跳过，稍后在管理面板中添加</Text>
                  </Alert>

                  <VStack spacing={4}>
                    <FormControl>
                      <FormLabel>域名</FormLabel>
                      <Input
                        value={domain}
                        onChange={(e) => setDomain(e.target.value)}
                        placeholder="example.com"
                      />
                    </FormControl>

                    <FormControl>
                      <FormLabel>目标地址</FormLabel>
                      <Input
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        placeholder="http://127.0.0.1:8080"
                      />
                      <FormHelperText>包含协议和端口，如 http://localhost:3000</FormHelperText>
                    </FormControl>
                  </VStack>
                </CardBody>
              </Card>

              {/* 提交按钮 */}
              <HStack w="full" justify="flex-end">
                <Button
                  type="submit"
                  colorScheme="blue"
                  size="lg"
                  isLoading={isLoading}
                  loadingText="设置中..."
                  leftIcon={<FiCheck />}
                >
                  完成设置
                </Button>
              </HStack>
            </VStack>
          </form>
        </VStack>
      </Box>
    </Box>
  )
}

export default FirstTimeSetup


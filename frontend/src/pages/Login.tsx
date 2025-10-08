import React, { useState, useEffect } from 'react'
import {
  Box,
  Card,
  CardBody,
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
  Spinner,
  Center,
  Image,
  IconButton,
  InputGroup,
  InputLeftElement,
  PinInput,
  PinInputField,
} from '@chakra-ui/react'
import { FiShield, FiUser, FiLock, FiRefreshCw, FiSmartphone } from 'react-icons/fi'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'

interface SystemConfig {
  require_captcha?: boolean
  require_totp?: boolean
}

const Login: React.FC = () => {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [captchaText, setCaptchaText] = useState('')
  const [captchaSessionId, setCaptchaSessionId] = useState('')
  const [captchaImageUrl, setCaptchaImageUrl] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [systemConfig, setSystemConfig] = useState<SystemConfig>({})
  
  const { login, isAuthenticated, isLoading: authLoading } = useAuth()
  const { adminPrefix } = useConfig()
  const navigate = useNavigate()
  const toast = useToast()

  // 加载系统配置（检查是否需要验证码和TOTP）
  useEffect(() => {
    loadSystemConfig()
  }, [adminPrefix])

  // 如果已经登录，重定向到仪表板
  useEffect(() => {
    if (isAuthenticated) {
      navigate(`${adminPrefix}/dashboard`)
    }
  }, [isAuthenticated, navigate, adminPrefix])

  // 加载验证码（如果需要）
  useEffect(() => {
    if (systemConfig.require_captcha) {
      loadCaptcha()
    }
  }, [systemConfig.require_captcha, adminPrefix])

  const loadSystemConfig = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/settings'), {
        credentials: 'include'
      })
      if (response.ok) {
        const data = await response.json()
        setSystemConfig({
          require_captcha: data.security?.enable_captcha || false,
          require_totp: data.server?.enable_totp || false
        })
      }
    } catch (error) {
      console.error('Failed to load system config:', error)
    }
  }

  const loadCaptcha = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/captcha/image') + '?_=' + Date.now(), {
        credentials: 'include'
      })
      if (response.ok) {
        const sessionId = response.headers.get('X-Captcha-Session')
        if (sessionId) {
          setCaptchaSessionId(sessionId)
        }
        const blob = await response.blob()
        const objectUrl = URL.createObjectURL(blob)
        setCaptchaImageUrl(objectUrl)
      }
    } catch (error) {
      console.error('Failed to load captcha:', error)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError('')

    // 验证必填项
    if (systemConfig.require_captcha && !captchaText) {
      setError('请输入验证码')
      setIsLoading(false)
      return
    }

    if (systemConfig.require_totp && totpCode.length !== 6) {
      setError('请输入 6 位 TOTP 验证码')
      setIsLoading(false)
      return
    }

    try {
      // 构建登录请求数据
      const loginData: any = {
        username,
        password
      }

      // 添加验证码（如果需要）
      if (systemConfig.require_captcha) {
        loginData.captcha_text = captchaText
        loginData.captcha_session_id = captchaSessionId
      }

      // 添加 TOTP（如果需要）
      if (systemConfig.require_totp) {
        loginData.totp_code = totpCode
      }

      // 直接调用 API（绕过 AuthContext 的简单登录方法）
      const response = await fetch(buildApiPath(adminPrefix, '/api/auth/login'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(loginData),
      })

      if (response.ok) {
        const userData = await response.json()
        toast({
          title: '登录成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        // 强制重新加载以更新认证状态
        window.location.href = `${adminPrefix}/dashboard`
      } else {
        const errorData = await response.json()
        setError(errorData.error || '用户名或密码错误')
        
        // 如果是验证码错误，重新加载验证码
        if (systemConfig.require_captcha) {
          loadCaptcha()
          setCaptchaText('')
        }
        
        // 清空 TOTP
        if (systemConfig.require_totp) {
          setTotpCode('')
        }
      }
    } catch (err) {
      setError('登录失败，请重试')
      console.error('Login error:', err)
      
      // 重新加载验证码
      if (systemConfig.require_captcha) {
        loadCaptcha()
      }
    } finally {
      setIsLoading(false)
    }
  }

  if (authLoading) {
    return (
      <Center h="100vh">
        <Spinner size="xl" />
      </Center>
    )
  }

  return (
    <Box
      minH="100vh"
      bgGradient="linear(to-br, blue.400, purple.500)"
      display="flex"
      alignItems="center"
      justifyContent="center"
      p={4}
    >
      <Card maxW="md" w="full" boxShadow="xl">
        <CardBody p={8}>
          <VStack spacing={6}>
            {/* 头部 */}
            <VStack spacing={2}>
              <Box
                p={3}
                borderRadius="full"
                bg="blue.500"
                color="white"
                display="flex"
                alignItems="center"
                justifyContent="center"
              >
                <FiShield size={24} />
              </Box>
              <Heading size="lg" textAlign="center">
                SSLcat 管理面板
              </Heading>
              <Text color="gray.600" textAlign="center">
                请输入您的登录凭据
              </Text>
            </VStack>

            {/* 错误提示 */}
            {error && (
              <Alert status="error" borderRadius="md">
                <AlertIcon />
                {error}
              </Alert>
            )}

            {/* 登录表单 */}
            <Box w="full">
              <form onSubmit={handleSubmit}>
                <VStack spacing={4}>
                  <FormControl isRequired>
                    <FormLabel>用户名</FormLabel>
                    <Input
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      placeholder="请输入用户名"
                      size="lg"
                      isDisabled={isLoading}
                    />
                  </FormControl>

                  <FormControl isRequired>
                    <FormLabel>密码</FormLabel>
                    <InputGroup>
                      <InputLeftElement pointerEvents="none" h="full">
                        <FiLock color="gray" />
                      </InputLeftElement>
                      <Input
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="请输入密码"
                        size="lg"
                        isDisabled={isLoading}
                      />
                    </InputGroup>
                  </FormControl>

                  {/* 图形验证码 */}
                  {systemConfig.require_captcha && (
                    <FormControl isRequired>
                      <FormLabel>图形验证码</FormLabel>
                      <HStack>
                        <Image
                          src={captchaImageUrl}
                          alt="验证码"
                          h="48px"
                          borderRadius="md"
                          border="1px solid"
                          borderColor="gray.200"
                        />
                        <IconButton
                          aria-label="刷新验证码"
                          icon={<FiRefreshCw />}
                          onClick={loadCaptcha}
                          variant="outline"
                          size="sm"
                        />
                      </HStack>
                      <Input
                        value={captchaText}
                        onChange={(e) => setCaptchaText(e.target.value)}
                        placeholder="请输入图片中的字符"
                        size="md"
                        mt={2}
                        isDisabled={isLoading}
                      />
                      <Text fontSize="xs" color="gray.500" mt={1}>不区分大小写</Text>
                    </FormControl>
                  )}

                  {/* TOTP 验证码 */}
                  {systemConfig.require_totp && (
                    <FormControl isRequired>
                      <FormLabel>
                        <HStack>
                          <FiSmartphone />
                          <Text>TOTP 验证码</Text>
                        </HStack>
                      </FormLabel>
                      <HStack justify="center">
                        <PinInput
                          size="lg"
                          value={totpCode}
                          onChange={setTotpCode}
                          isDisabled={isLoading}
                        >
                          <PinInputField />
                          <PinInputField />
                          <PinInputField />
                          <PinInputField />
                          <PinInputField />
                          <PinInputField />
                        </PinInput>
                      </HStack>
                      <Text fontSize="xs" color="gray.500" textAlign="center" mt={1}>
                        请输入您的身份验证应用中的 6 位数字
                      </Text>
                    </FormControl>
                  )}

                  <Button
                    type="submit"
                    colorScheme="blue"
                    size="lg"
                    w="full"
                    isLoading={isLoading}
                    loadingText="登录中..."
                    isDisabled={!username.trim() || !password.trim()}
                  >
                    登录
                  </Button>
                </VStack>
              </form>
            </Box>

            {/* 提示信息 */}
            <Text fontSize="sm" color="gray.500" textAlign="center">
              首次使用请使用超级管理员账户登录
            </Text>
          </VStack>
        </CardBody>
      </Card>
    </Box>
  )
}

export default Login

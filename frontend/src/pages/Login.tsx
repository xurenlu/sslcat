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
  Divider,
  Link,
} from '@chakra-ui/react'
import { FiShield, FiUser, FiLock, FiRefreshCw, FiSmartphone, FiKey } from 'react-icons/fi'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

interface SystemConfig {
  require_captcha?: boolean
  require_totp?: boolean
  totp_enabled?: boolean  // TOTP 是否已配置（用于显示仅TOTP登录选项）
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
  const [totpOnlyMode, setTotpOnlyMode] = useState(false)  // 仅 TOTP 登录模式（忘记密码时使用）
  const [totpOnlyCode, setTotpOnlyCode] = useState('')     // 仅 TOTP 登录的验证码
  const [totpOnlyNeedCaptcha, setTotpOnlyNeedCaptcha] = useState(false)  // TOTP-only 模式是否需要验证码
  const [totpOnlyCaptchaText, setTotpOnlyCaptchaText] = useState('')  // TOTP-only 模式的验证码文本
  const [totpOnlyCaptchaSessionId, setTotpOnlyCaptchaSessionId] = useState('')  // TOTP-only 模式的验证码会话ID
  const [totpOnlyCaptchaImageUrl, setTotpOnlyCaptchaImageUrl] = useState('')  // TOTP-only 模式的验证码图片
  
  const { login, isAuthenticated, isLoading: authLoading } = useAuth()
  const { adminPrefix } = useConfig()
  const navigate = useNavigate()
  const toast = useToast()
  const t = useTranslation()

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
          require_totp: data.server?.enable_totp || false,
          totp_enabled: data.server?.enable_totp || false  // TOTP 是否已配置
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

    // 验证必填项（默认登录模式：用户名和密码）
    if (systemConfig.require_captcha && !captchaText) {
      setError(t.login.enter_captcha)
      setIsLoading(false)
      return
    }

    try {
      // 构建登录请求数据（默认登录：用户名 + 密码，不包含 TOTP）
      const loginData: any = {
        username,
        password
      }

      // 添加验证码（如果需要）
      if (systemConfig.require_captcha) {
        loginData.captcha_text = captchaText
        loginData.captcha_session_id = captchaSessionId
      }

      // 注意：默认登录模式不使用 TOTP，即使启用了 TOTP

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

  // 加载 TOTP-only 模式的验证码
  const loadTotpOnlyCaptcha = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/captcha/image') + '?_=' + Date.now(), {
        credentials: 'include'
      })
      if (response.ok) {
        const sessionId = response.headers.get('X-Captcha-Session')
        if (sessionId) {
          setTotpOnlyCaptchaSessionId(sessionId)
        }
        const blob = await response.blob()
        const objectUrl = URL.createObjectURL(blob)
        setTotpOnlyCaptchaImageUrl(objectUrl)
      }
    } catch (error) {
      console.error('Failed to load captcha:', error)
    }
  }

  // 仅 TOTP 登录（忘记密码时使用）
  const handleTotpOnlyLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError('')

    if (totpOnlyCode.length !== 6) {
      setError('请输入完整的 6 位 TOTP 验证码')
      setIsLoading(false)
      return
    }

    // 如果需要验证码，检查验证码
    if (totpOnlyNeedCaptcha && !totpOnlyCaptchaText) {
      setError('请输入验证码')
      setIsLoading(false)
      return
    }

    try {
      const requestBody: any = { totp_code: totpOnlyCode }
      if (totpOnlyNeedCaptcha) {
        requestBody.captcha_text = totpOnlyCaptchaText
        requestBody.captcha_session_id = totpOnlyCaptchaSessionId
      }

      const response = await fetch(buildApiPath(adminPrefix, '/api/auth/totp-login'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(requestBody),
      })

      if (response.ok) {
        toast({
          title: 'TOTP 验证成功',
          description: '已使用 TOTP 紧急登录',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        window.location.href = `${adminPrefix}/dashboard`
      } else {
        const errorData = await response.json()
        setError(errorData.error || 'TOTP 验证码错误')
        
        // 如果服务器要求验证码，显示验证码输入框
        if (errorData.need_captcha) {
          setTotpOnlyNeedCaptcha(true)
          loadTotpOnlyCaptcha()
        }
        
        setTotpOnlyCode('')
        if (totpOnlyNeedCaptcha) {
          setTotpOnlyCaptchaText('')
        }
      }
    } catch (err) {
      setError('登录失败，请重试')
      console.error('TOTP login error:', err)
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
              {!totpOnlyMode ? (
                // 正常登录模式
                <form onSubmit={handleSubmit}>
                  <VStack spacing={4}>
                    <FormControl isRequired>
                      <FormLabel>用户名</FormLabel>
                      <Input
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        placeholder={t.login.username_placeholder}
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
                          placeholder={t.login.password_placeholder}
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
                            alt={t.login.captcha_alt}
                            h="48px"
                            borderRadius="md"
                            border="1px solid"
                            borderColor="gray.200"
                          />
                          <IconButton
                            aria-label={t.login.refresh_captcha}
                            icon={<FiRefreshCw />}
                            onClick={loadCaptcha}
                            variant="outline"
                            size="sm"
                          />
                        </HStack>
                        <Input
                          value={captchaText}
                          onChange={(e) => setCaptchaText(e.target.value)}
                          placeholder={t.login.captcha_placeholder}
                          size="md"
                          mt={2}
                          isDisabled={isLoading}
                        />
                        <Text fontSize="xs" color="gray.500" mt={1}>不区分大小写</Text>
                      </FormControl>
                    )}

                    <Button
                      type="submit"
                      colorScheme="blue"
                      size="lg"
                      w="full"
                      isLoading={isLoading}
                      loadingText={t.login.loading}
                      isDisabled={!username.trim() || !password.trim()}
                    >
                      登录
                    </Button>
                  </VStack>
                </form>
              ) : (
                // 仅 TOTP 登录模式（忘记密码时使用）
                <form onSubmit={handleTotpOnlyLogin}>
                  <VStack spacing={4}>
                    <Alert status="info" borderRadius="md">
                      <AlertIcon />
                      <Box>
                        <Text fontWeight="bold">紧急登录模式</Text>
                        <Text fontSize="sm">忘记密码时，可使用 TOTP 验证码直接登录超级管理员账户</Text>
                      </Box>
                    </Alert>

                    {/* 验证码（如果需要） */}
                    {totpOnlyNeedCaptcha && (
                      <FormControl isRequired>
                        <FormLabel>图形验证码</FormLabel>
                        <HStack>
                          <Image
                            src={totpOnlyCaptchaImageUrl}
                            alt="验证码"
                            h="48px"
                            borderRadius="md"
                            border="1px solid"
                            borderColor="gray.200"
                          />
                          <IconButton
                            aria-label="刷新验证码"
                            icon={<FiRefreshCw />}
                            onClick={loadTotpOnlyCaptcha}
                            variant="outline"
                            size="sm"
                          />
                        </HStack>
                        <Input
                          value={totpOnlyCaptchaText}
                          onChange={(e) => setTotpOnlyCaptchaText(e.target.value)}
                          placeholder="请输入验证码"
                          size="md"
                          mt={2}
                          isDisabled={isLoading}
                        />
                        <Text fontSize="xs" color="gray.500" mt={1}>不区分大小写</Text>
                      </FormControl>
                    )}

                    <FormControl isRequired>
                      <FormLabel>
                        <HStack>
                          <FiKey />
                          <Text>TOTP 验证码</Text>
                        </HStack>
                      </FormLabel>
                      <HStack justify="center">
                        <PinInput
                          size="lg"
                          value={totpOnlyCode}
                          onChange={setTotpOnlyCode}
                          isDisabled={isLoading}
                          autoFocus
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
                        请输入 Google Authenticator 等应用中的 6 位数字
                      </Text>
                    </FormControl>

                    <Button
                      type="submit"
                      colorScheme="orange"
                      size="lg"
                      w="full"
                      isLoading={isLoading}
                      loadingText="验证中..."
                      isDisabled={totpOnlyCode.length !== 6}
                      leftIcon={<FiKey />}
                    >
                      TOTP 紧急登录
                    </Button>
                  </VStack>
                </form>
              )}

              {/* 仅 TOTP 登录切换（只有启用了 TOTP 才显示） */}
              {systemConfig.totp_enabled && (
                <>
                  <Divider my={4} />
                  <Text textAlign="center" fontSize="sm">
                    {totpOnlyMode ? (
                      <Link
                        color="blue.500"
                        onClick={() => {
                          setTotpOnlyMode(false)
                          setError('')
                          setTotpOnlyCode('')
                        }}
                        cursor="pointer"
                      >
                        ← 返回正常登录
                      </Link>
                    ) : (
                      <Link
                        color="orange.500"
                        onClick={() => {
                          setTotpOnlyMode(true)
                          setError('')
                        }}
                        cursor="pointer"
                      >
                        忘记密码？使用 TOTP 紧急登录 →
                      </Link>
                    )}
                  </Text>
                </>
              )}
            </Box>

            {/* 提示信息 */}
            <Text fontSize="sm" color="gray.500" textAlign="center">
              {totpOnlyMode 
                ? '紧急登录仅限超级管理员使用'
                : '首次使用请使用超级管理员账户登录'
              }
            </Text>
          </VStack>
        </CardBody>
      </Card>
    </Box>
  )
}

export default Login

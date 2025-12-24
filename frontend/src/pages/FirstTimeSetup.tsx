import React, { useEffect, useMemo, useState } from 'react'
import {
  Alert,
  AlertIcon,
  AlertTitle,
  Badge,
  Box,
  Button,
  Card,
  CardBody,
  CardHeader,
  FormControl,
  FormErrorMessage,
  FormHelperText,
  FormLabel,
  HStack,
  Heading,
  IconButton,
  Image,
  Input,
  InputGroup,
  InputRightElement,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalContent,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  PinInput,
  PinInputField,
  Progress,
  Step,
  StepDescription,
  StepIcon,
  StepIndicator,
  StepNumber,
  StepSeparator,
  StepStatus,
  StepTitle,
  Stepper,
  Text,
  VStack,
  useDisclosure,
  useSteps,
  useToast,
} from '@chakra-ui/react'
import { FiAlertCircle, FiCheck, FiEye, FiEyeOff, FiKey, FiLock, FiMail, FiShield, FiSmartphone } from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'
import { Translation } from '../i18n'
import { captureError, captureMessage } from '../utils/sentry'

const MIN_PASSWORD_LENGTH = 10

type FieldName = 'newPassword' | 'confirmPassword' | 'adminEmail' | 'domain' | 'target'
type ExtendedFieldName = FieldName | 'proxyPair'

const initialTouched: Record<FieldName, boolean> = {
  newPassword: false,
  confirmPassword: false,
  adminEmail: false,
  domain: false,
  target: false,
}

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const domainRegex = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$/

type PasswordChecklistKey = 'length' | 'uppercase' | 'lowercase' | 'number' | 'special'

const computePasswordMetrics = (password: string, t: Translation) => {
  const trimmed = password.trim()
  const checks = {
    length: trimmed.length >= MIN_PASSWORD_LENGTH,
    uppercase: /[A-Z]/.test(trimmed),
    lowercase: /[a-z]/.test(trimmed),
    number: /\d/.test(trimmed),
    special: /[^A-Za-z0-9]/.test(trimmed),
  }

  const score = Object.values(checks).filter(Boolean).length

  let label = t.setup.password_not_filled
  let colorScheme: 'gray' | 'red' | 'yellow' | 'green' | 'blue' = 'gray'

  if (!trimmed) {
    label = t.setup.password_not_filled
    colorScheme = 'gray'
  } else if (score <= 2) {
    label = t.setup.password_weak
    colorScheme = 'red'
  } else if (score === 3) {
    label = t.setup.password_normal
    colorScheme = 'yellow'
  } else if (score === 4) {
    label = t.setup.password_good
    colorScheme = 'green'
  } else {
    label = t.setup.password_excellent
    colorScheme = 'blue'
  }

  return {
    score,
    label,
    colorScheme,
    checks,
  }
}

const getFirstErrorMessage = (errors: Partial<Record<ExtendedFieldName, string>>): string | undefined =>
  errors.newPassword ||
  errors.confirmPassword ||
  errors.adminEmail ||
  errors.proxyPair ||
  errors.domain ||
  errors.target

const FirstTimeSetup: React.FC = () => {
  const t = useTranslation()
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [adminEmail, setAdminEmail] = useState('')
  const [domain, setDomain] = useState('')
  const [target, setTarget] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const [touched, setTouched] = useState(initialTouched)
  const [submissionError, setSubmissionError] = useState<string | null>(null)
  
  const { adminPrefix } = useConfig()
  const toast = useToast()

  const { activeStep, setActiveStep } = useSteps({
    index: 0,
    count: 5,
  })

  // TOTP 相关状态
  const [totpEnabled, setTotpEnabled] = useState(false)
  const [totpLoading, setTotpLoading] = useState(false)
  const [totpQrCode, setTotpQrCode] = useState('')
  const [totpSecret, setTotpSecret] = useState('')
  const [totpVerifyCode, setTotpVerifyCode] = useState('')
  const { isOpen: isTotpModalOpen, onOpen: onTotpModalOpen, onClose: onTotpModalClose } = useDisclosure()

  // WebAuthn 相关状态
  const [webauthnEnabled, setWebauthnEnabled] = useState(false)
  const [webauthnLoading, setWebauthnLoading] = useState(false)
  const [webauthnDeviceName, setWebauthnDeviceName] = useState('')
  const { isOpen: isWebauthnModalOpen, onOpen: onWebauthnModalOpen, onClose: onWebauthnModalClose } = useDisclosure()

  const steps = [
    { title: t.setup.step1_title, description: t.setup.step1_desc },
    { title: t.setup.step2_title, description: t.setup.step2_desc },
    { title: t.setup.step3_title, description: t.setup.step3_desc },
    { title: 'TOTP 双因素认证', description: '设置 TOTP 验证码' },
    { title: '指纹/生物识别登录', description: '注册设备指纹识别' },
  ]

  const passwordMetrics = useMemo(() => computePasswordMetrics(newPassword, t), [newPassword, t])

  const fieldErrors = useMemo<Partial<Record<ExtendedFieldName, string>>>(() => {
    const errors: Partial<Record<ExtendedFieldName, string>> = {}

    if (!newPassword) {
      errors.newPassword = t.setup.password_error_required
    } else if (!passwordMetrics.checks.length) {
      errors.newPassword = t.setup.password_error_min_length
    } else if (Object.values(passwordMetrics.checks).filter(Boolean).length < 3) {
      errors.newPassword = t.setup.password_error_types
    }

    if (!confirmPassword) {
      errors.confirmPassword = t.setup.confirm_password_error_required
    } else if (confirmPassword !== newPassword) {
      errors.confirmPassword = t.setup.confirm_password_error_mismatch
    }

    if (!adminEmail) {
      errors.adminEmail = t.setup.admin_email_error_required
    } else if (!emailRegex.test(adminEmail)) {
      errors.adminEmail = t.setup.admin_email_error_format
    }

    if ((domain && !target) || (!domain && target)) {
      errors.proxyPair = t.setup.proxy_pair_error
    }

    if (domain && !domainRegex.test(domain)) {
      errors.domain = t.setup.domain_error_format
    }

    if (target) {
      try {
        const parsed = new URL(target)
        if (!['http:', 'https:'].includes(parsed.protocol)) {
          throw new Error('invalid protocol')
        }
      } catch (err) {
        errors.target = t.setup.target_error_format
      }
    }

    return errors
  }, [adminEmail, confirmPassword, domain, newPassword, passwordMetrics, target, t])

  const canSubmit = useMemo(() => !getFirstErrorMessage(fieldErrors), [fieldErrors])

  const newPasswordValid = Boolean(newPassword) && !fieldErrors.newPassword && !fieldErrors.confirmPassword
  const adminEmailValid = Boolean(adminEmail) && !fieldErrors.adminEmail

  const currentStep = useMemo(() => {
    if (!newPasswordValid) {
      return 0
    }
    if (!adminEmailValid) {
      return 1
    }
    return 2
  }, [adminEmailValid, newPasswordValid])

  useEffect(() => {
    if (activeStep !== currentStep) {
      setActiveStep(currentStep)
    }
  }, [activeStep, currentStep, setActiveStep])

  useEffect(() => {
    if (submissionError) {
      setSubmissionError(null)
    }
  }, [adminEmail, confirmPassword, domain, newPassword, submissionError, target])

  const markTouched = (field: FieldName) => {
    setTouched((prev) => ({ ...prev, [field]: true }))
  }

  const markAllTouched = () => {
    setTouched({
      newPassword: true,
      confirmPassword: true,
      adminEmail: true,
      domain: true,
      target: true,
    })
  }

  // 生成 TOTP 二维码
  const generateTotpQrCode = async () => {
    setTotpLoading(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/totp/generate'), {
        method: 'POST',
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          setTotpQrCode(data.qr_code)
          setTotpSecret(data.secret)
          onTotpModalOpen()
        } else {
          toast({
            title: '生成二维码失败',
            description: data.error,
            status: 'error',
            duration: 3000,
            isClosable: true,
          })
        }
      }
    } catch (error) {
      toast({
        title: '生成二维码失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setTotpLoading(false)
    }
  }

  // 启用 TOTP
  const enableTotp = async () => {
    if (totpVerifyCode.length !== 6) {
      toast({
        title: '请输入 6 位验证码',
        status: 'warning',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    setTotpLoading(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/totp/enable'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          secret: totpSecret,
          code: totpVerifyCode,
        }),
      })
      const data = await response.json()
      if (data.success) {
        setTotpEnabled(true)
        onTotpModalClose()
        setTotpVerifyCode('')
        setTotpQrCode('')
        setTotpSecret('')
        toast({
          title: 'TOTP 已启用',
          description: '双因素认证已成功开启',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
      } else {
        toast({
          title: '启用失败',
          description: data.error || '验证码错误',
          status: 'error',
          duration: 3000,
          isClosable: true,
        })
        setTotpVerifyCode('')
      }
    } catch (error) {
      toast({
        title: '启用失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setTotpLoading(false)
    }
  }

  // 开始 WebAuthn 注册
  const beginWebauthnRegistration = async () => {
    if (!webauthnDeviceName.trim()) {
      toast({
        title: '请输入设备名称',
        status: 'warning',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    setWebauthnLoading(true)
    try {
      // 获取当前用户名
      const meResponse = await fetch(buildApiPath(adminPrefix, '/api/auth/me'), {
        credentials: 'include',
      })
      if (!meResponse.ok) {
        throw new Error('获取用户信息失败')
      }
      const meData = await meResponse.json()
      const username = meData.username

      // 开始注册
      const beginResponse = await fetch(buildApiPath(adminPrefix, '/api/webauthn/register/begin'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          username,
          device_name: webauthnDeviceName,
        }),
      })

      if (!beginResponse.ok) {
        const errorData = await beginResponse.json()
        throw new Error(errorData.error || '开始注册失败')
      }

      const beginData = await beginResponse.json()
      if (!beginData.success) {
        throw new Error(beginData.error || '开始注册失败')
      }

      // 辅助函数：将 Base64 URL 编码的字符串转换为 ArrayBuffer
      const base64URLToArrayBuffer = (base64URL: string): ArrayBuffer => {
        const base64 = base64URL.replace(/-/g, '+').replace(/_/g, '/')
        const padded = base64 + '='.repeat((4 - base64.length % 4) % 4)
        const binary = atob(padded)
        const bytes = new Uint8Array(binary.length)
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i)
        }
        return bytes.buffer
      }

      // 调用浏览器 WebAuthn API
      const publicKeyOptions = { ...beginData.options }
      if (typeof publicKeyOptions.challenge === 'string') {
        publicKeyOptions.challenge = base64URLToArrayBuffer(publicKeyOptions.challenge)
      }
      if (publicKeyOptions.user && typeof publicKeyOptions.user.id === 'string') {
        publicKeyOptions.user.id = base64URLToArrayBuffer(publicKeyOptions.user.id)
      }

      const credential = await navigator.credentials.create({
        publicKey: publicKeyOptions,
      }) as PublicKeyCredential

      // 准备响应数据
      const response = credential.response as AuthenticatorAttestationResponse
      const arrayBufferToBase64URL = (buffer: ArrayBuffer): string => {
        const bytes = new Uint8Array(buffer)
        let binary = ''
        for (let i = 0; i < bytes.byteLength; i++) {
          binary += String.fromCharCode(bytes[i])
        }
        return btoa(binary)
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, '')
      }

      const credentialResponse = {
        id: credential.id,
        rawId: arrayBufferToBase64URL(credential.rawId),
        response: {
          attestationObject: arrayBufferToBase64URL(response.attestationObject),
          clientDataJSON: arrayBufferToBase64URL(response.clientDataJSON),
        },
        type: credential.type,
      }

      // 完成注册
      const finishResponse = await fetch(buildApiPath(adminPrefix, '/api/webauthn/register/finish'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          session_key: beginData.session_key,
          device_name: webauthnDeviceName,
          response: credentialResponse,
        }),
      })

      const finishData = await finishResponse.json()
      if (finishData.success) {
        const deviceName = webauthnDeviceName // 保存设备名称，因为后面会清空
        setWebauthnEnabled(true)
        onWebauthnModalClose()
        setWebauthnDeviceName('')
        toast({
          title: 'WebAuthn 注册成功',
          description: `设备 "${deviceName}" 已成功注册`,
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
      } else {
        throw new Error(finishData.error || '注册失败')
      }
    } catch (error) {
      toast({
        title: '注册失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setWebauthnLoading(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    markAllTouched()

    if (!canSubmit) {
      const firstError = getFirstErrorMessage(fieldErrors)
      toast({
        title: t.setup.form_incomplete_title,
        description: firstError || t.setup.form_incomplete_desc,
        status: 'error',
        duration: 4000,
      })
      setSubmissionError(firstError || t.setup.form_validation_error)
      setActiveStep(currentStep)
      return
    }

    setIsLoading(true)
    setSubmissionError(null)

    try {
      const formData = new URLSearchParams()
      formData.append('new_password', newPassword)
      formData.append('confirm_password', confirmPassword)
      formData.append('admin_email', adminEmail)
      if (domain) formData.append('domain', domain)
      if (target) formData.append('target', target)

      const response = await fetch(buildApiPath(adminPrefix, '/api/settings/first-setup'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        credentials: 'include',
        body: formData,
      })

      if (response.ok) {
        toast({
          title: t.setup.submit_success_title,
          description: t.setup.submit_success_desc,
          status: 'success',
          duration: 3000,
        })

        // 如果用户还没有设置 TOTP 或 WebAuthn，提示他们设置
        if (!totpEnabled || !webauthnEnabled) {
          setActiveStep(3) // 跳转到安全设置步骤
        } else {
          setTimeout(() => {
            window.location.href = `${adminPrefix}/dashboard`
          }, 1500)
        }
      } else {
        const error = (await response.text()) || t.setup.submit_error_unknown
        captureMessage(`first_time_setup_failed: ${error}`, 'error')
        setSubmissionError(error)
        toast({
          title: t.setup.submit_error_title,
          description: error,
          status: 'error',
          duration: 5000,
        })
      }
    } catch (error) {
      captureError(error as Error, { stage: 'first_time_setup' })
      const errorMessage = String(error)
      setSubmissionError(errorMessage)
      toast({
        title: t.setup.submit_error_title,
        description: errorMessage,
        status: 'error',
        duration: 5000,
      })
    } finally {
      setIsLoading(false)
    }
  }

  // 完成首次设置（包括安全设置）
  const handleCompleteSetup = async () => {
    // 如果用户已经设置了 TOTP 和 WebAuthn，或者选择跳过，则完成设置
    setTimeout(() => {
      window.location.href = `${adminPrefix}/dashboard`
    }, 500)
  }

  return (
    <Box minH="100vh" bg="gray.50" py={10} px={4}>
      <Box maxW="4xl" mx="auto">
        <VStack spacing={6}>
          {/* 头部 */}
          <VStack spacing={2}>
            <Heading size="xl">{t.setup.title}</Heading>
            <Text color="gray.600">{t.setup.subtitle}</Text>
          </VStack>

        {submissionError && (
          <Alert status="error" variant="left-accent" w="full">
            <AlertIcon />
            <Box>
              <AlertTitle fontSize="sm">{t.setup.submission_error_title}</AlertTitle>
              <Text fontSize="sm">{submissionError}</Text>
            </Box>
          </Alert>
        )}

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
                    <Heading size="md">{t.setup.step1_heading}</Heading>
                  </HStack>
                </CardHeader>
                <CardBody>
                  <VStack spacing={4}>
                    <Alert status="warning">
                      <AlertIcon />
                      <Box>
                        <Text fontWeight="bold">{t.setup.step1_security_warning}</Text>
                        <Text fontSize="sm">
                          {t.setup.step1_security_message}
                        </Text>
                      </Box>
                    </Alert>

                    <FormControl isRequired isInvalid={touched.newPassword && Boolean(fieldErrors.newPassword)}>
                      <FormLabel>{t.setup.new_password_label}</FormLabel>
                      <InputGroup>
                        <Input
                          type={showPassword ? 'text' : 'password'}
                          value={newPassword}
                          onChange={(e) => setNewPassword(e.target.value)}
                          onBlur={() => markTouched('newPassword')}
                          onFocus={() => setActiveStep(0)}
                          placeholder={t.setup.password_placeholder}
                          autoComplete="new-password"
                        />
                        <InputRightElement>
                          <IconButton
                            aria-label={showPassword ? t.setup.hide_password : t.setup.show_password}
                            icon={showPassword ? <FiEyeOff /> : <FiEye />}
                            onClick={() => setShowPassword(!showPassword)}
                            variant="ghost"
                            size="sm"
                          />
                        </InputRightElement>
                      </InputGroup>
                      <FormHelperText>
                        <HStack spacing={3} justify="space-between" align="center">
                          <Text fontSize="sm" color="gray.600">
                            {t.setup.password_strength}
                          </Text>
                          <Badge colorScheme={passwordMetrics.colorScheme} variant="subtle">
                            {passwordMetrics.label}
                          </Badge>
                        </HStack>
                      </FormHelperText>
                      <Progress
                        value={(passwordMetrics.score / 5) * 100}
                        size="sm"
                        colorScheme={passwordMetrics.colorScheme}
                        borderRadius="full"
                      />
                      <VStack align="flex-start" spacing={1} fontSize="xs" color="gray.600">
                        {(['length', 'uppercase', 'lowercase', 'number', 'special'] as PasswordChecklistKey[]).map((key) => {
                          const passed = passwordMetrics.checks[key]
                          const labels: Record<PasswordChecklistKey, string> = {
                            length: t.setup.password_checklist_length,
                            uppercase: t.setup.password_checklist_uppercase,
                            lowercase: t.setup.password_checklist_lowercase,
                            number: t.setup.password_checklist_number,
                            special: t.setup.password_checklist_special,
                          }
                          return (
                            <HStack key={key} spacing={1} color={passed ? 'green.600' : 'gray.500'}>
                              <Box
                                as={passed ? FiCheck : FiAlertCircle}
                                color={passed ? 'green.500' : 'gray.400'}
                                fontSize="0.75rem"
                              />
                              <Text>{labels[key]}</Text>
                            </HStack>
                          )
                        })}
                      </VStack>
                      <FormErrorMessage>{fieldErrors.newPassword}</FormErrorMessage>
                    </FormControl>

                    <FormControl isRequired isInvalid={touched.confirmPassword && Boolean(fieldErrors.confirmPassword)}>
                      <FormLabel>{t.setup.confirm_password_label}</FormLabel>
                      <InputGroup>
                        <Input
                          type={showConfirm ? 'text' : 'password'}
                          value={confirmPassword}
                          onChange={(e) => setConfirmPassword(e.target.value)}
                          onBlur={() => markTouched('confirmPassword')}
                          onFocus={() => setActiveStep(0)}
                          placeholder={t.setup.confirm_password_placeholder}
                          autoComplete="new-password"
                        />
                        <InputRightElement>
                          <IconButton
                            aria-label={showConfirm ? t.setup.hide_password : t.setup.show_password}
                            icon={showConfirm ? <FiEyeOff /> : <FiEye />}
                            onClick={() => setShowConfirm(!showConfirm)}
                            variant="ghost"
                            size="sm"
                          />
                        </InputRightElement>
                      </InputGroup>
                      <FormErrorMessage>{fieldErrors.confirmPassword}</FormErrorMessage>
                    </FormControl>
                  </VStack>
                </CardBody>
              </Card>

              {/* 步骤 2：SSL 配置 */}
              <Card w="full">
                <CardHeader bg="green.50">
                  <HStack>
                    <FiMail />
                    <Heading size="md">{t.setup.step2_heading}</Heading>
                  </HStack>
                </CardHeader>
                <CardBody>
                  <VStack spacing={4}>
                    <FormControl isRequired isInvalid={touched.adminEmail && Boolean(fieldErrors.adminEmail)}>
                      <FormLabel>{t.setup.admin_email_label}</FormLabel>
                      <InputGroup>
                        <Input
                          type="email"
                          value={adminEmail}
                          onChange={(e) => setAdminEmail(e.target.value)}
                          onBlur={() => markTouched('adminEmail')}
                          onFocus={() => setActiveStep(1)}
                          placeholder={t.setup.admin_email_placeholder}
                          autoComplete="email"
                        />
                        <InputRightElement pointerEvents="none" color="gray.400">
                          <FiMail />
                        </InputRightElement>
                      </InputGroup>
                      <FormHelperText>
                        {t.setup.admin_email_helper}
                      </FormHelperText>
                      <FormErrorMessage>{fieldErrors.adminEmail}</FormErrorMessage>
                    </FormControl>
                  </VStack>
                </CardBody>
              </Card>

              {/* 步骤 3：代理规则（可选） */}
              <Card w="full">
                <CardHeader bg="purple.50">
                  <HStack>
                    <FiCheck />
                    <Heading size="md">{t.setup.step3_heading}</Heading>
                  </HStack>
                </CardHeader>
                <CardBody>
                  <Alert status="info" mb={4}>
                    <AlertIcon />
                    <Text fontSize="sm">{t.setup.step3_info}</Text>
                  </Alert>

                  {(fieldErrors.proxyPair || fieldErrors.domain || fieldErrors.target) &&
                    (touched.domain || touched.target) && (
                      <Alert status="error" variant="left-accent" mb={4}>
                        <AlertIcon />
                        <VStack align="flex-start" spacing={1} fontSize="sm">
                          {fieldErrors.proxyPair && <Text>{fieldErrors.proxyPair}</Text>}
                          {fieldErrors.domain && <Text>{fieldErrors.domain}</Text>}
                          {fieldErrors.target && <Text>{fieldErrors.target}</Text>}
                        </VStack>
                      </Alert>
                    )}

                  <VStack spacing={4}>
                    <FormControl isInvalid={touched.domain && Boolean(fieldErrors.domain)}>
                      <FormLabel>{t.setup.domain_label}</FormLabel>
                      <Input
                        value={domain}
                        onChange={(e) => setDomain(e.target.value)}
                        onBlur={() => markTouched('domain')}
                        onFocus={() => setActiveStep(2)}
                        placeholder={t.setup.domain_placeholder}
                      />
                      <FormErrorMessage>{fieldErrors.domain}</FormErrorMessage>
                    </FormControl>

                    <FormControl isInvalid={touched.target && Boolean(fieldErrors.target)}>
                      <FormLabel>{t.setup.target_label}</FormLabel>
                      <Input
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        onBlur={() => markTouched('target')}
                        onFocus={() => setActiveStep(2)}
                        placeholder={t.setup.target_placeholder}
                      />
                      <FormHelperText>{t.setup.target_helper}</FormHelperText>
                      <FormErrorMessage>{fieldErrors.target}</FormErrorMessage>
                    </FormControl>
                  </VStack>
                </CardBody>
              </Card>

              {/* 步骤 4：TOTP 双因素认证（可选但强烈推荐） */}
              <Card w="full">
                <CardHeader bg="orange.50">
                  <HStack>
                    <FiKey />
                    <Heading size="md">TOTP 双因素认证</Heading>
                    {totpEnabled && (
                      <Badge colorScheme="green" ml={2}>
                        已设置
                      </Badge>
                    )}
                  </HStack>
                </CardHeader>
                <CardBody>
                  <VStack spacing={4}>
                    <Alert status="warning">
                      <AlertIcon />
                      <Box>
                        <Text fontWeight="bold">强烈推荐设置 TOTP 双因素认证</Text>
                        <Text fontSize="sm">
                          TOTP 双因素认证可以大幅提升账户安全性。即使密码泄露，攻击者也无法登录您的账户。
                          忘记密码时，您也可以使用 TOTP 验证码进行紧急登录。
                        </Text>
                      </Box>
                    </Alert>

                    {totpEnabled ? (
                      <Alert status="success">
                        <AlertIcon />
                        <Text>TOTP 双因素认证已成功设置</Text>
                      </Alert>
                    ) : (
                      <Button
                        colorScheme="orange"
                        size="lg"
                        w="full"
                        onClick={generateTotpQrCode}
                        isLoading={totpLoading}
                        leftIcon={<FiKey />}
                      >
                        设置 TOTP 双因素认证
                      </Button>
                    )}
                  </VStack>
                </CardBody>
              </Card>

              {/* 步骤 5：WebAuthn 指纹识别（可选但强烈推荐） */}
              <Card w="full">
                <CardHeader bg="purple.50">
                  <HStack>
                    <FiSmartphone />
                    <Heading size="md">指纹/生物识别登录</Heading>
                    {webauthnEnabled && (
                      <Badge colorScheme="green" ml={2}>
                        已设置
                      </Badge>
                    )}
                  </HStack>
                </CardHeader>
                <CardBody>
                  <VStack spacing={4}>
                    <Alert status="warning">
                      <AlertIcon />
                      <Box>
                        <Text fontWeight="bold">强烈推荐设置指纹/生物识别登录</Text>
                        <Text fontSize="sm">
                          指纹/生物识别登录是最便捷且安全的登录方式。设置后，您可以使用设备的生物识别功能（指纹、面容等）快速登录，无需输入密码。
                        </Text>
                      </Box>
                    </Alert>

                    {webauthnEnabled ? (
                      <Alert status="success">
                        <AlertIcon />
                        <Text>指纹识别登录已成功设置</Text>
                      </Alert>
                    ) : (
                      <Button
                        colorScheme="purple"
                        size="lg"
                        w="full"
                        onClick={onWebauthnModalOpen}
                        isLoading={webauthnLoading}
                        leftIcon={<FiSmartphone />}
                      >
                        设置指纹识别登录
                      </Button>
                    )}
                  </VStack>
                </CardBody>
              </Card>

              {/* 提交按钮 */}
              <HStack w="full" justify="space-between">
                {activeStep >= 3 && (
                  <Button
                    variant="outline"
                    size="lg"
                    onClick={() => {
                      // 如果用户已经设置了基本配置，允许跳过安全设置
                      if (newPasswordValid && adminEmailValid) {
                        handleCompleteSetup()
                      }
                    }}
                    isDisabled={isLoading}
                  >
                    跳过安全设置（不推荐）
                  </Button>
                )}
                <HStack>
                  {activeStep < 3 ? (
                    <Button
                      type="submit"
                      colorScheme="blue"
                      size="lg"
                      isLoading={isLoading}
                      isDisabled={!canSubmit || isLoading}
                      loadingText={t.setup.loading}
                      leftIcon={<FiCheck />}
                    >
                      {t.setup.submit_button}
                    </Button>
                  ) : (
                    <Button
                      colorScheme="green"
                      size="lg"
                      onClick={handleCompleteSetup}
                      isDisabled={isLoading}
                      leftIcon={<FiCheck />}
                    >
                      完成设置
                    </Button>
                  )}
                </HStack>
              </HStack>
            </VStack>
          </form>

          {/* TOTP 设置模态框 */}
          <Modal isOpen={isTotpModalOpen} onClose={onTotpModalClose} size="md">
            <ModalOverlay />
            <ModalContent>
              <ModalHeader>设置 TOTP 双因素认证</ModalHeader>
              <ModalCloseButton />
              <ModalBody>
                <VStack spacing={4}>
                  <Alert status="info">
                    <AlertIcon />
                    <Box>
                      <Text fontSize="sm" fontWeight="bold">
                        请使用手机应用扫描二维码
                      </Text>
                      <Text fontSize="xs">
                        推荐使用 Google Authenticator、Microsoft Authenticator 或 Authy 等应用
                      </Text>
                    </Box>
                  </Alert>

                  {totpQrCode && (
                    <Box textAlign="center">
                      <Image
                        src={totpQrCode}
                        alt="TOTP QR Code"
                        mx="auto"
                        borderRadius="md"
                        border="1px solid"
                        borderColor="gray.200"
                      />
                      <Text fontSize="xs" color="gray.500" mt={2}>
                        密钥: {totpSecret}
                      </Text>
                    </Box>
                  )}

                  <Box w="full">
                    <Text fontSize="sm" mb={2} textAlign="center">
                      输入应用中显示的 6 位数字验证码以完成设置
                    </Text>
                    <HStack justify="center">
                      <PinInput
                        size="lg"
                        value={totpVerifyCode}
                        onChange={setTotpVerifyCode}
                        isDisabled={totpLoading}
                      >
                        <PinInputField />
                        <PinInputField />
                        <PinInputField />
                        <PinInputField />
                        <PinInputField />
                        <PinInputField />
                      </PinInput>
                    </HStack>
                  </Box>
                </VStack>
              </ModalBody>
              <ModalFooter>
                <Button variant="ghost" mr={3} onClick={onTotpModalClose}>
                  取消
                </Button>
                <Button
                  colorScheme="blue"
                  onClick={enableTotp}
                  isLoading={totpLoading}
                  isDisabled={totpVerifyCode.length !== 6}
                >
                  确认启用
                </Button>
              </ModalFooter>
            </ModalContent>
          </Modal>

          {/* WebAuthn 设置模态框 */}
          <Modal isOpen={isWebauthnModalOpen} onClose={onWebauthnModalClose} size="md">
            <ModalOverlay />
            <ModalContent>
              <ModalHeader>设置指纹识别登录</ModalHeader>
              <ModalCloseButton />
              <ModalBody>
                <VStack spacing={4}>
                  <Alert status="info">
                    <AlertIcon />
                    <Box>
                      <Text fontSize="sm" fontWeight="bold">
                        请为您的设备命名
                      </Text>
                      <Text fontSize="xs">
                        例如：MacBook Pro、iPhone 13、Windows PC 等
                      </Text>
                    </Box>
                  </Alert>

                  <FormControl>
                    <FormLabel>设备名称</FormLabel>
                    <Input
                      value={webauthnDeviceName}
                      onChange={(e) => setWebauthnDeviceName(e.target.value)}
                      placeholder="例如：MacBook Pro"
                      size="lg"
                    />
                  </FormControl>
                </VStack>
              </ModalBody>
              <ModalFooter>
                <Button variant="ghost" mr={3} onClick={onWebauthnModalClose}>
                  取消
                </Button>
                <Button
                  colorScheme="purple"
                  onClick={beginWebauthnRegistration}
                  isLoading={webauthnLoading}
                  isDisabled={!webauthnDeviceName.trim()}
                >
                  开始注册
                </Button>
              </ModalFooter>
            </ModalContent>
          </Modal>
        </VStack>
      </Box>
    </Box>
  )
}

export default FirstTimeSetup


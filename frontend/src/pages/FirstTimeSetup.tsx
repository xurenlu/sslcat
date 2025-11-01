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
  Input,
  InputGroup,
  InputRightElement,
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
  useSteps,
  useToast,
} from '@chakra-ui/react'
import { FiAlertCircle, FiCheck, FiEye, FiEyeOff, FiLock, FiMail } from 'react-icons/fi'
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
    count: 3,
  })

  const steps = [
    { title: t.setup.step1_title, description: t.setup.step1_desc },
    { title: t.setup.step2_title, description: t.setup.step2_desc },
    { title: t.setup.step3_title, description: t.setup.step3_desc },
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

        setActiveStep(2)

        setTimeout(() => {
          window.location.href = `${adminPrefix}/dashboard`
        }, 1500)
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

              {/* 提交按钮 */}
              <HStack w="full" justify="flex-end">
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
              </HStack>
            </VStack>
          </form>
        </VStack>
      </Box>
    </Box>
  )
}

export default FirstTimeSetup


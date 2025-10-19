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
  Button,
  Icon,
  useToast,
  Alert,
  AlertIcon,
  Text,
  Divider,
  Badge,
} from '@chakra-ui/react'
import {
  FiLock,
  FiEye,
  FiEyeOff,
  FiUser,
  FiShield,
  FiSave,
} from 'react-icons/fi'
import { useConfig } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'
import { useAuth } from '../contexts/AuthContext'

const ChangePassword: React.FC = () => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  const { user, logout } = useAuth()
  const toast = useToast()

  const [formData, setFormData] = useState({
    currentPassword: '',
    newPassword: '',
    confirmPassword: '',
  })

  const [showPasswords, setShowPasswords] = useState({
    current: false,
    new: false,
    confirm: false,
  })

  const [loading, setLoading] = useState(false)

  const handleInputChange = (field: string, value: string) => {
    setFormData(prev => ({
      ...prev,
      [field]: value,
    }))
  }

  const togglePasswordVisibility = (field: keyof typeof showPasswords) => {
    setShowPasswords(prev => ({
      ...prev,
      [field]: !prev[field],
    }))
  }

  const validatePassword = (password: string) => {
    if (password.length < 6) {
      return t.users.passwordMinLength
    }
    if (!/(?=.*[a-zA-Z])/.test(password)) {
      return t.users.passwordMustContainLetter
    }
    if (!/(?=.*\d)/.test(password)) {
      return t.users.passwordMustContainNumber
    }
    return null
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    // 验证输入
    if (!formData.currentPassword || !formData.newPassword || !formData.confirmPassword) {
      toast({
        title: t.common.required,
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    if (formData.newPassword !== formData.confirmPassword) {
      toast({
        title: '新密码确认不匹配',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    const passwordError = validatePassword(formData.newPassword)
    if (passwordError) {
      toast({
        title: passwordError,
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    setLoading(true)

    try {
      const response = await fetch(`${adminPrefix}/api/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          currentPassword: formData.currentPassword,
          newPassword: formData.newPassword,
        }),
      })

      if (response.ok) {
        toast({
          title: '密码修改成功',
          description: '请重新登录以使用新密码',
          status: 'success',
          duration: 5000,
          isClosable: true,
        })

        // 清空表单
        setFormData({
          currentPassword: '',
          newPassword: '',
          confirmPassword: '',
        })

        // 延迟退出登录，让用户看到成功消息
        setTimeout(() => {
          logout()
        }, 2000)
      } else {
        const error = await response.json()
        toast({
          title: '密码修改失败',
          description: error.error || '未知错误',
          status: 'error',
          duration: 3000,
          isClosable: true,
        })
      }
    } catch (error) {
      console.error('密码修改失败:', error)
      toast({
        title: '密码修改失败',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  const handleReset = () => {
    setFormData({
      currentPassword: '',
      newPassword: '',
      confirmPassword: '',
    })
  }

  return (
    <Box p={6}>
      <VStack spacing={6} align="stretch" maxW="600px" mx="auto">
        {/* 页面标题 */}
        <Box textAlign="center">
          <Heading size="lg" display="flex" alignItems="center" justifyContent="center" gap={2} mb={2}>
            <Icon as={FiLock} />
            {t.users.changePassword}
          </Heading>
          <Text color="gray.600">
            {t.users.securityNotice}
          </Text>
        </Box>

        {/* 当前用户信息 */}
        <Card>
          <CardHeader>
            <HStack>
              <Icon as={FiUser} />
              <Text fontWeight="medium">{t.users.currentUserInfo}</Text>
            </HStack>
          </CardHeader>
          <CardBody>
            <VStack spacing={3} align="stretch">
              <HStack justify="space-between">
                <Text>{t.users.username}:</Text>
                <Badge colorScheme="blue" fontSize="sm">
                  {user?.username}
                </Badge>
              </HStack>
              <HStack justify="space-between">
                <Text>{t.users.role}:</Text>
                <Badge 
                  colorScheme={
                    user?.role === 'super_admin' ? 'red' :
                    user?.role === 'admin' ? 'blue' :
                    user?.role === 'operator' ? 'green' : 'gray'
                  }
                  fontSize="sm"
                >
                  {user?.role === 'super_admin' ? t.users.superAdmin :
                   user?.role === 'admin' ? t.users.admin :
                   user?.role === 'operator' ? t.users.operator : t.users.readOnly}
                </Badge>
              </HStack>
              <HStack justify="space-between">
                <Text>{t.users.status}:</Text>
                <Badge colorScheme={user?.is_active ? 'green' : 'red'} fontSize="sm">
                  {user?.is_active ? t.users.active : t.users.disabled}
                </Badge>
              </HStack>
            </VStack>
          </CardBody>
        </Card>

        {/* 密码修改表单 */}
        <Card>
          <CardHeader>
            <HStack>
              <Icon as={FiShield} />
              <Text fontWeight="medium">{t.users.changePassword}</Text>
            </HStack>
          </CardHeader>
          <CardBody>
            <form onSubmit={handleSubmit}>
              <VStack spacing={4}>
                {/* 当前密码 */}
                <FormControl isRequired>
                  <FormLabel>{t.users.currentPassword}</FormLabel>
                  <HStack>
                    <Input
                      type={showPasswords.current ? 'text' : 'password'}
                      value={formData.currentPassword}
                      onChange={(e) => handleInputChange('currentPassword', e.target.value)}
                      placeholder={t.users.currentPasswordPlaceholder}
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => togglePasswordVisibility('current')}
                    >
                      <Icon as={showPasswords.current ? FiEyeOff : FiEye} />
                    </Button>
                  </HStack>
                </FormControl>

                <Divider />

                {/* 新密码 */}
                <FormControl isRequired>
                  <FormLabel>{t.users.newPassword}</FormLabel>
                  <HStack>
                    <Input
                      type={showPasswords.new ? 'text' : 'password'}
                      value={formData.newPassword}
                      onChange={(e) => handleInputChange('newPassword', e.target.value)}
                      placeholder={t.users.newPasswordPlaceholder}
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => togglePasswordVisibility('new')}
                    >
                      <Icon as={showPasswords.new ? FiEyeOff : FiEye} />
                    </Button>
                  </HStack>
                </FormControl>

                {/* 确认新密码 */}
                <FormControl isRequired>
                  <FormLabel>{t.users.confirmPassword}</FormLabel>
                  <HStack>
                    <Input
                      type={showPasswords.confirm ? 'text' : 'password'}
                      value={formData.confirmPassword}
                      onChange={(e) => handleInputChange('confirmPassword', e.target.value)}
                      placeholder={t.users.confirmPasswordPlaceholder}
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => togglePasswordVisibility('confirm')}
                    >
                      <Icon as={showPasswords.confirm ? FiEyeOff : FiEye} />
                    </Button>
                  </HStack>
                </FormControl>

                {/* 密码要求提示 */}
                <Alert status="info" size="sm">
                  <AlertIcon />
                  <Text fontSize="sm">
                    {t.users.passwordRequirements}
                  </Text>
                </Alert>

                {/* 操作按钮 */}
                <HStack spacing={4} w="full" pt={4}>
                  <Button
                    type="button"
                    variant="outline"
                    onClick={handleReset}
                    flex={1}
                    isDisabled={loading}
                  >
                    {t.common.reset}
                  </Button>
                  <Button
                    type="submit"
                    colorScheme="brand"
                    leftIcon={<Icon as={FiSave} />}
                    flex={1}
                    isLoading={loading}
                    loadingText={t.users.changingPassword}
                  >
                    {t.users.changePassword}
                  </Button>
                </HStack>
              </VStack>
            </form>
          </CardBody>
        </Card>

        {/* 安全提示 */}
        <Alert status="warning">
          <AlertIcon />
          <VStack align="start" spacing={1}>
            <Text fontWeight="medium">{t.users.securityTips}</Text>
            <Text fontSize="sm">
              • {t.users.reLoginAfterChange}
            </Text>
            <Text fontSize="sm">
              • {t.users.useStrongPassword}
            </Text>
            <Text fontSize="sm">
              • {t.users.dontReusePassword}
            </Text>
          </VStack>
        </Alert>
      </VStack>
    </Box>
  )
}

export default ChangePassword

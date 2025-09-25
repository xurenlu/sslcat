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
  Heading,
  Text,
  useToast,
  Alert,
  AlertIcon,
  Spinner,
  Center,
} from '@chakra-ui/react'
import { FiShield, FiUser, FiLock } from 'react-icons/fi'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { useConfig } from '../contexts/ConfigContext'

const Login: React.FC = () => {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  
  const { login, isAuthenticated, isLoading: authLoading } = useAuth()
  const { adminPrefix } = useConfig()
  const navigate = useNavigate()
  const toast = useToast()

  // 如果已经登录，重定向到仪表板
  useEffect(() => {
    if (isAuthenticated) {
      navigate(`${adminPrefix}/dashboard`)
    }
  }, [isAuthenticated, navigate, adminPrefix])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError('')

    try {
      const success = await login(username, password)
      if (success) {
        toast({
          title: '登录成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        navigate(`${adminPrefix}/dashboard`)
      } else {
        setError('用户名或密码错误')
      }
    } catch (err) {
      setError('登录失败，请重试')
      console.error('Login error:', err)
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
                    <Input
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="请输入密码"
                      size="lg"
                      isDisabled={isLoading}
                    />
                  </FormControl>

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

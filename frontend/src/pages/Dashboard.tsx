import React, { useEffect, useState } from 'react'
import {
  Box,
  Heading,
  SimpleGrid,
  Stat,
  StatLabel,
  StatNumber,
  Card,
  CardBody,
  VStack,
  HStack,
  Button,
  Icon,
  Text,
  Flex,
  useToast,
  Spinner,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
} from '@chakra-ui/react'
import {
  FiRefreshCw,
  FiPlus,
  FiShield,
  FiSettings,
  FiZap,
  FiServer,
  FiCheckCircle,
} from 'react-icons/fi'
import { Link as RouterLink } from 'react-router-dom'
import { useTranslation } from '../hooks/useLanguage'

interface DashboardStats {
  activeRules: number
  cachedProxies: number
  publicIP: string
  goVersion: string
}

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats>({
    activeRules: 0,
    cachedProxies: 0,
    publicIP: '未知',
    goVersion: 'go1.21.0',
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const toast = useToast()
  const t = useTranslation()

  const refreshStats = async () => {
    setLoading(true)
    setError(null)
    try {
      // TODO: 实际的 API 调用
      // const response = await fetch('/api/stats')
      // const data = await response.json()
      // setStats(data)
      
      // 模拟数据
      setTimeout(() => {
        setStats({
          activeRules: 15,
          cachedProxies: 342,
          publicIP: '192.168.1.100',
          goVersion: 'go1.21.0',
        })
        setLoading(false)
        toast({
          title: t.common.success,
          description: '系统统计信息已更新',
          status: 'success',
          duration: 2000,
          isClosable: true,
        })
      }, 1000)
    } catch (error) {
      console.error('获取统计信息失败:', error)
      const errorMessage = error instanceof Error ? error.message : '未知错误'
      setError(errorMessage)
      setLoading(false)
      toast({
        title: '数据刷新失败',
        description: errorMessage,
        status: 'error',
        duration: 4000,
        isClosable: true,
      })
    }
  }

  useEffect(() => {
    refreshStats()
  }, [])

  const quickActions = [
    {
      title: '新增代理规则',
      icon: FiPlus,
      path: '/proxy/new',
      colorScheme: 'blue',
    },
    {
      title: '管理SSL证书',
      icon: FiShield,
      path: '/ssl',
      colorScheme: 'green',
    },
    {
      title: '安全设置',
      icon: FiShield,
      path: '/security',
      colorScheme: 'orange',
    },
    {
      title: '系统设置',
      icon: FiSettings,
      path: '/settings',
      colorScheme: 'purple',
    },
  ]

  return (
    <Box>
      <Flex justify="space-between" align="center" mb={6}>
        <Heading size="lg">{t.dashboard.title}</Heading>
        <Button
          leftIcon={<Icon as={FiRefreshCw} />}
          onClick={refreshStats}
          isLoading={loading}
          loadingText={t.common.loading}
          colorScheme="blue"
          variant="outline"
        >
          {t.common.refresh}
        </Button>
      </Flex>

      {/* 错误提示 */}
      {error && (
        <Alert status="error" mb={6}>
          <AlertIcon />
          <AlertTitle>数据加载失败！</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* 加载状态 */}
      {loading && (
        <Flex justify="center" align="center" py={8} mb={6}>
          <Spinner size="lg" color="blue.500" />
          <Text ml={4} color="gray.600">正在加载系统数据...</Text>
        </Flex>
      )}

      {/* 统计卡片 */}
      <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={6} mb={8}>
        <Card>
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="brand.500" fontWeight="bold" textTransform="uppercase" fontSize="xs">
                    活动域名
                  </StatLabel>
                  <StatNumber fontSize="2xl" fontWeight="bold">
                    {stats.activeRules}
                  </StatNumber>
                </Box>
                <Icon as={FiZap} boxSize={8} color="gray.300" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="green.500" fontWeight="bold" textTransform="uppercase" fontSize="xs">
                    总请求数
                  </StatLabel>
                  <StatNumber fontSize="2xl" fontWeight="bold">
                    {stats.cachedProxies}
                  </StatNumber>
                </Box>
                <Icon as={FiServer} boxSize={8} color="gray.300" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="purple.500" fontWeight="bold" textTransform="uppercase" fontSize="xs">
                    公网IP
                  </StatLabel>
                  <StatNumber fontSize="lg" fontWeight="bold">
                    {stats.publicIP}
                  </StatNumber>
                </Box>
                <Icon as={FiServer} boxSize={8} color="gray.300" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <Stat>
              <HStack justify="space-between">
                <Box>
                  <StatLabel color="orange.500" fontWeight="bold" textTransform="uppercase" fontSize="xs">
                    Go版本
                  </StatLabel>
                  <StatNumber fontSize="lg" fontWeight="bold">
                    {stats.goVersion}
                  </StatNumber>
                </Box>
                <Icon as={FiSettings} boxSize={8} color="gray.300" />
              </HStack>
            </Stat>
          </CardBody>
        </Card>
      </SimpleGrid>

      {/* 快捷操作 */}
      <Box mb={8}>
        <Heading size="md" mb={4}>快捷操作</Heading>
        <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={4}>
          {quickActions.map((action) => (
            <Button
              key={action.path}
              as={RouterLink}
              to={action.path}
              colorScheme={action.colorScheme}
              leftIcon={<Icon as={action.icon} />}
              h="60px"
              justifyContent="flex-start"
            >
              {action.title}
            </Button>
          ))}
        </SimpleGrid>
      </Box>

      {/* 系统信息 */}
      <SimpleGrid columns={{ base: 1, lg: 2 }} spacing={6}>
        <Card>
          <CardBody>
            <VStack align="stretch" spacing={4}>
              <Heading size="md">系统状态</Heading>
              <VStack align="stretch" spacing={3}>
                <HStack justify="space-between">
                  <Text fontWeight="medium">运行时间:</Text>
                  <Text>计算中...</Text>
                </HStack>
                <HStack justify="space-between">
                  <Text fontWeight="medium">公网IP:</Text>
                  <Text>{stats.publicIP}</Text>
                </HStack>
                <HStack justify="space-between">
                  <Text fontWeight="medium">版本:</Text>
                  <Text>SSLcat v1.0.0</Text>
                </HStack>
                <HStack justify="space-between">
                  <Text fontWeight="medium">Go版本:</Text>
                  <Text>{stats.goVersion}</Text>
                </HStack>
              </VStack>
            </VStack>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <VStack align="stretch" spacing={4}>
              <Heading size="md">最近活动</Heading>
              <VStack align="stretch" spacing={3}>
                <HStack>
                  <Icon as={FiCheckCircle} color="green.500" />
                  <Text>服务正常运行中</Text>
                </HStack>
                <HStack>
                  <Icon as={FiShield} color="blue.500" />
                  <Text>SSL证书状态良好</Text>
                </HStack>
                <HStack>
                  <Icon as={FiZap} color="purple.500" />
                  <Text>代理服务正常</Text>
                </HStack>
              </VStack>
            </VStack>
          </CardBody>
        </Card>
      </SimpleGrid>
    </Box>
  )
}

export default Dashboard

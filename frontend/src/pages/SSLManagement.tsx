import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  Button,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Card,
  CardBody,
  HStack,
  Badge,
  Icon,
  Flex,
  Text,
  IconButton,
  useToast,
  Progress,
  VStack,
} from '@chakra-ui/react'
import {
  FiShield,
  FiRefreshCw,
  FiDownload,
  FiTrash2,
  FiCheck,
  FiX,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'

interface SSLCertificate {
  id: string
  domain: string
  issuer: string
  expires: string
  status: 'valid' | 'expiring' | 'expired'
  autoRenew: boolean
  created: string
}

const SSLManagement: React.FC = () => {
  const [certificates, setCertificates] = useState<SSLCertificate[]>([])
  const [loading, setLoading] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const toast = useToast()
  const { adminPrefix } = useConfig()

  const refreshCertificates = async () => {
    setLoading(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/ssl-certs'), {
        method: 'GET',
        credentials: 'include', // 包含认证 cookies
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const data = await response.json()
      setCertificates(data || [])
    } catch (error) {
      console.error('获取SSL证书失败:', error)
      toast({
        title: '获取失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  const deleteCertificate = async (id: string) => {
    const cert = certificates.find(c => c.id === id)
    if (!cert) return

    if (!window.confirm(`确定要删除域名 "${cert.domain}" 的证书吗？\n\n此操作不可撤销，删除后将无法使用 HTTPS 访问该域名。`)) {
      return
    }

    try {
      // TODO: 实际的 API 调用
      setCertificates(certificates.filter(cert => cert.id !== id))
      toast({
        title: '证书删除成功',
        description: `域名 ${cert.domain} 的证书已删除`,
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
    } catch (error) {
      toast({
        title: '证书删除失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 4000,
        isClosable: true,
      })
    }
  }

  const renewCertificate = async (id: string) => {
    const cert = certificates.find(c => c.id === id)
    if (!cert) return

    try {
      // TODO: 实际的 API 调用
      toast({
        title: '证书更新已启动',
        description: `正在为域名 ${cert.domain} 申请新证书`,
        status: 'info',
        duration: 3000,
        isClosable: true,
      })

      // 模拟更新状态
      setCertificates(certs => certs.map(c => 
        c.id === id ? { ...c, status: 'valid' as const } : c
      ))

      // 延迟显示成功消息
      setTimeout(() => {
        toast({
          title: '证书更新成功',
          description: `域名 ${cert.domain} 的证书已成功更新`,
          status: 'success',
          duration: 4000,
          isClosable: true,
        })
      }, 2000)
    } catch (error) {
      toast({
        title: '证书更新失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 4000,
        isClosable: true,
      })
    }
  }

  const syncACMECertificates = async () => {
    setSyncing(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/ssl/sync-acme'), {
        method: 'POST',
        credentials: 'include',
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      toast({
        title: '同步成功',
        description: 'ACME 证书已同步到本地存储',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })

      // 同步后刷新证书列表
      refreshCertificates()
    } catch (error) {
      console.error('同步 ACME 证书失败:', error)
      toast({
        title: '同步失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setSyncing(false)
    }
  }

  useEffect(() => {
    refreshCertificates()
  }, [])

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'valid': return 'green'
      case 'expiring': return 'orange'
      case 'expired': return 'red'
      default: return 'gray'
    }
  }

  const getStatusText = (status: string) => {
    switch (status) {
      case 'valid': return '有效'
      case 'expiring': return '即将过期'
      case 'expired': return '已过期'
      default: return status
    }
  }

  const getDaysUntilExpiry = (expiryDate: string) => {
    const expiry = new Date(expiryDate)
    const now = new Date()
    const diff = expiry.getTime() - now.getTime()
    return Math.ceil(diff / (1000 * 3600 * 24))
  }

  return (
    <Box>
      <Flex justify="space-between" align="center" mb={6}>
        <HStack>
          <Icon as={FiShield} boxSize={6} />
          <Heading size="lg">SSL证书管理</Heading>
        </HStack>
        <HStack>
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            onClick={refreshCertificates}
            isLoading={loading}
            variant="outline"
          >
            刷新
          </Button>
          <Button
            leftIcon={<Icon as={FiShield} />}
            colorScheme="blue"
            mr={2}
          >
            申请证书
          </Button>
          <Button
            leftIcon={<Icon as={FiRefreshCw />}
            colorScheme="green"
            variant="outline"
            onClick={syncACMECertificates}
            isLoading={syncing}
          >
            同步 ACME 证书
          </Button>
        </HStack>
      </Flex>

      <Card>
        <CardBody>
          {certificates.length > 0 ? (
            <Table variant="simple">
              <Thead>
                <Tr>
                  <Th>域名</Th>
                  <Th>颁发机构</Th>
                  <Th>状态</Th>
                  <Th>过期时间</Th>
                  <Th>自动续签</Th>
                  <Th>创建时间</Th>
                  <Th>操作</Th>
                </Tr>
              </Thead>
              <Tbody>
                {certificates.map((cert) => {
                  const daysLeft = getDaysUntilExpiry(cert.expires)
                  return (
                    <Tr key={cert.id}>
                      <Td>
                        <Text fontFamily="mono">{cert.domain}</Text>
                      </Td>
                      <Td>{cert.issuer}</Td>
                      <Td>
                        <VStack align="start" spacing={1}>
                          <Badge colorScheme={getStatusColor(cert.status)}>
                            {getStatusText(cert.status)}
                          </Badge>
                          {cert.status === 'expiring' && (
                            <Text fontSize="xs" color="orange.600">
                              {daysLeft} 天后过期
                            </Text>
                          )}
                          {cert.status === 'expired' && (
                            <Text fontSize="xs" color="red.600">
                              已过期 {Math.abs(daysLeft)} 天
                            </Text>
                          )}
                        </VStack>
                      </Td>
                      <Td>
                        <VStack align="start" spacing={1}>
                          <Text fontSize="sm">{cert.expires}</Text>
                          {cert.status === 'valid' && (
                            <Progress
                              size="sm"
                              value={Math.max(0, Math.min(100, (daysLeft / 90) * 100))}
                              colorScheme={daysLeft > 30 ? 'green' : daysLeft > 7 ? 'orange' : 'red'}
                              w="80px"
                            />
                          )}
                        </VStack>
                      </Td>
                      <Td>
                        <Icon
                          as={cert.autoRenew ? FiCheck : FiX}
                          color={cert.autoRenew ? 'green.500' : 'red.500'}
                        />
                      </Td>
                      <Td>{cert.created}</Td>
                      <Td>
                        <HStack spacing={2}>
                          <IconButton
                            aria-label="更新证书"
                            icon={<FiRefreshCw />}
                            size="sm"
                            variant="ghost"
                            colorScheme="blue"
                            onClick={() => renewCertificate(cert.id)}
                          />
                          <IconButton
                            aria-label="下载证书"
                            icon={<FiDownload />}
                            size="sm"
                            variant="ghost"
                            colorScheme="green"
                          />
                          <IconButton
                            aria-label="删除证书"
                            icon={<FiTrash2 />}
                            size="sm"
                            variant="ghost"
                            colorScheme="red"
                            onClick={() => deleteCertificate(cert.id)}
                          />
                        </HStack>
                      </Td>
                    </Tr>
                  )
                })}
              </Tbody>
            </Table>
          ) : (
            <Box textAlign="center" py={8}>
              <Icon as={FiShield} boxSize={12} color="gray.300" mb={4} />
              <Text color="gray.500" mb={4}>暂无SSL证书</Text>
              <Button leftIcon={<Icon as={FiShield} />} colorScheme="blue">
                申请第一个证书
              </Button>
            </Box>
          )}
        </CardBody>
      </Card>
    </Box>
  )
}

export default SSLManagement

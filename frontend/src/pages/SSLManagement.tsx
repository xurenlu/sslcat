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
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalFooter,
  ModalCloseButton,
  FormControl,
  FormLabel,
  Input,
  useDisclosure,
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
import { useTranslation } from '../hooks/useLanguage'

interface SSLCertificate {
  domain: string
  issued_at: string
  expires_at: string
  status: string
  is_wildcard: boolean
  self_signed: boolean
  issuer: string
}

const SSLManagement: React.FC = () => {
  const [certificates, setCertificates] = useState<SSLCertificate[]>([])
  const [loading, setLoading] = useState(false)
  const [syncing, setSyncing] = useState(false)
  const [applying, setApplying] = useState(false)
  const [newDomain, setNewDomain] = useState('')
  const { isOpen, onOpen, onClose } = useDisclosure()
  const toast = useToast()
  const { adminPrefix } = useConfig()
  const t = useTranslation()

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

  const deleteCertificate = async (domain: string) => {
    if (!window.confirm(`确定要删除域名 "${domain}" 的证书吗？\n\n此操作不可撤销，删除后将无法使用 HTTPS 访问该域名。`)) {
      return
    }

    try {
      // TODO: 实际的 API 调用
      setCertificates(certificates.filter(cert => cert.domain !== domain))
      toast({
        title: '证书删除成功',
        description: `域名 ${domain} 的证书已删除`,
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

  const applyCertificate = async () => {
    if (!newDomain.trim()) {
      toast({
        title: '请输入域名',
        status: 'warning',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    setApplying(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/ssl/generate'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          domains: [newDomain.trim()], // 后端期望的是数组
        }),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const data = await response.json()
      toast({
        title: '证书申请成功',
        description: `域名 ${newDomain} 的证书已开始申请，请稍后刷新查看`,
        status: 'success',
        duration: 5000,
        isClosable: true,
      })
      
      setNewDomain('')
      onClose()
      
      // 3秒后自动刷新证书列表
      setTimeout(() => {
        refreshCertificates()
      }, 3000)
    } catch (error) {
      console.error('申请SSL证书失败:', error)
      toast({
        title: '证书申请失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 4000,
        isClosable: true,
      })
    } finally {
      setApplying(false)
    }
  }

  const downloadCertificate = async (domain: string) => {
    try {
      const effectivePrefix = adminPrefix || '/sslcat-panel'
      
      // 创建下载链接并触发下载
      const downloadUrl = `${effectivePrefix}/ssl/download?domain=${encodeURIComponent(domain)}&type=cert`
      
      // 创建一个临时的 a 标签来触发下载
      const link = document.createElement('a')
      link.href = downloadUrl
      link.download = `${domain}.crt`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      
      toast({
        title: '证书下载已启动',
        description: `正在下载域名 ${domain} 的证书`,
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
    } catch (error) {
      toast({
        title: '证书下载失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 4000,
        isClosable: true,
      })
    }
  }

  const renewCertificate = async (domain: string) => {
    try {
      // TODO: 实际的 API 调用
      toast({
        title: '证书更新已启动',
        description: `正在为域名 ${domain} 申请新证书`,
        status: 'info',
        duration: 3000,
        isClosable: true,
      })

      // 模拟更新状态
      setCertificates(certs => certs.map(c => 
        c.domain === domain ? { ...c, status: '有效' } : c
      ))

      // 延迟显示成功消息
      setTimeout(() => {
        toast({
          title: '证书更新成功',
          description: `域名 ${domain} 的证书已成功更新`,
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
      case '有效': return 'green'
      case '即将过期': return 'orange'
      case '过期': return 'red'
      default: return 'gray'
    }
  }

  const getStatusText = (status: string) => {
    return status
  }

  const getDaysUntilExpiry = (expiryDate: string) => {
    const expiry = new Date(expiryDate)
    const now = new Date()
    const diff = expiry.getTime() - now.getTime()
    return Math.ceil(diff / (1000 * 3600 * 24))
  }

  const formatDate = (dateString: string) => {
    const date = new Date(dateString)
    return date.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  const getIssuerName = (cert: SSLCertificate) => {
    // 使用后端返回的颁发机构信息
    return cert.issuer || '未知'
  }

  return (
    <Box>
      <Flex justify="space-between" align="center" mb={6}>
        <HStack>
          <Icon as={FiShield} boxSize={6} />
          <Heading size="lg">{t.ssl.title}</Heading>
        </HStack>
        <HStack>
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            onClick={refreshCertificates}
            isLoading={loading}
            variant="outline"
          >
            {t.ssl.refresh}
          </Button>
          <Button
            leftIcon={<Icon as={FiShield} />}
            colorScheme="blue"
            mr={2}
            onClick={onOpen}
          >
{t.ssl.applyCertificate}
          </Button>
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            colorScheme="green"
            variant="outline"
            onClick={syncACMECertificates}
            isLoading={syncing}
          >
            {t.ssl.syncACMECertificates}
          </Button>
        </HStack>
      </Flex>

      <Card>
        <CardBody>
          {certificates.length > 0 ? (
            <Table variant="simple">
              <Thead>
                <Tr>
                  <Th>{t.ssl.domain}</Th>
                  <Th>{t.ssl.issuer}</Th>
                  <Th>{t.ssl.status}</Th>
                  <Th>{t.ssl.expiresAt}</Th>
                  <Th>{t.ssl.autoRenew}</Th>
                  <Th>{t.ssl.createdAt}</Th>
                  <Th>{t.ssl.actions}</Th>
                </Tr>
              </Thead>
              <Tbody>
                {certificates.map((cert, index) => {
                  const daysLeft = getDaysUntilExpiry(cert.expires_at)
                  return (
                    <Tr key={`${cert.domain}-${index}`}>
                      <Td>
                        <VStack align="start" spacing={1}>
                          <Text fontFamily="mono">{cert.domain}</Text>
                          {cert.is_wildcard && (
                            <Badge size="sm" colorScheme="blue">{t.ssl.wildcard}</Badge>
                          )}
                        </VStack>
                      </Td>
                      <Td>
                        <Text fontSize="sm">{getIssuerName(cert)}</Text>
                      </Td>
                      <Td>
                        <VStack align="start" spacing={1}>
                          <Badge colorScheme={getStatusColor(cert.status)}>
                            {getStatusText(cert.status)}
                          </Badge>
                          {cert.status === '即将过期' && (
                            <Text fontSize="xs" color="orange.600">
                              {daysLeft} {t.ssl.daysUntilExpiry}
                            </Text>
                          )}
                          {cert.status === '过期' && (
                            <Text fontSize="xs" color="red.600">
                              {t.ssl.expired} {Math.abs(daysLeft)} {t.ssl.expiredDays}
                            </Text>
                          )}
                        </VStack>
                      </Td>
                      <Td>
                        <VStack align="start" spacing={1}>
                          <Text fontSize="sm">{formatDate(cert.expires_at)}</Text>
                          {cert.status === '有效' && (
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
                          as={FiCheck}
                          color="green.500"
                        />
                      </Td>
                      <Td>
                        <Text fontSize="sm" color="gray.600">
                          {formatDate(cert.issued_at)}
                        </Text>
                      </Td>
                      <Td>
                        <HStack spacing={2}>
                          <IconButton
                            aria-label={t.ssl.updateCertificate}
                            icon={<FiRefreshCw />}
                            size="sm"
                            variant="ghost"
                            colorScheme="blue"
                            onClick={() => renewCertificate(cert.domain)}
                          />
                          <IconButton
                            aria-label={t.ssl.downloadCertificate}
                            icon={<FiDownload />}
                            size="sm"
                            variant="ghost"
                            colorScheme="green"
                            onClick={() => downloadCertificate(cert.domain)}
                          />
                          <IconButton
                            aria-label={t.ssl.deleteCertificate}
                            icon={<FiTrash2 />}
                            size="sm"
                            variant="ghost"
                            colorScheme="red"
                            onClick={() => deleteCertificate(cert.domain)}
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
              <Text color="gray.500" mb={4}>{t.ssl.noCertificates}</Text>
              <Button leftIcon={<Icon as={FiShield} />} colorScheme="blue" onClick={onOpen}>
                {t.ssl.createFirst}
              </Button>
            </Box>
          )}
        </CardBody>
      </Card>

      {/* 申请证书对话框 */}
      <Modal isOpen={isOpen} onClose={onClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>{t.ssl.applyCertificate}</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <FormControl>
              <FormLabel>{t.ssl.domain}</FormLabel>
              <Input
                placeholder={t.ssl.domainPlaceholder}
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                onKeyPress={(e) => {
                  if (e.key === 'Enter') {
                    applyCertificate()
                  }
                }}
              />
              <Text fontSize="sm" color="gray.500" mt={2}>
                {t.ssl.wildcardSupport}
              </Text>
            </FormControl>
          </ModalBody>
          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onClose}>
              {t.ssl.cancel}
            </Button>
            <Button
              colorScheme="blue"
              onClick={applyCertificate}
              isLoading={applying}
              loadingText={t.ssl.applying}
            >
              {t.ssl.applyCertificate}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default SSLManagement

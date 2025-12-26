import React, { useState, useEffect, useCallback } from 'react'
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
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  Spinner,
  Divider,
  Alert,
  AlertIcon,
  AlertDescription,
} from '@chakra-ui/react'
import {
  FiShield,
  FiRefreshCw,
  FiDownload,
  FiTrash2,
  FiCheck,
  FiX,
  FiUpload,
  FiKey,
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
  const [uploading, setUploading] = useState(false)
  const [renewing, setRenewing] = useState(false)
  const [newDomain, setNewDomain] = useState('')
  const [renewDomain, setRenewDomain] = useState('')
  const [uploadDomain, setUploadDomain] = useState('')
  const [certFile, setCertFile] = useState<File | null>(null)
  const [keyFile, setKeyFile] = useState<File | null>(null)
  const [preflightLoading, setPreflightLoading] = useState(false)
  const [preflightData, setPreflightData] = useState<{
    dns_provider: { name: string; found: boolean; available: boolean }
    resolution: { resolved: boolean; points_to_server: boolean; info: string; error: string }
    challenge: { type: string; reason: string }
  } | null>(null)
  const [progressEvents, setProgressEvents] = useState<Array<{
    status: string
    message: string
    attempt: number
    maxAttempts: number
    progress: number
    error?: string
    timestamp: string
  }>>([])
  const [renewProgressEvents, setRenewProgressEvents] = useState<Array<{
    status: string
    message: string
    attempt: number
    maxAttempts: number
    progress: number
    error?: string
    timestamp: string
  }>>([])
  const [eventSource, setEventSource] = useState<EventSource | null>(null)
  const { isOpen, onOpen, onClose } = useDisclosure()
  const { isOpen: isUploadOpen, onOpen: onUploadOpen, onClose: onUploadClose } = useDisclosure()
  const { isOpen: isRenewOpen, onOpen: onRenewOpen, onClose: onRenewClose } = useDisclosure()
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

  // 预检域名信息
  const preflightDomain = useCallback(async (domain: string) => {
    if (!domain.trim()) {
      setPreflightData(null)
      return
    }

    setPreflightLoading(true)
    try {
      const response = await fetch(
        buildApiPath(adminPrefix, `/ssl/preflight?domain=${encodeURIComponent(domain.trim())}`),
        {
          method: 'GET',
          credentials: 'include',
        }
      )

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const data = await response.json()
      if (data.success) {
        setPreflightData(data)
      } else {
        setPreflightData(null)
      }
    } catch (error) {
      console.error('预检域名失败:', error)
      setPreflightData(null)
    } finally {
      setPreflightLoading(false)
    }
  }, [adminPrefix])

  // 监听域名输入变化，debounce 调用预检 API
  useEffect(() => {
    if (!isOpen) {
      // 对话框关闭时清空预检数据
      setPreflightData(null)
      return
    }

    const timer = setTimeout(() => {
      if (newDomain.trim()) {
        preflightDomain(newDomain)
      } else {
        setPreflightData(null)
      }
    }, 500) // 500ms debounce

    return () => clearTimeout(timer)
  }, [newDomain, isOpen, preflightDomain])

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

    // 清空之前的进度
    setProgressEvents([])
    setApplying(true)

    try {
      // 使用流式 API
      const response = await fetch(buildApiPath(adminPrefix, '/ssl/generate-stream'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          domain: newDomain.trim(),
        }),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      // 使用 EventSource 接收 SSE 事件
      const reader = response.body?.getReader()
      const decoder = new TextDecoder()

      if (!reader) {
        throw new Error('无法读取响应流')
      }

      let buffer = ''
      let isComplete = false

      while (!isComplete) {
        const { done, value } = await reader.read()
        
        if (done) {
          isComplete = true
          break
        }

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() || '' // 保留最后不完整的行

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const eventData = JSON.parse(line.slice(6))
              setProgressEvents(prev => [...prev, eventData])

              // 如果完成或失败，结束
              if (eventData.status === 'success' || eventData.status === 'failed' || eventData.status === 'completed') {
                isComplete = true
                
                if (eventData.status === 'success') {
                  toast({
                    title: '证书申请成功',
                    description: eventData.message || `域名 ${newDomain} 的证书申请成功`,
                    status: 'success',
                    duration: 5000,
                    isClosable: true,
                  })
                  
                  // 3秒后自动刷新证书列表并关闭对话框
                  setTimeout(() => {
                    refreshCertificates()
                    setNewDomain('')
                    setPreflightData(null)
                    setProgressEvents([])
                    onClose()
                  }, 3000)
                } else if (eventData.status === 'failed') {
                  toast({
                    title: '证书申请失败',
                    description: eventData.error || eventData.message || '未知错误',
                    status: 'error',
                    duration: 5000,
                    isClosable: true,
                  })
                }
              }
            } catch (e) {
              console.error('解析进度事件失败:', e)
            }
          }
        }
      }
    } catch (error) {
      console.error('申请SSL证书失败:', error)
      toast({
        title: '证书申请失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 4000,
        isClosable: true,
      })
      setProgressEvents(prev => [...prev, {
        status: 'failed',
        message: error instanceof Error ? error.message : '未知错误',
        attempt: 0,
        maxAttempts: 0,
        progress: 100,
        error: error instanceof Error ? error.message : '未知错误',
        timestamp: new Date().toISOString(),
      }])
    } finally {
      setApplying(false)
    }
  }

  const downloadCertificate = async (domain: string, type: 'cert' | 'key' | 'bundle' = 'cert') => {
    try {
      const effectivePrefix = adminPrefix || '/sslcat-panel'
      
      // 创建下载链接并触发下载
      const downloadUrl = `${effectivePrefix}/ssl/download?domain=${encodeURIComponent(domain)}&type=${type}`
      
      // 创建一个临时的 a 标签来触发下载
      const link = document.createElement('a')
      link.href = downloadUrl
      
      let filename = ''
      switch (type) {
        case 'cert':
          filename = `${domain}.crt`
          break
        case 'key':
          filename = `${domain}.key`
          break
        case 'bundle':
          filename = `${domain}-bundle.pem`
          break
      }
      link.download = filename
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      
      toast({
        title: '下载已启动',
        description: `正在下载域名 ${domain} 的${type === 'cert' ? '证书' : type === 'key' ? '私钥' : '证书包'}`,
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
    } catch (error) {
      toast({
        title: '下载失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 4000,
        isClosable: true,
      })
    }
  }

  const downloadAllCertificates = async () => {
    try {
      const effectivePrefix = adminPrefix || '/sslcat-panel'
      
      // 创建下载链接并触发下载
      const downloadUrl = `${effectivePrefix}/ssl/download-all`
      
      // 创建一个临时的 a 标签来触发下载
      const link = document.createElement('a')
      link.href = downloadUrl
      link.download = `sslcerts-${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.zip`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      
      toast({
        title: '下载已启动',
        description: `正在下载所有域名的 SSL 证书包`,
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
    } catch (error) {
      toast({
        title: '下载失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 4000,
        isClosable: true,
      })
    }
  }

  const uploadCertificate = async () => {
    if (!uploadDomain.trim()) {
      toast({
        title: '请输入域名',
        status: 'warning',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    if (!certFile || !keyFile) {
      toast({
        title: '请选择文件',
        description: '请同时选择证书文件和私钥文件',
        status: 'warning',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    setUploading(true)
    try {
      const formData = new FormData()
      formData.append('domain', uploadDomain.trim())
      formData.append('cert', certFile)
      formData.append('key', keyFile)

      const effectivePrefix = adminPrefix || '/sslcat-panel'
      const response = await fetch(`${effectivePrefix}/ssl/upload`, {
        method: 'POST',
        credentials: 'include',
        body: formData,
      })

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(errorText || `HTTP error! status: ${response.status}`)
      }

      toast({
        title: '证书上传成功',
        description: `域名 ${uploadDomain} 的证书已成功上传`,
        status: 'success',
        duration: 3000,
        isClosable: true,
      })

      // 清空表单
      setUploadDomain('')
      setCertFile(null)
      setKeyFile(null)
      onUploadClose()

      // 刷新证书列表
      setTimeout(() => {
        refreshCertificates()
      }, 1000)
    } catch (error) {
      console.error('上传SSL证书失败:', error)
      toast({
        title: '证书上传失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 4000,
        isClosable: true,
      })
    } finally {
      setUploading(false)
    }
  }

  const renewCertificate = async (domain: string) => {
    // 设置续期域名并打开进度对话框
    setRenewDomain(domain)
    setRenewProgressEvents([])
    setRenewing(true)
    onRenewOpen()

    try {
      // 使用流式 API
      const response = await fetch(buildApiPath(adminPrefix, '/ssl/retry-stream'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          domain: domain.trim(),
        }),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      // 使用 EventSource 接收 SSE 事件
      const reader = response.body?.getReader()
      const decoder = new TextDecoder()

      if (!reader) {
        throw new Error('无法读取响应流')
      }

      let buffer = ''
      let isComplete = false

      while (!isComplete) {
        const { done, value } = await reader.read()
        
        if (done) {
          isComplete = true
          break
        }

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() || '' // 保留最后不完整的行

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const eventData = JSON.parse(line.slice(6))
              setRenewProgressEvents(prev => [...prev, eventData])

              // 如果完成或失败，结束
              if (eventData.status === 'success' || eventData.status === 'failed' || eventData.status === 'completed') {
                isComplete = true
                
                if (eventData.status === 'success') {
                  toast({
                    title: '证书续期成功',
                    description: eventData.message || `域名 ${domain} 的证书已成功续期`,
                    status: 'success',
                    duration: 5000,
                    isClosable: true,
                  })
                  
                  // 3秒后自动刷新证书列表并关闭对话框
                  setTimeout(() => {
                    refreshCertificates()
                    setRenewDomain('')
                    setRenewProgressEvents([])
                    onRenewClose()
                  }, 3000)
                } else if (eventData.status === 'failed') {
                  toast({
                    title: '证书续期失败',
                    description: eventData.error || eventData.message || '未知错误',
                    status: 'error',
                    duration: 5000,
                    isClosable: true,
                  })
                }
              }
            } catch (e) {
              console.error('解析进度事件失败:', e)
            }
          }
        }
      }
    } catch (error) {
      console.error('证书续期失败:', error)
      toast({
        title: '证书续期失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 4000,
        isClosable: true,
      })
      setRenewProgressEvents(prev => [...prev, {
        status: 'failed',
        message: error instanceof Error ? error.message : '未知错误',
        attempt: 0,
        maxAttempts: 0,
        progress: 100,
        error: error instanceof Error ? error.message : '未知错误',
        timestamp: new Date().toISOString(),
      }])
    } finally {
      setRenewing(false)
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
            leftIcon={<Icon as={FiUpload} />}
            colorScheme="purple"
            mr={2}
            onClick={onUploadOpen}
          >
            上传证书
          </Button>
          <Button
            leftIcon={<Icon as={FiDownload} />}
            colorScheme="teal"
            mr={2}
            onClick={downloadAllCertificates}
            isDisabled={certificates.length === 0}
          >
            下载全部证书
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
                          <Menu>
                            <MenuButton
                              as={IconButton}
                              aria-label={t.ssl.downloadCertificate}
                              icon={<FiDownload />}
                              size="sm"
                              variant="ghost"
                              colorScheme="green"
                            />
                            <MenuList>
                              <MenuItem
                                icon={<FiShield />}
                                onClick={() => downloadCertificate(cert.domain, 'cert')}
                              >
                                下载证书
                              </MenuItem>
                              <MenuItem
                                icon={<FiKey />}
                                onClick={() => downloadCertificate(cert.domain, 'key')}
                              >
                                下载私钥
                              </MenuItem>
                              <MenuItem
                                icon={<FiDownload />}
                                onClick={() => downloadCertificate(cert.domain, 'bundle')}
                              >
                                下载证书包
                              </MenuItem>
                            </MenuList>
                          </Menu>
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
      <Modal
        isOpen={isOpen}
        onClose={() => {
          if (!applying) {
            setProgressEvents([])
            setPreflightData(null)
            onClose()
          }
        }}
        size="lg"
        closeOnOverlayClick={!applying}
      >
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>{t.ssl.applyCertificate}</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4} align="stretch">
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

              {/* 预检信息显示区域 */}
              {newDomain.trim() && (
                <>
                  <Divider />
                  <Box>
                    <Text fontSize="sm" fontWeight="semibold" mb={2}>
                      域名预检信息
                    </Text>
                    {preflightLoading ? (
                      <HStack spacing={2}>
                        <Spinner size="sm" />
                        <Text fontSize="sm" color="gray.500">
                          正在检查域名信息...
                        </Text>
                      </HStack>
                    ) : preflightData ? (
                      <VStack spacing={2} align="stretch" fontSize="sm">
                        {/* DNS 服务商信息 */}
                        <HStack spacing={2}>
                          <Text fontWeight="medium" minW="100px">
                            DNS 服务商:
                          </Text>
                          {preflightData.dns_provider.found ? (
                            <Badge colorScheme="green">
                              {preflightData.dns_provider.name}
                            </Badge>
                          ) : (
                            <Badge colorScheme="yellow">未在已配置的提供商中</Badge>
                          )}
                        </HStack>

                        {/* 域名解析信息 */}
                        <HStack spacing={2}>
                          <Text fontWeight="medium" minW="100px">
                            解析状态:
                          </Text>
                          {preflightData.resolution.error ? (
                            <Text color="red.500">{preflightData.resolution.error}</Text>
                          ) : (
                            <>
                              {preflightData.resolution.points_to_server ? (
                                <Badge colorScheme="green">指向本服务器</Badge>
                              ) : (
                                <Badge colorScheme="orange">未指向本服务器</Badge>
                              )}
                              <Text color="gray.600" fontSize="xs">
                                {preflightData.resolution.info}
                              </Text>
                            </>
                          )}
                        </HStack>

                        {/* 挑战方式信息 */}
                        <HStack spacing={2}>
                          <Text fontWeight="medium" minW="100px">
                            挑战方式:
                          </Text>
                          <Badge
                            colorScheme={
                              preflightData.challenge.type === 'DNS-01' ? 'blue' : 'purple'
                            }
                          >
                            {preflightData.challenge.type}
                          </Badge>
                          <Text color="gray.600" fontSize="xs">
                            {preflightData.challenge.reason}
                          </Text>
                        </HStack>
                      </VStack>
                    ) : (
                      <Text fontSize="sm" color="gray.500">
                        输入域名后将自动检查相关信息
                      </Text>
                    )}
                  </Box>
                </>
              )}

              {/* 申请进度显示区域 */}
              {applying && progressEvents.length > 0 && (
                <>
                  <Divider />
                  <Box>
                    <Text fontSize="sm" fontWeight="semibold" mb={3}>
                      申请进度
                    </Text>
                    <VStack spacing={3} align="stretch">
                      {/* 进度条 */}
                      {progressEvents.length > 0 && (
                        <Box>
                          <Progress
                            value={progressEvents[progressEvents.length - 1]?.progress || 0}
                            colorScheme={
                              progressEvents[progressEvents.length - 1]?.status === 'success'
                                ? 'green'
                                : progressEvents[progressEvents.length - 1]?.status === 'failed'
                                ? 'red'
                                : 'blue'
                            }
                            size="sm"
                            borderRadius="md"
                          />
                          <Text fontSize="xs" color="gray.500" mt={1} textAlign="right">
                            {progressEvents[progressEvents.length - 1]?.progress || 0}%
                          </Text>
                        </Box>
                      )}

                      {/* 进度事件列表 */}
                      <Box
                        maxH="200px"
                        overflowY="auto"
                        border="1px"
                        borderColor="gray.200"
                        borderRadius="md"
                        p={3}
                        bg="gray.50"
                      >
                        <VStack spacing={2} align="stretch">
                          {progressEvents.map((event, index) => (
                            <Box key={index} fontSize="sm">
                              <HStack spacing={2} align="start">
                                {event.status === 'success' && (
                                  <Icon as={FiCheck} color="green.500" mt={0.5} />
                                )}
                                {event.status === 'failed' && (
                                  <Icon as={FiX} color="red.500" mt={0.5} />
                                )}
                                {event.status !== 'success' && event.status !== 'failed' && (
                                  <Spinner size="xs" color="blue.500" />
                                )}
                                <Box flex={1}>
                                  <Text fontWeight="medium">{event.message}</Text>
                                  {event.error && (
                                    <Alert status="error" size="sm" mt={2} borderRadius="md">
                                      <AlertIcon />
                                      <AlertDescription fontSize="xs">{event.error}</AlertDescription>
                                    </Alert>
                                  )}
                                  {event.attempt > 0 && (
                                    <Text fontSize="xs" color="gray.500" mt={1}>
                                      尝试 {event.attempt}/{event.maxAttempts}
                                    </Text>
                                  )}
                                </Box>
                              </HStack>
                            </Box>
                          ))}
                        </VStack>
                      </Box>
                    </VStack>
                  </Box>
                </>
              )}
            </VStack>
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

      {/* 上传证书对话框 */}
      <Modal isOpen={isUploadOpen} onClose={onUploadClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>上传 SSL 证书</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl isRequired>
                <FormLabel>域名</FormLabel>
                <Input
                  placeholder="example.com"
                  value={uploadDomain}
                  onChange={(e) => setUploadDomain(e.target.value)}
                />
              </FormControl>
              <FormControl isRequired>
                <FormLabel>证书文件 (.crt/.pem)</FormLabel>
                <Input
                  type="file"
                  accept=".crt,.pem"
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    if (file) {
                      setCertFile(file)
                    }
                  }}
                />
                {certFile && (
                  <Text fontSize="sm" color="green.500" mt={1}>
                    已选择: {certFile.name}
                  </Text>
                )}
              </FormControl>
              <FormControl isRequired>
                <FormLabel>私钥文件 (.key/.pem)</FormLabel>
                <Input
                  type="file"
                  accept=".key,.pem"
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    if (file) {
                      setKeyFile(file)
                    }
                  }}
                />
                {keyFile && (
                  <Text fontSize="sm" color="green.500" mt={1}>
                    已选择: {keyFile.name}
                  </Text>
                )}
              </FormControl>
              <Text fontSize="sm" color="gray.500">
                支持 PEM 格式的证书和私钥文件
              </Text>
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onUploadClose}>
              取消
            </Button>
            <Button
              colorScheme="purple"
              onClick={uploadCertificate}
              isLoading={uploading}
              loadingText="上传中..."
            >
              上传证书
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* 续期证书对话框 */}
      <Modal
        isOpen={isRenewOpen}
        onClose={() => {
          if (!renewing) {
            setRenewProgressEvents([])
            setRenewDomain('')
            onRenewClose()
          }
        }}
        size="lg"
        closeOnOverlayClick={!renewing}
      >
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>续期证书</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4} align="stretch">
              <Box>
                <Text fontSize="sm" fontWeight="semibold" mb={2}>
                  域名
                </Text>
                <Text fontSize="md" fontFamily="mono" color="blue.600">
                  {renewDomain}
                </Text>
              </Box>

              {/* 续期进度显示区域 */}
              {renewing && renewProgressEvents.length > 0 && (
                <>
                  <Divider />
                  <Box>
                    <Text fontSize="sm" fontWeight="semibold" mb={3}>
                      续期进度
                    </Text>
                    <VStack spacing={3} align="stretch">
                      {/* 进度条 */}
                      {renewProgressEvents.length > 0 && (
                        <Box>
                          <Progress
                            value={renewProgressEvents[renewProgressEvents.length - 1]?.progress || 0}
                            colorScheme={
                              renewProgressEvents[renewProgressEvents.length - 1]?.status === 'success'
                                ? 'green'
                                : renewProgressEvents[renewProgressEvents.length - 1]?.status === 'failed'
                                ? 'red'
                                : 'blue'
                            }
                            size="sm"
                            borderRadius="md"
                          />
                          <Text fontSize="xs" color="gray.500" mt={1} textAlign="right">
                            {renewProgressEvents[renewProgressEvents.length - 1]?.progress || 0}%
                          </Text>
                        </Box>
                      )}

                      {/* 进度事件列表 */}
                      <Box
                        maxH="200px"
                        overflowY="auto"
                        border="1px"
                        borderColor="gray.200"
                        borderRadius="md"
                        p={3}
                        bg="gray.50"
                      >
                        <VStack spacing={2} align="stretch">
                          {renewProgressEvents.map((event, index) => (
                            <Box key={index} fontSize="sm">
                              <HStack spacing={2} align="start">
                                {event.status === 'success' && (
                                  <Icon as={FiCheck} color="green.500" mt={0.5} />
                                )}
                                {event.status === 'failed' && (
                                  <Icon as={FiX} color="red.500" mt={0.5} />
                                )}
                                {event.status !== 'success' && event.status !== 'failed' && (
                                  <Spinner size="xs" color="blue.500" />
                                )}
                                <Box flex={1}>
                                  <Text fontWeight="medium">{event.message}</Text>
                                  {event.error && (
                                    <Alert status="error" size="sm" mt={2} borderRadius="md">
                                      <AlertIcon />
                                      <AlertDescription fontSize="xs">{event.error}</AlertDescription>
                                    </Alert>
                                  )}
                                  {event.attempt > 0 && (
                                    <Text fontSize="xs" color="gray.500" mt={1}>
                                      尝试 {event.attempt}/{event.maxAttempts}
                                    </Text>
                                  )}
                                </Box>
                              </HStack>
                            </Box>
                          ))}
                        </VStack>
                      </Box>
                    </VStack>
                  </Box>
                </>
              )}

              {/* 如果还没有开始或者没有进度事件，显示提示信息 */}
              {!renewing && renewProgressEvents.length === 0 && (
                <Alert status="info" borderRadius="md">
                  <AlertIcon />
                  <AlertDescription fontSize="sm">
                    即将为域名 <strong>{renewDomain}</strong> 续期证书，请稍候...
                  </AlertDescription>
                </Alert>
              )}
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button
              variant="ghost"
              onClick={() => {
                if (!renewing) {
                  setRenewProgressEvents([])
                  setRenewDomain('')
                  onRenewClose()
                }
              }}
              isDisabled={renewing}
            >
              关闭
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default SSLManagement

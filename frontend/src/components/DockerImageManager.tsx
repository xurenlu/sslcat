import React, { useState, useEffect } from 'react'
import {
  Box,
  VStack,
  HStack,
  Text,
  Badge,
  Button,
  Icon,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  IconButton,
  useToast,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  useDisclosure,
  FormControl,
  FormLabel,
  FormHelperText,
  Input,
  Switch,
  Select,
  Alert,
  AlertIcon,
  Code,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  SimpleGrid,
  Card,
  CardBody,
  CardHeader,
  Heading,
} from '@chakra-ui/react'
import {
  FiPackage,
  FiTrash2,
  FiRefreshCw,
  FiSettings,
  FiUpload,
  FiDownload,
  FiServer,
  FiClock,
  FiHardDrive,
  FiCheckCircle,
  FiXCircle,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

interface DockerImage {
  name: string
  tag: string
  full_name: string
  size: number
  created_at: string
  pushed_at: string
  commit_hash: string
  build_status: string
  push_status: string
}

interface DockerRegistryConfig {
  enabled: boolean
  url: string
  username: string
  password: string
  namespace: string
  use_https: boolean
  timeout: number
  tag_strategy: string
  auto_push: boolean
  cleanup_policy: {
    enabled: boolean
    keep_images: number
    keep_days: number
    clean_interval: number
  }
  connection_status?: boolean
  connection_error?: string
}

interface DockerImageManagerProps {
  appName: string
}

const DockerImageManager: React.FC<DockerImageManagerProps> = ({ appName }) => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  const [images, setImages] = useState<DockerImage[]>([])
  const [registryConfig, setRegistryConfig] = useState<DockerRegistryConfig | null>(null)
  const [loading, setLoading] = useState(false)
  const toast = useToast()
  
  const { isOpen: isConfigOpen, onOpen: onConfigOpen, onClose: onConfigClose } = useDisclosure()

  // 加载Docker镜像列表
  const loadImages = async () => {
    setLoading(true)
    try {
      const response = await fetch(
        buildApiPath(adminPrefix, `/api/git-server/docker/images?app=${appName}`),
        { credentials: 'include' }
      )
      
      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          setImages(data.data || [])
        }
      }
    } catch (error) {
      console.error('Failed to load images:', error)
      toast({
        title: '加载失败',
        description: '无法加载Docker镜像列表',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  // 加载Registry配置
  const loadRegistryConfig = async () => {
    try {
      const response = await fetch(
        buildApiPath(adminPrefix, '/api/git-server/docker/config'),
        { credentials: 'include' }
      )
      
      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          setRegistryConfig(data.data)
        }
      }
    } catch (error) {
      console.error('Failed to load registry config:', error)
    }
  }

  // 更新Registry配置
  const updateRegistryConfig = async (config: DockerRegistryConfig) => {
    try {
      const response = await fetch(
        buildApiPath(adminPrefix, '/api/git-server/docker/config/update'),
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(config),
        }
      )
      
      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          setRegistryConfig(config)
          toast({
            title: '配置更新成功',
            description: 'Docker Registry配置已更新',
            status: 'success',
            duration: 3000,
            isClosable: true,
          })
          onConfigClose()
        }
      }
    } catch (error) {
      console.error('Failed to update registry config:', error)
      toast({
        title: '配置更新失败',
        description: '请检查配置并重试',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  // 测试Registry连接
  const testConnection = async () => {
    if (!registryConfig) {
      toast({
        title: '配置为空',
        description: '请先配置 Docker Registry',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    try {
      const response = await fetch(
        buildApiPath(adminPrefix, '/api/git-server/docker/test'),
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(registryConfig),
        }
      )
      
      const data = await response.json()
      
      toast({
        title: data.connected ? '连接成功' : '连接失败',
        description: data.message || data.error,
        status: data.connected ? 'success' : 'error',
        duration: 5000,
        isClosable: true,
      })
    } catch (error) {
      console.error('Failed to test connection:', error)
      toast({
        title: '测试失败',
        description: '无法测试Registry连接',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  // 格式化文件大小
  const formatSize = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  // 格式化时间
  const formatTime = (timeStr: string) => {
    return new Date(timeStr).toLocaleString()
  }

  useEffect(() => {
    loadImages()
    loadRegistryConfig()
  }, [appName])

  return (
    <Box>
      {/* Registry状态和配置 */}
      <Card mb={6}>
        <CardHeader>
          <HStack justify="space-between">
            <Heading size="md" display="flex" alignItems="center">
              <Icon as={FiServer} mr={2} />
              Docker Registry
            </Heading>
            <HStack>
              <Button
                size="sm"
                leftIcon={<Icon as={FiSettings} />}
                onClick={onConfigOpen}
              >
                配置
              </Button>
              <Button
                size="sm"
                leftIcon={<Icon as={FiRefreshCw} />}
                onClick={loadImages}
                isLoading={loading}
              >
                刷新
              </Button>
            </HStack>
          </HStack>
        </CardHeader>
        <CardBody>
          {registryConfig ? (
            <SimpleGrid columns={{ base: 2, md: 4 }} spacing={4}>
              <Stat>
                <StatLabel>状态</StatLabel>
                <StatNumber>
                  <Badge colorScheme={registryConfig.enabled ? 'green' : 'gray'}>
                    {registryConfig.enabled ? '已启用' : '已禁用'}
                  </Badge>
                </StatNumber>
                <StatHelpText>
                  {registryConfig.connection_status ? (
                    <HStack>
                      <Icon as={FiCheckCircle} color="green.500" />
                      <Text>连接正常</Text>
                    </HStack>
                  ) : (
                    <HStack>
                      <Icon as={FiXCircle} color="red.500" />
                      <Text>连接异常</Text>
                    </HStack>
                  )}
                </StatHelpText>
              </Stat>

              <Stat>
                <StatLabel>仓库地址</StatLabel>
                <StatNumber fontSize="md">
                  {registryConfig.url || '本地Docker'}
                </StatNumber>
                <StatHelpText>{registryConfig.namespace}</StatHelpText>
              </Stat>

              <Stat>
                <StatLabel>标签策略</StatLabel>
                <StatNumber fontSize="md">{registryConfig.tag_strategy}</StatNumber>
                <StatHelpText>
                  {registryConfig.auto_push ? '自动推送' : '手动推送'}
                </StatHelpText>
              </Stat>

              <Stat>
                <StatLabel>镜像数量</StatLabel>
                <StatNumber>{images.length}</StatNumber>
                <StatHelpText>当前应用镜像</StatHelpText>
              </Stat>
            </SimpleGrid>
          ) : (
            <Alert status="info">
              <AlertIcon />
              正在加载Registry配置...
            </Alert>
          )}
        </CardBody>
      </Card>

      {/* 镜像列表 */}
      <Card>
        <CardHeader>
          <Heading size="md" display="flex" alignItems="center">
            <Icon as={FiPackage} mr={2} />
            Docker镜像 ({images.length})
          </Heading>
        </CardHeader>
        <CardBody>
          {images.length === 0 ? (
            <Alert status="info">
              <AlertIcon />
              <VStack align="start">
                <Text>暂无Docker镜像</Text>
                <Text fontSize="sm">
                  推送代码到Git仓库时会自动构建Docker镜像（如果启用了Docker Registry）
                </Text>
              </VStack>
            </Alert>
          ) : (
            <Table variant="simple" size="sm">
              <Thead>
                <Tr>
                  <Th>镜像名称</Th>
                  <Th>标签</Th>
                  <Th>大小</Th>
                  <Th>创建时间</Th>
                  <Th>提交哈希</Th>
                  <Th>状态</Th>
                  <Th>操作</Th>
                </Tr>
              </Thead>
              <Tbody>
                {images.map((image, index) => (
                  <Tr key={index}>
                    <Td>
                      <Code fontSize="xs">{image.name}</Code>
                    </Td>
                    <Td>
                      <Badge colorScheme="blue" fontSize="xs">
                        {image.tag}
                      </Badge>
                    </Td>
                    <Td>{formatSize(image.size)}</Td>
                    <Td>{formatTime(image.created_at)}</Td>
                    <Td>
                      {image.commit_hash && (
                        <Code fontSize="xs">
                          {image.commit_hash.slice(0, 8)}
                        </Code>
                      )}
                    </Td>
                    <Td>
                      <VStack spacing={1} align="start">
                        <Badge
                          colorScheme={image.build_status === 'success' ? 'green' : 'red'}
                          fontSize="xs"
                        >
                          构建: {image.build_status}
                        </Badge>
                        <Badge
                          colorScheme={image.push_status === 'success' ? 'green' : 'red'}
                          fontSize="xs"
                        >
                          推送: {image.push_status}
                        </Badge>
                      </VStack>
                    </Td>
                    <Td>
                      <IconButton
                        aria-label={t.docker.delete_image}
                        icon={<Icon as={FiTrash2} />}
                        size="sm"
                        colorScheme="red"
                        variant="ghost"
                        onClick={() => {
                          // TODO: 实现删除镜像功能
                          toast({
                            title: '功能开发中',
                            description: '镜像删除功能正在开发中',
                            status: 'info',
                            duration: 2000,
                            isClosable: true,
                          })
                        }}
                      />
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          )}
        </CardBody>
      </Card>

      {/* Registry配置弹窗 */}
      <Modal isOpen={isConfigOpen} onClose={onConfigClose} size="lg">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>Docker Registry 配置</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            {registryConfig && (
              <VStack spacing={4} align="stretch">
                <FormControl display="flex" alignItems="center">
                  <FormLabel mb="0">启用Docker Registry</FormLabel>
                  <Switch
                    isChecked={registryConfig.enabled}
                    onChange={(e) => setRegistryConfig({
                      ...registryConfig,
                      enabled: e.target.checked
                    })}
                  />
                </FormControl>

                {registryConfig.enabled && (
                  <>
                    <FormControl>
                      <FormLabel>仓库地址</FormLabel>
                      <Input
                        value={registryConfig.url}
                        onChange={(e) => setRegistryConfig({
                          ...registryConfig,
                          url: e.target.value
                        })}
                        placeholder="registry.example.com"
                      />
                      <FormHelperText>
                        请勿包含 http:// 或 https:// 前缀，系统会自动添加
                      </FormHelperText>
                    </FormControl>

                    <FormControl display="flex" alignItems="center">
                      <FormLabel mb="0">使用 HTTPS</FormLabel>
                      <Switch
                        isChecked={registryConfig.use_https}
                        onChange={(e) => setRegistryConfig({
                          ...registryConfig,
                          use_https: e.target.checked
                        })}
                      />
                    </FormControl>

                    <HStack>
                      <FormControl>
                        <FormLabel>用户名</FormLabel>
                        <Input
                          value={registryConfig.username}
                          onChange={(e) => setRegistryConfig({
                            ...registryConfig,
                            username: e.target.value
                          })}
                        />
                      </FormControl>

                      <FormControl>
                        <FormLabel>密码</FormLabel>
                        <Input
                          type="text"
                          value={registryConfig.password}
                          onChange={(e) => setRegistryConfig({
                            ...registryConfig,
                            password: e.target.value
                          })}
                        />
                      </FormControl>
                    </HStack>

                    <HStack>
                      <FormControl>
                        <FormLabel>命名空间</FormLabel>
                        <Input
                          value={registryConfig.namespace}
                          onChange={(e) => setRegistryConfig({
                            ...registryConfig,
                            namespace: e.target.value
                          })}
                          placeholder="sslcat"
                        />
                      </FormControl>

                      <FormControl>
                        <FormLabel>标签策略</FormLabel>
                        <Select
                          value={registryConfig.tag_strategy}
                          onChange={(e) => setRegistryConfig({
                            ...registryConfig,
                            tag_strategy: e.target.value
                          })}
                        >
                          <option value="commit">Git提交哈希</option>
                          <option value="timestamp">时间戳</option>
                          <option value="version">版本号</option>
                        </Select>
                      </FormControl>
                    </HStack>

                    <FormControl display="flex" alignItems="center">
                      <FormLabel mb="0">自动推送镜像</FormLabel>
                      <Switch
                        isChecked={registryConfig.auto_push}
                        onChange={(e) => setRegistryConfig({
                          ...registryConfig,
                          auto_push: e.target.checked
                        })}
                      />
                    </FormControl>

                    <Box>
                      <Text fontWeight="medium" mb={2}>清理策略</Text>
                      <VStack spacing={3} align="stretch">
                        <FormControl display="flex" alignItems="center">
                          <FormLabel mb="0">启用自动清理</FormLabel>
                          <Switch
                            isChecked={registryConfig.cleanup_policy.enabled}
                            onChange={(e) => setRegistryConfig({
                              ...registryConfig,
                              cleanup_policy: {
                                ...registryConfig.cleanup_policy,
                                enabled: e.target.checked
                              }
                            })}
                          />
                        </FormControl>

                        {registryConfig.cleanup_policy.enabled && (
                          <HStack>
                            <FormControl>
                              <FormLabel>保留镜像数</FormLabel>
                              <Input
                                type="number"
                                value={registryConfig.cleanup_policy.keep_images}
                                onChange={(e) => setRegistryConfig({
                                  ...registryConfig,
                                  cleanup_policy: {
                                    ...registryConfig.cleanup_policy,
                                    keep_images: parseInt(e.target.value) || 10
                                  }
                                })}
                                min="1"
                                max="100"
                              />
                            </FormControl>

                            <FormControl>
                              <FormLabel>保留天数</FormLabel>
                              <Input
                                type="number"
                                value={registryConfig.cleanup_policy.keep_days}
                                onChange={(e) => setRegistryConfig({
                                  ...registryConfig,
                                  cleanup_policy: {
                                    ...registryConfig.cleanup_policy,
                                    keep_days: parseInt(e.target.value) || 30
                                  }
                                })}
                                min="1"
                                max="365"
                              />
                            </FormControl>
                          </HStack>
                        )}
                      </VStack>
                    </Box>

                    <HStack>
                      <Button
                        leftIcon={<Icon as={FiCheckCircle} />}
                        onClick={testConnection}
                        size="sm"
                      >
                        测试连接
                      </Button>
                    </HStack>
                  </>
                )}
              </VStack>
            )}
          </ModalBody>

          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onConfigClose}>
              取消
            </Button>
            <Button
              colorScheme="blue"
              onClick={() => registryConfig && updateRegistryConfig(registryConfig)}
            >
              保存配置
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default DockerImageManager

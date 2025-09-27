import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  Card,
  CardBody,
  CardHeader,
  VStack,
  HStack,
  Button,
  Icon,
  useToast,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  Text,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  FormControl,
  FormLabel,
  Input,
  Select,
  Spinner,
  Center,
  Alert,
  AlertIcon,
  Tooltip,
  useDisclosure,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  SimpleGrid,
  Progress,
} from '@chakra-ui/react'
import {
  FiHardDrive,
  FiRefreshCw,
  FiTrash2,
  FiPlus,
  FiDatabase,
  FiClock,
  FiDownload,
  FiActivity,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

interface CacheStats {
  enabled: boolean
  cache_dir: string
  max_size_bytes: number
  current_size_bytes: number
  total_objects: number
  hit_rate: number
  cache_rules: CacheRule[]
}

interface CacheRule {
  id: string
  match_type: string
  pattern: string
  media_types: string[]
  ttl_seconds: number
}

interface CacheObject {
  key: string
  path: string
  host: string
  content_type: string
  size_bytes: number
  created_at: string
  expires_at: string
  last_access: string
  hit_count: number
}

const CDNManagement: React.FC = () => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  const toast = useToast()
  const { isOpen: isAddRuleOpen, onOpen: onAddRuleOpen, onClose: onAddRuleClose } = useDisclosure()
  
  const [stats, setStats] = useState<CacheStats | null>(null)
  const [objects, setObjects] = useState<CacheObject[]>([])
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  
  // 添加规则表单
  const [ruleForm, setRuleForm] = useState({
    match_type: 'prefix',
    pattern: '',
    media_types: [] as string[],
    ttl_seconds: 3600,
  })

  // 获取缓存统计
  const fetchStats = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/cdn/stats'), {
        credentials: 'include',
      })
      
      if (response.ok) {
        const data = await response.json()
        setStats(data)
      } else {
        toast({
          title: '获取CDN统计失败',
          status: 'error',
          duration: 3000,
          isClosable: true,
        })
      }
    } catch (error) {
      console.error('获取CDN统计失败:', error)
      toast({
        title: '获取CDN统计失败',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  // 获取缓存对象列表
  const fetchObjects = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/cdn/objects'), {
        credentials: 'include',
      })
      
      if (response.ok) {
        const data = await response.json()
        setObjects(data.objects || [])
      } else {
        toast({
          title: '获取缓存对象失败',
          status: 'error',
          duration: 3000,
          isClosable: true,
        })
      }
    } catch (error) {
      console.error('获取缓存对象失败:', error)
      toast({
        title: '获取缓存对象失败',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  // 清理缓存
  const clearCache = async (pattern?: string) => {
    setActionLoading(true)
    try {
      const url = pattern 
        ? buildApiPath(adminPrefix, `/cdn/purge?pattern=${encodeURIComponent(pattern)}`)
        : buildApiPath(adminPrefix, '/cdn/purge')
        
      const response = await fetch(url, {
        method: 'POST',
        credentials: 'include',
      })
      
      if (response.ok) {
        toast({
          title: pattern ? '缓存清理成功' : '全部缓存清理成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        fetchStats()
        fetchObjects()
      } else {
        const error = await response.json()
        toast({
          title: '缓存清理失败',
          description: error.error || '未知错误',
          status: 'error',
          duration: 3000,
          isClosable: true,
        })
      }
    } catch (error) {
      console.error('缓存清理失败:', error)
      toast({
        title: '缓存清理失败',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setActionLoading(false)
    }
  }

  // 添加缓存规则
  const addRule = async () => {
    setActionLoading(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/cdn/rules'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(ruleForm),
      })
      
      if (response.ok) {
        toast({
          title: '缓存规则添加成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        onAddRuleClose()
        setRuleForm({
          match_type: 'prefix',
          pattern: '',
          media_types: [],
          ttl_seconds: 3600,
        })
        fetchStats()
      } else {
        const error = await response.json()
        toast({
          title: '添加缓存规则失败',
          description: error.error || '未知错误',
          status: 'error',
          duration: 3000,
          isClosable: true,
        })
      }
    } catch (error) {
      console.error('添加缓存规则失败:', error)
      toast({
        title: '添加缓存规则失败',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setActionLoading(false)
    }
  }

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString('zh-CN')
  }

  useEffect(() => {
    const loadData = async () => {
      setLoading(true)
      await Promise.all([fetchStats(), fetchObjects()])
      setLoading(false)
    }
    loadData()
  }, [])

  if (loading) {
    return (
      <Center h="400px">
        <Spinner size="xl" />
      </Center>
    )
  }

  const usagePercentage = stats ? (stats.current_size_bytes / stats.max_size_bytes) * 100 : 0

  return (
    <Box p={6}>
      <VStack spacing={6} align="stretch">
        {/* 页面标题 */}
        <HStack justify="space-between">
          <Heading size="lg" display="flex" alignItems="center" gap={2}>
            <Icon as={FiHardDrive} />
            {t.cdn.title}
          </Heading>
          <HStack spacing={3}>
            <Button
              leftIcon={<Icon as={FiPlus} />}
              colorScheme="blue"
              onClick={onAddRuleOpen}
            >
{t.cdn.addRule}
            </Button>
            <Button
              leftIcon={<Icon as={FiRefreshCw} />}
              onClick={() => {
                fetchStats()
                fetchObjects()
              }}
            >
{t.cdn.refresh}
            </Button>
            <Button
              leftIcon={<Icon as={FiTrash2} />}
              colorScheme="red"
              variant="outline"
              onClick={() => clearCache()}
              isLoading={actionLoading}
            >
{t.cdn.clearAllCache}
            </Button>
          </HStack>
        </HStack>

        {/* 缓存统计 */}
        {stats && (
          <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={6}>
            <Card>
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center" gap={2}>
                    <Icon as={FiDatabase} />
                    存储使用
                  </StatLabel>
                  <StatNumber>{formatBytes(stats.current_size_bytes)}</StatNumber>
                  <StatHelpText>
                    总容量: {formatBytes(stats.max_size_bytes)}
                  </StatHelpText>
                  <Progress 
                    value={usagePercentage} 
                    colorScheme={usagePercentage > 80 ? 'red' : usagePercentage > 60 ? 'yellow' : 'green'}
                    size="sm"
                    mt={2}
                  />
                </Stat>
              </CardBody>
            </Card>

            <Card>
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center" gap={2}>
                    <Icon as={FiDownload} />
                    缓存对象
                  </StatLabel>
                  <StatNumber>{stats.total_objects}</StatNumber>
                  <StatHelpText>已缓存文件数量</StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card>
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center" gap={2}>
                    <Icon as={FiActivity} />
                    命中率
                  </StatLabel>
                  <StatNumber>{stats.hit_rate.toFixed(1)}%</StatNumber>
                  <StatHelpText>缓存命中率</StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card>
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center" gap={2}>
                    <Icon as={FiClock} />
                    缓存规则
                  </StatLabel>
                  <StatNumber>{stats.cache_rules.length}</StatNumber>
                  <StatHelpText>活跃规则数量</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
          </SimpleGrid>
        )}

        {/* 缓存规则 */}
        <Card>
          <CardHeader>
            <Heading size="md">缓存规则</Heading>
          </CardHeader>
          <CardBody>
            {stats?.cache_rules.length ? (
              <Table variant="simple">
                <Thead>
                  <Tr>
                    <Th>匹配类型</Th>
                    <Th>模式</Th>
                    <Th>媒体类型</Th>
                    <Th>TTL</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {stats.cache_rules.map((rule) => (
                    <Tr key={rule.id}>
                      <Td>
                        <Badge colorScheme="blue">
                          {rule.match_type === 'prefix' ? '前缀' : 
                           rule.match_type === 'suffix' ? '后缀' : '媒体类型'}
                        </Badge>
                      </Td>
                      <Td fontFamily="mono">{rule.pattern || '*'}</Td>
                      <Td fontSize="sm">
                        {rule.media_types?.length ? rule.media_types.join(', ') : '-'}
                      </Td>
                      <Td>{rule.ttl_seconds}s</Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            ) : (
              <Alert status="info">
                <AlertIcon />
                暂无缓存规则，缓存将使用域名级配置
              </Alert>
            )}
          </CardBody>
        </Card>

        {/* 缓存对象 */}
        <Card>
          <CardHeader>
            <Heading size="md">缓存对象</Heading>
          </CardHeader>
          <CardBody>
            {objects.length ? (
              <Table variant="simple">
                <Thead>
                  <Tr>
                    <Th>路径</Th>
                    <Th>主机</Th>
                    <Th>类型</Th>
                    <Th>大小</Th>
                    <Th>过期时间</Th>
                    <Th>最后访问</Th>
                    <Th>命中次数</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {objects.map((obj) => (
                    <Tr key={obj.key}>
                      <Td fontFamily="mono" fontSize="sm">{obj.path}</Td>
                      <Td>{obj.host}</Td>
                      <Td fontSize="sm">{obj.content_type}</Td>
                      <Td>{formatBytes(obj.size_bytes)}</Td>
                      <Td fontSize="sm">{formatDate(obj.expires_at)}</Td>
                      <Td fontSize="sm">{formatDate(obj.last_access)}</Td>
                      <Td>{obj.hit_count}</Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            ) : (
              <Alert status="info">
                <AlertIcon />
                暂无缓存对象
              </Alert>
            )}
          </CardBody>
        </Card>
      </VStack>

      {/* 添加缓存规则对话框 */}
      <Modal isOpen={isAddRuleOpen} onClose={onAddRuleClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>添加缓存规则</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>匹配类型</FormLabel>
                <Select
                  value={ruleForm.match_type}
                  onChange={(e) => setRuleForm(prev => ({ ...prev, match_type: e.target.value }))}
                >
                  <option value="prefix">前缀匹配</option>
                  <option value="suffix">后缀匹配</option>
                  <option value="media">媒体类型匹配</option>
                </Select>
              </FormControl>
              
              {(ruleForm.match_type === 'prefix' || ruleForm.match_type === 'suffix') && (
                <FormControl>
                  <FormLabel>路径模式</FormLabel>
                  <Input
                    value={ruleForm.pattern}
                    onChange={(e) => setRuleForm(prev => ({ ...prev, pattern: e.target.value }))}
                    placeholder="例如: /images/, .js, .css"
                  />
                </FormControl>
              )}
              
              {ruleForm.match_type === 'media' && (
                <FormControl>
                  <FormLabel>媒体类型（逗号分隔）</FormLabel>
                  <Input
                    value={ruleForm.media_types.join(', ')}
                    onChange={(e) => setRuleForm(prev => ({ 
                      ...prev, 
                      media_types: e.target.value.split(',').map(s => s.trim()).filter(s => s) 
                    }))}
                    placeholder="例如: image/, text/css, application/javascript"
                  />
                </FormControl>
              )}
              
              <FormControl>
                <FormLabel>缓存时间（秒）</FormLabel>
                <Input
                  type="number"
                  value={ruleForm.ttl_seconds}
                  onChange={(e) => setRuleForm(prev => ({ ...prev, ttl_seconds: parseInt(e.target.value) || 3600 }))}
                />
              </FormControl>
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onAddRuleClose}>
              取消
            </Button>
            <Button 
              colorScheme="blue" 
              onClick={addRule}
              isLoading={actionLoading}
            >
              添加
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default CDNManagement

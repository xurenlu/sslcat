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
import { FeatureGate } from '../components/FeatureGate'
import { CacheParticles } from '../components/CacheParticles'
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Legend,
  Tooltip as RechartsTooltip,
} from 'recharts'

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
          title: t.cdn.getStatsFailed,
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
          title: t.cdn.getObjectsFailed,
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
          title: pattern ? t.cdn.clearCacheSuccess : t.cdn.clearAllCacheSuccess,
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        fetchStats()
        fetchObjects()
      } else {
        const error = await response.json()
        toast({
          title: t.cdn.clearCacheFailed,
          description: error.error || t.cdn.unknownError,
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
          title: t.cdn.addRuleSuccess,
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
          title: t.cdn.addRuleFailed,
          description: error.error || t.cdn.unknownError,
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
                    {t.cdn.storageUsage}
                  </StatLabel>
                  <StatNumber>{formatBytes(stats.current_size_bytes)}</StatNumber>
                  <StatHelpText>
                    {t.cdn.totalCapacity}: {formatBytes(stats.max_size_bytes)}
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
                    {t.cdn.cachedObjects}
                  </StatLabel>
                  <StatNumber>{stats.total_objects}</StatNumber>
                  <StatHelpText>{t.cdn.cachedFilesCount}</StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card>
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center" gap={2}>
                    <Icon as={FiActivity} />
                    {t.cdn.hitRate}
                  </StatLabel>
                  <StatNumber>{stats.hit_rate.toFixed(1)}%</StatNumber>
                  <StatHelpText>{t.cdn.cacheHitRate}</StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card>
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center" gap={2}>
                    <Icon as={FiClock} />
                    {t.cdn.cacheRules}
                  </StatLabel>
                  <StatNumber>{stats.cache_rules.length}</StatNumber>
                  <StatHelpText>{t.cdn.activeRulesCount}</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
          </SimpleGrid>
        )}

        {/* 缓存规则 */}
        <Card>
          <CardHeader>
            <Heading size="md">{t.cdn.cacheRules}</Heading>
          </CardHeader>
          <CardBody>
            {stats?.cache_rules.length ? (
              <Table variant="simple">
                <Thead>
                  <Tr>
                    <Th>{t.cdn.matchType}</Th>
                    <Th>{t.cdn.pattern}</Th>
                    <Th>{t.cdn.mediaType}</Th>
                    <Th>{t.cdn.ttl}</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {stats.cache_rules.map((rule) => (
                    <Tr key={rule.id}>
                      <Td>
                        <Badge colorScheme="blue">
                          {rule.match_type === 'prefix' ? t.cdn.prefix : 
                           rule.match_type === 'suffix' ? t.cdn.suffix : t.cdn.media}
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
                {t.cdn.noCacheRules}
              </Alert>
            )}
          </CardBody>
        </Card>

        {/* 缓存对象可视化 */}
        {objects.length > 0 && (
          <Card mb={6}>
            <CardHeader>
              <Heading size="md">缓存对象可视化</Heading>
            </CardHeader>
            <CardBody>
              <FeatureGate
                require={['canvas2d']}
                fallback={
                  <Box>
                    <Text mb={4} fontSize="sm" color="gray.600">
                      您的浏览器不支持 Canvas，使用图表视图
                    </Text>
                    <Box height="300px">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={[
                              { name: '高命中率', value: objects.filter((o) => o.hit_count > 10).length },
                              { name: '中命中率', value: objects.filter((o) => o.hit_count > 5 && o.hit_count <= 10).length },
                              { name: '低命中率', value: objects.filter((o) => o.hit_count <= 5).length },
                            ]}
                            cx="50%"
                            cy="50%"
                            labelLine={false}
                            label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                            outerRadius={80}
                            fill="#8884d8"
                            dataKey="value"
                          >
                            <Cell fill="#00ff00" />
                            <Cell fill="#ffaa00" />
                            <Cell fill="#ff0000" />
                          </Pie>
                          <RechartsTooltip />
                          <Legend />
                        </PieChart>
                      </ResponsiveContainer>
                    </Box>
                  </Box>
                }
                showFallbackNotice={false}
              >
                <CacheParticles
                  objects={objects}
                  hitRate={stats?.hit_rate || 0}
                  height={400}
                />
              </FeatureGate>
            </CardBody>
          </Card>
        )}

        {/* 缓存对象 */}
        <Card>
          <CardHeader>
            <Heading size="md">{t.cdn.cachedObjects}</Heading>
          </CardHeader>
          <CardBody>
            {objects.length ? (
              <Table variant="simple">
                <Thead>
                  <Tr>
                    <Th>{t.cdn.path}</Th>
                    <Th>{t.cdn.host}</Th>
                    <Th>{t.cdn.type}</Th>
                    <Th>{t.cdn.size}</Th>
                    <Th>{t.cdn.expiresAt}</Th>
                    <Th>{t.cdn.lastAccess}</Th>
                    <Th>{t.cdn.hitCount}</Th>
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
                {t.cdn.noCacheObjects}
              </Alert>
            )}
          </CardBody>
        </Card>
      </VStack>

      {/* 添加缓存规则对话框 */}
      <Modal isOpen={isAddRuleOpen} onClose={onAddRuleClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>{t.cdn.addRuleModal}</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>{t.cdn.matchType}</FormLabel>
                <Select
                  value={ruleForm.match_type}
                  onChange={(e) => setRuleForm(prev => ({ ...prev, match_type: e.target.value }))}
                >
                  <option value="prefix">{t.cdn.prefixMatch}</option>
                  <option value="suffix">{t.cdn.suffixMatch}</option>
                  <option value="media">{t.cdn.mediaTypeMatch}</option>
                </Select>
              </FormControl>
              
              {(ruleForm.match_type === 'prefix' || ruleForm.match_type === 'suffix') && (
                <FormControl>
                  <FormLabel>{t.cdn.pathPattern}</FormLabel>
                  <Input
                    value={ruleForm.pattern}
                    onChange={(e) => setRuleForm(prev => ({ ...prev, pattern: e.target.value }))}
                    placeholder={t.cdn.pathPatternPlaceholder}
                  />
                </FormControl>
              )}
              
              {ruleForm.match_type === 'media' && (
                <FormControl>
                  <FormLabel>{t.cdn.mediaTypes}</FormLabel>
                  <Input
                    value={ruleForm.media_types.join(', ')}
                    onChange={(e) => setRuleForm(prev => ({ 
                      ...prev, 
                      media_types: e.target.value.split(',').map(s => s.trim()).filter(s => s) 
                    }))}
                    placeholder={t.cdn.mediaTypesPlaceholder}
                  />
                </FormControl>
              )}
              
              <FormControl>
                <FormLabel>{t.cdn.cacheTimeSeconds}</FormLabel>
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
              {t.cdn.cancel}
            </Button>
            <Button 
              colorScheme="blue" 
              onClick={addRule}
              isLoading={actionLoading}
            >
              {t.cdn.add}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default CDNManagement

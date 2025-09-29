import React from 'react'
import {
  Box,
  Heading,
  FormControl,
  FormLabel,
  Input,
  Switch,
  VStack,
  HStack,
  Icon,
  Text,
  SimpleGrid,
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  NumberIncrementStepper,
  NumberDecrementStepper,
  Badge,
  Alert,
  AlertIcon,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Button,
  useToast,
  Divider,
} from '@chakra-ui/react'
import { 
  FiDatabase, 
  FiClock,
  FiHardDrive,
  FiTrendingUp,
  FiRefreshCw,
  FiTrash2
} from 'react-icons/fi'

interface UpstreamCacheStats {
  enabled: boolean
  cache_dir: string
  hits: number
  misses: number
  stores: number
  hit_rate: number
  default_ttl: string
  respect_upstream: boolean
  max_size_bytes: number
}

interface UpstreamCacheConfigProps {
  // 缓存配置
  enabled: boolean
  cache_dir: string
  max_size_bytes: number
  default_ttl_seconds: number
  respect_upstream: boolean
  
  // 统计信息（可选）
  stats?: UpstreamCacheStats
  
  // 事件处理函数
  onFieldChange: (field: string, value: any) => void
  onPurgeCache?: () => void
  onRefreshStats?: () => void
}

const UpstreamCacheConfig: React.FC<UpstreamCacheConfigProps> = ({
  enabled,
  cache_dir,
  max_size_bytes,
  default_ttl_seconds,
  respect_upstream,
  stats,
  onFieldChange,
  onPurgeCache,
  onRefreshStats
}) => {
  const toast = useToast()

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${seconds}秒`
    if (seconds < 3600) return `${Math.round(seconds / 60)}分钟`
    if (seconds < 86400) return `${Math.round(seconds / 3600)}小时`
    return `${Math.round(seconds / 86400)}天`
  }

  const handlePurgeCache = async () => {
    if (onPurgeCache) {
      try {
        await onPurgeCache()
        toast({
          title: '缓存清理成功',
          description: '所有上游缓存已清理',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
      } catch (error) {
        toast({
          title: '缓存清理失败',
          description: '请稍后重试',
          status: 'error',
          duration: 3000,
          isClosable: true,
        })
      }
    }
  }

  return (
    <Box>
      {/* 缓存开关 */}
      <Box mb={6}>
        <Heading size="md" mb={4} display="flex" alignItems="center">
          <Icon as={FiDatabase} mr={2} />
          上游缓存配置
        </Heading>
        
        <FormControl display="flex" alignItems="center">
          <FormLabel htmlFor="upstream-cache-switch" mb="0">
            启用上游缓存
          </FormLabel>
          <Switch
            id="upstream-cache-switch"
            isChecked={enabled}
            onChange={(e) => onFieldChange('enabled', e.target.checked)}
          />
        </FormControl>
        
        <Text fontSize="sm" color="gray.500" mt={2}>
          启用后会缓存从上游服务器返回的静态文件，遵循Cache-Control策略
        </Text>
      </Box>

      {enabled && (
        <VStack spacing={6} align="stretch">
          {/* 缓存统计信息 */}
          {stats && (
            <Box>
              <HStack justify="space-between" mb={4}>
                <Heading size="sm" display="flex" alignItems="center">
                  <Icon as={FiTrendingUp} mr={2} />
                  缓存统计
                </Heading>
                <HStack>
                  <Button
                    size="sm"
                    leftIcon={<Icon as={FiRefreshCw} />}
                    onClick={onRefreshStats}
                  >
                    刷新
                  </Button>
                  <Button
                    size="sm"
                    colorScheme="red"
                    leftIcon={<Icon as={FiTrash2} />}
                    onClick={handlePurgeCache}
                  >
                    清理缓存
                  </Button>
                </HStack>
              </HStack>
              
              <SimpleGrid columns={{ base: 2, md: 4 }} spacing={4}>
                <Stat>
                  <StatLabel>命中率</StatLabel>
                  <StatNumber color={stats.hit_rate > 80 ? 'green.500' : stats.hit_rate > 60 ? 'yellow.500' : 'red.500'}>
                    {stats.hit_rate.toFixed(1)}%
                  </StatNumber>
                  <StatHelpText>
                    命中 {stats.hits} / 总计 {stats.hits + stats.misses}
                  </StatHelpText>
                </Stat>

                <Stat>
                  <StatLabel>缓存条目</StatLabel>
                  <StatNumber>{stats.stores}</StatNumber>
                  <StatHelpText>已存储文件数</StatHelpText>
                </Stat>

                <Stat>
                  <StatLabel>缓存大小</StatLabel>
                  <StatNumber>{formatBytes(stats.max_size_bytes)}</StatNumber>
                  <StatHelpText>最大缓存大小</StatHelpText>
                </Stat>

                <Stat>
                  <StatLabel>默认TTL</StatLabel>
                  <StatNumber>{stats.default_ttl}</StatNumber>
                  <StatHelpText>缓存过期时间</StatHelpText>
                </Stat>
              </SimpleGrid>
            </Box>
          )}

          <Divider />

          {/* 缓存配置参数 */}
          <Box>
            <Heading size="sm" mb={4} display="flex" alignItems="center">
              <Icon as={FiHardDrive} mr={2} />
              缓存参数
            </Heading>
            
            <VStack spacing={4} align="stretch">
              <FormControl>
                <FormLabel>缓存目录</FormLabel>
                <Input
                  value={cache_dir}
                  onChange={(e) => onFieldChange('cache_dir', e.target.value)}
                  placeholder="./data/upstream-cache"
                />
                <Text fontSize="sm" color="gray.500" mt={1}>
                  上游缓存文件存储目录
                </Text>
              </FormControl>

              <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                <FormControl>
                  <FormLabel>最大缓存大小 (MB)</FormLabel>
                  <NumberInput
                    value={Math.round(max_size_bytes / 1024 / 1024)}
                    onChange={(_, value) => onFieldChange('max_size_bytes', (value || 1024) * 1024 * 1024)}
                    min={100}
                    max={10240}
                  >
                    <NumberInputField />
                    <NumberInputStepper>
                      <NumberIncrementStepper />
                      <NumberDecrementStepper />
                    </NumberInputStepper>
                  </NumberInput>
                  <Text fontSize="sm" color="gray.500" mt={1}>
                    缓存目录的最大大小限制
                  </Text>
                </FormControl>

                <FormControl>
                  <FormLabel>默认TTL (秒)</FormLabel>
                  <NumberInput
                    value={default_ttl_seconds}
                    onChange={(_, value) => onFieldChange('default_ttl_seconds', value || 3600)}
                    min={60}
                    max={86400}
                  >
                    <NumberInputField />
                    <NumberInputStepper>
                      <NumberIncrementStepper />
                      <NumberDecrementStepper />
                    </NumberInputStepper>
                  </NumberInput>
                  <Text fontSize="sm" color="gray.500" mt={1}>
                    {formatDuration(default_ttl_seconds)} (当上游未指定时使用)
                  </Text>
                </FormControl>
              </SimpleGrid>

              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">遵循上游Cache-Control</FormLabel>
                <Switch
                  isChecked={respect_upstream}
                  onChange={(e) => onFieldChange('respect_upstream', e.target.checked)}
                />
                <Text fontSize="sm" color="gray.500" ml={4}>
                  优先使用上游服务器的缓存指令
                </Text>
              </FormControl>
            </VStack>
          </Box>

          <Alert status="info">
            <AlertIcon />
            <VStack align="start" spacing={1}>
              <Text fontWeight="medium">缓存策略说明</Text>
              <Text fontSize="sm">
                • 只缓存GET/HEAD请求的静态资源（CSS、JS、图片等）
              </Text>
              <Text fontSize="sm">
                • 遵循上游的Cache-Control、Expires等缓存指令
              </Text>
              <Text fontSize="sm">
                • 自动压缩存储，节省60-90%磁盘空间
              </Text>
              <Text fontSize="sm">
                • 定期清理过期文件，避免磁盘空间浪费
              </Text>
            </VStack>
          </Alert>

          {!stats && (
            <Alert status="warning">
              <AlertIcon />
              <Text fontSize="sm">
                缓存统计信息需要在服务运行时才能获取。启动服务后可查看详细的缓存使用情况。
              </Text>
            </Alert>
          )}
        </VStack>
      )}
    </Box>
  )
}

export default UpstreamCacheConfig

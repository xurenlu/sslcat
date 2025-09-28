import React from 'react'
import {
  Box,
  Heading,
  FormControl,
  FormLabel,
  Switch,
  Select,
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
  Divider,
  Alert,
  AlertIcon,
  CheckboxGroup,
  Checkbox,
  Stack,
} from '@chakra-ui/react'
import { 
  FiZap, 
  FiSettings,
  FiFile,
  FiInfo
} from 'react-icons/fi'

interface CompressionConfigProps {
  // 压缩配置
  enabled: boolean
  algorithms: string[]
  min_size: number
  gzip_level: number
  brotli_level: number
  types: string[]
  excluded_types: string[]
  content_types: string[]
  
  // 事件处理函数
  onFieldChange: (field: string, value: any) => void
}

const CompressionConfig: React.FC<CompressionConfigProps> = ({
  enabled,
  algorithms,
  min_size,
  gzip_level,
  brotli_level,
  types,
  excluded_types,
  content_types,
  onFieldChange
}) => {
  const algorithmOptions = [
    { value: 'br', label: 'Brotli (推荐)', description: '最新的压缩算法，压缩率最高' },
    { value: 'gzip', label: 'Gzip', description: '经典压缩算法，兼容性最好' },
    { value: 'deflate', label: 'Deflate', description: '基础压缩算法' }
  ]

  const defaultFileTypes = [
    '.js', '.css', '.html', '.htm', '.xml', '.json', 
    '.txt', '.svg', '.md', '.yaml', '.yml', '.csv'
  ]

  const defaultExcludedTypes = [
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp3', '.mp4', '.avi', '.mov', '.pdf',
    '.gz', '.br', '.zip', '.rar', '.7z'
  ]

  const defaultContentTypes = [
    'text/css', 'text/plain', 'text/xml',
    'application/javascript', 'application/json',
    'application/xml', 'image/svg+xml'
  ]

  const handleAlgorithmChange = (selectedAlgorithms: string[]) => {
    onFieldChange('algorithms', selectedAlgorithms)
  }

  const handleFileTypesChange = (selectedTypes: string[]) => {
    onFieldChange('types', selectedTypes)
  }

  const handleExcludedTypesChange = (selectedTypes: string[]) => {
    onFieldChange('excluded_types', selectedTypes)
  }

  const handleContentTypesChange = (selectedTypes: string[]) => {
    onFieldChange('content_types', selectedTypes)
  }

  return (
    <Box>
      {/* 压缩开关 */}
      <Box mb={6}>
        <Heading size="md" mb={4} display="flex" alignItems="center">
          <Icon as={FiZap} mr={2} />
          内容压缩配置
        </Heading>
        
        <FormControl display="flex" alignItems="center">
          <FormLabel htmlFor="compression-switch" mb="0">
            启用内容压缩
          </FormLabel>
          <Switch
            id="compression-switch"
            isChecked={enabled}
            onChange={(e) => onFieldChange('enabled', e.target.checked)}
          />
        </FormControl>
        
        <Text fontSize="sm" color="gray.500" mt={2}>
          启用后可以自动压缩文本内容，显著减少传输大小和提升加载速度
        </Text>
      </Box>

      {enabled && (
        <VStack spacing={6} align="stretch">
          {/* 压缩算法选择 */}
          <Box>
            <Heading size="sm" mb={4} display="flex" alignItems="center">
              <Icon as={FiSettings} mr={2} />
              压缩算法 (按优先级排序)
            </Heading>
            
            <CheckboxGroup
              value={algorithms}
              onChange={handleAlgorithmChange}
            >
              <VStack align="stretch" spacing={3}>
                {algorithmOptions.map(option => (
                  <Box key={option.value} p={3} border="1px" borderColor="gray.200" borderRadius="md">
                    <HStack justify="space-between">
                      <VStack align="start" spacing={1}>
                        <HStack>
                          <Checkbox value={option.value}>
                            <Text fontWeight="medium">{option.label}</Text>
                          </Checkbox>
                          {option.value === 'br' && (
                            <Badge colorScheme="green" size="sm">推荐</Badge>
                          )}
                        </HStack>
                        <Text fontSize="sm" color="gray.600">
                          {option.description}
                        </Text>
                      </VStack>
                    </HStack>
                  </Box>
                ))}
              </VStack>
            </CheckboxGroup>
            
            <Alert status="info" mt={4}>
              <AlertIcon />
              <Text fontSize="sm">
                客户端会根据Accept-Encoding头部自动选择支持的最优算法。建议同时启用Brotli和Gzip以获得最佳兼容性。
              </Text>
            </Alert>
          </Box>

          <Divider />

          {/* 压缩参数配置 */}
          <Box>
            <Heading size="sm" mb={4} display="flex" alignItems="center">
              <Icon as={FiSettings} mr={2} />
              压缩参数
            </Heading>
            
            <SimpleGrid columns={{ base: 1, md: 3 }} spacing={4}>
              <FormControl>
                <FormLabel>最小文件大小 (字节)</FormLabel>
                <NumberInput
                  value={min_size}
                  onChange={(_, value) => onFieldChange('min_size', value || 1024)}
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
                  小于此大小的文件不会被压缩
                </Text>
              </FormControl>

              <FormControl>
                <FormLabel>Gzip压缩级别</FormLabel>
                <NumberInput
                  value={gzip_level}
                  onChange={(_, value) => onFieldChange('gzip_level', value || 6)}
                  min={1}
                  max={9}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
                <Text fontSize="sm" color="gray.500" mt={1}>
                  1=最快，9=最佳压缩
                </Text>
              </FormControl>

              <FormControl>
                <FormLabel>Brotli压缩级别</FormLabel>
                <NumberInput
                  value={brotli_level}
                  onChange={(_, value) => onFieldChange('brotli_level', value || 6)}
                  min={0}
                  max={11}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
                <Text fontSize="sm" color="gray.500" mt={1}>
                  0=最快，11=最佳压缩
                </Text>
              </FormControl>
            </SimpleGrid>
          </Box>

          <Divider />

          {/* 可压缩文件类型 */}
          <Box>
            <Heading size="sm" mb={4} display="flex" alignItems="center">
              <Icon as={FiFile} mr={2} />
              可压缩文件类型
            </Heading>
            
            <CheckboxGroup
              value={types}
              onChange={handleFileTypesChange}
            >
              <SimpleGrid columns={{ base: 2, md: 4, lg: 6 }} spacing={2}>
                {defaultFileTypes.map(type => (
                  <Checkbox key={type} value={type}>
                    <Text fontSize="sm">{type}</Text>
                  </Checkbox>
                ))}
              </SimpleGrid>
            </CheckboxGroup>
            
            <Text fontSize="sm" color="gray.500" mt={2}>
              选择需要压缩的文件扩展名
            </Text>
          </Box>

          <Divider />

          {/* 排除的文件类型 */}
          <Box>
            <Heading size="sm" mb={4} display="flex" alignItems="center">
              <Icon as={FiFile} mr={2} />
              排除的文件类型
            </Heading>
            
            <CheckboxGroup
              value={excluded_types}
              onChange={handleExcludedTypesChange}
            >
              <SimpleGrid columns={{ base: 2, md: 4, lg: 6 }} spacing={2}>
                {defaultExcludedTypes.map(type => (
                  <Checkbox key={type} value={type}>
                    <Text fontSize="sm">{type}</Text>
                  </Checkbox>
                ))}
              </SimpleGrid>
            </CheckboxGroup>
            
            <Text fontSize="sm" color="gray.500" mt={2}>
              这些文件类型不会被压缩（通常是已压缩或二进制文件）
            </Text>
          </Box>

          <Divider />

          {/* Content-Type配置 */}
          <Box>
            <Heading size="sm" mb={4} display="flex" alignItems="center">
              <Icon as={FiInfo} mr={2} />
              可压缩Content-Type
            </Heading>
            
            <CheckboxGroup
              value={content_types}
              onChange={handleContentTypesChange}
            >
              <SimpleGrid columns={{ base: 1, md: 2 }} spacing={2}>
                {defaultContentTypes.map(type => (
                  <Checkbox key={type} value={type}>
                    <Text fontSize="sm">{type}</Text>
                  </Checkbox>
                ))}
              </SimpleGrid>
            </CheckboxGroup>
            
            <Text fontSize="sm" color="gray.500" mt={2}>
              根据HTTP Content-Type头部判断是否压缩
            </Text>
          </Box>

          <Alert status="success" mt={4}>
            <AlertIcon />
            <VStack align="start" spacing={1}>
              <Text fontWeight="medium">压缩效果预期</Text>
              <Text fontSize="sm">
                • Brotli压缩: 通常可达到98.9%的压缩率
              </Text>
              <Text fontSize="sm">
                • Gzip压缩: 通常可达到98.1%的压缩率
              </Text>
              <Text fontSize="sm">
                • 文本文件压缩效果最佳，图片等二进制文件效果有限
              </Text>
            </VStack>
          </Alert>
        </VStack>
      )}
    </Box>
  )
}

export default CompressionConfig

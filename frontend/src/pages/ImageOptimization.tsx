import React, { useState, useEffect } from 'react';
import {
  Box,
  Heading,
  VStack,
  HStack,
  FormControl,
  FormLabel,
  Switch,
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  NumberIncrementStepper,
  NumberDecrementStepper,
  Button,
  useToast,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  StatGroup,
  Card,
  CardHeader,
  CardBody,
  Text,
  Input,
  Tag,
  TagLabel,
  TagCloseButton,
  Wrap,
  WrapItem,
  Divider,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Spinner,
} from '@chakra-ui/react';
import api from '../utils/api';

interface ImageOptConfig {
  enabled: boolean;
  auto_webp: boolean;
  webp_quality: number;
  jpeg_quality: number;
  png_level: number;
  strip_metadata: boolean;
  allow_resize: boolean;
  max_width: number;
  max_height: number;
  allowed_sizes: number[];
  cache_enabled: boolean;
  cache_ttl: number;
  max_cache_size: number;
  include_patterns: string[];
  exclude_patterns: string[];
}

interface ImageOptStats {
  enabled: boolean;
  total_requests: number;
  cache_hits: number;
  cache_misses: number;
  cache_hit_rate: number;
  cache_items: number;
  cache_size_mb: number;
  total_bytes_saved_mb: number;
  compression_rate: number;
}

const ImageOptimization: React.FC = () => {
  const [config, setConfig] = useState<ImageOptConfig>({
    enabled: false,
    auto_webp: true,
    webp_quality: 80,
    jpeg_quality: 85,
    png_level: 6,
    strip_metadata: true,
    allow_resize: true,
    max_width: 2000,
    max_height: 2000,
    allowed_sizes: [100, 200, 400, 800, 1200],
    cache_enabled: true,
    cache_ttl: 86400,
    max_cache_size: 1073741824,
    include_patterns: ['*.jpg', '*.jpeg', '*.png', '*.gif'],
    exclude_patterns: ['/admin/*', '/api/*'],
  });

  const [stats, setStats] = useState<ImageOptStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [newPattern, setNewPattern] = useState('');
  const [newExcludePattern, setNewExcludePattern] = useState('');
  const [newSize, setNewSize] = useState('');

  const toast = useToast();

  useEffect(() => {
    loadConfig();
    loadStats();
    const interval = setInterval(loadStats, 10000); // 每10秒更新统计
    return () => clearInterval(interval);
  }, []);

  const loadConfig = async () => {
    try {
      const response: any = await api.get(`${window.location.pathname.split('/')[1]}/api/image-optimization/config`);
      if (response.success) {
        setConfig(response.config);
      }
    } catch (error) {
      toast({
        title: '加载配置失败',
        status: 'error',
        duration: 3000,
      });
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const response: any = await api.get(`${window.location.pathname.split('/')[1]}/api/image-optimization/stats`);
      if (response.success) {
        setStats(response.stats);
      }
    } catch (error) {
      // 静默失败，不显示错误
    }
  };

  const saveConfig = async () => {
    setSaving(true);
    try {
      const response: any = await api.post(
        `${window.location.pathname.split('/')[1]}/api/image-optimization/config`,
        { config }
      );
      if (response.success) {
        toast({
          title: '保存成功',
          description: response.message,
          status: 'success',
          duration: 3000,
        });
      }
    } catch (error: any) {
      toast({
        title: '保存失败',
        description: error.message || '未知错误',
        status: 'error',
        duration: 3000,
      });
    } finally {
      setSaving(false);
    }
  };

  const clearCache = async () => {
    try {
      const response: any = await api.post(
        `${window.location.pathname.split('/')[1]}/api/image-optimization/cache/clear`,
        {}
      );
      if (response.success) {
        toast({
          title: '缓存已清空',
          status: 'success',
          duration: 3000,
        });
        loadStats();
      }
    } catch (error: any) {
      toast({
        title: '清空失败',
        description: error.message || '未知错误',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const addPattern = () => {
    if (newPattern && !config.include_patterns.includes(newPattern)) {
      setConfig({
        ...config,
        include_patterns: [...config.include_patterns, newPattern],
      });
      setNewPattern('');
    }
  };

  const removePattern = (pattern: string) => {
    setConfig({
      ...config,
      include_patterns: config.include_patterns.filter((p) => p !== pattern),
    });
  };

  const addExcludePattern = () => {
    if (newExcludePattern && !config.exclude_patterns.includes(newExcludePattern)) {
      setConfig({
        ...config,
        exclude_patterns: [...config.exclude_patterns, newExcludePattern],
      });
      setNewExcludePattern('');
    }
  };

  const removeExcludePattern = (pattern: string) => {
    setConfig({
      ...config,
      exclude_patterns: config.exclude_patterns.filter((p) => p !== pattern),
    });
  };

  const addSize = () => {
    const size = parseInt(newSize);
    if (size > 0 && !config.allowed_sizes.includes(size)) {
      setConfig({
        ...config,
        allowed_sizes: [...config.allowed_sizes, size].sort((a, b) => a - b),
      });
      setNewSize('');
    }
  };

  const removeSize = (size: number) => {
    setConfig({
      ...config,
      allowed_sizes: config.allowed_sizes.filter((s) => s !== size),
    });
  };

  if (loading) {
    return (
      <Box textAlign="center" py={10}>
        <Spinner size="xl" />
      </Box>
    );
  }

  return (
    <Box p={6}>
      <Heading mb={6}>🖼️ 图片优化</Heading>

      <Alert status="info" mb={6}>
        <AlertIcon />
        <Box>
          <AlertTitle>图片优化功能</AlertTitle>
          <AlertDescription>
            自动将图片转换为 WebP 格式、调整尺寸、智能压缩，减少带宽消耗 30-70%
          </AlertDescription>
        </Box>
      </Alert>

      {/* 统计信息 */}
      {stats && (
        <StatGroup mb={6}>
          <Stat>
            <StatLabel>总请求数</StatLabel>
            <StatNumber>{stats.total_requests.toLocaleString()}</StatNumber>
          </Stat>
          <Stat>
            <StatLabel>缓存命中率</StatLabel>
            <StatNumber>{stats.cache_hit_rate.toFixed(1)}%</StatNumber>
            <StatHelpText>{stats.cache_hits} / {stats.cache_hits + stats.cache_misses}</StatHelpText>
          </Stat>
          <Stat>
            <StatLabel>节省带宽</StatLabel>
            <StatNumber>{stats.total_bytes_saved_mb.toFixed(1)} MB</StatNumber>
            <StatHelpText>压缩率 {stats.compression_rate.toFixed(1)}%</StatHelpText>
          </Stat>
          <Stat>
            <StatLabel>缓存大小</StatLabel>
            <StatNumber>{stats.cache_size_mb.toFixed(1)} MB</StatNumber>
            <StatHelpText>{stats.cache_items} 个项目</StatHelpText>
          </Stat>
        </StatGroup>
      )}

      <VStack spacing={6} align="stretch">
        {/* 基础设置 */}
        <Card>
          <CardHeader>
            <Heading size="md">基础设置</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">启用图片优化</FormLabel>
                <Switch
                  isChecked={config.enabled}
                  onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
                />
              </FormControl>

              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">自动转换为 WebP</FormLabel>
                <Switch
                  isChecked={config.auto_webp}
                  onChange={(e) => setConfig({ ...config, auto_webp: e.target.checked })}
                  isDisabled={!config.enabled}
                />
              </FormControl>

              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">移除图片元数据（EXIF）</FormLabel>
                <Switch
                  isChecked={config.strip_metadata}
                  onChange={(e) => setConfig({ ...config, strip_metadata: e.target.checked })}
                  isDisabled={!config.enabled}
                />
              </FormControl>
            </VStack>
          </CardBody>
        </Card>

        {/* 质量设置 */}
        <Card>
          <CardHeader>
            <Heading size="md">压缩质量</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl>
                <FormLabel>WebP 质量 (0-100)</FormLabel>
                <NumberInput
                  value={config.webp_quality}
                  min={0}
                  max={100}
                  isDisabled={!config.enabled}
                  onChange={(_, num) => setConfig({ ...config, webp_quality: num })}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
                <Text fontSize="sm" color="gray.500" mt={1}>
                  推荐值：80（质量与大小的最佳平衡）
                </Text>
              </FormControl>

              <FormControl>
                <FormLabel>JPEG 质量 (0-100)</FormLabel>
                <NumberInput
                  value={config.jpeg_quality}
                  min={0}
                  max={100}
                  isDisabled={!config.enabled}
                  onChange={(_, num) => setConfig({ ...config, jpeg_quality: num })}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
                <Text fontSize="sm" color="gray.500" mt={1}>
                  推荐值：85（视觉无损）
                </Text>
              </FormControl>

              <FormControl>
                <FormLabel>PNG 压缩级别 (0-9)</FormLabel>
                <NumberInput
                  value={config.png_level}
                  min={0}
                  max={9}
                  isDisabled={!config.enabled}
                  onChange={(_, num) => setConfig({ ...config, png_level: num })}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
                <Text fontSize="sm" color="gray.500" mt={1}>
                  推荐值：6（平衡压缩率和速度）
                </Text>
              </FormControl>
            </VStack>
          </CardBody>
        </Card>

        {/* 尺寸调整 */}
        <Card>
          <CardHeader>
            <Heading size="md">尺寸调整</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">允许尺寸调整</FormLabel>
                <Switch
                  isChecked={config.allow_resize}
                  onChange={(e) => setConfig({ ...config, allow_resize: e.target.checked })}
                  isDisabled={!config.enabled}
                />
              </FormControl>

              <HStack>
                <FormControl>
                  <FormLabel>最大宽度 (px)</FormLabel>
                  <NumberInput
                    value={config.max_width}
                    min={100}
                    max={5000}
                    isDisabled={!config.enabled || !config.allow_resize}
                    onChange={(_, num) => setConfig({ ...config, max_width: num })}
                  >
                    <NumberInputField />
                  </NumberInput>
                </FormControl>

                <FormControl>
                  <FormLabel>最大高度 (px)</FormLabel>
                  <NumberInput
                    value={config.max_height}
                    min={100}
                    max={5000}
                    isDisabled={!config.enabled || !config.allow_resize}
                    onChange={(_, num) => setConfig({ ...config, max_height: num })}
                  >
                    <NumberInputField />
                  </NumberInput>
                </FormControl>
              </HStack>

              <FormControl>
                <FormLabel>允许的尺寸列表</FormLabel>
                <HStack mb={2}>
                  <Input
                    placeholder="输入尺寸，如 800"
                    value={newSize}
                    onChange={(e) => setNewSize(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && addSize()}
                    isDisabled={!config.enabled || !config.allow_resize}
                  />
                  <Button onClick={addSize} isDisabled={!config.enabled || !config.allow_resize}>
                    添加
                  </Button>
                </HStack>
                <Wrap>
                  {config.allowed_sizes.map((size) => (
                    <WrapItem key={size}>
                      <Tag size="lg" colorScheme="blue">
                        <TagLabel>{size}px</TagLabel>
                        <TagCloseButton onClick={() => removeSize(size)} />
                      </Tag>
                    </WrapItem>
                  ))}
                </Wrap>
                <Text fontSize="sm" color="gray.500" mt={2}>
                  用户只能请求这些尺寸，防止滥用。如：/image.jpg?width=800
                </Text>
              </FormControl>
            </VStack>
          </CardBody>
        </Card>

        {/* 缓存设置 */}
        <Card>
          <CardHeader>
            <Heading size="md">缓存设置</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">启用缓存</FormLabel>
                <Switch
                  isChecked={config.cache_enabled}
                  onChange={(e) => setConfig({ ...config, cache_enabled: e.target.checked })}
                  isDisabled={!config.enabled}
                />
              </FormControl>

              <FormControl>
                <FormLabel>缓存 TTL（秒）</FormLabel>
                <NumberInput
                  value={config.cache_ttl}
                  min={60}
                  max={86400 * 7}
                  isDisabled={!config.enabled || !config.cache_enabled}
                  onChange={(_, num) => setConfig({ ...config, cache_ttl: num })}
                >
                  <NumberInputField />
                </NumberInput>
                <Text fontSize="sm" color="gray.500" mt={1}>
                  推荐值：86400（24小时）
                </Text>
              </FormControl>

              <FormControl>
                <FormLabel>最大缓存大小 (MB)</FormLabel>
                <NumberInput
                  value={config.max_cache_size / 1024 / 1024}
                  min={100}
                  max={10240}
                  isDisabled={!config.enabled || !config.cache_enabled}
                  onChange={(_, num) => setConfig({ ...config, max_cache_size: num * 1024 * 1024 })}
                >
                  <NumberInputField />
                </NumberInput>
                <Text fontSize="sm" color="gray.500" mt={1}>
                  推荐值：1024（1GB）
                </Text>
              </FormControl>

              <Button
                colorScheme="red"
                variant="outline"
                onClick={clearCache}
                isDisabled={!config.enabled || !config.cache_enabled}
              >
                清空图片缓存
              </Button>
            </VStack>
          </CardBody>
        </Card>

        {/* 路径过滤 */}
        <Card>
          <CardHeader>
            <Heading size="md">路径过滤</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl>
                <FormLabel>包含的路径模式</FormLabel>
                <HStack mb={2}>
                  <Input
                    placeholder="如: *.jpg 或 /images/*"
                    value={newPattern}
                    onChange={(e) => setNewPattern(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && addPattern()}
                    isDisabled={!config.enabled}
                  />
                  <Button onClick={addPattern} isDisabled={!config.enabled}>
                    添加
                  </Button>
                </HStack>
                <Wrap>
                  {config.include_patterns.map((pattern) => (
                    <WrapItem key={pattern}>
                      <Tag size="lg" colorScheme="green">
                        <TagLabel>{pattern}</TagLabel>
                        <TagCloseButton onClick={() => removePattern(pattern)} />
                      </Tag>
                    </WrapItem>
                  ))}
                </Wrap>
              </FormControl>

              <Divider />

              <FormControl>
                <FormLabel>排除的路径模式</FormLabel>
                <HStack mb={2}>
                  <Input
                    placeholder="如: /admin/* 或 /api/*"
                    value={newExcludePattern}
                    onChange={(e) => setNewExcludePattern(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && addExcludePattern()}
                    isDisabled={!config.enabled}
                  />
                  <Button onClick={addExcludePattern} isDisabled={!config.enabled}>
                    添加
                  </Button>
                </HStack>
                <Wrap>
                  {config.exclude_patterns.map((pattern) => (
                    <WrapItem key={pattern}>
                      <Tag size="lg" colorScheme="red">
                        <TagLabel>{pattern}</TagLabel>
                        <TagCloseButton onClick={() => removeExcludePattern(pattern)} />
                      </Tag>
                    </WrapItem>
                  ))}
                </Wrap>
              </FormControl>
            </VStack>
          </CardBody>
        </Card>

        {/* 使用说明 */}
        <Card>
          <CardHeader>
            <Heading size="md">使用说明</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={2} align="stretch" fontSize="sm">
              <Text fontWeight="bold">URL 参数：</Text>
              <Text>• <code>?width=800</code> - 调整宽度为 800px</Text>
              <Text>• <code>?height=600</code> - 调整高度为 600px</Text>
              <Text>• <code>?quality=90</code> - 指定质量</Text>
              <Text>• <code>?format=webp</code> - 指定输出格式</Text>
              <Divider my={2} />
              <Text fontWeight="bold">示例：</Text>
              <Text><code>https://example.com/photo.jpg?width=800</code></Text>
              <Text><code>https://example.com/photo.jpg?width=400&quality=90</code></Text>
              <Divider my={2} />
              <Text fontWeight="bold">效果：</Text>
              <Text>• JPEG → WebP：节省 30-50% 带宽</Text>
              <Text>• PNG → WebP：节省 40-70% 带宽</Text>
              <Text>• 尺寸调整：节省 80-95% 带宽（移动端）</Text>
            </VStack>
          </CardBody>
        </Card>

        {/* 保存按钮 */}
        <Button
          colorScheme="blue"
          size="lg"
          onClick={saveConfig}
          isLoading={saving}
          loadingText="保存中..."
        >
          保存配置
        </Button>
      </VStack>
    </Box>
  );
};

export default ImageOptimization;


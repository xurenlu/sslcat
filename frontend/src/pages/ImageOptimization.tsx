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
import { useTranslation } from '../hooks/useLanguage';

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
  const t = useTranslation();
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
    const interval = setInterval(loadStats, 10000); // Update stats every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const loadConfig = async () => {
    try {
      const response: any = await api.get('/image-optimization/config');
      if (response.success) {
        setConfig(response.config);
      }
    } catch (error) {
      toast({
        title: t.imageOptimization.loadConfigFailed,
        status: 'error',
        duration: 3000,
      });
    } finally {
      setLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      const response: any = await api.get('/image-optimization/stats');
      if (response.success) {
        setStats(response.stats);
      }
    } catch (error) {
      // Silent failure, no error display
    }
  };

  const saveConfig = async () => {
    setSaving(true);
    try {
      const response: any = await api.post(
        '/image-optimization/config',
        { config }
      );
      if (response.success) {
        toast({
          title: t.imageOptimization.saveSuccess,
          description: response.message,
          status: 'success',
          duration: 3000,
        });
      }
    } catch (error: any) {
      toast({
        title: t.imageOptimization.saveFailed,
        description: error.message || t.common.unknownError,
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
        '/image-optimization/cache/clear',
        {}
      );
      if (response.success) {
        toast({
          title: t.imageOptimization.cacheCleared,
          status: 'success',
          duration: 3000,
        });
        loadStats();
      }
    } catch (error: any) {
      toast({
          title: t.imageOptimization.clearFailed,
          description: error.message || t.common.unknownError,
        status: 'error',
        duration: 3000,
      });
    }
  };

  const addPattern = () => {
    if (newPattern && !(config.include_patterns || []).includes(newPattern)) {
      setConfig({
        ...config,
        include_patterns: [...(config.include_patterns || []), newPattern],
      });
      setNewPattern('');
    }
  };

  const removePattern = (pattern: string) => {
    setConfig({
      ...config,
      include_patterns: (config.include_patterns || []).filter((p) => p !== pattern),
    });
  };

  const addExcludePattern = () => {
    if (newExcludePattern && !(config.exclude_patterns || []).includes(newExcludePattern)) {
      setConfig({
        ...config,
        exclude_patterns: [...(config.exclude_patterns || []), newExcludePattern],
      });
      setNewExcludePattern('');
    }
  };

  const removeExcludePattern = (pattern: string) => {
    setConfig({
      ...config,
      exclude_patterns: (config.exclude_patterns || []).filter((p) => p !== pattern),
    });
  };

  const addSize = () => {
    const size = parseInt(newSize);
    if (size > 0 && !(config.allowed_sizes || []).includes(size)) {
      setConfig({
        ...config,
        allowed_sizes: [...(config.allowed_sizes || []), size].sort((a, b) => a - b),
      });
      setNewSize('');
    }
  };

  const removeSize = (size: number) => {
    setConfig({
      ...config,
      allowed_sizes: (config.allowed_sizes || []).filter((s) => s !== size),
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
      <Heading mb={6}>{t.imageOptimization.title}</Heading>

      <Alert status="info" mb={6}>
        <AlertIcon />
        <Box>
          <AlertTitle>{t.imageOptimization.title}</AlertTitle>
          <AlertDescription>
            {t.imageOptimization.description}
          </AlertDescription>
        </Box>
      </Alert>

      {/* Statistics */}
      {stats && (
        <StatGroup mb={6}>
          <Stat>
            <StatLabel>{t.imageOptimization.totalRequests}</StatLabel>
            <StatNumber>{stats.total_requests.toLocaleString()}</StatNumber>
          </Stat>
          <Stat>
            <StatLabel>{t.imageOptimization.cacheHitRate}</StatLabel>
            <StatNumber>{stats.cache_hit_rate.toFixed(1)}%</StatNumber>
            <StatHelpText>{stats.cache_hits} / {stats.cache_hits + stats.cache_misses}</StatHelpText>
          </Stat>
          <Stat>
            <StatLabel>{t.imageOptimization.bandwidthSaved}</StatLabel>
            <StatNumber>{stats.total_bytes_saved_mb.toFixed(1)} MB</StatNumber>
            <StatHelpText>{t.imageOptimization.compressionRate} {stats.compression_rate.toFixed(1)}%</StatHelpText>
          </Stat>
          <Stat>
            <StatLabel>{t.imageOptimization.cacheSize}</StatLabel>
            <StatNumber>{stats.cache_size_mb.toFixed(1)} MB</StatNumber>
            <StatHelpText>{stats.cache_items} {t.imageOptimization.items}</StatHelpText>
          </Stat>
        </StatGroup>
      )}

      <VStack spacing={6} align="stretch">
        {/* Basic Settings */}
        <Card>
          <CardHeader>
            <Heading size="md">{t.imageOptimization.basicSettings}</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">{t.imageOptimization.enableImageOptimization}</FormLabel>
                <Switch
                  isChecked={config.enabled}
                  onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
                />
              </FormControl>

              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">{t.imageOptimization.autoConvertWebP}</FormLabel>
                <Switch
                  isChecked={config.auto_webp}
                  onChange={(e) => setConfig({ ...config, auto_webp: e.target.checked })}
                  isDisabled={!config.enabled}
                />
              </FormControl>

              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">{t.imageOptimization.removeMetadata}</FormLabel>
                <Switch
                  isChecked={config.strip_metadata}
                  onChange={(e) => setConfig({ ...config, strip_metadata: e.target.checked })}
                  isDisabled={!config.enabled}
                />
              </FormControl>
            </VStack>
          </CardBody>
        </Card>

        {/* Quality Settings */}
        <Card>
          <CardHeader>
            <Heading size="md">{t.imageOptimization.compressionQuality}</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl>
                <FormLabel>{t.imageOptimization.webpQuality}</FormLabel>
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
                  {t.imageOptimization.webpQualityRecommendation}
                </Text>
              </FormControl>

              <FormControl>
                <FormLabel>{t.imageOptimization.jpegQuality}</FormLabel>
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
                  {t.imageOptimization.jpegQualityRecommendation}
                </Text>
              </FormControl>

              <FormControl>
                <FormLabel>{t.imageOptimization.pngLevel}</FormLabel>
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
                  {t.imageOptimization.pngCompressionRecommendation}
                </Text>
              </FormControl>
            </VStack>
          </CardBody>
        </Card>

        {/* Size Adjustment */}
        <Card>
          <CardHeader>
            <Heading size="md">{t.imageOptimization.sizeAdjustment}</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">{t.imageOptimization.allowResize}</FormLabel>
                <Switch
                  isChecked={config.allow_resize}
                  onChange={(e) => setConfig({ ...config, allow_resize: e.target.checked })}
                  isDisabled={!config.enabled}
                />
              </FormControl>

              <HStack>
                <FormControl>
                  <FormLabel>{t.imageOptimization.maxWidth}</FormLabel>
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
                  <FormLabel>{t.imageOptimization.maxHeight}</FormLabel>
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
                <FormLabel>{t.imageOptimization.allowedSizes}</FormLabel>
                <HStack mb={2}>
                  <Input
                    placeholder={t.imageOptimization.sizeInputPlaceholder}
                    value={newSize}
                    onChange={(e) => setNewSize(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && addSize()}
                    isDisabled={!config.enabled || !config.allow_resize}
                  />
                  <Button onClick={addSize} isDisabled={!config.enabled || !config.allow_resize}>
                    {t.common.add}
                  </Button>
                </HStack>
                <Wrap>
                  {(config.allowed_sizes || []).map((size) => (
                    <WrapItem key={size}>
                      <Tag size="lg" colorScheme="blue">
                        <TagLabel>{size}px</TagLabel>
                        <TagCloseButton onClick={() => removeSize(size)} />
                      </Tag>
                    </WrapItem>
                  ))}
                </Wrap>
                <Text fontSize="sm" color="gray.500" mt={2}>
                  {t.imageOptimization.allowedSizesDescription}
                </Text>
              </FormControl>
            </VStack>
          </CardBody>
        </Card>

        {/* Cache Settings */}
        <Card>
          <CardHeader>
            <Heading size="md">{t.imageOptimization.cacheSettings}</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">{t.imageOptimization.enableCache}</FormLabel>
                <Switch
                  isChecked={config.cache_enabled}
                  onChange={(e) => setConfig({ ...config, cache_enabled: e.target.checked })}
                  isDisabled={!config.enabled}
                />
              </FormControl>

              <FormControl>
                <FormLabel>{t.imageOptimization.cacheTTL}</FormLabel>
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
                  {t.imageOptimization.cacheTTLRecommendation}
                </Text>
              </FormControl>

              <FormControl>
                <FormLabel>{t.imageOptimization.maxCacheSize}</FormLabel>
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
                  {t.imageOptimization.maxCacheSizeRecommendation}
                </Text>
              </FormControl>

              <Button
                colorScheme="red"
                variant="outline"
                onClick={clearCache}
                isDisabled={!config.enabled || !config.cache_enabled}
              >
                {t.imageOptimization.clearImageCache}
              </Button>
            </VStack>
          </CardBody>
        </Card>

        {/* Path Filtering */}
        <Card>
          <CardHeader>
            <Heading size="md">{t.imageOptimization.pathFiltering}</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl>
                <FormLabel>{t.imageOptimization.includePatterns}</FormLabel>
                <HStack mb={2}>
                  <Input
                    placeholder={t.imageOptimization.includePatternPlaceholder}
                    value={newPattern}
                    onChange={(e) => setNewPattern(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && addPattern()}
                    isDisabled={!config.enabled}
                  />
                  <Button onClick={addPattern} isDisabled={!config.enabled}>
                    {t.common.add}
                  </Button>
                </HStack>
                <Wrap>
                  {(config.include_patterns || []).map((pattern) => (
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
                <FormLabel>{t.imageOptimization.excludePatterns}</FormLabel>
                <HStack mb={2}>
                  <Input
                    placeholder={t.imageOptimization.excludePatternPlaceholder}
                    value={newExcludePattern}
                    onChange={(e) => setNewExcludePattern(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && addExcludePattern()}
                    isDisabled={!config.enabled}
                  />
                  <Button onClick={addExcludePattern} isDisabled={!config.enabled}>
                    {t.common.add}
                  </Button>
                </HStack>
                <Wrap>
                  {(config.exclude_patterns || []).map((pattern) => (
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

        {/* Usage Instructions */}
        <Card>
          <CardHeader>
            <Heading size="md">{t.imageOptimization.instructions}</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={2} align="stretch" fontSize="sm">
              <Text fontWeight="bold">{t.imageOptimization.urlParams}:</Text>
              <Text>• <code>?width=800</code> - {t.imageOptimization.adjustWidth}</Text>
              <Text>• <code>?height=600</code> - {t.imageOptimization.adjustHeight}</Text>
              <Text>• <code>?quality=90</code> - {t.imageOptimization.specifyQuality}</Text>
              <Text>• <code>?format=webp</code> - {t.imageOptimization.specifyFormat}</Text>
              <Divider my={2} />
              <Text fontWeight="bold">{t.imageOptimization.examples}:</Text>
              <Text><code>https://example.com/photo.jpg?width=800</code></Text>
              <Text><code>https://example.com/photo.jpg?width=400&quality=90</code></Text>
              <Divider my={2} />
              <Text fontWeight="bold">{t.imageOptimization.effects}:</Text>
              <Text>• JPEG → WebP: {t.imageOptimization.bandwidthSavedJPEG}</Text>
              <Text>• PNG → WebP: {t.imageOptimization.bandwidthSavedPNG}</Text>
              <Text>• {t.imageOptimization.sizeAdjustment}: {t.imageOptimization.bandwidthSavedMobile}</Text>
            </VStack>
          </CardBody>
        </Card>

        {/* 保存按钮 */}
        <Button
          colorScheme="blue"
          size="lg"
          onClick={saveConfig}
          isLoading={saving}
          loadingText={t.imageOptimization.saving}
        >
{t.imageOptimization.save}
        </Button>
      </VStack>
    </Box>
  );
};

export default ImageOptimization;


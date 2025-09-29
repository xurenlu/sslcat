import React, { useState, useEffect } from 'react'
import {
  Box,
  Card,
  CardBody,
  CardHeader,
  Heading,
  VStack,
  HStack,
  FormControl,
  FormLabel,
  Input,
  Switch,
  Button,
  Text,
  Badge,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Textarea,
  SimpleGrid,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  useToast,
  Divider,
  Icon,
  Tooltip,
  Select,
  Tag,
  TagLabel,
  TagCloseButton,
  Wrap,
  WrapItem,
} from '@chakra-ui/react'
import {
  FiGlobe,
  FiDatabase,
  FiShield,
  FiRefreshCw,
  FiUpload,
  FiInfo,
  FiCheckCircle,
  FiAlertCircle,
  FiX,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'
import GeoIPSetupGuide from './GeoIPSetupGuide'

interface GeoIPConfig {
  enabled: boolean
  database_path: string
  update_interval: number
  allow_unknown: boolean
  allowed_countries: string[]
  blocked_countries: string[]
}

interface GeoIPStats {
  enabled: boolean
  city_db_loaded: boolean
  asn_db_loaded: boolean
  cache_size: number
  cache_max_size: number
  cache_ttl_hours: number
  last_update: string
  allowed_countries: string[]
  blocked_countries: string[]
  allow_unknown: boolean
}

interface CountryOption {
  code: string
  name: string
  flag: string
}

// 常用国家列表 - 将在组件内部使用翻译
const getCommonCountries = (t: any): CountryOption[] => [
  { code: 'CN', name: t.geoIP.commonCountries.china, flag: '🇨🇳' },
  { code: 'US', name: t.geoIP.commonCountries.usa, flag: '🇺🇸' },
  { code: 'JP', name: t.geoIP.commonCountries.japan, flag: '🇯🇵' },
  { code: 'KR', name: t.geoIP.commonCountries.southKorea, flag: '🇰🇷' },
  { code: 'SG', name: t.geoIP.commonCountries.singapore, flag: '🇸🇬' },
  { code: 'GB', name: t.geoIP.commonCountries.uk, flag: '🇬🇧' },
  { code: 'DE', name: t.geoIP.commonCountries.germany, flag: '🇩🇪' },
  { code: 'FR', name: t.geoIP.commonCountries.france, flag: '🇫🇷' },
  { code: 'CA', name: t.geoIP.commonCountries.canada, flag: '🇨🇦' },
  { code: 'AU', name: t.geoIP.commonCountries.australia, flag: '🇦🇺' },
  { code: 'IN', name: t.geoIP.commonCountries.india, flag: '🇮🇳' },
  { code: 'BR', name: t.geoIP.commonCountries.brazil, flag: '🇧🇷' },
  { code: 'RU', name: t.geoIP.commonCountries.russia, flag: '🇷🇺' },
  { code: 'IT', name: t.geoIP.commonCountries.italy, flag: '🇮🇹' },
  { code: 'ES', name: t.geoIP.commonCountries.spain, flag: '🇪🇸' },
  { code: 'NL', name: t.geoIP.commonCountries.netherlands, flag: '🇳🇱' },
  { code: 'SE', name: t.geoIP.commonCountries.sweden, flag: '🇸🇪' },
  { code: 'NO', name: t.geoIP.commonCountries.norway, flag: '🇳🇴' },
  { code: 'CH', name: t.geoIP.commonCountries.switzerland, flag: '🇨🇭' },
  { code: 'HK', name: t.geoIP.commonCountries.hongKong, flag: '🇭🇰' },
  { code: 'TW', name: t.geoIP.commonCountries.taiwan, flag: '🇹🇼' },
  { code: 'MO', name: t.geoIP.commonCountries.macau, flag: '🇲🇴' },
]

const GeoIPConfig: React.FC = () => {
  const [config, setConfig] = useState<GeoIPConfig>({
    enabled: false,
    database_path: './data/geoip/GeoLite2-City.mmdb',
    update_interval: 168, // 7天
    allow_unknown: true,
    allowed_countries: [],
    blocked_countries: [],
  })
  
  const [stats, setStats] = useState<GeoIPStats | null>(null)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [selectedCountry, setSelectedCountry] = useState('')
  const [showSetupGuide, setShowSetupGuide] = useState(false)
  
  const toast = useToast()
  const { adminPrefix } = useConfig()
  const t = useTranslation()

  // 加载配置和状态
  const loadConfig = async () => {
    setLoading(true)
    try {
      // 加载GeoIP配置
      const configResponse = await fetch(buildApiPath(adminPrefix, '/api/geoip/config'), {
        credentials: 'include',
      })
      
      if (configResponse.ok) {
        const configData = await configResponse.json()
        setConfig(configData)
      }

      // 加载GeoIP统计信息
      const statsResponse = await fetch(buildApiPath(adminPrefix, '/api/geoip/stats'), {
        credentials: 'include',
      })
      
      if (statsResponse.ok) {
        const statsData = await statsResponse.json()
        setStats(statsData.geoip || statsData)
      }
    } catch (error) {
      console.error('加载GeoIP配置失败:', error)
      toast({
        title: '加载失败',
        description: '无法加载地理位置过滤配置',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  // 保存配置
  const saveConfig = async () => {
    setSaving(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/geoip/config'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(config),
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      toast({
        title: '保存成功',
        description: '地理位置过滤配置已更新',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })

      // 重新加载状态
      loadConfig()
    } catch (error) {
      console.error('保存配置失败:', error)
      toast({
        title: '保存失败',
        description: '无法保存地理位置过滤配置',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setSaving(false)
    }
  }

  // 添加允许国家
  const addAllowedCountry = () => {
    if (selectedCountry && !config.allowed_countries.includes(selectedCountry)) {
      setConfig({
        ...config,
        allowed_countries: [...config.allowed_countries, selectedCountry],
      })
      setSelectedCountry('')
    }
  }

  // 删除允许国家
  const removeAllowedCountry = (countryCode: string) => {
    setConfig({
      ...config,
      allowed_countries: config.allowed_countries.filter(c => c !== countryCode),
    })
  }

  // 添加阻止国家
  const addBlockedCountry = () => {
    if (selectedCountry && !config.blocked_countries.includes(selectedCountry)) {
      setConfig({
        ...config,
        blocked_countries: [...config.blocked_countries, selectedCountry],
      })
      setSelectedCountry('')
    }
  }

  // 删除阻止国家
  const removeBlockedCountry = (countryCode: string) => {
    setConfig({
      ...config,
      blocked_countries: config.blocked_countries.filter(c => c !== countryCode),
    })
  }

  // 获取国家名称
  const getCountryName = (code: string) => {
    const countries = getCommonCountries(t)
    const country = countries.find(c => c.code === code)
    return country ? `${country.flag} ${country.name}` : code
  }

  // 测试地理位置功能
  const testGeoIP = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/geoip/test'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          test_ips: ['8.8.8.8', '114.114.114.114', '1.1.1.1']
        }),
      })

      if (response.ok) {
        const data = await response.json()
        toast({
          title: '测试成功',
          description: `测试了${data.results?.length || 0}个IP地址`,
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
      } else {
        throw new Error('测试失败')
      }
    } catch (error) {
      toast({
        title: '测试失败',
        description: '地理位置功能测试失败',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  useEffect(() => {
    loadConfig()
  }, [])

  // 如果要显示设置指南
  if (showSetupGuide) {
    return (
      <VStack spacing={6} align="stretch">
        <HStack>
            <Button
              leftIcon={<FiX />}
              variant="outline"
              onClick={() => setShowSetupGuide(false)}
            >
              {t.geoIP.backToConfig}
            </Button>
            <Text fontSize="lg" fontWeight="bold">{t.geoIP.setupGuideTitle}</Text>
        </HStack>
        <GeoIPSetupGuide />
      </VStack>
    )
  }

  return (
    <VStack spacing={6} align="stretch">
      {/* 状态概览 */}
      <Card>
        <CardHeader>
          <HStack>
            <Icon as={FiGlobe} color="blue.500" />
            <Heading size="md">{t.geoIP.title}</Heading>
            <Button
              size="sm"
              variant="outline"
              leftIcon={<FiRefreshCw />}
              onClick={loadConfig}
              isLoading={loading}
            >
              {t.geoIP.loading}
            </Button>
          </HStack>
        </CardHeader>
        <CardBody>
          {stats ? (
            <SimpleGrid columns={{ base: 2, md: 4 }} spacing={4}>
              <Stat>
                <StatLabel>{t.geoIP.status}</StatLabel>
                <StatNumber>
                  <Badge colorScheme={stats.enabled ? 'green' : 'gray'}>
                    {stats.enabled ? t.geoIP.enabled : t.geoIP.disabled}
                  </Badge>
                </StatNumber>
                <StatHelpText>{t.geoIP.enableGeoFiltering}</StatHelpText>
              </Stat>
              
              <Stat>
                <StatLabel>{t.geoIP.cityDatabase}</StatLabel>
                <StatNumber>
                  <Badge colorScheme={stats.city_db_loaded ? 'green' : 'red'}>
                    {stats.city_db_loaded ? t.geoIP.loaded : t.geoIP.notLoaded}
                  </Badge>
                </StatNumber>
                <StatHelpText>GeoLite2-City.mmdb</StatHelpText>
              </Stat>
              
              <Stat>
                <StatLabel>ASN数据库</StatLabel>
                <StatNumber>
                  <Badge colorScheme={stats.asn_db_loaded ? 'green' : 'orange'}>
                    {stats.asn_db_loaded ? '已加载' : '未加载'}
                  </Badge>
                </StatNumber>
                <StatHelpText>GeoLite2-ASN.mmdb (可选)</StatHelpText>
              </Stat>
              
              <Stat>
                <StatLabel>缓存使用</StatLabel>
                <StatNumber>{stats.cache_size}/{stats.cache_max_size}</StatNumber>
                <StatHelpText>缓存的IP查询结果</StatHelpText>
              </Stat>
            </SimpleGrid>
          ) : (
            <Alert status="warning">
              <AlertIcon />
              <AlertDescription>无法获取地理位置过滤状态信息</AlertDescription>
            </Alert>
          )}
        </CardBody>
      </Card>

      {/* 数据库设置提示 */}
      {(!stats?.city_db_loaded || !stats?.asn_db_loaded) && (
        <Alert status="info">
          <AlertIcon />
          <Box>
            <AlertTitle>GeoIP数据库设置指南</AlertTitle>
            <AlertDescription>
              <VStack align="start" spacing={2} mt={2}>
                <Text>
                  <Icon as={FiDatabase} mr={2} />
                  请将MaxMind GeoLite2数据库文件放置到以下位置：
                </Text>
                <Box bg="gray.50" p={3} borderRadius="md" fontFamily="mono" fontSize="sm">
                  <Text color="green.600">✓ ./data/geoip/GeoLite2-City.mmdb (必需)</Text>
                  <Text color="orange.600">○ ./data/geoip/GeoLite2-ASN.mmdb (可选)</Text>
                </Box>
                <HStack spacing={4} mt={3}>
                  <Text fontSize="sm" color="gray.600">
                    数据库文件可从 MaxMind 免费下载（需要注册账户）
                  </Text>
                  <Button
                    size="sm"
                    colorScheme="blue"
                    variant="outline"
                    onClick={() => setShowSetupGuide(true)}
                  >
                    查看详细设置指南
                  </Button>
                </HStack>
              </VStack>
            </AlertDescription>
          </Box>
        </Alert>
      )}

      {/* 基础配置 */}
      <Card>
        <CardHeader>
          <Heading size="md">基础设置</Heading>
        </CardHeader>
        <CardBody>
          <VStack spacing={4} align="stretch">
            <FormControl>
              <HStack>
                <FormLabel mb={0}>启用地理位置过滤</FormLabel>
                <Switch
                  isChecked={config.enabled}
                  onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
                  colorScheme="green"
                />
              </HStack>
              <Text fontSize="sm" color="gray.600" mt={1}>
                启用后将根据访问者的地理位置进行访问控制
              </Text>
            </FormControl>

            <FormControl>
              <FormLabel>数据库文件路径</FormLabel>
              <Input
                value={config.database_path}
                onChange={(e) => setConfig({ ...config, database_path: e.target.value })}
                placeholder="./data/geoip/GeoLite2-City.mmdb"
                fontFamily="mono"
                fontSize="sm"
              />
              <Text fontSize="sm" color="gray.600" mt={1}>
                GeoLite2-City.mmdb 数据库文件的路径
              </Text>
            </FormControl>

            <FormControl>
              <HStack>
                <FormLabel mb={0}>允许未知位置</FormLabel>
                <Switch
                  isChecked={config.allow_unknown}
                  onChange={(e) => setConfig({ ...config, allow_unknown: e.target.checked })}
                  colorScheme="blue"
                />
              </HStack>
              <Text fontSize="sm" color="gray.600" mt={1}>
                当无法确定访问者地理位置时是否允许访问
              </Text>
            </FormControl>

            <FormControl>
              <FormLabel>数据库更新间隔 (小时)</FormLabel>
              <Input
                type="number"
                value={config.update_interval}
                onChange={(e) => setConfig({ ...config, update_interval: parseInt(e.target.value) || 168 })}
                min={1}
                max={8760}
              />
              <Text fontSize="sm" color="gray.600" mt={1}>
                自动检查数据库更新的间隔时间，默认168小时（7天）
              </Text>
            </FormControl>
          </VStack>
        </CardBody>
      </Card>

      {/* 国家访问控制 */}
      <Card>
        <CardHeader>
          <Heading size="md">国家访问控制</Heading>
        </CardHeader>
        <CardBody>
          <VStack spacing={6} align="stretch">
            {/* 允许列表 */}
            <Box>
              <FormLabel>允许的国家</FormLabel>
              <Text fontSize="sm" color="gray.600" mb={3}>
                只有这些国家的访问者可以访问（留空表示允许所有国家）
              </Text>
              
              <HStack mb={3}>
                <Select
                  placeholder="选择国家..."
                  value={selectedCountry}
                  onChange={(e) => setSelectedCountry(e.target.value)}
                  maxW="300px"
                >
                  {getCommonCountries(t)
                    .filter(country => !config.allowed_countries.includes(country.code))
                    .map(country => (
                      <option key={country.code} value={country.code}>
                        {country.flag} {country.name} ({country.code})
                      </option>
                    ))}
                </Select>
                <Button
                  onClick={addAllowedCountry}
                  isDisabled={!selectedCountry || config.allowed_countries.includes(selectedCountry)}
                  colorScheme="green"
                  size="sm"
                >
                  添加到允许列表
                </Button>
              </HStack>

              <Wrap>
                {config.allowed_countries.map(countryCode => (
                  <WrapItem key={countryCode}>
                    <Tag size="md" colorScheme="green" borderRadius="full">
                      <TagLabel>{getCountryName(countryCode)}</TagLabel>
                      <TagCloseButton onClick={() => removeAllowedCountry(countryCode)} />
                    </Tag>
                  </WrapItem>
                ))}
              </Wrap>
              
              {config.allowed_countries.length === 0 && (
                <Text fontSize="sm" color="gray.500" fontStyle="italic">
                  未设置允许列表，将允许所有国家访问（除了阻止列表中的国家）
                </Text>
              )}
            </Box>

            <Divider />

            {/* 阻止列表 */}
            <Box>
              <FormLabel>阻止的国家</FormLabel>
              <Text fontSize="sm" color="gray.600" mb={3}>
                这些国家的访问者将被拒绝访问
              </Text>
              
              <HStack mb={3}>
                <Select
                  placeholder="选择国家..."
                  value={selectedCountry}
                  onChange={(e) => setSelectedCountry(e.target.value)}
                  maxW="300px"
                >
                  {getCommonCountries(t)
                    .filter(country => !config.blocked_countries.includes(country.code))
                    .map(country => (
                      <option key={country.code} value={country.code}>
                        {country.flag} {country.name} ({country.code})
                      </option>
                    ))}
                </Select>
                <Button
                  onClick={addBlockedCountry}
                  isDisabled={!selectedCountry || config.blocked_countries.includes(selectedCountry)}
                  colorScheme="red"
                  size="sm"
                >
                  添加到阻止列表
                </Button>
              </HStack>

              <Wrap>
                {config.blocked_countries.map(countryCode => (
                  <WrapItem key={countryCode}>
                    <Tag size="md" colorScheme="red" borderRadius="full">
                      <TagLabel>{getCountryName(countryCode)}</TagLabel>
                      <TagCloseButton onClick={() => removeBlockedCountry(countryCode)} />
                    </Tag>
                  </WrapItem>
                ))}
              </Wrap>
              
              {config.blocked_countries.length === 0 && (
                <Text fontSize="sm" color="gray.500" fontStyle="italic">
                  未设置阻止列表
                </Text>
              )}
            </Box>
          </VStack>
        </CardBody>
      </Card>

      {/* 操作按钮 */}
      <Card>
        <CardBody>
          <HStack spacing={4}>
            <Button
              colorScheme="blue"
              leftIcon={<FiCheckCircle />}
              onClick={saveConfig}
              isLoading={saving}
              loadingText="保存中..."
            >
              保存配置
            </Button>
            
            <Button
              variant="outline"
              leftIcon={<FiRefreshCw />}
              onClick={testGeoIP}
              isDisabled={!stats?.enabled || !stats?.city_db_loaded}
            >
              测试功能
            </Button>
            
            <Button
              variant="outline"
              leftIcon={<FiInfo />}
              onClick={() => window.open('https://www.maxmind.com/', '_blank')}
            >
              获取数据库
            </Button>
          </HStack>
        </CardBody>
      </Card>
    </VStack>
  )
}

export default GeoIPConfig

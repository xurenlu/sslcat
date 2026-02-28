import React, { useState, useEffect, useRef } from 'react'
import {
  Box,
  Heading,
  Text,
  Card,
  CardBody,
  SimpleGrid,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  HStack,
  VStack,
  Button,
  Icon,
  useToast,
  Badge,
  Divider,
  useColorModeValue,
  Spinner,
  Alert,
  AlertIcon,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Progress,
} from '@chakra-ui/react'
import {
  FiGlobe,
  FiTarget,
  FiShield,
  FiActivity,
  FiRefreshCw,
  FiAlertTriangle,
  FiMapPin,
  FiClock,
  FiCheckCircle,
  FiXCircle,
} from 'react-icons/fi'
import { MapContainer, TileLayer, Marker, Popup, CircleMarker, useMap } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

// 修复 Leaflet 默认图标问题
import L from 'leaflet'
// 使用更安全的方式修复默认图标
const DefaultIcon = L.icon({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png',
  iconSize: [25, 41],
  iconAnchor: [12, 41],
  popupAnchor: [1, -34],
})
L.Marker.prototype.options.icon = DefaultIcon

interface AttackData {
  source_ip: string
  country: string
  country_code: string
  city: string
  latitude: number
  longitude: number
  attack_type: string
  count: number
  last_seen: string
  blocked: boolean
}

interface AttackStats {
  total_attacks: number
  blocked_attacks: number
  by_type: { [key: string]: number }
  by_country: { [key: string]: number }
  top_ips: Array<{ ip: string; count: number; blocked: boolean }>
  time_range: {
    hours: number
    start: string
    end: string
  }
}

const AttackMap: React.FC = () => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  const toast = useToast()

  const [attacks, setAttacks] = useState<AttackData[]>([])
  const [stats, setStats] = useState<AttackStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [selectedHours, setSelectedHours] = useState(24)
  const [mapCenter, setMapCenter] = useState<[number, number]>([20, 0])
  const [wsConnected, setWsConnected] = useState(false)

  const bgColor = useColorModeValue('white', 'gray.800')
  const borderColor = useColorModeValue('gray.200', 'gray.700')
  const wsRef = useRef<WebSocket | null>(null)

  const loadAttacks = async () => {
    try {
      const response = await fetch(
        buildApiPath(adminPrefix, `/api/attack-map/recent?hours=${selectedHours}`),
        { credentials: 'include' }
      )
      if (response.ok) {
        const data = await response.json()
        setAttacks(data.attacks || [])
      }
    } catch (error) {
      console.error('Error loading attacks:', error)
    }
  }

  const loadStats = async () => {
    try {
      const response = await fetch(
        buildApiPath(adminPrefix, `/api/attack-map/stats?hours=${selectedHours}`),
        { credentials: 'include' }
      )
      if (response.ok) {
        const data = await response.json()
        setStats(data)
      }
    } catch (error) {
      console.error('Error loading stats:', error)
    }
  }

  const loadData = async () => {
    setLoading(true)
    await Promise.all([loadAttacks(), loadStats()])
    setLoading(false)
  }

  const handleRefresh = async () => {
    setRefreshing(true)
    await loadData()
    setRefreshing(false)
    toast({
      title: '刷新成功',
      status: 'success',
      duration: 2000,
      isClosable: true,
    })
  }

  // WebSocket 连接
  useEffect(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    const wsUrl = `${protocol}//${host}${adminPrefix}/api/attack-map/ws`

    wsRef.current = new WebSocket(wsUrl)

    wsRef.current.onopen = () => {
      setWsConnected(true)
      console.log('Attack map WebSocket connected')
    }

    wsRef.current.onclose = () => {
      setWsConnected(false)
      console.log('Attack map WebSocket disconnected')
    }

    wsRef.current.onerror = (error) => {
      console.error('WebSocket error:', error)
      setWsConnected(false)
    }

    wsRef.current.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data)
        if (message.type === 'attack' || message.type === 'scan' || message.type === 'block') {
          // 新的攻击事件，刷新数据
          loadAttacks()
        }
      } catch (error) {
        console.error('Error parsing WebSocket message:', error)
      }
    }

    return () => {
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [adminPrefix])

  useEffect(() => {
    loadData()
  }, [adminPrefix, selectedHours])

  const getAttackTypeColor = (type: string) => {
    const colors: { [key: string]: string } = {
      sql_injection: 'red',
      xss: 'orange',
      path_traversal: 'yellow',
      command_injection: 'red',
      scanner_detection: 'purple',
      ddos: 'red',
      brute_force: 'orange',
    }
    return colors[type] || 'blue'
  }

  const getAttackTypeLabel = (type: string) => {
    const labels: { [key: string]: string } = {
      sql_injection: 'SQL注入',
      xss: 'XSS攻击',
      path_traversal: '路径遍历',
      command_injection: '命令注入',
      scanner_detection: '扫描检测',
      ddos: 'DDoS攻击',
      brute_force: '暴力破解',
    }
    return labels[type] || type
  }

  const getCircleRadius = (count: number) => {
    // 根据攻击次数计算圆圈大小
    return Math.min(50, 10 + count * 2)
  }

  const getCircleColor = (blocked: boolean) => {
    return blocked ? '#ef4444' : '#f59e0b'
  }

  if (loading) {
    return (
      <Box p={6} display="flex" justifyContent="center" alignItems="center" minH="400px">
        <VStack spacing={4}>
          <Spinner size="xl" thickness="4px" speed="0.65s" emptyColor="gray.200" color="blue.500" />
          <Text>加载中...</Text>
        </VStack>
      </Box>
    )
  }

  return (
    <Box p={6}>
      <VStack spacing={6} align="stretch">
        {/* Header */}
        <HStack justify="space-between">
          <Heading size="lg" display="flex" alignItems="center">
            <Icon as={FiGlobe} mr={3} />
            实时攻击地图
          </Heading>
          <HStack>
            <Badge colorScheme={wsConnected ? 'green' : 'gray'}>
              {wsConnected ? '实时连接' : '离线'}
            </Badge>
            <Button
              leftIcon={<Icon as={FiRefreshCw} />}
              variant="outline"
              onClick={handleRefresh}
              isLoading={refreshing}
            >
              刷新
            </Button>
          </HStack>
        </HStack>

        {/* Summary Stats */}
        {stats && (
          <SimpleGrid columns={{ base: 1, md: 4 }} spacing={4}>
            <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center">
                    <Icon as={FiTarget} mr={2} color="blue.500" />
                    总攻击次数
                  </StatLabel>
                  <StatNumber>{stats.total_attacks.toLocaleString()}</StatNumber>
                  <StatHelpText>过去 {selectedHours} 小时</StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center">
                    <Icon as={FiShield} mr={2} color="green.500" />
                    已阻止
                  </StatLabel>
                  <StatNumber>{stats.blocked_attacks.toLocaleString()}</StatNumber>
                  <StatHelpText>
                    {stats.total_attacks > 0
                      ? `${((stats.blocked_attacks / stats.total_attacks) * 100).toFixed(1)}% 阻止率`
                      : '-'}
                  </StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center">
                    <Icon as={FiActivity} mr={2} color="purple.500" />
                    攻击来源
                  </StatLabel>
                  <StatNumber>{Object.keys(stats.by_country).length}</StatNumber>
                  <StatHelpText>个国家/地区</StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
              <CardBody>
                <Stat>
                  <StatLabel display="flex" alignItems="center">
                    <Icon as={FiAlertTriangle} mr={2} color="orange.500" />
                    活跃IP
                  </StatLabel>
                  <StatNumber>{stats.top_ips.length}</StatNumber>
                  <StatHelpText>攻击源IP数量</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
          </SimpleGrid>
        )}

        {/* Map and Details */}
        <SimpleGrid columns={{ base: 1, lg: 2 }} spacing={6}>
          {/* Map */}
          <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
            <CardBody>
              <VStack spacing={4} align="stretch">
                <HStack justify="space-between">
                  <Heading size="md">攻击来源地图</Heading>
                  <Button
                    size="sm"
                    variant={selectedHours === 1 ? 'solid' : 'outline'}
                    onClick={() => setSelectedHours(1)}
                  >
                    1小时
                  </Button>
                  <Button
                    size="sm"
                    variant={selectedHours === 24 ? 'solid' : 'outline'}
                    onClick={() => setSelectedHours(24)}
                  >
                    24小时
                  </Button>
                  <Button
                    size="sm"
                    variant={selectedHours === 168 ? 'solid' : 'outline'}
                    onClick={() => setSelectedHours(168)}
                  >
                    7天
                  </Button>
                </HStack>

                <Box h="400px" borderRadius="md" overflow="hidden">
                  {loading ? (
                    <Box h="100%" display="flex" alignItems="center" justifyContent="center">
                      <Spinner size="xl" />
                    </Box>
                  ) : (
                    <MapContainer
                      key={String(wsConnected)}
                      center={[30, 0]}
                      zoom={2}
                      style={{ height: '100%', width: '100%' }}
                    >
                    <TileLayer
                      attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
                      url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                    />
                    {attacks.map((attack, idx) => (
                      <CircleMarker
                        key={idx}
                        center={[attack.latitude, attack.longitude]}
                        radius={getCircleRadius(attack.count)}
                        pathOptions={{
                          color: getCircleColor(attack.blocked),
                          fillColor: getCircleColor(attack.blocked),
                          fillOpacity: 0.5,
                        }}
                      >
                        <Popup>
                          <VStack align="start" spacing={2}>
                            <Text fontWeight="bold">{attack.city}, {attack.country}</Text>
                            <Text fontSize="sm">IP: {attack.source_ip}</Text>
                            <Badge colorScheme={getAttackTypeColor(attack.attack_type)}>
                              {getAttackTypeLabel(attack.attack_type)}
                            </Badge>
                            <Text fontSize="sm">攻击次数: {attack.count}</Text>
                            <Text fontSize="sm">
                              最后一次: {new Date(attack.last_seen).toLocaleString('zh-CN')}
                            </Text>
                            {attack.blocked ? (
                              <Badge colorScheme="red">已阻止</Badge>
                            ) : (
                              <Badge colorScheme="yellow">未阻止</Badge>
                            )}
                          </VStack>
                        </Popup>
                      </CircleMarker>
                    ))}
                  </MapContainer>
                  )}
                </Box>
              </VStack>
            </CardBody>
          </Card>

          {/* Attack List */}
          <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
            <CardBody>
              <VStack spacing={4} align="stretch">
                <Heading size="md">攻击详情</Heading>

                {attacks.length === 0 ? (
                  <Alert status="success">
                    <AlertIcon />
                    <Box>
                      <Text fontWeight="bold">安全状态良好</Text>
                      <Text fontSize="sm">过去 {selectedHours} 小时内未检测到攻击</Text>
                    </Box>
                  </Alert>
                ) : (
                  <Box overflowY="auto" maxH="400px">
                    <Table size="sm">
                      <Thead position="sticky" top={0} bg="white" zIndex={1}>
                        <Tr>
                          <Th>位置</Th>
                          <Th>类型</Th>
                          <Th>次数</Th>
                          <Th>状态</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {attacks.map((attack, idx) => (
                          <Tr key={idx}>
                            <Td>
                              <VStack align="start" spacing={0}>
                                <HStack>
                                  <Icon as={FiMapPin} color="gray.400" />
                                  <Text fontSize="sm">
                                    {attack.city}, {attack.country}
                                  </Text>
                                </HStack>
                                <Text fontSize="xs" color="gray.500">
                                  {attack.source_ip}
                                </Text>
                              </VStack>
                            </Td>
                            <Td>
                              <Badge colorScheme={getAttackTypeColor(attack.attack_type)}>
                                {getAttackTypeLabel(attack.attack_type)}
                              </Badge>
                            </Td>
                            <Td>
                              <Text fontWeight="bold">{attack.count}</Text>
                            </Td>
                            <Td>
                              {attack.blocked ? (
                                <Badge colorScheme="red" display="flex" alignItems="center" gap={1}>
                                  <Icon as={FiCheckCircle} boxSize={3} />
                                  已阻止
                                </Badge>
                              ) : (
                                <Badge colorScheme="yellow" display="flex" alignItems="center" gap={1}>
                                  <Icon as={FiXCircle} boxSize={3} />
                                  未阻止
                                </Badge>
                              )}
                            </Td>
                          </Tr>
                        ))}
                      </Tbody>
                    </Table>
                  </Box>
                )}
              </VStack>
            </CardBody>
          </Card>
        </SimpleGrid>

        {/* Attack Type Distribution */}
        {stats && stats.by_type && Object.keys(stats.by_type).length > 0 && (
          <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
            <CardBody>
              <Heading size="md" mb={4}>攻击类型分布</Heading>
              <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={4}>
                {Object.entries(stats.by_type).map(([type, count]) => (
                  <Box key={type}>
                    <HStack justify="space-between" mb={2}>
                      <Badge colorScheme={getAttackTypeColor(type)}>
                        {getAttackTypeLabel(type)}
                      </Badge>
                      <Text fontWeight="bold">{count}</Text>
                    </HStack>
                    <Progress
                      value={(count / stats.total_attacks) * 100}
                      colorScheme={getAttackTypeColor(type)}
                      borderRadius="md"
                    />
                  </Box>
                ))}
              </SimpleGrid>
            </CardBody>
          </Card>
        )}
      </VStack>
    </Box>
  )
}

export default AttackMap

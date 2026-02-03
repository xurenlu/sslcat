import React, { useEffect, useRef, useState } from 'react'
import { Box, Text, VStack, HStack, Badge } from '@chakra-ui/react'
import { MapContainer, TileLayer, CircleMarker, Popup, useMap } from 'react-leaflet'
import 'leaflet/dist/leaflet.css'
import L from 'leaflet'
import { ParticleSystem } from '../utils/canvasUtils'

// 修复 Leaflet 默认图标问题
delete (L.Icon.Default.prototype as any)._getIconUrl
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png',
})

interface GeoDataPoint {
  country: string
  countryCode: string
  lat: number
  lng: number
  count: number
}

interface GeoHeatmapProps {
  data: GeoDataPoint[]
  height?: number
}

// 国家代码到坐标的映射（简化版，实际应使用完整数据库）
const COUNTRY_COORDS: Record<string, [number, number]> = {
  CN: [35.8617, 104.1954],
  US: [37.0902, -95.7129],
  JP: [36.2048, 138.2529],
  GB: [55.3781, -3.4360],
  DE: [51.1657, 10.4515],
  FR: [46.2276, 2.2137],
  KR: [35.9078, 127.7669],
  IN: [20.5937, 78.9629],
  BR: [-14.2350, -51.9253],
  RU: [61.5240, 105.3188],
}

// Canvas 粒子层组件（用于现代浏览器）
const ParticleLayer: React.FC<{ data: GeoDataPoint[] }> = ({ data }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const particleSystemRef = useRef<ParticleSystem | null>(null)
  const mapRef = useRef<L.Map | null>(null)
  const map = useMap()

  useEffect(() => {
    mapRef.current = map

    // 创建 Canvas overlay
    const canvas = canvasRef.current
    if (!canvas) return

    const bounds = map.getBounds()
    const size = map.getSize()

    canvas.width = size.x
    canvas.height = size.y

    // 创建粒子系统
    particleSystemRef.current = new ParticleSystem(canvas)

    // 根据地理位置数据添加粒子
    data.forEach((point) => {
      const latlng = L.latLng(point.lat, point.lng)
      const pixel = map.latLngToContainerPoint(latlng)

      // 根据请求数量添加粒子
      const particleCount = Math.min(Math.floor(point.count / 10), 50)
      particleSystemRef.current?.addParticles(particleCount, {
        x: pixel.x,
        y: pixel.y,
        spread: 20,
        color: getColorByCount(point.count),
        sizeRange: [1, 3],
      })
    })

    particleSystemRef.current.start()

    // 地图移动时更新粒子位置
    const updateParticles = () => {
      if (!particleSystemRef.current || !mapRef.current) return

      particleSystemRef.current.clear()
      const currentBounds = mapRef.current.getBounds()
      const currentSize = mapRef.current.getSize()

      canvas.width = currentSize.x
      canvas.height = currentSize.y

      data.forEach((point) => {
        const latlng = L.latLng(point.lat, point.lng)
        if (currentBounds.contains(latlng)) {
          const pixel = mapRef.current!.latLngToContainerPoint(latlng)
          const particleCount = Math.min(Math.floor(point.count / 10), 50)
          particleSystemRef.current.addParticles(particleCount, {
            x: pixel.x,
            y: pixel.y,
            spread: 20,
            color: getColorByCount(point.count),
            sizeRange: [1, 3],
          })
        }
      })
    }

    map.on('moveend', updateParticles)
    map.on('zoomend', updateParticles)

    return () => {
      particleSystemRef.current?.stop()
      map.off('moveend', updateParticles)
      map.off('zoomend', updateParticles)
    }
  }, [data, map])

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'absolute',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
        zIndex: 500,
      }}
    />
  )
}

// 根据请求数量获取颜色
function getColorByCount(count: number): string {
  if (count > 10000) return '#ff0000' // 红色 - 高流量
  if (count > 5000) return '#ff8800' // 橙色
  if (count > 1000) return '#ffaa00' // 黄色
  if (count > 100) return '#88ff00' // 黄绿
  return '#00ff00' // 绿色 - 低流量
}

export const GeoHeatmap: React.FC<GeoHeatmapProps> = ({ data, height = 500 }) => {
  const [selectedCountry, setSelectedCountry] = useState<GeoDataPoint | null>(null)

  // 如果没有数据，显示空状态
  if (!data || data.length === 0) {
    return (
      <Box height={height} borderRadius="md" bg="gray.100" display="flex" alignItems="center" justifyContent="center">
        <Text color="gray.500">暂无地理位置数据</Text>
      </Box>
    )
  }

  // 获取最大请求数（用于归一化）
  const maxCount = Math.max(...data.map((d) => d.count), 1)

  return (
    <VStack align="stretch" spacing={4}>
      <HStack justify="space-between">
        <Text fontWeight="semibold">请求地理位置分布</Text>
        <Badge colorScheme="blue">
          共 {data.length} 个国家/地区
        </Badge>
      </HStack>

      <Box height={height} borderRadius="md" overflow="hidden" position="relative">
        <MapContainer
          center={[20, 0]}
          zoom={2}
          style={{ height: '100%', width: '100%' }}
          scrollWheelZoom={true}
        >
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />

          {/* Canvas 粒子层（现代浏览器） */}
          <ParticleLayer data={data} />

          {/* 标记点（fallback，也用于交互） */}
          {data.map((point, idx) => {
            const radius = Math.sqrt(point.count / maxCount) * 20 + 5
            const color = getColorByCount(point.count)

            return (
              <CircleMarker
                key={idx}
                center={[point.lat, point.lng]}
                radius={radius}
                pathOptions={{
                  color,
                  fillColor: color,
                  fillOpacity: 0.6,
                }}
                eventHandlers={{
                  click: () => setSelectedCountry(point),
                }}
              >
                <Popup>
                  <VStack align="start" spacing={1}>
                    <Text fontWeight="bold">{point.country}</Text>
                    <Text fontSize="sm">请求数: {point.count.toLocaleString()}</Text>
                  </VStack>
                </Popup>
              </CircleMarker>
            )
          })}
        </MapContainer>
      </Box>

      {/* 选中国家详情 */}
      {selectedCountry && (
        <Box p={4} bg="blue.50" borderRadius="md" borderWidth="1px" borderColor="blue.200">
          <HStack justify="space-between">
            <VStack align="start" spacing={1}>
              <Text fontWeight="bold">{selectedCountry.country}</Text>
              <Text fontSize="sm" color="gray.600">
                请求数: {selectedCountry.count.toLocaleString()}
              </Text>
            </VStack>
            <Badge colorScheme="blue" fontSize="lg">
              {selectedCountry.count.toLocaleString()}
            </Badge>
          </HStack>
        </Box>
      )}
    </VStack>
  )
}

import React, { useEffect, useRef } from 'react'
import { Box, Text, VStack, HStack, Badge } from '@chakra-ui/react'
import { RadarRenderer } from '../utils/canvasUtils'

interface ThreatDetection {
  type: string
  severity: string
  description?: string
  confidence: number
}

interface ThreatRadarProps {
  threats: ThreatDetection[]
  height?: number
}

export const ThreatRadar: React.FC<ThreatRadarProps> = ({ threats, height = 400 }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const radarRef = useRef<RadarRenderer | null>(null)

  useEffect(() => {
    if (!canvasRef.current || !threats || threats.length === 0) return

    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    // 设置 Canvas 尺寸
    const resizeCanvas = () => {
      const rect = canvas.getBoundingClientRect()
      canvas.width = rect.width * window.devicePixelRatio
      canvas.height = height * window.devicePixelRatio
      ctx.scale(window.devicePixelRatio, window.devicePixelRatio)
    }

    resizeCanvas()
    window.addEventListener('resize', resizeCanvas)

    // 提取威胁类型作为轴
    const threatTypes = Array.from(new Set(threats.map((t) => t.type)))
    const axes = threatTypes.length > 0 ? threatTypes : ['未知威胁']

    // 创建雷达图渲染器
    radarRef.current = new RadarRenderer(canvas, axes, {
      radius: Math.min(canvas.width, canvas.height) * 0.3,
    })

    // 计算每个威胁类型的平均置信度（归一化到 0-1）
    const values = axes.map((axis) => {
      const axisThreats = threats.filter((t) => t.type === axis)
      if (axisThreats.length === 0) return 0
      const avgConfidence = axisThreats.reduce((sum, t) => sum + t.confidence, 0) / axisThreats.length
      return Math.min(avgConfidence / 100, 1) // 假设 confidence 是 0-100
    })

    radarRef.current.setValues(values)
    radarRef.current.draw()

    return () => {
      window.removeEventListener('resize', resizeCanvas)
    }
  }, [threats, height])

  if (!threats || threats.length === 0) {
    return (
      <Box height={height} borderRadius="md" bg="gray.100" display="flex" alignItems="center" justifyContent="center">
        <Text color="gray.500">暂无威胁数据</Text>
      </Box>
    )
  }

  // 统计威胁类型
  const threatStats = threats.reduce((acc, threat) => {
    if (!acc[threat.type]) {
      acc[threat.type] = { count: 0, totalConfidence: 0 }
    }
    acc[threat.type].count++
    acc[threat.type].totalConfidence += threat.confidence
    return acc
  }, {} as Record<string, { count: number; totalConfidence: number }>)

  return (
    <VStack align="stretch" spacing={4}>
      <HStack justify="space-between">
        <Text fontWeight="semibold">威胁类型分布雷达图</Text>
        <Badge colorScheme="purple">{threats.length} 个威胁</Badge>
      </HStack>

      <Box
        width="100%"
        height={height}
        borderRadius="md"
        bg="black"
        overflow="hidden"
        position="relative"
        borderWidth="1px"
        borderColor="gray.700"
        display="flex"
        alignItems="center"
        justifyContent="center"
      >
        <canvas
          ref={canvasRef}
          style={{
            width: '100%',
            height: '100%',
            display: 'block',
          }}
        />
      </Box>

      {/* 威胁统计 */}
      <Box p={4} bg="purple.50" borderRadius="md" borderWidth="1px" borderColor="purple.200">
        <VStack align="stretch" spacing={2}>
          <Text fontWeight="bold" fontSize="sm">威胁类型统计</Text>
          {Object.entries(threatStats).map(([type, stats]) => (
            <HStack key={type} justify="space-between">
              <Text fontSize="sm">{type}</Text>
              <HStack spacing={2}>
                <Badge colorScheme="purple">{stats.count}</Badge>
                <Text fontSize="xs" color="gray.600">
                  平均置信度: {(stats.totalConfidence / stats.count).toFixed(1)}%
                </Text>
              </HStack>
            </HStack>
          ))}
        </VStack>
      </Box>
    </VStack>
  )
}

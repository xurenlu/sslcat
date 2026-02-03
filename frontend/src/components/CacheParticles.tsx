import React, { useEffect, useRef, useState } from 'react'
import { Box, Text, VStack, HStack, Badge } from '@chakra-ui/react'
import { ParticleSystem } from '../utils/canvasUtils'
import { createFrameRateLimiter } from '../utils/canvasUtils'

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

interface CacheParticlesProps {
  objects: CacheObject[]
  hitRate: number
  height?: number
}

export const CacheParticles: React.FC<CacheParticlesProps> = ({
  objects,
  hitRate,
  height = 400,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const particleSystemRef = useRef<ParticleSystem | null>(null)
  const animationFrameRef = useRef<number | null>(null)
  const [selectedObject, setSelectedObject] = useState<CacheObject | null>(null)

  useEffect(() => {
    if (!canvasRef.current || !objects || objects.length === 0) return

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

    // 创建粒子系统
    particleSystemRef.current = new ParticleSystem(canvas)

    // 根据缓存对象添加粒子
    const maxSize = Math.max(...objects.map((o) => o.size_bytes), 1)
    const maxHits = Math.max(...objects.map((o) => o.hit_count), 1)

    objects.slice(0, 100).forEach((obj, idx) => {
      // 粒子位置（随机分布）
      const x = Math.random() * (canvas.width / window.devicePixelRatio)
      const y = Math.random() * (canvas.height / window.devicePixelRatio)

      // 根据命中率选择颜色（高命中率 = 绿色，低命中率 = 红色）
      const hitRatio = obj.hit_count / maxHits
      const color = hitRatio > 0.7 ? '#00ff00' : hitRatio > 0.4 ? '#ffaa00' : '#ff0000'

      // 根据文件大小决定粒子大小
      const size = Math.max(1, Math.min(5, (obj.size_bytes / maxSize) * 5))

      // 根据命中次数添加粒子数量
      const particleCount = Math.min(Math.floor(obj.hit_count / 10) + 1, 10)

      for (let i = 0; i < particleCount; i++) {
        setTimeout(() => {
          if (particleSystemRef.current) {
            particleSystemRef.current.addParticle({
              x: x + (Math.random() - 0.5) * 50,
              y: y + (Math.random() - 0.5) * 50,
              vx: (Math.random() - 0.5) * 0.5,
              vy: (Math.random() - 0.5) * 0.5,
              size,
              color,
              alpha: 0.8,
              life: 300,
              maxLife: 300,
            })
          }
        }, idx * 10)
      }
    })

    // 启动动画
    particleSystemRef.current.start()

    return () => {
      window.removeEventListener('resize', resizeCanvas)
      particleSystemRef.current?.stop()
      if (animationFrameRef.current !== null) {
        cancelAnimationFrame(animationFrameRef.current)
      }
    }
  }, [objects, height])

  if (!objects || objects.length === 0) {
    return (
      <Box height={height} borderRadius="md" bg="gray.100" display="flex" alignItems="center" justifyContent="center">
        <Text color="gray.500">暂无缓存对象</Text>
      </Box>
    )
  }

  return (
    <VStack align="stretch" spacing={4}>
      <HStack justify="space-between">
        <Text fontWeight="semibold">缓存对象可视化</Text>
        <HStack spacing={2}>
          <Badge colorScheme="blue">{objects.length} 个对象</Badge>
          <Badge colorScheme={hitRate > 80 ? 'green' : hitRate > 50 ? 'yellow' : 'red'}>
            命中率: {hitRate.toFixed(1)}%
          </Badge>
        </HStack>
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
      >
        {/* 说明文字 */}
        <Box
          position="absolute"
          top="10px"
          left="10px"
          bg="rgba(0, 0, 0, 0.7)"
          px={3}
          py={2}
          borderRadius="md"
          zIndex={10}
        >
          <VStack align="start" spacing={1}>
            <Text color="white" fontSize="xs">
              每个粒子代表一个缓存对象
            </Text>
            <Text color="white" fontSize="xs">
              颜色 = 命中率，大小 = 文件大小
            </Text>
          </VStack>
        </Box>

        <canvas
          ref={canvasRef}
          style={{
            width: '100%',
            height: '100%',
            display: 'block',
          }}
        />
      </Box>

      {/* 图例 */}
      <HStack spacing={4} fontSize="sm" flexWrap="wrap">
        <HStack>
          <Box w={4} h={4} bg="#00ff00" borderRadius="sm" />
          <Text>高命中率 (&gt;70%)</Text>
        </HStack>
        <HStack>
          <Box w={4} h={4} bg="#ffaa00" borderRadius="sm" />
          <Text>中命中率 (40-70%)</Text>
        </HStack>
        <HStack>
          <Box w={4} h={4} bg="#ff0000" borderRadius="sm" />
          <Text>低命中率 (&lt;40%)</Text>
        </HStack>
      </HStack>
    </VStack>
  )
}

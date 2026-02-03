import React, { useEffect, useRef, useState } from 'react'
import { Box, Text, VStack, HStack, Badge, Tooltip } from '@chakra-ui/react'
import { ParticleSystem } from '../utils/canvasUtils'
import { createFrameRateLimiter } from '../utils/canvasUtils'

interface SecurityEvent {
  id: string
  type: 'ddos_attack' | 'bruteforce' | 'suspicious_ip' | 'malware'
  severity: 'low' | 'medium' | 'high' | 'critical'
  source: string
  description: string
  timestamp: string
  blocked: boolean
}

interface AttackFlowProps {
  events: SecurityEvent[]
  height?: number
}

// 根据威胁等级获取颜色
function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical':
      return '#ff0000' // 红色
    case 'high':
      return '#ff6600' // 橙色
    case 'medium':
      return '#ffaa00' // 黄色
    case 'low':
      return '#ffff00' // 浅黄
    default:
      return '#888888'
  }
}

// 根据攻击类型获取颜色
function getTypeColor(type: string): string {
  switch (type) {
    case 'ddos_attack':
      return '#ff0000'
    case 'bruteforce':
      return '#ff6600'
    case 'malware':
      return '#8800ff'
    case 'suspicious_ip':
      return '#ffaa00'
    default:
      return '#888888'
  }
}

export const AttackFlow: React.FC<AttackFlowProps> = ({ events, height = 500 }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const particleSystemRef = useRef<ParticleSystem | null>(null)
  const animationFrameRef = useRef<number | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null)

  useEffect(() => {
    if (!canvasRef.current || !events || events.length === 0) return

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

    // 根据事件添加粒子流
    const centerX = canvas.width / window.devicePixelRatio / 2
    const centerY = canvas.height / window.devicePixelRatio / 2

    events.slice(0, 20).forEach((event, idx) => {
      // 攻击源位置（左侧随机分布）
      const sourceX = 50 + Math.random() * 100
      const sourceY = (idx / events.length) * (height - 100) + 50

      // 目标位置（中心）
      const targetX = centerX
      const targetY = centerY

      // 计算方向向量
      const dx = targetX - sourceX
      const dy = targetY - sourceY
      const distance = Math.sqrt(dx * dx + dy * dy)
      const vx = (dx / distance) * 2
      const vy = (dy / distance) * 2

      // 根据严重程度添加粒子数量
      const particleCount = event.severity === 'critical' ? 30 : event.severity === 'high' ? 20 : event.severity === 'medium' ? 10 : 5

      for (let i = 0; i < particleCount; i++) {
        const delay = Math.random() * 100 // 延迟，形成流动效果
        setTimeout(() => {
          if (particleSystemRef.current) {
            particleSystemRef.current.addParticle({
              x: sourceX + Math.random() * 20,
              y: sourceY + Math.random() * 20,
              vx,
              vy,
              size: event.severity === 'critical' ? 4 : event.severity === 'high' ? 3 : 2,
              color: getSeverityColor(event.severity),
              alpha: 0.8,
              life: 200,
              maxLife: 200,
            })
          }
        }, delay)
      }
    })

    // 启动动画
    particleSystemRef.current.start()

    // 添加点击事件
    const handleClick = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect()
      const x = e.clientX - rect.left
      const y = e.clientY - rect.top

      // 查找点击的事件（简化：根据 Y 坐标）
      const clickedEvent = events[Math.floor((y / height) * events.length)]
      if (clickedEvent) {
        setSelectedEvent(clickedEvent)
      }
    }

    canvas.addEventListener('click', handleClick)

    return () => {
      window.removeEventListener('resize', resizeCanvas)
      canvas.removeEventListener('click', handleClick)
      particleSystemRef.current?.stop()
      if (animationFrameRef.current !== null) {
        cancelAnimationFrame(animationFrameRef.current)
      }
    }
  }, [events, height])

  if (!events || events.length === 0) {
    return (
      <Box height={height} borderRadius="md" bg="gray.100" display="flex" alignItems="center" justifyContent="center">
        <Text color="gray.500">暂无安全事件数据</Text>
      </Box>
    )
  }

  return (
    <VStack align="stretch" spacing={4}>
      <HStack justify="space-between">
        <Text fontWeight="semibold">攻击流可视化</Text>
        <Badge colorScheme="red">{events.length} 个事件</Badge>
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
        {/* 攻击源标签（左侧） */}
        <Box
          position="absolute"
          left="10px"
          top="10px"
          bg="rgba(255, 0, 0, 0.8)"
          px={2}
          py={1}
          borderRadius="md"
          zIndex={10}
        >
          <Text color="white" fontSize="xs" fontWeight="bold">攻击源</Text>
        </Box>

        {/* 目标标签（中心） */}
        <Box
          position="absolute"
          left="50%"
          top="50%"
          transform="translate(-50%, -50%)"
          bg="rgba(0, 255, 0, 0.8)"
          px={3}
          py={2}
          borderRadius="md"
          zIndex={10}
          borderWidth="2px"
          borderColor="green.400"
        >
          <Text color="white" fontSize="sm" fontWeight="bold">SSLcat Gateway</Text>
        </Box>

        <canvas
          ref={canvasRef}
          style={{
            width: '100%',
            height: '100%',
            display: 'block',
            cursor: 'pointer',
          }}
        />
      </Box>

      {/* 选中事件详情 */}
      {selectedEvent && (
        <Box p={4} bg="red.50" borderRadius="md" borderWidth="1px" borderColor="red.200">
          <VStack align="start" spacing={2}>
            <HStack>
              <Badge colorScheme={selectedEvent.severity === 'critical' ? 'red' : selectedEvent.severity === 'high' ? 'orange' : 'yellow'}>
                {selectedEvent.severity}
              </Badge>
              <Badge colorScheme={selectedEvent.blocked ? 'green' : 'red'}>
                {selectedEvent.blocked ? '已阻止' : '未阻止'}
              </Badge>
              <Text fontWeight="bold">{selectedEvent.type}</Text>
            </HStack>
            <Text fontSize="sm">
              <strong>来源:</strong> {selectedEvent.source}
            </Text>
            <Text fontSize="sm">
              <strong>描述:</strong> {selectedEvent.description}
            </Text>
            <Text fontSize="sm" color="gray.600">
              <strong>时间:</strong> {new Date(selectedEvent.timestamp).toLocaleString()}
            </Text>
          </VStack>
        </Box>
      )}

      {/* 图例 */}
      <HStack spacing={4} fontSize="sm" flexWrap="wrap">
        <HStack>
          <Box w={4} h={4} bg="#ff0000" borderRadius="sm" />
          <Text>Critical</Text>
        </HStack>
        <HStack>
          <Box w={4} h={4} bg="#ff6600" borderRadius="sm" />
          <Text>High</Text>
        </HStack>
        <HStack>
          <Box w={4} h={4} bg="#ffaa00" borderRadius="sm" />
          <Text>Medium</Text>
        </HStack>
        <HStack>
          <Box w={4} h={4} bg="#ffff00" borderRadius="sm" />
          <Text>Low</Text>
        </HStack>
      </HStack>
    </VStack>
  )
}

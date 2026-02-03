import React, { useEffect, useRef, useState } from 'react'
import { Box, Text, HStack, VStack } from '@chakra-ui/react'
import { WaveformRenderer } from '../utils/canvasUtils'
import { createFrameRateLimiter } from '../utils/canvasUtils'

interface PerformanceWaveformProps {
  data: number[]
  label: string
  color?: string
  fillColor?: string
  height?: number
  realtime?: boolean
  onDataPoint?: (value: number) => void
}

export const PerformanceWaveform: React.FC<PerformanceWaveformProps> = ({
  data,
  label,
  color = '#00ff00',
  fillColor = 'rgba(0, 255, 0, 0.2)',
  height = 300,
  realtime = false,
  onDataPoint,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const waveformRef = useRef<WaveformRenderer | null>(null)
  const animationFrameRef = useRef<number | null>(null)
  const [currentValue, setCurrentValue] = useState<number>(0)

  useEffect(() => {
    if (!canvasRef.current) return

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

    // 创建波形渲染器
    waveformRef.current = new WaveformRenderer(canvas, {
      maxDataPoints: 100,
      lineColor: color,
      fillColor: fillColor,
      lineWidth: 2,
    })

    // 设置初始数据
    if (data.length > 0) {
      waveformRef.current.setData(data)
      waveformRef.current.draw()
      setCurrentValue(data[data.length - 1] || 0)
    }

    // 实时更新（如果需要）
    if (realtime && onDataPoint) {
      const limiter = createFrameRateLimiter(60)
      const animate = () => {
        limiter(() => {
          if (waveformRef.current) {
            waveformRef.current.draw()
          }
        })
        animationFrameRef.current = requestAnimationFrame(animate)
      }
      animate()
    } else {
      // 非实时模式：限制重绘频率
      const limiter = createFrameRateLimiter(30)
      const animate = () => {
        limiter(() => {
          if (waveformRef.current) {
            waveformRef.current.draw()
          }
        })
        animationFrameRef.current = requestAnimationFrame(animate)
      }
      animate()
    }

    return () => {
      window.removeEventListener('resize', resizeCanvas)
      if (animationFrameRef.current !== null) {
        cancelAnimationFrame(animationFrameRef.current)
      }
    }
  }, [data, color, fillColor, height, realtime, onDataPoint])

  // 更新数据
  useEffect(() => {
    if (waveformRef.current && data.length > 0) {
      waveformRef.current.setData(data)
      waveformRef.current.draw()
      setCurrentValue(data[data.length - 1] || 0)
    }
  }, [data])

  return (
    <VStack align="stretch" spacing={2}>
      <HStack justify="space-between">
        <Text fontWeight="semibold" fontSize="sm" color="gray.600">
          {label}
        </Text>
        <Text fontFamily="mono" fontSize="lg" fontWeight="bold" color={color}>
          {currentValue.toFixed(2)}%
        </Text>
      </HStack>
      <Box
        width="100%"
        height={height}
        borderRadius="md"
        bg="black"
        overflow="hidden"
        position="relative"
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
    </VStack>
  )
}

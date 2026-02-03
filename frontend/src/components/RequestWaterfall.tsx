import React, { useEffect, useRef, useState } from 'react'
import { Box, Text, VStack, HStack, Badge, Tooltip } from '@chakra-ui/react'
import { WaterfallRenderer } from '../utils/canvasUtils'

interface SlowRequestRecord {
  id: string
  timestamp: string
  method: string
  url: string
  status_code: number
  response_time: number
  backend_id?: string
  backend_addr?: string
}

interface RequestWaterfallProps {
  requests: SlowRequestRecord[]
  maxTime?: number
  height?: number
}

export const RequestWaterfall: React.FC<RequestWaterfallProps> = ({
  requests,
  maxTime,
  height = 400,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const waterfallRef = useRef<WaterfallRenderer | null>(null)
  const [selectedRequest, setSelectedRequest] = useState<SlowRequestRecord | null>(null)

  useEffect(() => {
    if (!canvasRef.current || !requests || requests.length === 0) return

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

    // 创建瀑布图渲染器
    waterfallRef.current = new WaterfallRenderer(canvas)

    // 计算最大时间
    const calculatedMaxTime =
      maxTime ||
      Math.max(
        ...requests.map((r) => {
          const startTime = new Date(r.timestamp).getTime()
          return startTime + r.response_time
        }),
        1000
      )

    // 设置请求数据
    const startTime = requests.length > 0 ? new Date(requests[0].timestamp).getTime() : 0
    waterfallRef.current.setRequests(
      requests.map((req) => ({
        startTime: new Date(req.timestamp).getTime() - startTime,
        duration: req.response_time,
        statusCode: req.status_code,
        label: `${req.method} ${req.url.substring(0, 30)}`,
      })),
      calculatedMaxTime - startTime
    )

    waterfallRef.current.draw()

    // 添加点击事件
    const handleClick = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect()
      const x = e.clientX - rect.left
      const y = e.clientY - rect.top

      // 查找点击的请求
      const clickedRequest = requests.find((req, idx) => {
        const reqStartTime = new Date(req.timestamp).getTime() - startTime
        const reqX = (reqStartTime / (calculatedMaxTime - startTime)) * rect.width
        const reqY = idx * 22
        const reqWidth = (req.response_time / (calculatedMaxTime - startTime)) * rect.width

        return x >= reqX && x <= reqX + reqWidth && y >= reqY && y <= reqY + 20
      })

      if (clickedRequest) {
        setSelectedRequest(clickedRequest)
      }
    }

    canvas.addEventListener('click', handleClick)

    return () => {
      window.removeEventListener('resize', resizeCanvas)
      canvas.removeEventListener('click', handleClick)
    }
  }, [requests, maxTime, height])

  if (!requests || requests.length === 0) {
    return (
      <Box height={height} borderRadius="md" bg="gray.100" display="flex" alignItems="center" justifyContent="center">
        <Text color="gray.500">暂无慢请求数据</Text>
      </Box>
    )
  }

  return (
    <VStack align="stretch" spacing={4}>
      <HStack justify="space-between">
        <Text fontWeight="semibold">请求时间轴瀑布图</Text>
        <Badge colorScheme="blue">{requests.length} 个请求</Badge>
      </HStack>

      <Box
        width="100%"
        height={height}
        borderRadius="md"
        bg="black"
        overflow="auto"
        position="relative"
        borderWidth="1px"
        borderColor="gray.700"
      >
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

      {/* 选中请求详情 */}
      {selectedRequest && (
        <Box p={4} bg="blue.50" borderRadius="md" borderWidth="1px" borderColor="blue.200">
          <VStack align="start" spacing={2}>
            <HStack>
              <Badge colorScheme={selectedRequest.status_code >= 500 ? 'red' : selectedRequest.status_code >= 400 ? 'orange' : 'green'}>
                {selectedRequest.status_code}
              </Badge>
              <Text fontWeight="bold">{selectedRequest.method}</Text>
              <Text fontSize="sm" color="gray.600">{selectedRequest.url}</Text>
            </HStack>
            <HStack spacing={4}>
              <Text fontSize="sm">
                <strong>响应时间:</strong> {selectedRequest.response_time}ms
              </Text>
              <Text fontSize="sm">
                <strong>时间:</strong> {new Date(selectedRequest.timestamp).toLocaleString()}
              </Text>
              {selectedRequest.backend_addr && (
                <Text fontSize="sm">
                  <strong>后端:</strong> {selectedRequest.backend_addr}
                </Text>
              )}
            </HStack>
          </VStack>
        </Box>
      )}

      {/* 图例 */}
      <HStack spacing={4} fontSize="sm">
        <HStack>
          <Box w={4} h={4} bg="#00ff00" borderRadius="sm" />
          <Text>2xx 成功</Text>
        </HStack>
        <HStack>
          <Box w={4} h={4} bg="#0088ff" borderRadius="sm" />
          <Text>3xx 重定向</Text>
        </HStack>
        <HStack>
          <Box w={4} h={4} bg="#ff8800" borderRadius="sm" />
          <Text>4xx 客户端错误</Text>
        </HStack>
        <HStack>
          <Box w={4} h={4} bg="#ff0000" borderRadius="sm" />
          <Text>5xx 服务器错误</Text>
        </HStack>
      </HStack>
    </VStack>
  )
}

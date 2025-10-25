import React from 'react'
import {
  Box,
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
  Text,
  Icon,
  Heading,
  SimpleGrid,
  Tooltip,
  Badge,
} from '@chakra-ui/react'
import { FiWifi, FiClock, FiLayers, FiActivity } from 'react-icons/fi'
import { useTranslation } from '../hooks/useLanguage'

interface WebSocketConfigProps {
  websocket_optimized: boolean
  websocket_buffer_size: number
  websocket_read_timeout: number
  websocket_write_timeout: number
  websocket_ping_interval: number
  onFieldChange: (field: string, value: any) => void
}

const WebSocketConfig: React.FC<WebSocketConfigProps> = ({
  websocket_optimized,
  websocket_buffer_size,
  websocket_read_timeout,
  websocket_write_timeout,
  websocket_ping_interval,
  onFieldChange,
}) => {
  const t = useTranslation()
  
  return (
    <Box>
      <VStack spacing={6} align="stretch">
        {/* WebSocket优化开关 */}
        <FormControl display="flex" alignItems="center" justifyContent="space-between">
          <HStack>
            <Icon as={FiWifi} color="blue.500" />
            <FormLabel mb="0" fontWeight="medium">
              启用WebSocket优化
            </FormLabel>
            <Tooltip label={t.websocket.tooltip}>
              <Badge colorScheme="blue" fontSize="xs">推荐</Badge>
            </Tooltip>
          </HStack>
          <Switch
            isChecked={websocket_optimized}
            onChange={(e) => onFieldChange('websocket_optimized', e.target.checked)}
            colorScheme="blue"
          />
        </FormControl>

        {websocket_optimized && (
          <Box>
            <Heading size="sm" mb={4} display="flex" alignItems="center">
              <Icon as={FiActivity} mr={2} />
              WebSocket优化参数
            </Heading>
            
            <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
              {/* 缓冲区大小 */}
              <FormControl>
                <FormLabel display="flex" alignItems="center">
                  <Icon as={FiLayers} mr={2} />
                  缓冲区大小
                </FormLabel>
                <NumberInput
                  value={websocket_buffer_size}
                  onChange={(_, value) => onFieldChange('websocket_buffer_size', value || 100)}
                  min={10}
                  max={1000}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
                <Text fontSize="sm" color="gray.500" mt={1}>
                  消息缓冲队列大小，默认100。高并发时可适当增加。
                </Text>
              </FormControl>

              {/* 读取超时 */}
              <FormControl>
                <FormLabel display="flex" alignItems="center">
                  <Icon as={FiClock} mr={2} />
                  读取超时 (秒)
                </FormLabel>
                <NumberInput
                  value={websocket_read_timeout}
                  onChange={(_, value) => onFieldChange('websocket_read_timeout', value || 30)}
                  min={5}
                  max={300}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
                <Text fontSize="sm" color="gray.500" mt={1}>
                  从WebSocket读取数据的超时时间，默认30秒。
                </Text>
              </FormControl>

              {/* 写入超时 */}
              <FormControl>
                <FormLabel display="flex" alignItems="center">
                  <Icon as={FiClock} mr={2} />
                  写入超时 (秒)
                </FormLabel>
                <NumberInput
                  value={websocket_write_timeout}
                  onChange={(_, value) => onFieldChange('websocket_write_timeout', value || 10)}
                  min={1}
                  max={60}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
                <Text fontSize="sm" color="gray.500" mt={1}>
                  向WebSocket写入数据的超时时间，默认10秒。
                </Text>
              </FormControl>

              {/* 心跳间隔 */}
              <FormControl>
                <FormLabel display="flex" alignItems="center">
                  <Icon as={FiActivity} mr={2} />
                  心跳间隔 (秒)
                </FormLabel>
                <NumberInput
                  value={websocket_ping_interval}
                  onChange={(_, value) => onFieldChange('websocket_ping_interval', value || 30)}
                  min={10}
                  max={300}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
                <Text fontSize="sm" color="gray.500" mt={1}>
                  WebSocket连接心跳检测间隔，默认30秒。
                </Text>
              </FormControl>
            </SimpleGrid>

            {/* 优化说明 */}
            <Box mt={4} p={4} bg="blue.50" borderRadius="md" borderLeft="4px" borderLeftColor="blue.500">
              <Text fontSize="sm" color="blue.700">
                <strong>优化效果：</strong>
              </Text>
              <VStack align="start" spacing={1} mt={2}>
                <Text fontSize="sm" color="blue.600">• 缓冲保护：网络波动时数据暂存在缓冲区中</Text>
                <Text fontSize="sm" color="blue.600">• 异步传输：读写分离，避免一端阻塞影响另一端</Text>
                <Text fontSize="sm" color="blue.600">• 优雅关闭：连接关闭时给予缓冲数据传输时间</Text>
                <Text fontSize="sm" color="blue.600">• 连接监控：实时监控连接状态，及时发现问题</Text>
              </VStack>
            </Box>
          </Box>
        )}

        {!websocket_optimized && (
          <Box p={4} bg="yellow.50" borderRadius="md" borderLeft="4px" borderLeftColor="yellow.500">
            <Text fontSize="sm" color="yellow.700">
              <strong>注意：</strong>关闭WebSocket优化后将使用简单的数据转发模式，可能在网络不稳定时丢失数据。
              建议保持启用状态以获得更好的连接稳定性。
            </Text>
          </Box>
        )}
      </VStack>
    </Box>
  )
}

export default WebSocketConfig

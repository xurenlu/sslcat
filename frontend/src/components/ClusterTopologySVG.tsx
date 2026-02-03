import React, { useState } from 'react'
import { Box, VStack, HStack, Text, Badge } from '@chakra-ui/react'
import { FiServer, FiLink } from 'react-icons/fi'
import { motion } from 'framer-motion'

interface ClusterTopologySVGProps {
  currentNode: {
    mode?: string
    node_name?: string
    node_id?: string
  }
  masterNode?: {
    host?: string
    reachable?: boolean
  }
  syncStatus?: {
    config_enabled?: boolean
    cert_enabled?: boolean
    last_sync_at?: string
  }
}

const MotionBox = motion(Box)

export const ClusterTopologySVG: React.FC<ClusterTopologySVGProps> = ({
  currentNode,
  masterNode,
  syncStatus,
}) => {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null)

  const isSlave = currentNode.mode === 'slave'
  const isMaster = currentNode.mode === 'master'
  const masterReachable = masterNode?.reachable

  return (
    <Box
      width="100%"
      height="400px"
      borderRadius="lg"
      overflow="hidden"
      bg="linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)"
      position="relative"
    >
      <style>
        {`
          @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.6; }
          }
          @keyframes dashMove {
            0% { stroke-dashoffset: 0; }
            100% { stroke-dashoffset: 10; }
          }
        `}
      </style>

      <svg width="100%" height="100%" style={{ position: 'absolute', top: 0, left: 0 }}>
        {/* 当前节点 */}
        <g>
          <circle
            cx="400"
            cy={isSlave ? "250" : "200"}
            r="40"
            fill={isMaster ? "#8800ff" : isSlave ? "#ff8800" : "#888888"}
            opacity="0.8"
            style={{
              filter: `drop-shadow(0 0 12px ${isMaster ? "#8800ff" : isSlave ? "#ff8800" : "#888888"})`,
              animation: 'pulse 2s ease-in-out infinite',
              cursor: 'pointer',
            }}
            onMouseEnter={() => setHoveredNode('current')}
            onMouseLeave={() => setHoveredNode(null)}
          />
          <text
            x="400"
            y={isSlave ? "250" : "200"}
            textAnchor="middle"
            fill="white"
            fontSize="14"
            fontWeight="bold"
            dy="5"
          >
            {currentNode.node_name || '当前节点'}
          </text>
          <text
            x="400"
            y={isSlave ? "310" : "260"}
            textAnchor="middle"
            fill={isMaster ? "#8800ff" : isSlave ? "#ff8800" : "#888888"}
            fontSize="12"
          >
            {isMaster ? 'Master' : isSlave ? 'Slave' : 'Standalone'}
          </text>
        </g>

        {/* Master 节点（如果是 slave 模式） */}
        {isSlave && masterNode?.host && (
          <g>
            {/* 连接线 */}
            <line
              x1="400"
              y1="250"
              x2="400"
              y2="150"
              stroke={masterReachable ? "#00ff00" : "#ff0000"}
              strokeWidth="3"
              strokeDasharray="5,5"
              style={{
                animation: syncStatus?.config_enabled || syncStatus?.cert_enabled
                  ? 'dashMove 1s linear infinite'
                  : 'none',
              }}
            />

            {/* Master 节点 */}
            <circle
              cx="400"
              cy="150"
              r="35"
              fill="#8800ff"
              opacity={masterReachable ? 0.9 : 0.5}
              style={{
                filter: masterReachable
                  ? 'drop-shadow(0 0 12px #8800ff)'
                  : 'none',
                animation: masterReachable ? 'pulse 2s ease-in-out infinite' : 'none',
                cursor: 'pointer',
              }}
              onMouseEnter={() => setHoveredNode('master')}
              onMouseLeave={() => setHoveredNode(null)}
            />
            <text
              x="400"
              y="150"
              textAnchor="middle"
              fill="white"
              fontSize="12"
              fontWeight="bold"
              dy="4"
            >
              Master
            </text>
            <text
              x="400"
              y="110"
              textAnchor="middle"
              fill="#8800ff"
              fontSize="11"
            >
              {masterNode.host}
            </text>
          </g>
        )}

        {/* 同步状态指示 */}
        {isSlave && (syncStatus?.config_enabled || syncStatus?.cert_enabled) && (
          <g>
            <circle
              cx="400"
              cy="200"
              r="5"
              fill="#00ff00"
              style={{
                animation: 'pulse 1s ease-in-out infinite',
              }}
            />
            <text
              x="420"
              y="205"
              fill="#00ff00"
              fontSize="10"
            >
              同步中...
            </text>
          </g>
        )}
      </svg>

      {/* 信息面板 */}
      {hoveredNode && (
        <MotionBox
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          position="absolute"
          bottom="20px"
          left="50%"
          transform="translateX(-50%)"
          bg="rgba(0, 0, 0, 0.8)"
          px={4}
          py={2}
          borderRadius="md"
        >
          <Text color="white" fontSize="sm">
            {hoveredNode === 'current'
              ? `${currentNode.node_name || '当前节点'} (${currentNode.mode})`
              : `Master: ${masterNode?.host || '未知'}`}
          </Text>
        </MotionBox>
      )}

      {/* 状态卡片（底部） */}
      <Box
        position="absolute"
        bottom="0"
        left="0"
        right="0"
        bg="rgba(0, 0, 0, 0.6)"
        p={4}
      >
        <HStack justify="center" spacing={6}>
          <VStack spacing={1}>
            <HStack>
              <FiServer color={isMaster ? "#8800ff" : isSlave ? "#ff8800" : "#888888"} />
              <Text color="white" fontSize="sm" fontWeight="bold">
                {currentNode.node_name || '当前节点'}
              </Text>
            </HStack>
            <Badge colorScheme={isMaster ? "purple" : isSlave ? "orange" : "gray"}>
              {isMaster ? 'Master' : isSlave ? 'Slave' : 'Standalone'}
            </Badge>
          </VStack>

          {isSlave && masterNode && (
            <>
              <Box w="1px" h="40px" bg="gray.600" />
              <VStack spacing={1}>
                <HStack>
                  <FiLink color={masterReachable ? "#00ff00" : "#ff0000"} />
                  <Text color="white" fontSize="sm" fontWeight="bold">
                    Master
                  </Text>
                </HStack>
                <Badge colorScheme={masterReachable ? "green" : "red"}>
                  {masterReachable ? "已连接" : "未连接"}
                </Badge>
              </VStack>
            </>
          )}
        </HStack>
      </Box>
    </Box>
  )
}

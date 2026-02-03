import React, { useState } from 'react'
import {
  Box,
  VStack,
  HStack,
  Text,
  Badge,
  Icon,
  SimpleGrid,
} from '@chakra-ui/react'
import { FiZap, FiShield, FiServer } from 'react-icons/fi'
import { motion } from 'framer-motion'

interface DashboardFallbackProps {
  stats: {
    activeRules: number
    sslCertificates: number
    wafEnabled: boolean
    wafBlocked: number
  }
}

const MotionBox = motion(Box)

// SVG 节点组件
const SVGNode: React.FC<{
  x: number
  y: number
  label: string
  value: number
  color: string
  icon: React.ElementType
  onHover?: (label: string | null) => void
}> = ({ x, y, label, value, color, icon: IconComponent, onHover }) => {
  const [hovered, setHovered] = useState(false)

  return (
    <g>
      {/* 连接线（从中心到节点） */}
      <line
        x1="400"
        y1="300"
        x2={x}
        y2={y}
        stroke={color}
        strokeWidth="2"
        strokeDasharray="5,5"
        opacity="0.5"
        style={{
          animation: 'dashMove 2s linear infinite',
        }}
      >
        <animate
          attributeName="stroke-dashoffset"
          values="0;10"
          dur="1s"
          repeatCount="indefinite"
        />
      </line>

      {/* 节点圆圈 */}
      <circle
        cx={x}
        cy={y}
        r={hovered ? 35 : 30}
        fill={color}
        opacity={hovered ? 0.9 : 0.7}
        style={{
          filter: 'drop-shadow(0 0 8px ' + color + ')',
          transition: 'all 0.3s ease',
          cursor: 'pointer',
        }}
        onMouseEnter={() => {
          setHovered(true)
          onHover?.(label)
        }}
        onMouseLeave={() => {
          setHovered(false)
          onHover?.(null)
        }}
      >
        <animate
          attributeName="r"
          values="30;35;30"
          dur="2s"
          repeatCount="indefinite"
        />
      </circle>

      {/* 图标 */}
      <foreignObject x={x - 20} y={y - 20} width="40" height="40">
        <Box display="flex" alignItems="center" justifyContent="center" h="100%">
          <Icon as={IconComponent} boxSize={6} color="white" />
        </Box>
      </foreignObject>

      {/* 标签 */}
      <text
        x={x}
        y={y + 50}
        textAnchor="middle"
        fill="white"
        fontSize="14"
        fontWeight="bold"
      >
        {label}
      </text>
      <text
        x={x}
        y={y + 70}
        textAnchor="middle"
        fill={color}
        fontSize="12"
      >
        {value}
      </text>
    </g>
  )
}

export const DashboardFallback: React.FC<DashboardFallbackProps> = ({
  stats,
}) => {
  const [hoveredLabel, setHoveredLabel] = useState<string | null>(null)

  const nodes = [
    {
      x: 400,
      y: 150,
      label: '代理服务',
      value: stats.activeRules,
      color: '#00ff00',
      icon: FiZap,
    },
    {
      x: 200,
      y: 300,
      label: 'SSL证书',
      value: stats.sslCertificates,
      color: '#0088ff',
      icon: FiShield,
    },
    {
      x: 600,
      y: 300,
      label: 'WAF防护',
      value: stats.wafBlocked,
      color: '#ff0088',
      icon: FiServer,
    },
  ]

  return (
    <Box
      width="100%"
      height="500px"
      borderRadius="lg"
      overflow="hidden"
      bg="linear-gradient(135deg, #1a1a2e 0%, #16213e 100%)"
      position="relative"
    >
      <style>
        {`
          @keyframes dashMove {
            0% { stroke-dashoffset: 0; }
            100% { stroke-dashoffset: 10; }
          }
        `}
      </style>

      <svg width="100%" height="100%" style={{ position: 'absolute', top: 0, left: 0 }}>
        {/* 中心节点 */}
        <circle
          cx="400"
          cy="300"
          r="40"
          fill="#00ff00"
          opacity="0.8"
          style={{
            filter: 'drop-shadow(0 0 12px #00ff00)',
            animation: 'pulse 2s ease-in-out infinite',
          }}
        >
          <animate
            attributeName="r"
            values="40;45;40"
            dur="2s"
            repeatCount="indefinite"
          />
        </circle>
        <text
          x="400"
          y="310"
          textAnchor="middle"
          fill="white"
          fontSize="16"
          fontWeight="bold"
        >
          SSLcat
        </text>

        {/* 渲染节点 */}
        {nodes.map((node, idx) => (
          <SVGNode
            key={idx}
            {...node}
            onHover={setHoveredLabel}
          />
        ))}
      </svg>

      {/* 信息面板 */}
      {hoveredLabel && (
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
            当前选中: {hoveredLabel}
          </Text>
        </MotionBox>
      )}

      {/* 统计卡片（底部） */}
      <Box
        position="absolute"
        bottom="0"
        left="0"
        right="0"
        bg="rgba(0, 0, 0, 0.6)"
        p={4}
      >
        <SimpleGrid columns={3} spacing={4}>
          {nodes.map((node, idx) => (
            <VStack key={idx} spacing={1}>
              <HStack>
                <Icon as={node.icon} color={node.color} />
                <Text color="white" fontSize="sm" fontWeight="bold">
                  {node.label}
                </Text>
              </HStack>
              <Text color={node.color} fontSize="xl" fontWeight="bold">
                {node.value}
              </Text>
            </VStack>
          ))}
        </SimpleGrid>
      </Box>
    </Box>
  )
}

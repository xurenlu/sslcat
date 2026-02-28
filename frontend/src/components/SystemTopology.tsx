import React, { useEffect, useRef, useState, useMemo } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { OrbitControls, Text, Line, Sphere, Trail } from '@react-three/drei'
import * as THREE from 'three'
import { Box, VStack, HStack, Text as ChakraText, Badge, useTheme } from '@chakra-ui/react'
import { FiActivity, FiShield, FiGlobe, FiServer, FiDatabase } from 'react-icons/fi'

interface SystemNode {
  id: string
  name: string
  type: 'client' | 'firewall' | 'loadbalancer' | 'proxy' | 'waf' | 'ssl' | 'cdn' | 'dns' | 'backend' | 'cache'
  position: [number, number, number]
  value: number
  status: 'healthy' | 'warning' | 'error'
  icon?: any
  stats?: Record<string, string | number>
}

interface FlowParticle {
  id: string
  from: string
  to: string
  progress: number
  speed: number
  color: string
}

interface SystemTopologyProps {
  stats: {
    activeRules: number
    sslCertificates: number
    wafEnabled: boolean
    wafBlocked: number
    totalRequests?: number
    cachedProxies?: number
  }
  width?: number
  height?: number
}

// 节点类型配置
const NODE_CONFIG: Record<string, { color: string; size: number; icon: any }> = {
  client: { color: '#64748b', size: 0.4, icon: FiGlobe },
  firewall: { color: '#ef4444', size: 0.5, icon: FiShield },
  loadbalancer: { color: '#f59e0b', size: 0.45, icon: FiActivity },
  proxy: { color: '#10b981', size: 0.5, icon: FiServer },
  waf: { color: '#8b5cf6', size: 0.5, icon: FiShield },
  ssl: { color: '#3b82f6', size: 0.45, icon: FiShield },
  cdn: { color: '#06b6d4', size: 0.4, icon: FiGlobe },
  dns: { color: '#84cc16', size: 0.35, icon: FiServer },
  backend: { color: '#ec4899', size: 0.55, icon: FiDatabase },
  cache: { color: '#f97316', size: 0.35, icon: FiDatabase },
}

// 3D 节点组件
const SystemNode3D: React.FC<{
  node: SystemNode
  onHover?: (node: SystemNode | null) => void
  isHovered?: boolean
}> = ({ node, onHover, isHovered }) => {
  const meshRef = useRef<THREE.Mesh>(null)
  const glowRef = useRef<THREE.Mesh>(null)
  const [localHovered, setLocalHovered] = useState(false)
  const config = NODE_CONFIG[node.type] || NODE_CONFIG.proxy

  useFrame((state) => {
    if (meshRef.current) {
      // 悬停时旋转
      if (localHovered || isHovered) {
        meshRef.current.rotation.y += 0.02
      }
      // 呼吸效果
      const scale = config.size * (1 + Math.sin(state.clock.elapsedTime * 2) * 0.1)
      meshRef.current.scale.setScalar(scale)
    }
    if (glowRef.current) {
      glowRef.current.scale.setScalar(config.size * 1.5 + Math.sin(state.clock.elapsedTime * 3) * 0.2)
    }
  })

  const statusColor = useMemo(() => {
    switch (node.status) {
      case 'healthy': return '#10b981'
      case 'warning': return '#f59e0b'
      case 'error': return '#ef4444'
      default: return config.color
    }
  }, [node.status, config.color])

  return (
    <group position={node.position}>
      {/* 光晕效果 */}
      <mesh ref={glowRef}>
        <sphereGeometry args={[config.size, 16, 16]} />
        <meshBasicMaterial
          color={statusColor}
          transparent
          opacity={0.15}
        />
      </mesh>

      {/* 主节点 */}
      <mesh
        ref={meshRef}
        onPointerOver={(e) => {
          e.stopPropagation()
          setLocalHovered(true)
          onHover?.(node)
        }}
        onPointerOut={(e) => {
          e.stopPropagation()
          setLocalHovered(false)
          onHover?.(null)
        }}
      >
        <sphereGeometry args={[config.size, 32, 32]} />
        <meshStandardMaterial
          color={config.color}
          emissive={config.color}
          emissiveIntensity={localHovered || isHovered ? 0.8 : 0.4}
          metalness={0.3}
          roughness={0.4}
        />
      </mesh>

      {/* 状态指示环 */}
      <mesh rotation={[Math.PI / 2, 0, 0]}>
        <ringGeometry args={[config.size * 1.1, config.size * 1.15, 32]} />
        <meshBasicMaterial color={statusColor} side={THREE.DoubleSide} />
      </mesh>

      {/* 标签 */}
      {(localHovered || isHovered) && (
        <Text
          position={[0, config.size + 0.4, 0]}
          fontSize={0.2}
          color="white"
          anchorX="center"
          anchorY="middle"
          outlineWidth={0.02}
          outlineColor="#000"
        >
          {node.name}
        </Text>
      )}
    </group>
  )
}

// 连接线组件
const ConnectionLine3D: React.FC<{
  start: [number, number, number]
  end: [number, number, number]
  color?: string
  hasTraffic?: boolean
}> = ({ start, end, color = '#10b981', hasTraffic = false }) => {
  const lineRef = useRef<any>(null)

  useFrame((state) => {
    if (lineRef.current && hasTraffic) {
      // 流量动画效果
      const material = lineRef.current.material as THREE.LineBasicMaterial
      material.opacity = 0.5 + Math.sin(state.clock.elapsedTime * 4) * 0.5
    }
  })

  const points = [new THREE.Vector3(...start), new THREE.Vector3(...end)]

  return (
    <Line
      ref={lineRef}
      points={points}
      color={color}
      lineWidth={hasTraffic ? 3 : 1.5}
      opacity={hasTraffic ? 0.8 : 0.3}
      transparent
      dashed={false}
    />
  )
}

// 流量粒子组件
const FlowParticle: React.FC<{
  from: [number, number, number]
  to: [number, number, number]
  color: string
  speed?: number
}> = ({ from, to, color, speed = 1 }) => {
  const meshRef = useRef<THREE.Mesh>(null)
  const [progress, setProgress] = useState(0)

  useFrame((state, delta) => {
    setProgress((p) => {
      const newP = p + delta * speed
      return newP > 1 ? 0 : newP
    })
  })

  const position: [number, number, number] = [
    from[0] + (to[0] - from[0]) * progress,
    from[1] + (to[1] - from[1]) * progress,
    from[2] + (to[2] - from[2]) * progress,
  ]

  return (
    <mesh ref={meshRef} position={position}>
      <sphereGeometry args={[0.08, 8, 8]} />
      <meshBasicMaterial color={color} />
    </mesh>
  )
}

// 主场景组件
const SystemTopologyScene: React.FC<{
  stats: SystemTopologyProps['stats']
  onNodeHover?: (node: SystemNode | null) => void
}> = ({ stats, onNodeHover }) => {
  const [hoveredNode, setHoveredNode] = useState<SystemNode | null>(null)
  const [particles, setParticles] = useState<FlowParticle[]>([])

  // 构建系统节点
  const nodes: SystemNode[] = useMemo(() => [
    {
      id: 'client',
      name: '客户端',
      type: 'client',
      position: [-5, 2, 0],
      value: 100,
      status: 'healthy',
    },
    {
      id: 'firewall',
      name: '防火墙',
      type: 'firewall',
      position: [-3, 1, 0],
      value: 1,
      status: 'healthy',
      stats: { blocked: stats.wafBlocked || 0 },
    },
    {
      id: 'loadbalancer',
      name: '负载均衡',
      type: 'loadbalancer',
      position: [-1, 0, 0],
      value: 1,
      status: 'healthy',
    },
    {
      id: 'waf',
      name: `WAF防护`,
      type: 'waf',
      position: [1, 1, 1],
      value: stats.wafBlocked || 0,
      status: stats.wafEnabled ? 'healthy' : 'warning',
      stats: {
        enabled: stats.wafEnabled ? '启用' : '禁用',
        blocked: stats.wafBlocked || 0,
      },
    },
    {
      id: 'ssl',
      name: `SSL终止`,
      type: 'ssl',
      position: [1, -1, -1],
      value: stats.sslCertificates || 0,
      status: stats.sslCertificates > 0 ? 'healthy' : 'warning',
      stats: { certificates: stats.sslCertificates || 0 },
    },
    {
      id: 'proxy',
      name: `反向代理`,
      type: 'proxy',
      position: [3, 0, 0],
      value: stats.activeRules || 0,
      status: stats.activeRules > 0 ? 'healthy' : 'warning',
      stats: { rules: stats.activeRules || 0 },
    },
    {
      id: 'cache',
      name: '缓存',
      type: 'cache',
      position: [4, 1.5, 0],
      value: 1,
      status: 'healthy',
    },
    {
      id: 'backend',
      name: '后端服务',
      type: 'backend',
      position: [5, 0, 0],
      value: 1,
      status: 'healthy',
    },
  ], [stats])

  // 连接关系
  const connections: Array<{
    from: string
    to: string
    hasTraffic: boolean
    color: string
  }> = useMemo(() => [
    { from: 'client', to: 'firewall', hasTraffic: true, color: '#10b981' },
    { from: 'firewall', to: 'loadbalancer', hasTraffic: true, color: '#10b981' },
    { from: 'loadbalancer', to: 'waf', hasTraffic: stats.wafEnabled, color: '#8b5cf6' },
    { from: 'loadbalancer', to: 'ssl', hasTraffic: stats.sslCertificates > 0, color: '#3b82f6' },
    { from: 'waf', to: 'proxy', hasTraffic: stats.wafEnabled, color: '#8b5cf6' },
    { from: 'ssl', to: 'proxy', hasTraffic: stats.sslCertificates > 0, color: '#3b82f6' },
    { from: 'proxy', to: 'cache', hasTraffic: true, color: '#f97316' },
    { from: 'proxy', to: 'backend', hasTraffic: true, color: '#ec4899' },
  ], [stats])

  // 流量粒子
  useEffect(() => {
    const newParticles: FlowParticle[] = []
    connections.forEach((conn, idx) => {
      if (conn.hasTraffic) {
        const fromNode = nodes.find((n) => n.id === conn.from)
        const toNode = nodes.find((n) => n.id === conn.to)
        if (fromNode && toNode) {
          for (let i = 0; i < 3; i++) {
            newParticles.push({
              id: `particle-${idx}-${i}`,
              from: conn.from,
              to: conn.to,
              progress: i * 0.33,
              speed: 0.3 + Math.random() * 0.2,
              color: conn.color,
            })
          }
        }
      }
    })
    setParticles(newParticles)
  }, [connections, nodes])

  const getNodeById = (id: string) => nodes.find((n) => n.id === id)

  return (
    <>
      {/* 灯光 */}
      <ambientLight intensity={0.4} />
      <directionalLight position={[10, 10, 5]} intensity={0.8} />
      <pointLight position={[-5, 5, 5]} intensity={0.5} color="#10b981" />
      <pointLight position={[5, -5, -5]} intensity={0.5} color="#8b5cf6" />

      {/* 渲染连接线 */}
      {connections.map((conn, idx) => {
        const fromNode = getNodeById(conn.from)
        const toNode = getNodeById(conn.to)
        if (!fromNode || !toNode) return null

        return (
          <ConnectionLine3D
            key={`line-${idx}`}
            start={fromNode.position}
            end={toNode.position}
            color={conn.color}
            hasTraffic={conn.hasTraffic}
          />
        )
      })}

      {/* 渲染流量粒子 */}
      {particles.map((particle) => {
        const fromNode = getNodeById(particle.from)
        const toNode = getNodeById(particle.to)
        if (!fromNode || !toNode) return null

        return (
          <FlowParticle
            key={particle.id}
            from={fromNode.position}
            to={toNode.position}
            color={particle.color}
            speed={particle.speed}
          />
        )
      })}

      {/* 渲染节点 */}
      {nodes.map((node) => (
        <SystemNode3D
          key={node.id}
          node={node}
          onHover={(n) => {
            setHoveredNode(n)
            onNodeHover?.(n)
          }}
          isHovered={hoveredNode?.id === node.id}
        />
      ))}

      {/* 轨道控制器 */}
      <OrbitControls
        enableDamping
        dampingFactor={0.05}
        minDistance={5}
        maxDistance={20}
        autoRotate
        autoRotateSpeed={0.5}
      />
    </>
  )
}

// 信息面板
const NodeInfoPanel: React.FC<{
  node: SystemNode | null
}> = ({ node }) => {
  const theme = useTheme()

  if (!node) return null

  const config = NODE_CONFIG[node.type] || NODE_CONFIG.proxy
  const Icon = config.icon

  return (
    <Box
      position="absolute"
      top={4}
      right={4}
      bg="rgba(0, 0, 0, 0.8)"
      backdropBlur="md"
      p={4}
      borderRadius="lg"
      borderWidth={1}
      borderColor={config.color}
      minW="250px"
      boxShadow={`0 0 20px ${config.color}40`}
    >
      <VStack align="start" spacing={3}>
        <HStack spacing={3}>
          <Box p={2} bg={`${config.color}20`} borderRadius="md">
            <Icon as={Icon} boxSize={5} color={config.color} />
          </Box>
          <Box>
            <ChakraText fontSize="lg" fontWeight="bold" color="white">
              {node.name}
            </ChakraText>
            <Badge
              mt={1}
              colorScheme={
                node.status === 'healthy' ? 'green' :
                node.status === 'warning' ? 'yellow' : 'red'
              }
            >
              {node.status === 'healthy' ? '正常' :
               node.status === 'warning' ? '警告' : '错误'}
            </Badge>
          </Box>
        </HStack>

        {node.stats && (
          <VStack align="start" spacing={2} w="full">
            {Object.entries(node.stats).map(([key, value]) => (
              <HStack key={key} justify="space-between" w="full">
                <ChakraText fontSize="sm" color="gray.400">
                  {key}:
                </ChakraText>
                <ChakraText fontSize="sm" fontWeight="bold" color="white">
                  {value}
                </ChakraText>
              </HStack>
            ))}
          </VStack>
        )}

        <HStack justify="space-between" w="full">
          <ChakraText fontSize="xs" color="gray.500">类型</ChakraText>
          <ChakraText fontSize="xs" color="gray.300">{node.type}</ChakraText>
        </HStack>
      </VStack>
    </Box>
  )
}

// 图例
const TopologyLegend: React.FC = () => {
  const items = [
    { label: '客户端', type: 'client' as const },
    { label: '防火墙', type: 'firewall' as const },
    { label: '负载均衡', type: 'loadbalancer' as const },
    { label: 'WAF', type: 'waf' as const },
    { label: 'SSL', type: 'ssl' as const },
    { label: '代理', type: 'proxy' as const },
    { label: '缓存', type: 'cache' as const },
    { label: '后端', type: 'backend' as const },
  ]

  return (
    <Box
      position="absolute"
      bottom={4}
      left={4}
      bg="rgba(0, 0, 0, 0.7)"
      backdropBlur="md"
      p={3}
      borderRadius="lg"
    >
      <VStack align="start" spacing={2}>
        <ChakraText fontSize="xs" color="gray.400" mb={1}>系统组件</ChakraText>
        {items.map((item) => {
          const config = NODE_CONFIG[item.type]
          return (
            <HStack key={item.type} spacing={2}>
              <Box
                w={3}
                h={3}
                borderRadius="full"
                bg={config.color}
                boxShadow={`0 0 8px ${config.color}`}
              />
              <ChakraText fontSize="xs" color="gray.300">{item.label}</ChakraText>
            </HStack>
          )
        })}
      </VStack>
    </Box>
  )
}

export const SystemTopology: React.FC<SystemTopologyProps> = ({
  stats,
  width = 800,
  height = 500,
}) => {
  const [hoveredNode, setHoveredNode] = useState<SystemNode | null>(null)

  return (
    <Box width={width} height={height} position="relative" borderRadius="lg" overflow="hidden">
      <Box
        position="absolute"
        top={0}
        left={0}
        right={0}
        bottom={0}
        bg="radial-gradient(circle at center, #1a1a2e 0%, #0f0f1a 100%)"
      />

      <Canvas
        camera={{ position: [0, 5, 10], fov: 50 }}
        gl={{
          antialias: true,
          alpha: true,
          powerPreference: 'high-performance',
        }}
      >
        <SystemTopologyScene stats={stats} onNodeHover={(node) => setHoveredNode(node)} />
      </Canvas>

      <NodeInfoPanel node={hoveredNode} />
      <TopologyLegend />

      {/* 标题 */}
      <Box
        position="absolute"
        top={4}
        left={4}
        bg="rgba(0, 0, 0, 0.6)"
        backdropBlur="md"
        px={3}
        py={2}
        borderRadius="md"
      >
        <ChakraText fontSize="sm" fontWeight="bold" color="white">
          系统架构拓扑
        </ChakraText>
        <ChakraText fontSize="xs" color="gray.400">
          实时流量监控
        </ChakraText>
      </Box>
    </Box>
  )
}

export default SystemTopology

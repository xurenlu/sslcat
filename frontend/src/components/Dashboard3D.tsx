import React, { useEffect, useRef, useState } from 'react'
import { Canvas } from '@react-three/fiber'
import { OrbitControls, Text, Line } from '@react-three/drei'
import * as THREE from 'three'
import { Box } from '@chakra-ui/react'

interface SystemNode {
  id: string
  name: string
  type: 'proxy' | 'ssl' | 'waf' | 'cdn' | 'dns'
  position: [number, number, number]
  value: number
  status: 'healthy' | 'warning' | 'error'
}

interface Dashboard3DProps {
  stats: {
    activeRules: number
    sslCertificates: number
    wafEnabled: boolean
    wafBlocked: number
  }
  width?: number
  height?: number
}

// 3D 节点组件
const SystemNode3D: React.FC<{
  node: SystemNode
  onHover?: (node: SystemNode | null) => void
}> = ({ node, onHover }) => {
  const meshRef = useRef<THREE.Mesh>(null)
  const [hovered, setHovered] = useState(false)

  // 根据类型选择颜色
  const getColor = () => {
    switch (node.type) {
      case 'proxy':
        return node.status === 'healthy' ? '#00ff00' : node.status === 'warning' ? '#ffaa00' : '#ff0000'
      case 'ssl':
        return '#0088ff'
      case 'waf':
        return '#ff0088'
      case 'cdn':
        return '#8800ff'
      case 'dns':
        return '#00ffff'
      default:
        return '#ffffff'
    }
  }

  // 脉冲动画
  useEffect(() => {
    if (!meshRef.current) return

    const mesh = meshRef.current
    let pulsePhase = 0

    const animate = () => {
      pulsePhase += 0.05
      const scale = 1 + Math.sin(pulsePhase) * 0.1
      mesh.scale.setScalar(scale)
      requestAnimationFrame(animate)
    }

    animate()
  }, [])

  return (
    <group position={node.position}>
      <mesh
        ref={meshRef}
        onPointerOver={() => {
          setHovered(true)
          onHover?.(node)
        }}
        onPointerOut={() => {
          setHovered(false)
          onHover?.(null)
        }}
      >
        <sphereGeometry args={[0.3, 32, 32]} />
        <meshStandardMaterial
          color={getColor()}
          emissive={getColor()}
          emissiveIntensity={hovered ? 0.8 : 0.4}
        />
      </mesh>
      {hovered && (
        <Text
          position={[0, 0.6, 0]}
          fontSize={0.2}
          color="white"
          anchorX="center"
          anchorY="middle"
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
}> = ({ start, end, color = '#00ff00' }) => {
  const points = [new THREE.Vector3(...start), new THREE.Vector3(...end)]

  return (
    <Line
      points={points}
      color={color}
      lineWidth={2}
      dashed={false}
    />
  )
}

const Dashboard3DScene: React.FC<Dashboard3DProps> = ({ stats }) => {
  const [hoveredNode, setHoveredNode] = useState<SystemNode | null>(null)

  // 构建节点数据
  const nodes: SystemNode[] = [
    {
      id: 'proxy',
      name: `代理服务 (${stats.activeRules})`,
      type: 'proxy',
      position: [0, 0, 0],
      value: stats.activeRules,
      status: stats.activeRules > 0 ? 'healthy' : 'warning',
    },
    {
      id: 'ssl',
      name: `SSL证书 (${stats.sslCertificates})`,
      type: 'ssl',
      position: [-2, 1, 0],
      value: stats.sslCertificates,
      status: stats.sslCertificates > 0 ? 'healthy' : 'warning',
    },
    {
      id: 'waf',
      name: `WAF防护 (${stats.wafBlocked})`,
      type: 'waf',
      position: [2, 1, 0],
      value: stats.wafBlocked,
      status: stats.wafEnabled ? 'healthy' : 'error',
    },
  ]

  // 连接关系
  const connections: Array<{ from: string; to: string }> = [
    { from: 'proxy', to: 'ssl' },
    { from: 'proxy', to: 'waf' },
  ]

  const getNodeById = (id: string) => nodes.find((n) => n.id === id)

  return (
    <>
      <ambientLight intensity={0.6} />
      <directionalLight position={[5, 5, 5]} intensity={0.8} />

      {/* 渲染节点 */}
      {nodes.map((node) => (
        <SystemNode3D key={node.id} node={node} onHover={setHoveredNode} />
      ))}

      {/* 渲染连接线 */}
      {connections.map((conn, idx) => {
        const fromNode = getNodeById(conn.from)
        const toNode = getNodeById(conn.to)
        if (!fromNode || !toNode) return null

        return (
          <ConnectionLine3D
            key={idx}
            start={fromNode.position}
            end={toNode.position}
            color="#00ff00"
          />
        )
      })}

      {/* 轨道控制器 */}
      <OrbitControls
        enableDamping
        dampingFactor={0.05}
        minDistance={3}
        maxDistance={10}
      />
    </>
  )
}

export const Dashboard3D: React.FC<Dashboard3DProps> = ({
  stats,
  width = 800,
  height = 600,
}) => {
  // 性能优化：限制节点数量
  const maxNodes = 10

  return (
    <Box width={width} height={height} borderRadius="lg" overflow="hidden" bg="black">
      <Canvas
        camera={{ position: [0, 0, 5], fov: 50 }}
        gl={{ 
          antialias: true, 
          alpha: false,
          powerPreference: 'high-performance',
          preserveDrawingBuffer: false, // 不保留绘制缓冲区，节省内存
        }}
        performance={{ min: 0.5 }} // 性能监控：低于 50% 帧率时降级
      >
        <Dashboard3DScene stats={stats} />
      </Canvas>
    </Box>
  )
}

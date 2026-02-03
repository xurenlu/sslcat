import React, { useState } from 'react'
import { Canvas } from '@react-three/fiber'
import { OrbitControls, Text, Line } from '@react-three/drei'
import * as THREE from 'three'
import { Box } from '@chakra-ui/react'

interface ClusterNode {
  id: string
  name: string
  mode: 'master' | 'slave' | 'standalone'
  position: [number, number, number]
  status: 'connected' | 'disconnected' | 'syncing'
}

interface ClusterTopologyProps {
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
  width?: number
  height?: number
}

// 3D 节点组件
const ClusterNode3D: React.FC<{
  node: ClusterNode
  onHover?: (node: ClusterNode | null) => void
}> = ({ node, onHover }) => {
  const [hovered, setHovered] = useState(false)

  const getColor = () => {
    if (node.mode === 'master') return '#8800ff' // 紫色
    if (node.mode === 'slave') return '#ff8800' // 橙色
    return '#888888' // 灰色
  }

  const getSize = () => {
    if (node.mode === 'master') return 0.4
    return 0.3
  }

  return (
    <group position={node.position}>
      <mesh
        onPointerOver={() => {
          setHovered(true)
          onHover?.(node)
        }}
        onPointerOut={() => {
          setHovered(false)
          onHover?.(null)
        }}
      >
        <sphereGeometry args={[getSize(), 32, 32]} />
        <meshStandardMaterial
          color={getColor()}
          emissive={getColor()}
          emissiveIntensity={hovered ? 0.8 : node.status === 'connected' ? 0.5 : 0.2}
        />
      </mesh>
      <Text
        position={[0, 0.6, 0]}
        fontSize={0.15}
        color="white"
        anchorX="center"
        anchorY="middle"
      >
        {node.name}
      </Text>
      {node.status === 'syncing' && (
        <mesh>
          <ringGeometry args={[getSize() + 0.1, getSize() + 0.2, 32]} />
          <meshBasicMaterial color={getColor()} transparent opacity={0.5} />
        </mesh>
      )}
    </group>
  )
}

// 连接线组件
const ConnectionLine3D: React.FC<{
  start: [number, number, number]
  end: [number, number, number]
  color?: string
  pulsing?: boolean
}> = ({ start, end, color = '#00ff00', pulsing = false }) => {
  const points = [new THREE.Vector3(...start), new THREE.Vector3(...end)]

  return (
    <Line
      points={points}
      color={color}
      lineWidth={pulsing ? 3 : 2}
      dashed={false}
    />
  )
}

const ClusterTopologyScene: React.FC<ClusterTopologyProps> = ({
  currentNode,
  masterNode,
  syncStatus,
}) => {
  const [hoveredNode, setHoveredNode] = useState<ClusterNode | null>(null)

  // 构建节点数据
  const nodes: ClusterNode[] = []

  // 当前节点
  if (currentNode.mode) {
    nodes.push({
      id: currentNode.node_id || 'current',
      name: currentNode.node_name || '当前节点',
      mode: currentNode.mode as 'master' | 'slave' | 'standalone',
      position: [0, 0, 0],
      status: 'connected',
    })
  }

  // Master 节点（如果是 slave 模式）
  if (currentNode.mode === 'slave' && masterNode?.host) {
    nodes.push({
      id: 'master',
      name: `Master: ${masterNode.host}`,
      mode: 'master',
      position: [0, 2, 0],
      status: masterNode.reachable ? 'connected' : 'disconnected',
    })
  }

  // 连接关系
  const connections: Array<{ from: string; to: string; pulsing?: boolean }> = []
  if (currentNode.mode === 'slave' && masterNode?.host) {
    connections.push({
      from: currentNode.node_id || 'current',
      to: 'master',
      pulsing: syncStatus?.config_enabled || syncStatus?.cert_enabled,
    })
  }

  const getNodeById = (id: string) => nodes.find((n) => n.id === id)

  return (
    <>
      <ambientLight intensity={0.6} />
      <directionalLight position={[5, 5, 5]} intensity={0.8} />

      {/* 渲染节点 */}
      {nodes.map((node) => (
        <ClusterNode3D key={node.id} node={node} onHover={setHoveredNode} />
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
            color={toNode.status === 'connected' ? '#00ff00' : '#ff0000'}
            pulsing={conn.pulsing}
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

export const ClusterTopology: React.FC<ClusterTopologyProps> = ({
  currentNode,
  masterNode,
  syncStatus,
  width = 800,
  height = 500,
}) => {
  return (
    <Box width={width} height={height} borderRadius="lg" overflow="hidden" bg="black">
      <Canvas
        camera={{ position: [0, 0, 5], fov: 50 }}
        gl={{ antialias: true, alpha: false }}
      >
        <ClusterTopologyScene
          currentNode={currentNode}
          masterNode={masterNode}
          syncStatus={syncStatus}
        />
      </Canvas>
    </Box>
  )
}

/**
 * WebGL/Three.js 工具函数
 * 提供 Three.js 场景创建、性能优化、内存管理等通用功能
 */

import * as THREE from 'three'

/**
 * 创建基础 Three.js 场景（带相机、渲染器、灯光）
 */
export function createBasicScene(
  container: HTMLElement,
  options?: {
    backgroundColor?: number | string
    antialias?: boolean
    alpha?: boolean
    cameraPosition?: [number, number, number]
    enableOrbitControls?: boolean
  }
) {
  const {
    backgroundColor = 0x0a0a0a,
    antialias = true,
    alpha = false,
    cameraPosition = [0, 0, 5],
    enableOrbitControls = false,
  } = options || {}

  // 场景
  const scene = new THREE.Scene()
  if (typeof backgroundColor === 'string') {
    scene.background = new THREE.Color(backgroundColor)
  } else {
    scene.background = new THREE.Color(backgroundColor)
  }

  // 相机
  const camera = new THREE.PerspectiveCamera(
    75,
    container.clientWidth / container.clientHeight,
    0.1,
    1000
  )
  camera.position.set(...cameraPosition)

  // 渲染器
  const renderer = new THREE.WebGLRenderer({
    antialias,
    alpha,
    powerPreference: 'high-performance', // 优先使用独立显卡
  })
  renderer.setSize(container.clientWidth, container.clientHeight)
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2)) // 限制像素比，避免性能问题
  container.appendChild(renderer.domElement)

  // 基础灯光
  const ambientLight = new THREE.AmbientLight(0xffffff, 0.6)
  scene.add(ambientLight)

  const directionalLight = new THREE.DirectionalLight(0xffffff, 0.8)
  directionalLight.position.set(5, 5, 5)
  scene.add(directionalLight)

  // 轨道控制器（如果需要）
  // 注意：OrbitControls 应该在使用 @react-three/fiber 时通过 @react-three/drei 的 OrbitControls 组件使用
  // 这里保留接口但不实际实现，避免类型错误
  let controls: any = null
  if (enableOrbitControls) {
    // OrbitControls 应该在使用 React Three Fiber 时通过组件方式使用
    // 这里仅作为占位，实际使用时请使用 @react-three/drei 的 OrbitControls 组件
  }

  // 响应式调整
  const handleResize = () => {
    camera.aspect = container.clientWidth / container.clientHeight
    camera.updateProjectionMatrix()
    renderer.setSize(container.clientWidth, container.clientHeight)
  }
  window.addEventListener('resize', handleResize)

  return {
    scene,
    camera,
    renderer,
    controls,
    cleanup: () => {
      window.removeEventListener('resize', handleResize)
      renderer.dispose()
      if (controls) {
        controls.dispose()
      }
      // 清理场景中的对象
      scene.traverse((object) => {
        if (object instanceof THREE.Mesh) {
          object.geometry.dispose()
          if (Array.isArray(object.material)) {
            object.material.forEach((mat) => mat.dispose())
          } else {
            object.material.dispose()
          }
        }
      })
    },
  }
}

/**
 * 创建粒子系统几何体
 */
export function createParticleGeometry(count: number, spread: number = 10) {
  const geometry = new THREE.BufferGeometry()
  const positions = new Float32Array(count * 3)
  const colors = new Float32Array(count * 3)
  const sizes = new Float32Array(count)

  for (let i = 0; i < count; i++) {
    const i3 = i * 3
    // 位置
    positions[i3] = (Math.random() - 0.5) * spread
    positions[i3 + 1] = (Math.random() - 0.5) * spread
    positions[i3 + 2] = (Math.random() - 0.5) * spread

    // 颜色（随机）
    colors[i3] = Math.random()
    colors[i3 + 1] = Math.random()
    colors[i3 + 2] = Math.random()

    // 大小
    sizes[i] = Math.random() * 0.5 + 0.1
  }

  geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3))
  geometry.setAttribute('color', new THREE.BufferAttribute(colors, 3))
  geometry.setAttribute('size', new THREE.BufferAttribute(sizes, 1))

  return geometry
}

/**
 * 创建连接线（用于节点之间的连线）
 */
export function createConnectionLine(
  start: THREE.Vector3,
  end: THREE.Vector3,
  color: number = 0x00ff00
) {
  const geometry = new THREE.BufferGeometry().setFromPoints([start, end])
  const material = new THREE.LineBasicMaterial({ color })
  return new THREE.Line(geometry, material)
}

/**
 * 创建脉冲动画材质（用于节点高亮）
 */
export function createPulseMaterial(baseColor: number = 0x00ff00) {
  const material = new THREE.MeshStandardMaterial({
    color: baseColor,
    emissive: baseColor,
    emissiveIntensity: 0.5,
  })

  let pulsePhase = 0
  const pulseSpeed = 0.02

  const animate = () => {
    pulsePhase += pulseSpeed
    const intensity = 0.5 + Math.sin(pulsePhase) * 0.3
    material.emissiveIntensity = intensity
  }

  return { material, animate }
}

/**
 * 创建节点（球体，用于拓扑图）
 */
export function createNode(
  position: [number, number, number],
  options?: {
    color?: number
    size?: number
    label?: string
    pulse?: boolean
  }
) {
  const {
    color = 0x00ff00,
    size = 0.5,
    label,
    pulse = false,
  } = options || {}

  const geometry = new THREE.SphereGeometry(size, 32, 32)
  const material = pulse
    ? createPulseMaterial(color).material
    : new THREE.MeshStandardMaterial({ color })

  const mesh = new THREE.Mesh(geometry, material)
  mesh.position.set(...position)

  // 添加标签（如果需要）
  if (label) {
    // 可以使用 CSS2DRenderer 或 Sprite 添加文本标签
    // 这里简化处理，实际使用时可以扩展
  }

  return mesh
}

/**
 * 性能监控：限制帧率
 */
export function createFrameRateLimiter(targetFPS: number = 60) {
  let lastTime = 0
  const frameInterval = 1000 / targetFPS

  return (callback: () => void) => {
    const now = performance.now()
    const elapsed = now - lastTime

    if (elapsed >= frameInterval) {
      lastTime = now - (elapsed % frameInterval)
      callback()
    }
  }
}

/**
 * 性能监控：检测帧率
 */
export function createFrameRateMonitor(callback: (fps: number) => void) {
  let lastTime = performance.now()
  let frameCount = 0
  let fps = 0

  const measure = () => {
    frameCount++
    const now = performance.now()
    const elapsed = now - lastTime

    if (elapsed >= 1000) {
      fps = Math.round((frameCount * 1000) / elapsed)
      callback(fps)
      frameCount = 0
      lastTime = now
    }

    requestAnimationFrame(measure)
  }

  measure()
}

/**
 * 批量创建节点（用于大型拓扑图）
 */
export function createNodeCluster(
  count: number,
  spread: number = 10,
  options?: {
    baseColor?: number
    sizeRange?: [number, number]
  }
) {
  const {
    baseColor = 0x00ff00,
    sizeRange = [0.3, 0.8],
  } = options || {}

  const nodes: THREE.Mesh[] = []
  const geometry = new THREE.SphereGeometry(1, 16, 16)

  for (let i = 0; i < count; i++) {
    const size = sizeRange[0] + Math.random() * (sizeRange[1] - sizeRange[0])
    const material = new THREE.MeshStandardMaterial({
      color: baseColor,
      opacity: 0.8,
      transparent: true,
    })

    const node = new THREE.Mesh(geometry.clone(), material)
    node.scale.setScalar(size)
    node.position.set(
      (Math.random() - 0.5) * spread,
      (Math.random() - 0.5) * spread,
      (Math.random() - 0.5) * spread
    )

    nodes.push(node)
  }

  return nodes
}

/**
 * 清理 Three.js 资源（防止内存泄漏）
 */
export function disposeThreeObject(object: THREE.Object3D) {
  object.traverse((child) => {
    if (child instanceof THREE.Mesh) {
      child.geometry.dispose()
      if (Array.isArray(child.material)) {
        child.material.forEach((mat) => mat.dispose())
      } else {
        child.material.dispose()
      }
    }
  })
}

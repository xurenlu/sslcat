/**
 * Canvas 2D 工具函数库
 * 提供粒子系统、波形图、瀑布图等常用可视化功能
 */

import * as TWEEN from '@tweenjs/tween.js'

export interface Particle {
  x: number
  y: number
  vx: number
  vy: number
  size: number
  color: string
  alpha: number
  life: number
  maxLife: number
}

export interface WaveformPoint {
  x: number
  y: number
  value: number
}

/**
 * 粒子系统类
 */
export class ParticleSystem {
  private particles: Particle[] = []
  private canvas: HTMLCanvasElement
  private ctx: CanvasRenderingContext2D
  private animationId: number | null = null
  private isRunning = false

  constructor(canvas: HTMLCanvasElement) {
    this.canvas = canvas
    const ctx = canvas.getContext('2d')
    if (!ctx) {
      throw new Error('Canvas 2D context not available')
    }
    this.ctx = ctx
  }

  /**
   * 添加粒子
   */
  addParticle(particle: Partial<Particle> & { x: number; y: number }) {
    this.particles.push({
      x: particle.x,
      y: particle.y,
      vx: particle.vx || (Math.random() - 0.5) * 2,
      vy: particle.vy || (Math.random() - 0.5) * 2,
      size: particle.size || Math.random() * 3 + 1,
      color: particle.color || '#00ff00',
      alpha: particle.alpha ?? 1,
      life: particle.life ?? particle.maxLife ?? 100,
      maxLife: particle.maxLife ?? 100,
    })
  }

  /**
   * 批量添加粒子
   */
  addParticles(count: number, options?: {
    x?: number
    y?: number
    spread?: number
    color?: string
    sizeRange?: [number, number]
  }) {
    const {
      x = this.canvas.width / 2,
      y = this.canvas.height / 2,
      spread = 50,
      color = '#00ff00',
      sizeRange = [1, 4],
    } = options || {}

    for (let i = 0; i < count; i++) {
      this.addParticle({
        x: x + (Math.random() - 0.5) * spread,
        y: y + (Math.random() - 0.5) * spread,
        color,
        size: sizeRange[0] + Math.random() * (sizeRange[1] - sizeRange[0]),
      })
    }
  }

  /**
   * 更新粒子状态
   */
  update() {
    this.particles = this.particles.filter((p) => {
      p.x += p.vx
      p.y += p.vy
      p.life--
      p.alpha = p.life / p.maxLife

      // 边界反弹
      if (p.x < 0 || p.x > this.canvas.width) p.vx *= -1
      if (p.y < 0 || p.y > this.canvas.height) p.vy *= -1

      return p.life > 0
    })

    // 更新 Tween 动画
    TWEEN.update()
  }

  /**
   * 绘制粒子
   */
  draw() {
    this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height)

    this.particles.forEach((p) => {
      this.ctx.save()
      this.ctx.globalAlpha = p.alpha
      this.ctx.fillStyle = p.color
      this.ctx.beginPath()
      this.ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2)
      this.ctx.fill()
      this.ctx.restore()
    })
  }

  /**
   * 启动动画循环（带性能优化）
   */
  start() {
    if (this.isRunning) return

    this.isRunning = true
    let lastTime = performance.now()
    const targetFPS = 60
    const frameInterval = 1000 / targetFPS

    const animate = (currentTime: number) => {
      if (!this.isRunning) return

      const elapsed = currentTime - lastTime

      if (elapsed >= frameInterval) {
        // 限制粒子数量（性能优化：超过 1000 个时自动清理）
        if (this.particles.length > 1000) {
          this.particles = this.particles.slice(-1000)
        }

        this.update()
        this.draw()
        lastTime = currentTime - (elapsed % frameInterval)
      }

      this.animationId = requestAnimationFrame(animate)
    }
    animate(performance.now())
  }

  /**
   * 停止动画
   */
  stop() {
    this.isRunning = false
    if (this.animationId !== null) {
      cancelAnimationFrame(this.animationId)
      this.animationId = null
    }
  }

  /**
   * 清理所有粒子
   */
  clear() {
    this.particles = []
  }

  /**
   * 获取粒子数量
   */
  getParticleCount(): number {
    return this.particles.length
  }
}

/**
 * 波形图绘制器
 */
export class WaveformRenderer {
  private canvas: HTMLCanvasElement
  private ctx: CanvasRenderingContext2D
  private data: number[] = []
  private maxDataPoints: number
  private lineColor: string
  private fillColor: string
  private lineWidth: number

  constructor(
    canvas: HTMLCanvasElement,
    options?: {
      maxDataPoints?: number
      lineColor?: string
      fillColor?: string
      lineWidth?: number
    }
  ) {
    this.canvas = canvas
    const ctx = canvas.getContext('2d')
    if (!ctx) {
      throw new Error('Canvas 2D context not available')
    }
    this.ctx = ctx

    const {
      maxDataPoints = 100,
      lineColor = '#00ff00',
      fillColor = 'rgba(0, 255, 0, 0.2)',
      lineWidth = 2,
    } = options || {}

    this.maxDataPoints = maxDataPoints
    this.lineColor = lineColor
    this.fillColor = fillColor
    this.lineWidth = lineWidth
  }

  /**
   * 添加数据点
   */
  addDataPoint(value: number) {
    this.data.push(value)
    if (this.data.length > this.maxDataPoints) {
      this.data.shift()
    }
  }

  /**
   * 设置数据
   */
  setData(data: number[]) {
    this.data = data.slice(-this.maxDataPoints)
  }

  /**
   * 绘制波形
   */
  draw() {
    const { width, height } = this.canvas
    const ctx = this.ctx

    ctx.clearRect(0, 0, width, height)

    if (this.data.length === 0) return

    const stepX = width / this.maxDataPoints
    const centerY = height / 2
    const maxValue = Math.max(...this.data.map(Math.abs), 1)

    ctx.beginPath()
    ctx.strokeStyle = this.lineColor
    ctx.lineWidth = this.lineWidth
    ctx.lineJoin = 'round'
    ctx.lineCap = 'round'

    // 绘制波形线
    this.data.forEach((value, index) => {
      const x = index * stepX
      const y = centerY - (value / maxValue) * (centerY * 0.8)

      if (index === 0) {
        ctx.moveTo(x, y)
      } else {
        ctx.lineTo(x, y)
      }
    })

    ctx.stroke()

    // 填充区域
    if (this.fillColor) {
      ctx.lineTo(width, centerY)
      ctx.lineTo(0, centerY)
      ctx.closePath()
      ctx.fillStyle = this.fillColor
      ctx.fill()
    }
  }
}

/**
 * 瀑布图绘制器（用于请求时间轴可视化）
 */
export class WaterfallRenderer {
  private canvas: HTMLCanvasElement
  private ctx: CanvasRenderingContext2D
  private bars: Array<{
    x: number
    y: number
    width: number
    height: number
    color: string
    label?: string
  }> = []
  private barHeight: number = 20
  private spacing: number = 2

  constructor(canvas: HTMLCanvasElement) {
    this.canvas = canvas
    const ctx = canvas.getContext('2d')
    if (!ctx) {
      throw new Error('Canvas 2D context not available')
    }
    this.ctx = ctx
  }

  /**
   * 添加请求条
   */
  addRequest(options: {
    startTime: number
    duration: number
    statusCode: number
    label?: string
    maxTime?: number
  }) {
    const {
      startTime,
      duration,
      statusCode,
      label,
      maxTime = 1000,
    } = options

    const { width, height } = this.canvas
    const x = (startTime / maxTime) * width
    const w = (duration / maxTime) * width
    const y = this.bars.length * (this.barHeight + this.spacing)

    // 根据状态码选择颜色
    let color = '#00ff00' // 2xx
    if (statusCode >= 500) color = '#ff0000' // 5xx
    else if (statusCode >= 400) color = '#ff8800' // 4xx
    else if (statusCode >= 300) color = '#0088ff' // 3xx

    this.bars.push({ x, y, width: w, height: this.barHeight, color, label })
  }

  /**
   * 设置请求数据
   */
  setRequests(requests: Array<{
    startTime: number
    duration: number
    statusCode: number
    label?: string
  }>, maxTime?: number) {
    this.bars = []
    const max = maxTime || Math.max(...requests.map((r) => r.startTime + r.duration), 1000)

    requests.forEach((req) => {
      this.addRequest({ ...req, maxTime: max })
    })
  }

  /**
   * 绘制瀑布图
   */
  draw() {
    const ctx = this.ctx
    const { width, height } = this.canvas

    ctx.clearRect(0, 0, width, height)

    // 绘制时间轴
    ctx.strokeStyle = '#666'
    ctx.lineWidth = 1
    ctx.beginPath()
    ctx.moveTo(0, 0)
    ctx.lineTo(width, 0)
    ctx.stroke()

    // 绘制请求条
    this.bars.forEach((bar) => {
      ctx.fillStyle = bar.color
      ctx.fillRect(bar.x, bar.y, bar.width, bar.height)

      // 绘制标签
      if (bar.label && bar.width > 50) {
        ctx.fillStyle = '#fff'
        ctx.font = '12px monospace'
        ctx.fillText(bar.label, bar.x + 4, bar.y + 14)
      }
    })
  }
}

/**
 * 雷达图绘制器（用于威胁分析）
 */
export class RadarRenderer {
  private canvas: HTMLCanvasElement
  private ctx: CanvasRenderingContext2D
  private centerX: number
  private centerY: number
  private radius: number
  private axes: string[] = []
  private values: number[] = []

  constructor(
    canvas: HTMLCanvasElement,
    axes: string[],
    options?: {
      radius?: number
    }
  ) {
    this.canvas = canvas
    const ctx = canvas.getContext('2d')
    if (!ctx) {
      throw new Error('Canvas 2D context not available')
    }
    this.ctx = ctx

    this.axes = axes
    this.centerX = canvas.width / 2
    this.centerY = canvas.height / 2
    this.radius = options?.radius || Math.min(canvas.width, canvas.height) * 0.4
  }

  /**
   * 设置数值（0-1之间）
   */
  setValues(values: number[]) {
    this.values = values.slice(0, this.axes.length)
  }

  /**
   * 绘制雷达图
   */
  draw() {
    const ctx = this.ctx
    const { width, height } = this.canvas

    ctx.clearRect(0, 0, width, height)

    const angleStep = (Math.PI * 2) / this.axes.length

    // 绘制网格线
    ctx.strokeStyle = '#333'
    ctx.lineWidth = 1
    for (let i = 1; i <= 5; i++) {
      const r = (this.radius * i) / 5
      ctx.beginPath()
      for (let j = 0; j < this.axes.length; j++) {
        const angle = j * angleStep - Math.PI / 2
        const x = this.centerX + Math.cos(angle) * r
        const y = this.centerY + Math.sin(angle) * r
        if (j === 0) {
          ctx.moveTo(x, y)
        } else {
          ctx.lineTo(x, y)
        }
      }
      ctx.closePath()
      ctx.stroke()
    }

    // 绘制轴线
    ctx.strokeStyle = '#666'
    ctx.lineWidth = 1
    for (let i = 0; i < this.axes.length; i++) {
      const angle = i * angleStep - Math.PI / 2
      const x = this.centerX + Math.cos(angle) * this.radius
      const y = this.centerY + Math.sin(angle) * this.radius
      ctx.beginPath()
      ctx.moveTo(this.centerX, this.centerY)
      ctx.lineTo(x, y)
      ctx.stroke()

      // 绘制标签
      ctx.fillStyle = '#fff'
      ctx.font = '12px sans-serif'
      ctx.textAlign = 'center'
      const labelX = this.centerX + Math.cos(angle) * (this.radius + 20)
      const labelY = this.centerY + Math.sin(angle) * (this.radius + 20)
      ctx.fillText(this.axes[i], labelX, labelY)
    }

    // 绘制数据区域
    if (this.values.length > 0) {
      ctx.fillStyle = 'rgba(0, 255, 0, 0.3)'
      ctx.strokeStyle = '#00ff00'
      ctx.lineWidth = 2
      ctx.beginPath()

      for (let i = 0; i < this.values.length; i++) {
        const angle = i * angleStep - Math.PI / 2
        const r = this.radius * this.values[i]
        const x = this.centerX + Math.cos(angle) * r
        const y = this.centerY + Math.sin(angle) * r

        if (i === 0) {
          ctx.moveTo(x, y)
        } else {
          ctx.lineTo(x, y)
        }
      }

      ctx.closePath()
      ctx.fill()
      ctx.stroke()
    }
  }
}

/**
 * 工具函数：创建渐变
 */
export function createGradient(
  ctx: CanvasRenderingContext2D,
  x0: number,
  y0: number,
  x1: number,
  y1: number,
  colors: Array<{ offset: number; color: string }>
): CanvasGradient {
  const gradient = ctx.createLinearGradient(x0, y0, x1, y1)
  colors.forEach(({ offset, color }) => {
    gradient.addColorStop(offset, color)
  })
  return gradient
}

/**
 * 工具函数：绘制圆角矩形
 */
export function drawRoundedRect(
  ctx: CanvasRenderingContext2D,
  x: number,
  y: number,
  width: number,
  height: number,
  radius: number
) {
  ctx.beginPath()
  ctx.moveTo(x + radius, y)
  ctx.lineTo(x + width - radius, y)
  ctx.quadraticCurveTo(x + width, y, x + width, y + radius)
  ctx.lineTo(x + width, y + height - radius)
  ctx.quadraticCurveTo(x + width, y + height, x + width - radius, y + height)
  ctx.lineTo(x + radius, y + height)
  ctx.quadraticCurveTo(x, y + height, x, y + height - radius)
  ctx.lineTo(x, y + radius)
  ctx.quadraticCurveTo(x, y, x + radius, y)
  ctx.closePath()
}

/**
 * 工具函数：限制帧率
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

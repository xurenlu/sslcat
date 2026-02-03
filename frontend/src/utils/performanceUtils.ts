/**
 * 性能优化工具函数
 * Web Workers、虚拟滚动、内存管理等
 */

/**
 * 创建 Web Worker 用于数据处理
 */
export function createDataProcessorWorker(script: string): Worker | null {
  if (typeof Worker === 'undefined') {
    return null
  }

  try {
    const blob = new Blob([script], { type: 'application/javascript' })
    const url = URL.createObjectURL(blob)
    const worker = new Worker(url)
    
    // 清理 URL
    worker.addEventListener('message', () => {
      // Worker 完成后清理
    })
    
    return worker
  } catch (e) {
    console.warn('Failed to create Web Worker:', e)
    return null
  }
}

/**
 * 大数据集处理 Worker 脚本模板
 */
export const DATA_PROCESSOR_WORKER_SCRIPT = `
self.onmessage = function(e) {
  const { type, data } = e.data
  
  switch (type) {
    case 'process':
      // 处理数据
      const processed = data.map((item, index) => {
        // 示例：数据转换
        return {
          ...item,
          processed: true,
          index
        }
      })
      
      self.postMessage({
        type: 'processed',
        data: processed
      })
      break
      
    case 'aggregate':
      // 聚合数据
      const aggregated = data.reduce((acc, item) => {
        const key = item.category || 'other'
        if (!acc[key]) {
          acc[key] = { count: 0, total: 0 }
        }
        acc[key].count++
        acc[key].total += item.value || 0
        return acc
      }, {})
      
      self.postMessage({
        type: 'aggregated',
        data: aggregated
      })
      break
      
    default:
      self.postMessage({
        type: 'error',
        error: 'Unknown message type'
      })
  }
}
`

/**
 * 虚拟滚动配置
 */
export interface VirtualScrollConfig {
  itemHeight: number
  containerHeight: number
  overscan?: number // 额外渲染的项目数（上下各）
}

/**
 * 计算虚拟滚动可见范围
 */
export function calculateVisibleRange(
  scrollTop: number,
  config: VirtualScrollConfig
): { start: number; end: number; offsetY: number } {
  const { itemHeight, containerHeight, overscan = 5 } = config

  const start = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan)
  const visibleCount = Math.ceil(containerHeight / itemHeight)
  const end = start + visibleCount + overscan * 2

  return {
    start,
    end,
    offsetY: start * itemHeight,
  }
}

/**
 * 节流函数（用于滚动事件）
 */
export function throttle<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout | null = null
  let previous = 0

  return function (this: any, ...args: Parameters<T>) {
    const now = Date.now()
    const remaining = wait - (now - previous)

    if (remaining <= 0 || remaining > wait) {
      if (timeout) {
        clearTimeout(timeout)
        timeout = null
      }
      previous = now
      func.apply(this, args)
    } else if (!timeout) {
      timeout = setTimeout(() => {
        previous = Date.now()
        timeout = null
        func.apply(this, args)
      }, remaining)
    }
  }
}

/**
 * 防抖函数（用于搜索输入）
 */
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  wait: number
): (...args: Parameters<T>) => void {
  let timeout: NodeJS.Timeout | null = null

  return function (this: any, ...args: Parameters<T>) {
    if (timeout) {
      clearTimeout(timeout)
    }
    timeout = setTimeout(() => {
      func.apply(this, args)
      timeout = null
    }, wait)
  }
}

/**
 * 内存监控（检测内存泄漏）
 */
export class MemoryMonitor {
  private measurements: Array<{ timestamp: number; usedJSHeapSize: number }> = []
  private maxMeasurements = 100

  /**
   * 记录当前内存使用
   */
  record(): number | null {
    if (typeof performance === 'undefined' || !(performance as any).memory) {
      return null
    }

    const memory = (performance as any).memory
    const used = memory.usedJSHeapSize

    this.measurements.push({
      timestamp: Date.now(),
      usedJSHeapSize: used,
    })

    if (this.measurements.length > this.maxMeasurements) {
      this.measurements.shift()
    }

    return used
  }

  /**
   * 获取内存使用趋势
   */
  getTrend(): 'increasing' | 'decreasing' | 'stable' | 'unknown' {
    if (this.measurements.length < 10) {
      return 'unknown'
    }

    const recent = this.measurements.slice(-10)
    const first = recent[0].usedJSHeapSize
    const last = recent[recent.length - 1].usedJSHeapSize
    const diff = last - first
    const percentChange = (diff / first) * 100

    if (percentChange > 10) return 'increasing'
    if (percentChange < -10) return 'decreasing'
    return 'stable'
  }

  /**
   * 清理旧数据
   */
  clear() {
    this.measurements = []
  }
}

/**
 * Three.js 场景内存清理工具
 */
export function cleanupThreeScene(scene: any) {
  if (!scene) return

  scene.traverse((object: any) => {
    if (object.geometry) {
      object.geometry.dispose()
    }
    if (object.material) {
      if (Array.isArray(object.material)) {
        object.material.forEach((mat: any) => mat.dispose())
      } else {
        object.material.dispose()
      }
    }
    if (object.texture) {
      object.texture.dispose()
    }
  })

  // 清空场景
  while (scene.children.length > 0) {
    scene.remove(scene.children[0])
  }
}

/**
 * Canvas 内存清理工具
 */
export function cleanupCanvas(canvas: HTMLCanvasElement) {
  const ctx = canvas.getContext('2d')
  if (ctx) {
    ctx.clearRect(0, 0, canvas.width, canvas.height)
    // 重置 Canvas 尺寸可以释放内存
    canvas.width = 0
    canvas.height = 0
  }
}

/**
 * 批量处理数据（分块处理，避免阻塞主线程）
 */
export async function processDataInChunks<T, R>(
  data: T[],
  processor: (chunk: T[]) => R[],
  chunkSize: number = 1000,
  delay: number = 0
): Promise<R[]> {
  const results: R[] = []

  for (let i = 0; i < data.length; i += chunkSize) {
    const chunk = data.slice(i, i + chunkSize)
    const chunkResults = processor(chunk)
    results.push(...chunkResults)

    // 让出主线程
    if (delay > 0 && i + chunkSize < data.length) {
      await new Promise((resolve) => setTimeout(resolve, delay))
    }
  }

  return results
}

/**
 * 请求空闲时间执行任务（使用 requestIdleCallback 或 setTimeout fallback）
 */
export function runWhenIdle(callback: () => void, timeout: number = 5000) {
  if (typeof window !== 'undefined' && 'requestIdleCallback' in window) {
    ;(window as any).requestIdleCallback(callback, { timeout })
  } else {
    setTimeout(callback, 0)
  }
}

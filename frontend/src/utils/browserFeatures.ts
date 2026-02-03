/**
 * 浏览器特性检测工具
 * 检测 WebGL、Canvas、Web Animations API 等现代浏览器特性
 * 用于决定使用哪种可视化方案（WebGL -> Canvas -> SVG -> HTML）
 */

export interface BrowserFeatures {
  webgl: boolean
  webgl2: boolean
  canvas: boolean
  canvas2d: boolean
  webAnimations: boolean
  intersectionObserver: boolean
  cssGrid: boolean
  cssCustomProperties: boolean
  requestIdleCallback: boolean
  webWorkers: boolean
  // 性能相关
  hardwareAcceleration: boolean
  // 浏览器信息
  userAgent: string
  browser: 'chrome' | 'firefox' | 'safari' | 'edge' | 'ie' | 'unknown'
  version: number
}

let cachedFeatures: BrowserFeatures | null = null

/**
 * 检测 WebGL 支持
 */
function detectWebGL(): { webgl: boolean; webgl2: boolean } {
  try {
    const canvas = document.createElement('canvas')
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl')
    const gl2 = canvas.getContext('webgl2')
    
    return {
      webgl: !!gl,
      webgl2: !!gl2,
    }
  } catch (e) {
    return { webgl: false, webgl2: false }
  }
}

/**
 * 检测 Canvas 支持
 */
function detectCanvas(): { canvas: boolean; canvas2d: boolean } {
  try {
    const canvas = document.createElement('canvas')
    const ctx = canvas.getContext('2d')
    
    return {
      canvas: !!canvas,
      canvas2d: !!ctx,
    }
  } catch (e) {
    return { canvas: false, canvas2d: false }
  }
}

/**
 * 检测 Web Animations API
 */
function detectWebAnimations(): boolean {
  return typeof document !== 'undefined' && 
    'animate' in document.createElement('div')
}

/**
 * 检测 Intersection Observer
 */
function detectIntersectionObserver(): boolean {
  return typeof window !== 'undefined' && 
    'IntersectionObserver' in window
}

/**
 * 检测 CSS Grid
 */
function detectCSSGrid(): boolean {
  if (typeof window === 'undefined' || !window.CSS) return false
  
  return CSS.supports('display', 'grid')
}

/**
 * 检测 CSS Custom Properties (CSS Variables)
 */
function detectCSSCustomProperties(): boolean {
  if (typeof window === 'undefined' || !window.CSS) return false
  
  return CSS.supports('color', 'var(--test)')
}

/**
 * 检测 requestIdleCallback
 */
function detectRequestIdleCallback(): boolean {
  return typeof window !== 'undefined' && 
    'requestIdleCallback' in window
}

/**
 * 检测 Web Workers
 */
function detectWebWorkers(): boolean {
  return typeof Worker !== 'undefined'
}

/**
 * 检测硬件加速（通过 WebGL 扩展）
 */
function detectHardwareAcceleration(): boolean {
  try {
    const canvas = document.createElement('canvas')
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl') as WebGLRenderingContext | null
    
    if (!gl) return false
    
    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info')
    if (debugInfo) {
      const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) as string
      // 如果渲染器包含 GPU 相关关键词，认为支持硬件加速
      return /gpu|nvidia|amd|intel|radeon|geforce/i.test(renderer)
    }
    
    return true // 有 WebGL 就假设支持硬件加速
  } catch (e) {
    return false
  }
}

/**
 * 解析浏览器信息
 */
function parseBrowserInfo(): { browser: BrowserFeatures['browser']; version: number } {
  if (typeof navigator === 'undefined') {
    return { browser: 'unknown', version: 0 }
  }
  
  const ua = navigator.userAgent.toLowerCase()
  
  // Chrome (包括 Edge Chromium)
  if (ua.includes('chrome') && !ua.includes('edg')) {
    const match = ua.match(/chrome\/(\d+)/)
    return { browser: 'chrome', version: match ? parseInt(match[1]) : 0 }
  }
  
  // Edge Chromium
  if (ua.includes('edg')) {
    const match = ua.match(/edg\/(\d+)/)
    return { browser: 'edge', version: match ? parseInt(match[1]) : 0 }
  }
  
  // Firefox
  if (ua.includes('firefox')) {
    const match = ua.match(/firefox\/(\d+)/)
    return { browser: 'firefox', version: match ? parseInt(match[1]) : 0 }
  }
  
  // Safari
  if (ua.includes('safari') && !ua.includes('chrome')) {
    const match = ua.match(/version\/(\d+)/)
    return { browser: 'safari', version: match ? parseInt(match[1]) : 0 }
  }
  
  // IE
  if (ua.includes('msie') || ua.includes('trident')) {
    const match = ua.match(/(?:msie |rv:)(\d+)/)
    return { browser: 'ie', version: match ? parseInt(match[1]) : 0 }
  }
  
  return { browser: 'unknown', version: 0 }
}

/**
 * 检测所有浏览器特性（单例模式，结果缓存）
 */
export function detectBrowserFeatures(): BrowserFeatures {
  if (cachedFeatures) {
    return cachedFeatures
  }
  
  const webgl = detectWebGL()
  const canvas = detectCanvas()
  const browserInfo = parseBrowserInfo()
  
  cachedFeatures = {
    webgl: webgl.webgl,
    webgl2: webgl.webgl2,
    canvas: canvas.canvas,
    canvas2d: canvas.canvas2d,
    webAnimations: detectWebAnimations(),
    intersectionObserver: detectIntersectionObserver(),
    cssGrid: detectCSSGrid(),
    cssCustomProperties: detectCSSCustomProperties(),
    requestIdleCallback: detectRequestIdleCallback(),
    webWorkers: detectWebWorkers(),
    hardwareAcceleration: detectHardwareAcceleration(),
    userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : '',
    browser: browserInfo.browser,
    version: browserInfo.version,
  }
  
  return cachedFeatures
}

/**
 * 检查是否支持指定的特性组合
 * @param required 必需的特性数组，如 ['webgl', 'canvas']
 * @returns 是否全部支持
 */
export function hasFeatures(required: Array<keyof BrowserFeatures>): boolean {
  const features = detectBrowserFeatures()
  
  return required.every(key => {
    const value = features[key]
    return typeof value === 'boolean' ? value : true
  })
}

/**
 * 获取推荐的渲染方案
 * @returns 'webgl' | 'canvas' | 'svg' | 'html'
 */
export function getRecommendedRenderer(): 'webgl' | 'canvas' | 'svg' | 'html' {
  const features = detectBrowserFeatures()
  
  if (features.webgl || features.webgl2) {
    return 'webgl'
  }
  
  if (features.canvas2d) {
    return 'canvas'
  }
  
  if (features.canvas) {
    return 'svg' // SVG 比 Canvas 兼容性更好
  }
  
  return 'html'
}

/**
 * 获取降级方案
 * @param preferred 首选方案
 * @returns 降级后的方案
 */
export function getFallbackRenderer(
  preferred: 'webgl' | 'canvas' | 'svg' | 'html'
): 'webgl' | 'canvas' | 'svg' | 'html' {
  const features = detectBrowserFeatures()
  
  switch (preferred) {
    case 'webgl':
      if (features.canvas2d) return 'canvas'
      if (features.canvas) return 'svg'
      return 'html'
      
    case 'canvas':
      if (features.canvas) return 'svg'
      return 'html'
      
    case 'svg':
      return 'html'
      
    default:
      return 'html'
  }
}

/**
 * 检查是否为老旧浏览器（需要特殊处理）
 */
export function isLegacyBrowser(): boolean {
  const features = detectBrowserFeatures()
  
  // IE11 或更早
  if (features.browser === 'ie') {
    return true
  }
  
  // Safari < 12
  if (features.browser === 'safari' && features.version < 12) {
    return true
  }
  
  // Firefox < 60
  if (features.browser === 'firefox' && features.version < 60) {
    return true
  }
  
  // Chrome < 70
  if (features.browser === 'chrome' && features.version < 70) {
    return true
  }
  
  return false
}

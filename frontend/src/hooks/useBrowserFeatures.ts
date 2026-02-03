import { useState, useEffect } from 'react'
import {
  detectBrowserFeatures,
  hasFeatures,
  getRecommendedRenderer,
  getFallbackRenderer,
  isLegacyBrowser,
  type BrowserFeatures,
} from '../utils/browserFeatures'

/**
 * React Hook 封装浏览器特性检测
 */
export function useBrowserFeatures() {
  const [features, setFeatures] = useState<BrowserFeatures | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // 延迟检测，避免阻塞初始渲染
    const timer = setTimeout(() => {
      const detected = detectBrowserFeatures()
      setFeatures(detected)
      setLoading(false)
    }, 0)

    return () => clearTimeout(timer)
  }, [])

  return {
    features,
    loading,
    hasFeatures: (required: Array<keyof BrowserFeatures>) =>
      features ? hasFeatures(required) : false,
    getRecommendedRenderer: () =>
      features ? getRecommendedRenderer() : 'html',
    getFallbackRenderer: (preferred: 'webgl' | 'canvas' | 'svg' | 'html') =>
      features ? getFallbackRenderer(preferred) : 'html',
    isLegacyBrowser: () => (features ? isLegacyBrowser() : true),
  }
}

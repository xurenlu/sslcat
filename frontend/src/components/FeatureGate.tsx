import React, { ReactNode } from 'react'
import { Box, Alert, AlertIcon, AlertTitle, AlertDescription, Button } from '@chakra-ui/react'
import { useBrowserFeatures } from '../hooks/useBrowserFeatures'
import { hasFeatures, getFallbackRenderer } from '../utils/browserFeatures'

export interface FeatureGateProps {
  /**
   * 必需的特性列表，如 ['webgl', 'canvas']
   */
  require: Array<'webgl' | 'webgl2' | 'canvas' | 'canvas2d' | 'webAnimations' | 'intersectionObserver'>
  
  /**
   * 当特性不支持时的降级组件
   */
  fallback: ReactNode
  
  /**
   * 现代组件（特性支持时渲染）
   */
  children: ReactNode
  
  /**
   * 是否显示降级提示
   */
  showFallbackNotice?: boolean
  
  /**
   * 自定义降级提示文案
   */
  fallbackMessage?: string
  
  /**
   * 允许手动切换到降级视图
   */
  allowManualFallback?: boolean
  
  /**
   * 手动降级回调
   */
  onManualFallback?: () => void
}

/**
 * FeatureGate 组件
 * 根据浏览器特性自动选择渲染现代组件或降级组件
 */
export const FeatureGate: React.FC<FeatureGateProps> = ({
  require,
  fallback,
  children,
  showFallbackNotice = true,
  fallbackMessage,
  allowManualFallback = false,
  onManualFallback,
}) => {
  const { features, loading } = useBrowserFeatures()
  const [forceFallback, setForceFallback] = React.useState(false)

  if (loading) {
    // 加载中显示降级组件，避免闪烁
    return <>{fallback}</>
  }

  const supported = features ? hasFeatures(require) : false
  const shouldUseFallback = forceFallback || !supported

  if (shouldUseFallback) {
    return (
      <Box>
        {showFallbackNotice && (
          <Alert status="info" mb={4} borderRadius="md">
            <AlertIcon />
            <Box flex={1}>
              <AlertTitle>使用简化视图</AlertTitle>
              <AlertDescription>
                {fallbackMessage ||
                  `您的浏览器不支持 ${require.join('、')} 特性，已自动切换到简化视图以确保兼容性。`}
              </AlertDescription>
            </Box>
            {allowManualFallback && !forceFallback && (
              <Button
                size="sm"
                variant="outline"
                onClick={() => {
                  setForceFallback(false)
                  onManualFallback?.()
                }}
              >
                尝试现代视图
              </Button>
            )}
          </Alert>
        )}
        {fallback}
      </Box>
    )
  }

  return (
    <Box>
      {allowManualFallback && (
        <Box mb={2} textAlign="right">
          <Button
            size="xs"
            variant="ghost"
            onClick={() => setForceFallback(true)}
          >
            切换到简化视图
          </Button>
        </Box>
      )}
      {children}
    </Box>
  )
}

/**
 * 简化的 FeatureGate，只检查单个特性
 */
export const SimpleFeatureGate: React.FC<{
  feature: 'webgl' | 'canvas' | 'svg'
  fallback: ReactNode
  children: ReactNode
}> = ({ feature, fallback, children }) => {
  const featureMap: Record<'webgl' | 'canvas' | 'svg', Array<'webgl' | 'webgl2' | 'canvas' | 'canvas2d' | 'webAnimations' | 'intersectionObserver'>> = {
    webgl: ['webgl'],
    canvas: ['canvas2d'],
    svg: ['canvas'], // SVG 不需要特殊检测，所有浏览器都支持
  }

  return (
    <FeatureGate require={featureMap[feature]} fallback={fallback} showFallbackNotice={false}>
      {children}
    </FeatureGate>
  )
}

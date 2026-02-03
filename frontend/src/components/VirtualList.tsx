import React, { useState, useEffect, useRef, useMemo } from 'react'
import { Box, VStack } from '@chakra-ui/react'
import { calculateVisibleRange, throttle } from '../utils/performanceUtils'

interface VirtualListProps<T> {
  items: T[]
  itemHeight: number
  containerHeight: number
  renderItem: (item: T, index: number) => React.ReactNode
  overscan?: number
  onScroll?: (scrollTop: number) => void
}

/**
 * 虚拟滚动列表组件
 * 只渲染可见区域的项目，提升大数据集性能
 */
export function VirtualList<T>({
  items,
  itemHeight,
  containerHeight,
  renderItem,
  overscan = 5,
  onScroll,
}: VirtualListProps<T>) {
  const [scrollTop, setScrollTop] = useState(0)
  const containerRef = useRef<HTMLDivElement>(null)

  const { start, end, offsetY } = useMemo(
    () =>
      calculateVisibleRange(scrollTop, {
        itemHeight,
        containerHeight,
        overscan,
      }),
    [scrollTop, itemHeight, containerHeight, overscan]
  )

  const visibleItems = useMemo(() => items.slice(start, end), [items, start, end])

  const totalHeight = items.length * itemHeight

  const handleScroll = throttle((e: React.UIEvent<HTMLDivElement>) => {
    const newScrollTop = e.currentTarget.scrollTop
    setScrollTop(newScrollTop)
    onScroll?.(newScrollTop)
  }, 16) // ~60fps

  return (
    <Box
      ref={containerRef}
      height={containerHeight}
      overflowY="auto"
      onScroll={handleScroll}
      style={{ position: 'relative' }}
    >
      {/* 占位元素，保持总高度 */}
      <Box height={totalHeight} position="relative">
        {/* 可见项目容器 */}
        <Box
          style={{
            position: 'absolute',
            top: offsetY,
            left: 0,
            right: 0,
          }}
        >
          <VStack spacing={0} align="stretch">
            {visibleItems.map((item, idx) => (
              <Box key={start + idx} height={itemHeight}>
                {renderItem(item, start + idx)}
              </Box>
            ))}
          </VStack>
        </Box>
      </Box>
    </Box>
  )
}

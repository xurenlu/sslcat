import { useCallback } from 'react'
import { useToast } from '@chakra-ui/react'
import { captureError } from '../utils/sentry'
import { TOAST_DURATION } from '../constants'

interface ErrorHandlerOptions {
  context?: string
  showToast?: boolean
  logToSentry?: boolean
  title?: string
  description?: string
}

/**
 * 统一的错误处理 Hook
 * 提供统一的错误消息格式、Toast 提示和 Sentry 错误上报
 */
export const useErrorHandler = () => {
  const toast = useToast()

  const handleError = useCallback(
    (error: unknown, options: ErrorHandlerOptions = {}) => {
      const {
        context = '操作',
        showToast = true,
        logToSentry = true,
      } = options

      // 提取错误消息
      const errorMessage =
        error instanceof Error
          ? error.message
          : typeof error === 'string'
          ? error
          : '未知错误'

      // 记录到 Sentry
      if (logToSentry && error instanceof Error) {
        captureError(error, { context })
      }

      // 显示 Toast 提示
      if (showToast) {
        toast({
          title: options.title || `${context}失败`,
          description: options.description || errorMessage,
          status: 'error',
          duration: TOAST_DURATION.MEDIUM,
          isClosable: true,
        })
      }

      // 返回错误对象以便调用方可以进一步处理
      return error instanceof Error ? error : new Error(errorMessage)
    },
    [toast]
  )

  return { handleError }
}


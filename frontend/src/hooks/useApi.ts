import { useState, useEffect, useCallback } from 'react'
import { useToast } from '@chakra-ui/react'
import { useTranslation } from './useLanguage'
import { TOAST_DURATION } from '../constants'

interface UseApiOptions {
  immediate?: boolean
  onSuccess?: (data: any) => void
  onError?: (error: any) => void
}

export function useApi<T = any>(
  apiFunction: () => Promise<T>,
  options: UseApiOptions = {}
) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const toast = useToast()
  const t = useTranslation()

  const { immediate = true, onSuccess, onError } = options

  const execute = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const result = await apiFunction()
      setData(result)
      onSuccess?.(result)
      return result
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err))
      setError(error)
      onError?.(error)
      toast({
        title: t.common.apiError || 'API Error',
        description: error.message,
        status: 'error',
        duration: TOAST_DURATION.MEDIUM,
        isClosable: true,
      })
      throw error
    } finally {
      setLoading(false)
    }
  }, [apiFunction, onSuccess, onError, toast, t])

  useEffect(() => {
    if (immediate) {
      execute()
    }
  }, [execute, immediate])

  return {
    data,
    loading,
    error,
    execute,
    refetch: execute,
  }
}

export function useMutation<T = any, P = any>(
  mutationFunction: (params: P) => Promise<T>,
  options: UseApiOptions = {}
) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  const toast = useToast()
  const t = useTranslation()

  const { onSuccess, onError } = options

  const mutate = useCallback(async (params: P) => {
    try {
      setLoading(true)
      setError(null)
      const result = await mutationFunction(params)
      setData(result)
      onSuccess?.(result)
      return result
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err))
      setError(error)
      onError?.(error)
      toast({
        title: t.common.operationFailed || 'Operation Failed',
        description: error.message,
        status: 'error',
        duration: TOAST_DURATION.MEDIUM,
        isClosable: true,
      })
      throw error
    } finally {
      setLoading(false)
    }
  }, [mutationFunction, onSuccess, onError, toast, t])

  return {
    data,
    loading,
    error,
    mutate,
  }
}

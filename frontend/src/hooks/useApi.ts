import { useState, useEffect, useCallback } from 'react'
import { useToast } from '@chakra-ui/react'

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
      const error = err as Error
      setError(error)
      onError?.(error)
      toast({
        title: 'API 错误',
        description: error.message,
        status: 'error',
        duration: 5000,
        isClosable: true,
      })
      throw error
    } finally {
      setLoading(false)
    }
  }, [apiFunction, onSuccess, onError, toast])

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
      const error = err as Error
      setError(error)
      onError?.(error)
      toast({
        title: '操作失败',
        description: error.message,
        status: 'error',
        duration: 5000,
        isClosable: true,
      })
      throw error
    } finally {
      setLoading(false)
    }
  }, [mutationFunction, onSuccess, onError, toast])

  return {
    data,
    loading,
    error,
    mutate,
  }
}

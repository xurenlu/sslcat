import React from 'react'
import { Center, Spinner, Text } from '@chakra-ui/react'
import { useAuth } from '../contexts/AuthContext'
import { useConfig } from '../contexts/ConfigContext'
import { useNavigate } from 'react-router-dom'
import { useEffect } from 'react'
import { useTranslation } from '../hooks/useLanguage'

interface AuthGuardProps {
  children: React.ReactNode
}

const AuthGuard: React.FC<AuthGuardProps> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth()
  const { adminPrefix } = useConfig()
  const navigate = useNavigate()
  const t = useTranslation()

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      navigate(`${adminPrefix}/login`)
    }
  }, [isAuthenticated, isLoading, navigate, adminPrefix])

  if (isLoading) {
    return (
      <Center h="100vh">
        <Spinner size="xl" />
      </Center>
    )
  }

  if (!isAuthenticated) {
    return (
      <Center h="100vh">
        <Text>{t.common.redirectingToLogin || 'Redirecting to login...'}</Text>
      </Center>
    )
  }

  return <>{children}</>
}

export default AuthGuard

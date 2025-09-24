import React from 'react'
import {
  Flex,
  Spinner,
  Text,
  Box,
  VStack,
} from '@chakra-ui/react'

interface LoadingOverlayProps {
  isLoading: boolean
  message?: string
  children: React.ReactNode
  overlay?: boolean
}

const LoadingOverlay: React.FC<LoadingOverlayProps> = ({
  isLoading,
  message = '加载中...',
  children,
  overlay = false,
}) => {
  if (!isLoading) {
    return <>{children}</>
  }

  if (overlay) {
    return (
      <Box position="relative">
        {children}
        <Flex
          position="absolute"
          top={0}
          left={0}
          right={0}
          bottom={0}
          bg="rgba(255, 255, 255, 0.8)"
          backdropFilter="blur(2px)"
          justify="center"
          align="center"
          zIndex={10}
        >
          <VStack spacing={3}>
            <Spinner size="lg" color="blue.500" thickness="3px" />
            <Text color="gray.600" fontSize="sm" fontWeight="medium">
              {message}
            </Text>
          </VStack>
        </Flex>
      </Box>
    )
  }

  return (
    <Flex justify="center" align="center" py={12}>
      <VStack spacing={4}>
        <Spinner size="xl" color="blue.500" thickness="4px" />
        <Text color="gray.600" fontSize="lg" fontWeight="medium">
          {message}
        </Text>
      </VStack>
    </Flex>
  )
}

export default LoadingOverlay

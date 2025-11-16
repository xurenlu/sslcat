import React from 'react'
import {
  Box,
  HStack,
  Text,
  Code,
  IconButton,
  Icon,
} from '@chakra-ui/react'
import { FiCopy } from 'react-icons/fi'
import { useToast } from '@chakra-ui/react'
import { useTranslation } from '../hooks/useLanguage'
import { TOAST_DURATION } from '../constants'

interface GitCommandToastProps {
  gitCommands: string
}

export const GitCommandToast: React.FC<GitCommandToastProps> = ({ gitCommands }) => {
  const toast = useToast()
  const t = useTranslation()

  const handleCopy = () => {
    navigator.clipboard.writeText(gitCommands)
    toast({
      title: t.gitServer.copyToClipboard,
      status: 'success',
      duration: TOAST_DURATION.SHORT,
      isClosable: true,
    })
  }

  return (
    <Box fontSize="sm">
      <Text mb={2}>{t.gitServer.executeInProjectDir}</Text>
      <HStack spacing={2} align="stretch">
        <Code display="block" p={2} fontSize="xs" flex={1} whiteSpace="pre">
          {gitCommands}
        </Code>
        <IconButton
          aria-label={t.gitServer.copyCommand}
          icon={<Icon as={FiCopy} />}
          size="sm"
          onClick={handleCopy}
        />
      </HStack>
    </Box>
  )
}


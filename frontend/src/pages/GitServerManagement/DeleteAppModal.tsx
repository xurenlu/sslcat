import React, { useState } from 'react'
import {
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  VStack,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Box,
  Text,
  Input,
  Button,
} from '@chakra-ui/react'
import { useTranslation } from '../../hooks/useLanguage'
import { GitApp } from './types'

interface DeleteAppModalProps {
  isOpen: boolean
  onClose: () => void
  onDelete: (appName: string) => Promise<void>
  app: GitApp | null
}

const DeleteAppModal: React.FC<DeleteAppModalProps> = ({
  isOpen,
  onClose,
  onDelete,
  app,
}) => {
  const t = useTranslation()
  const [confirmInput, setConfirmInput] = useState('')
  const [loading, setLoading] = useState(false)

  const handleDelete = async () => {
    if (!app) return

    // 验证输入的应用名称
    if (confirmInput !== app.name) {
      return
    }

    try {
      setLoading(true)
      await onDelete(app.name)
      setConfirmInput('')
      onClose()
    } catch (error) {
      // 错误由 onDelete 处理
    } finally {
      setLoading(false)
    }
  }

  const handleClose = () => {
    if (!loading) {
      setConfirmInput('')
      onClose()
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={handleClose} size="md">
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>{t.frontend.delete_app_confirm}</ModalHeader>
        <ModalCloseButton isDisabled={loading} />
        <ModalBody>
          <VStack spacing={4} align="stretch">
            <Alert status="error" variant="left-accent">
              <AlertIcon />
              <Box>
                <AlertTitle fontSize="sm">{t.common.warning}</AlertTitle>
                <AlertDescription fontSize="sm">
                  {t.frontend.delete_app_warning}
                </AlertDescription>
              </Box>
            </Alert>

            {app && (
              <>
                <Box>
                  <Text fontSize="sm" mb={2}>
                    {t.frontend.delete_app_instruction.replace('{appName}', app.name)}
                  </Text>
                  <Input
                    value={confirmInput}
                    onChange={(e) => setConfirmInput(e.target.value)}
                    placeholder={app.name}
                    isDisabled={loading}
                    autoFocus
                  />
                </Box>

                <Box bg="gray.50" p={3} borderRadius="md">
                  <Text fontSize="sm" fontWeight="medium" mb={1}>
                    {t.gitServer.appName}:
                  </Text>
                  <Text fontSize="sm">{t.gitServer.appName}: {app.name}</Text>
                  {app.domain && <Text fontSize="sm">{t.gitServer.domain}: {app.domain}</Text>}
                  {app.port && <Text fontSize="sm">{t.gitServer.port}: {app.port}</Text>}
                </Box>
              </>
            )}
          </VStack>
        </ModalBody>

        <ModalFooter>
          <Button
            variant="ghost"
            mr={3}
            onClick={handleClose}
            isDisabled={loading}
          >
            {t.common.cancel}
          </Button>
          <Button
            colorScheme="red"
            onClick={handleDelete}
            isLoading={loading}
            isDisabled={!app || confirmInput !== app.name}
          >
            {t.common.delete}
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  )
}

export default DeleteAppModal


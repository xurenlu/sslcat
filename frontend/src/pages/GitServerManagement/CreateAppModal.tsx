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
  FormControl,
  FormLabel,
  Input,
  Switch,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Box,
  Text,
  Code,
  Button,
} from '@chakra-ui/react'
import { useTranslation } from '../../hooks/useLanguage'
import { GitServerConfig } from './types'
import { TOAST_DURATION } from '../../constants'

interface CreateAppModalProps {
  isOpen: boolean
  onClose: () => void
  onCreate: (name: string, autoSSL: boolean) => Promise<void>
  config: GitServerConfig
}

const CreateAppModal: React.FC<CreateAppModalProps> = ({
  isOpen,
  onClose,
  onCreate,
  config,
}) => {
  const t = useTranslation()
  const [name, setName] = useState('')
  const [autoSSL, setAutoSSL] = useState(true)
  const [loading, setLoading] = useState(false)

  const handleSubmit = async () => {
    if (!name.trim()) {
      return
    }

    try {
      setLoading(true)
      await onCreate(name, autoSSL)
      setName('')
      setAutoSSL(true)
      onClose()
    } catch (error) {
      // 错误由 onCreate 处理
    } finally {
      setLoading(false)
    }
  }

  const handleClose = () => {
    if (!loading) {
      setName('')
      setAutoSSL(true)
      onClose()
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={handleClose} size="lg">
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>{t.gitServer.createAppTitle}</ModalHeader>
        <ModalCloseButton isDisabled={loading} />
        <ModalBody>
          <VStack spacing={4} align="stretch">
            <Alert status="info" variant="left-accent">
              <AlertIcon />
              <Box>
                <AlertTitle fontSize="sm">{t.common.info}</AlertTitle>
                <AlertDescription fontSize="sm">
                  {t.gitServer.createAppDescription}
                </AlertDescription>
              </Box>
            </Alert>

            <FormControl isRequired>
              <FormLabel>{t.gitServer.appName}</FormLabel>
              <Input
                value={name}
                onChange={(e) =>
                  setName(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ''))
                }
                placeholder={t.gitServer.appNamePlaceholder}
                isDisabled={loading}
              />
              <Text fontSize="sm" color="gray.500" mt={1}>
                {t.gitServer.appNameHint}
              </Text>
            </FormControl>

            {name && config.domainSuffix && (
              <Alert status="success" variant="subtle">
                <AlertIcon />
                <Box fontSize="sm">
                  <Text fontWeight="medium">{t.gitServer.previewInfo}</Text>
                  <Text>
                    {t.gitServer.gitAddress}:{' '}
                    <Code fontSize="xs">
                      git@{window.location.hostname}:{name}.git
                    </Code>
                  </Text>
                  <Text>
                    {t.gitServer.accessDomain}:{' '}
                    <Code fontSize="xs">
                      {name}.{config.domainSuffix}
                    </Code>
                  </Text>
                  <Text>
                    {t.gitServer.autoAssignPort.replace('{start}', String(config.portRange[0])).replace('{end}', String(config.portRange[1]))}
                  </Text>
                </Box>
              </Alert>
            )}

            <FormControl display="flex" alignItems="center">
              <FormLabel mb="0">{t.gitServer.enableAutoSSL}</FormLabel>
              <Switch
                isChecked={autoSSL}
                onChange={(e) => setAutoSSL(e.target.checked)}
                isDisabled={loading}
              />
            </FormControl>
          </VStack>
        </ModalBody>

        <ModalFooter>
          <Button variant="ghost" mr={3} onClick={handleClose} isDisabled={loading}>
            {t.common.cancel}
          </Button>
          <Button
            colorScheme="blue"
            onClick={handleSubmit}
            isLoading={loading}
            isDisabled={!name.trim()}
          >
            {t.gitServer.createApp}
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  )
}

export default CreateAppModal


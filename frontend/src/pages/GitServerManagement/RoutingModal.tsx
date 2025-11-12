import React, { useState, useEffect } from 'react'
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
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  NumberIncrementStepper,
  NumberDecrementStepper,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Box,
  Button,
} from '@chakra-ui/react'
import { useTranslation } from '../../hooks/useLanguage'
import { GitApp, GitServerConfig } from './types'

interface RoutingModalProps {
  isOpen: boolean
  onClose: () => void
  onSave: (appName: string, domain: string, port: number) => Promise<void>
  app: GitApp | null
  config: GitServerConfig
}

const RoutingModal: React.FC<RoutingModalProps> = ({
  isOpen,
  onClose,
  onSave,
  app,
  config,
}) => {
  const t = useTranslation()
  const [domain, setDomain] = useState('')
  const [port, setPort] = useState<number>(0)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (isOpen && app) {
      setDomain(app.domain || '')
      setPort(app.port || 0)
    }
  }, [isOpen, app])

  const handleSave = async () => {
    if (!app) return

    try {
      setLoading(true)
      await onSave(app.name, domain.trim(), port)
      onClose()
    } catch (error) {
      // 错误由 onSave 处理
    } finally {
      setLoading(false)
    }
  }

  const handleClose = () => {
    if (!loading) {
      setDomain('')
      setPort(0)
      onClose()
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={handleClose} size="md">
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>{app ? `${t.gitServer.routingTitle}：${app.name}` : t.gitServer.routingTitle}</ModalHeader>
        <ModalCloseButton isDisabled={loading} />
        <ModalBody>
          <VStack spacing={4} align="stretch">
            <Alert status="info" variant="left-accent">
              <AlertIcon />
              <Box>
                <AlertTitle fontSize="sm">{t.common.info}</AlertTitle>
                <AlertDescription fontSize="sm">
                  {t.gitServer.routingDescription.replace('{suffix}', config.domainSuffix)}
                </AlertDescription>
              </Box>
            </Alert>

            <FormControl>
              <FormLabel>{t.gitServer.customDomain}</FormLabel>
              <Input
                placeholder={
                  config.domainSuffix ? t.gitServer.domainPlaceholder.replace('{suffix}', config.domainSuffix) : t.gitServer.domain
                }
                value={domain}
                onChange={(e) => setDomain(e.target.value.trim())}
                isDisabled={loading}
              />
            </FormControl>

            <FormControl isRequired>
              <FormLabel>{t.gitServer.portLabel}</FormLabel>
              <NumberInput
                min={1}
                max={65535}
                value={port || ''}
                onChange={(_, value) => setPort(value)}
                isDisabled={loading}
              >
                <NumberInputField placeholder={t.frontend.port_placeholder} />
                <NumberInputStepper>
                  <NumberIncrementStepper />
                  <NumberDecrementStepper />
                </NumberInputStepper>
              </NumberInput>
            </FormControl>
          </VStack>
        </ModalBody>
        <ModalFooter>
          <Button onClick={handleClose} mr={3} variant="ghost" isDisabled={loading}>
            {t.common.cancel}
          </Button>
          <Button colorScheme="purple" onClick={handleSave} isLoading={loading}>
            {t.common.save}
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  )
}

export default RoutingModal


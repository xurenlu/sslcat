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
  HStack,
  FormControl,
  FormLabel,
  Input,
  Button,
  IconButton,
  Icon,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Box,
} from '@chakra-ui/react'
import { FiPlus, FiTrash2 } from 'react-icons/fi'
import { useTranslation } from '../../hooks/useLanguage'
import { GitApp } from './types'

interface EnvVarModalProps {
  isOpen: boolean
  onClose: () => void
  onSave: (appName: string, envVars: Record<string, string>) => Promise<void>
  app: GitApp | null
}

const EnvVarModal: React.FC<EnvVarModalProps> = ({
  isOpen,
  onClose,
  onSave,
  app,
}) => {
  const t = useTranslation()
  const [envVars, setEnvVars] = useState<Array<{ id: string; key: string; value: string }>>([
    { id: Date.now().toString(), key: '', value: '' },
  ])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (isOpen && app) {
      const existingVars = app.envVars || {}
      const entries = Object.entries(existingVars).map(([key, value], index) => ({
        id: `${Date.now()}-${index}`,
        key,
        value: String(value ?? ''),
      }))
      setEnvVars(
        entries.length > 0 ? entries : [{ id: Date.now().toString(), key: '', value: '' }]
      )
    }
  }, [isOpen, app])

  const addEnvRow = () => {
    setEnvVars((prev) => [...prev, { id: Date.now().toString(), key: '', value: '' }])
  }

  const updateEnvRow = (index: number, field: 'key' | 'value', value: string) => {
    setEnvVars((prev) =>
      prev.map((item, i) => (i === index ? { ...item, [field]: value } : item))
    )
  }

  const removeEnvRow = (index: number) => {
    setEnvVars((prev) => {
      const next = prev.filter((_, i) => i !== index)
      return next.length > 0 ? next : [{ id: Date.now().toString(), key: '', value: '' }]
    })
  }

  const handleSave = async () => {
    if (!app) return

    const filteredVars = envVars
      .filter((item) => item.key.trim() !== '')
      .reduce<Record<string, string>>((acc, item) => {
        acc[item.key] = item.value
        return acc
      }, {})

    try {
      setLoading(true)
      await onSave(app.name, filteredVars)
      onClose()
    } catch (error) {
      // 错误由 onSave 处理
    } finally {
      setLoading(false)
    }
  }

  const handleClose = () => {
    if (!loading) {
      setEnvVars([{ id: Date.now().toString(), key: '', value: '' }])
      onClose()
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={handleClose} size="xl">
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>{app ? `${t.gitServer.envVarsTitle}：${app.name}` : t.gitServer.envVarsTitle}</ModalHeader>
        <ModalCloseButton isDisabled={loading} />
        <ModalBody>
          <VStack spacing={4} align="stretch">
            <Alert status="info" variant="left-accent">
              <AlertIcon />
              <Box>
                <AlertTitle fontSize="sm">{t.common.info}</AlertTitle>
                <AlertDescription fontSize="sm">
                  {t.gitServer.envVarsDescription}
                </AlertDescription>
              </Box>
            </Alert>
            <VStack spacing={3} align="stretch">
              {envVars.map((item, index) => (
                <HStack key={item.id} spacing={3} align="flex-start">
                  <FormControl>
                    <FormLabel fontSize="sm">{t.gitServer.varName}</FormLabel>
                    <Input
                      placeholder={t.frontend.env_var_name}
                      value={item.key}
                      onChange={(e) => updateEnvRow(index, 'key', e.target.value)}
                      isDisabled={loading}
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel fontSize="sm">{t.gitServer.varValue}</FormLabel>
                    <Input
                      placeholder={t.frontend.env_var_value}
                      value={item.value}
                      onChange={(e) => updateEnvRow(index, 'value', e.target.value)}
                      isDisabled={loading}
                    />
                  </FormControl>
                  <IconButton
                    aria-label={t.frontend.delete}
                    icon={<Icon as={FiTrash2} />}
                    variant="ghost"
                    colorScheme="red"
                    mt={6}
                    onClick={() => removeEnvRow(index)}
                    isDisabled={loading || envVars.length === 1}
                  />
                </HStack>
              ))}
            </VStack>
            <Button
              leftIcon={<Icon as={FiPlus} />}
              variant="ghost"
              colorScheme="blue"
              onClick={addEnvRow}
              alignSelf="flex-start"
              isDisabled={loading}
            >
              {t.gitServer.addVar}
            </Button>
          </VStack>
        </ModalBody>
        <ModalFooter>
          <Button onClick={handleClose} mr={3} variant="ghost" isDisabled={loading}>
            {t.common.cancel}
          </Button>
          <Button colorScheme="blue" onClick={handleSave} isLoading={loading}>
            {t.common.save}
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  )
}

export default EnvVarModal


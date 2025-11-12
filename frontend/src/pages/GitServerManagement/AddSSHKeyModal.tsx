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
  Textarea,
  Button,
  Text,
} from '@chakra-ui/react'
import { useTranslation } from '../../hooks/useLanguage'

interface AddSSHKeyModalProps {
  isOpen: boolean
  onClose: () => void
  onAdd: (name: string, publicKey: string) => Promise<void>
}

// 从 SSH 公钥中解析名称（通常是公钥末尾的注释部分）
const parseKeyName = (publicKey: string): string => {
  const trimmed = publicKey.trim()
  if (!trimmed) return ''

  // SSH 公钥格式: ssh-rsa AAAAB3NzaC... user@hostname
  const parts = trimmed.split(/\s+/)
  if (parts.length >= 3) {
    // 返回最后一部分作为名称（通常是 user@hostname）
    return parts[parts.length - 1]
  }
  return ''
}

const AddSSHKeyModal: React.FC<AddSSHKeyModalProps> = ({
  isOpen,
  onClose,
  onAdd,
}) => {
  const t = useTranslation()
  const [name, setName] = useState('')
  const [publicKey, setPublicKey] = useState('')
  const [loading, setLoading] = useState(false)

  const handlePublicKeyChange = (value: string) => {
    setPublicKey(value)
    // 只在名称为空时自动填充
    if (!name && value.trim()) {
      const parsedName = parseKeyName(value)
      if (parsedName) {
        setName(parsedName)
      }
    }
  }

  const handleSubmit = async () => {
    if (!name.trim() || !publicKey.trim()) {
      return
    }

    try {
      setLoading(true)
      await onAdd(name, publicKey)
      setName('')
      setPublicKey('')
      onClose()
    } catch (error) {
      // 错误由 onAdd 处理
    } finally {
      setLoading(false)
    }
  }

  const handleClose = () => {
    if (!loading) {
      setName('')
      setPublicKey('')
      onClose()
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={handleClose} size="lg">
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>{t.gitServer.addSSHKey}</ModalHeader>
        <ModalCloseButton isDisabled={loading} />
        <ModalBody>
          <VStack spacing={4}>
            <FormControl>
              <FormLabel>{t.gitServer.keyName}</FormLabel>
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="deploy-key-1"
                isDisabled={loading}
              />
            </FormControl>

            <FormControl>
              <FormLabel>{t.gitServer.publicKey}</FormLabel>
              <Textarea
                value={publicKey}
                onChange={(e) => handlePublicKeyChange(e.target.value)}
                placeholder={t.gitServer.publicKeyPlaceholder}
                rows={6}
                isDisabled={loading}
              />
              <Text fontSize="xs" color="gray.500" mt={1}>
                {t.gitServer.autoExtractName}
              </Text>
            </FormControl>
          </VStack>
        </ModalBody>

        <ModalFooter>
          <Button variant="ghost" mr={3} onClick={handleClose} isDisabled={loading}>
            {t.common.cancel}
          </Button>
          <Button
            colorScheme="green"
            onClick={handleSubmit}
            isLoading={loading}
            isDisabled={!name.trim() || !publicKey.trim()}
          >
            {t.gitServer.addKey}
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  )
}

export default AddSSHKeyModal


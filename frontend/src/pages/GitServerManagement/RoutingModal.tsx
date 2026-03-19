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
  Text,
  Checkbox,
  Link,
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
  const [domainChanged, setDomainChanged] = useState(false)
  const [confirmDomainChange, setConfirmDomainChange] = useState(false)

  useEffect(() => {
    if (isOpen && app) {
      setDomain(app.domain || '')
      setPort(app.port || 0)
      setDomainChanged(false)
      setConfirmDomainChange(false)
    }
  }, [isOpen, app])

  useEffect(() => {
    if (isOpen && app) {
      setDomainChanged(domain !== (app.domain || ''))
    }
  }, [domain, app])

  const handleSave = async () => {
    if (!app) return

    // 如果域名发生变化，需要确认
    if (domainChanged && !confirmDomainChange) {
      setConfirmDomainChange(true)
      return
    }

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
      setDomainChanged(false)
      setConfirmDomainChange(false)
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
            {domainChanged && !confirmDomainChange && (
              <Alert status="error" variant="left-accent">
                <AlertIcon />
                <Box>
                  <AlertTitle fontSize="sm">{t.common.warning || '警告'}</AlertTitle>
                  <AlertDescription fontSize="sm">
                    {t.gitServer.domainChangeWarning || '检测到域名变化！修改域名将：\n1. 备份当前应用数据\n2. 创建新域名的应用配置\n3. 复制 Git 仓库数据\n4. 更新代理规则并申请新证书\n\n旧应用数据将被保留作为备份。'}
                  </AlertDescription>
                </Box>
              </Alert>
            )}

            {confirmDomainChange && (
              <Alert status="warning" variant="left-accent">
                <AlertIcon />
                <Box>
                  <AlertTitle fontSize="sm">{t.common.confirm || '确认'}</AlertTitle>
                  <AlertDescription fontSize="sm">
                    {t.gitServer.domainChangeConfirm || `即将修改域名：\n从：${app?.domain || '空'}\n到：${domain}\n\n此操作不可撤销，确定继续吗？`}
                  </AlertDescription>
                </Box>
              </Alert>
            )}

            <FormControl>
              <FormLabel>{t.gitServer.customDomain}</FormLabel>
              <Input
                placeholder={
                  config.domainSuffix
                    ? `${app?.name || 'app'}.${config.domainSuffix}`
                    : t.gitServer.domain
                }
                value={domain}
                onChange={(e) => setDomain(e.target.value.trim())}
                isDisabled={loading}
              />
              {domainChanged && (
                <Text fontSize="xs" color="orange.500" mt={1} fontWeight="bold">
                  {t.gitServer.domainWillChange || '⚠️ 域名将发生变化'}
                </Text>
              )}
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
          <Button
            colorScheme={domainChanged && !confirmDomainChange ? "red" : "blue"}
            onClick={handleSave}
            isLoading={loading}
            isDisabled={!port || port <= 0 || !domain.trim()}
          >
            {domainChanged && !confirmDomainChange
              ? (t.common.confirm || '确认修改域名')
              : (t.common.save || '保存')}
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  )
}

export default RoutingModal

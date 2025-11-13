import React from 'react'
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
  Switch,
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  NumberIncrementStepper,
  NumberDecrementStepper,
  HStack,
  Text,
  Select,
  Button,
} from '@chakra-ui/react'
import { useTranslation } from '../../hooks/useLanguage'
import { GitServerConfig } from './types'

interface ConfigModalProps {
  isOpen: boolean
  onClose: () => void
  onSave: (config: GitServerConfig) => Promise<GitServerConfig>
  config: GitServerConfig
  loading?: boolean
}

const ConfigModal: React.FC<ConfigModalProps> = ({
  isOpen,
  onClose,
  onSave,
  config,
  loading = false,
}) => {
  const t = useTranslation()
  const [localConfig, setLocalConfig] = React.useState<GitServerConfig>(config)

  React.useEffect(() => {
    if (isOpen) {
      setLocalConfig(config)
    }
  }, [isOpen, config])

  const handleSave = async () => {
    await onSave(localConfig)
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} size="xl">
      <ModalOverlay />
      <ModalContent maxH="90vh" overflowY="auto">
        <ModalHeader>{t.gitServer.configTitle}</ModalHeader>
        <ModalCloseButton isDisabled={loading} />
        <ModalBody>
          <VStack spacing={4}>
            <FormControl display="flex" alignItems="center">
              <FormLabel mb="0">{t.gitServer.enableGitServer}</FormLabel>
              <Switch
                isChecked={localConfig.enabled}
                onChange={(e) =>
                  setLocalConfig({ ...localConfig, enabled: e.target.checked })
                }
                isDisabled={loading}
              />
            </FormControl>

            <FormControl>
              <FormLabel>{t.gitServer.sshPort}</FormLabel>
              <Input
                type="number"
                value={localConfig.port}
                onChange={(e) =>
                  setLocalConfig({ ...localConfig, port: parseInt(e.target.value) || 22 })
                }
                isDisabled={loading}
              />
            </FormControl>

            <FormControl>
              <FormLabel>{t.gitServer.webhookUrl}</FormLabel>
              <Input
                value={localConfig.webhook}
                onChange={(e) =>
                  setLocalConfig({ ...localConfig, webhook: e.target.value })
                }
                placeholder="https://your-domain.com/webhook"
                isDisabled={loading}
              />
              <Text fontSize="sm" color="gray.500" mt={1}>
                {t.gitServer.webhookDescription}
              </Text>
            </FormControl>

            <FormControl>
              <FormLabel>{t.gitServer.defaultBranch}</FormLabel>
              <Input
                value={localConfig.defaultBranch}
                onChange={(e) =>
                  setLocalConfig({ ...localConfig, defaultBranch: e.target.value })
                }
                placeholder="main"
                isDisabled={loading}
              />
              <Text fontSize="sm" color="gray.500" mt={1}>
                {t.gitServer.defaultBranchDescription}
              </Text>
            </FormControl>

            <FormControl display="flex" alignItems="center">
              <FormLabel mb="0">{t.gitServer.defaultAutoSSL}</FormLabel>
              <Switch
                isChecked={localConfig.autoSSL}
                onChange={(e) =>
                  setLocalConfig({ ...localConfig, autoSSL: e.target.checked })
                }
                isDisabled={loading}
              />
            </FormControl>

            <FormControl>
              <FormLabel>{t.gitServer.domainSuffix}</FormLabel>
              <Input
                value={localConfig.domainSuffix}
                onChange={(e) =>
                  setLocalConfig({ ...localConfig, domainSuffix: e.target.value })
                }
                placeholder="localhost"
                isDisabled={loading}
              />
              <Text fontSize="sm" color="gray.500" mt={1}>
                {t.gitServer.domainSuffixDescription.replace('{suffix}', localConfig.domainSuffix)}
              </Text>
            </FormControl>

            <FormControl>
              <FormLabel>{t.gitServer.portRange}</FormLabel>
              <HStack>
                <NumberInput
                  min={1000}
                  max={65535}
                  value={localConfig.portRange[0]}
                  onChange={(_, value) =>
                    setLocalConfig({
                      ...localConfig,
                      portRange: [value, localConfig.portRange[1]],
                    })
                  }
                  isDisabled={loading}
                >
                  <NumberInputField placeholder={t.frontend.start_port} />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
                <Text>-</Text>
                <NumberInput
                  min={1000}
                  max={65535}
                  value={localConfig.portRange[1]}
                  onChange={(_, value) =>
                    setLocalConfig({
                      ...localConfig,
                      portRange: [localConfig.portRange[0], value],
                    })
                  }
                  isDisabled={loading}
                >
                  <NumberInputField placeholder={t.frontend.end_port} />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
              </HStack>
              <Text fontSize="sm" color="gray.500" mt={1}>
                {t.gitServer.portRangeDescription}
              </Text>
            </FormControl>

            <FormControl>
              <FormLabel>{t.gitServer.welcomeMessage}</FormLabel>
              <Textarea
                value={localConfig.welcomeMessage}
                onChange={(e) =>
                  setLocalConfig({ ...localConfig, welcomeMessage: e.target.value })
                }
                placeholder={t.frontend.welcome_message}
                rows={3}
                isDisabled={loading}
              />
              <Text fontSize="sm" color="gray.500" mt={1}>
                {t.gitServer.welcomeMessageDescription}
              </Text>
            </FormControl>

            <FormControl>
              <FormLabel>{t.gitServer.defaultStrategy}</FormLabel>
              <Select
                value={localConfig.defaultStrategy}
                onChange={(e) =>
                  setLocalConfig({ ...localConfig, defaultStrategy: e.target.value })
                }
                isDisabled={loading}
              >
                <option value="auto">{t.common.auto || '自动检测'}</option>
                <option value="docker">Docker容器</option>
                <option value="static">静态文件</option>
                <option value="nodejs">Node.js应用</option>
                <option value="python">Python应用</option>
                <option value="go">Go应用</option>
                <option value="php">PHP应用</option>
              </Select>
              <Text fontSize="sm" color="gray.500" mt={1}>
                {t.git.deployment_strategy_desc}
              </Text>
            </FormControl>

            <FormControl>
              <FormLabel>{t.gitServer.buildTimeout}</FormLabel>
              <NumberInput
                min={60}
                max={3600}
                value={localConfig.buildTimeout}
                onChange={(_, value) =>
                  setLocalConfig({ ...localConfig, buildTimeout: value })
                }
                isDisabled={loading}
              >
                <NumberInputField placeholder="300" />
                <NumberInputStepper>
                  <NumberIncrementStepper />
                  <NumberDecrementStepper />
                </NumberInputStepper>
              </NumberInput>
              <Text fontSize="sm" color="gray.500" mt={1}>
                {t.gitServer.buildTimeoutDescription}
              </Text>
            </FormControl>

            <FormControl display="flex" alignItems="center">
              <FormLabel mb="0">{t.gitServer.autoDomain}</FormLabel>
              <Switch
                isChecked={localConfig.autoDomain}
                onChange={(e) =>
                  setLocalConfig({ ...localConfig, autoDomain: e.target.checked })
                }
                isDisabled={loading}
              />
            </FormControl>
          </VStack>
        </ModalBody>

        <ModalFooter>
          <Button variant="ghost" mr={3} onClick={onClose} isDisabled={loading}>
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

export default ConfigModal


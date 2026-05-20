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
  NumberInput,
  NumberInputField,
  Radio,
  RadioGroup,
  Switch,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Box,
  Text,
  Code,
  Button,
  SimpleGrid,
  Textarea,
} from '@chakra-ui/react'
import { useTranslation } from '../../hooks/useLanguage'
import { CreateAppRuntimeOptions, GitServerConfig, RunnerSourceType } from './types'

interface CreateAppModalProps {
  isOpen: boolean
  onClose: () => void
  onCreate: (name: string, autoSSL: boolean, options?: CreateAppRuntimeOptions) => Promise<void>
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
  const [sourceType, setSourceType] = useState<RunnerSourceType>('git')
  const [artifactFiles, setArtifactFiles] = useState<File[]>([])
  const [artifactPaths, setArtifactPaths] = useState<string[]>([])
  const [dockerImage, setDockerImage] = useState('')
  const [startCommand, setStartCommand] = useState('')
  const [workDir, setWorkDir] = useState('')
  const [internalPort, setInternalPort] = useState(8080)
  const [envText, setEnvText] = useState('')

  const parseEnvVars = () => {
    return envText
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean)
      .reduce<Record<string, string>>((acc, line) => {
        const separator = line.indexOf('=')
        if (separator > 0) {
          acc[line.slice(0, separator).trim()] = line.slice(separator + 1).trim()
        }
        return acc
      }, {})
  }

  const resetForm = () => {
    setName('')
    setAutoSSL(true)
    setSourceType('git')
    setArtifactFiles([])
    setArtifactPaths([])
    setDockerImage('')
    setStartCommand('')
    setWorkDir('')
    setInternalPort(8080)
    setEnvText('')
  }

  const buildCreateOptions = (): CreateAppRuntimeOptions | undefined => {
    const envVars = parseEnvVars()
    if (sourceType === 'git') {
      return { sourceType }
    }
    if (sourceType === 'docker_image') {
      return {
        sourceType,
        runtime: {
          source_type: sourceType,
          runtime_type: 'docker_image',
          internal_port: internalPort,
          env_vars: envVars,
          docker_image: {
            image: dockerImage.trim(),
            internal_port: internalPort,
            env_vars: envVars,
          },
        },
      }
    }
    return {
      sourceType,
      artifact: {
        files: artifactFiles,
        paths: artifactPaths,
        startCommand: startCommand.trim(),
        workDir: workDir.trim(),
        internalPort,
        envVars,
      },
    }
  }

  const handleSubmit = async () => {
    if (!name.trim()) {
      return
    }

    try {
      setLoading(true)
      await onCreate(name, autoSSL, buildCreateOptions())
      resetForm()
      onClose()
    } catch (error) {
      // 错误由 onCreate 处理
    } finally {
      setLoading(false)
    }
  }

  const handleClose = () => {
    if (!loading) {
      resetForm()
      onClose()
    }
  }

  const handleArtifactFiles = (files: FileList | null) => {
    const nextFiles = Array.from(files || [])
    setArtifactFiles(nextFiles)
    setArtifactPaths(nextFiles.map((file) => {
      const relativePath = (file as File & { webkitRelativePath?: string }).webkitRelativePath
      return relativePath || file.name
    }))
  }

  const isSubmitDisabled =
    !name.trim() ||
    (sourceType === 'docker_image' && !dockerImage.trim()) ||
    ((sourceType === 'directory' || sourceType === 'binary') && artifactFiles.length === 0)

  return (
    <Modal isOpen={isOpen} onClose={handleClose} size="2xl" scrollBehavior="inside">
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

            <FormControl>
              <FormLabel>{t.gitServer.runnerSource}</FormLabel>
              <RadioGroup value={sourceType} onChange={(value) => setSourceType(value as RunnerSourceType)}>
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={3}>
                  <Radio value="git">{t.gitServer.runnerSourceGit}</Radio>
                  <Radio value="directory">{t.gitServer.runnerSourceDirectory}</Radio>
                  <Radio value="binary">{t.gitServer.runnerSourceBinary}</Radio>
                  <Radio value="docker_image">{t.gitServer.runnerSourceDockerImage}</Radio>
                </SimpleGrid>
              </RadioGroup>
            </FormControl>

            {sourceType === 'directory' && (
              <FormControl isRequired>
                <FormLabel>{t.gitServer.uploadDirectory}</FormLabel>
                <Input
                  type="file"
                  multiple
                  isDisabled={loading}
                  onChange={(event) => handleArtifactFiles(event.target.files)}
                  {...{ webkitdirectory: '', directory: '' }}
                />
                <Text fontSize="sm" color="gray.500" mt={1}>
                  {t.gitServer.selectedFiles.replace('{count}', String(artifactFiles.length))}
                </Text>
              </FormControl>
            )}

            {sourceType === 'binary' && (
              <FormControl isRequired>
                <FormLabel>{t.gitServer.uploadBinary}</FormLabel>
                <Input
                  type="file"
                  isDisabled={loading}
                  onChange={(event) => handleArtifactFiles(event.target.files)}
                />
              </FormControl>
            )}

            {sourceType === 'docker_image' && (
              <FormControl isRequired>
                <FormLabel>{t.gitServer.dockerImageName}</FormLabel>
                <Input
                  value={dockerImage}
                  onChange={(event) => setDockerImage(event.target.value)}
                  placeholder={t.gitServer.dockerImagePlaceholder}
                  isDisabled={loading}
                />
              </FormControl>
            )}

            {sourceType !== 'git' && (
              <>
                {sourceType !== 'docker_image' && (
                  <FormControl>
                    <FormLabel>{t.gitServer.startCommand}</FormLabel>
                    <Input
                      value={startCommand}
                      onChange={(event) => setStartCommand(event.target.value)}
                      placeholder={t.gitServer.startCommandPlaceholder}
                      isDisabled={loading}
                    />
                  </FormControl>
                )}

                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={3}>
                  <FormControl>
                    <FormLabel>{t.gitServer.workDir}</FormLabel>
                    <Input
                      value={workDir}
                      onChange={(event) => setWorkDir(event.target.value)}
                      placeholder={t.gitServer.workDirPlaceholder}
                      isDisabled={loading}
                    />
                  </FormControl>
                  <FormControl>
                    <FormLabel>{t.gitServer.internalPort}</FormLabel>
                    <NumberInput
                      min={1}
                      max={65535}
                      value={internalPort}
                      onChange={(_, value) => setInternalPort(Number.isFinite(value) ? value : 8080)}
                      isDisabled={loading}
                    >
                      <NumberInputField />
                    </NumberInput>
                  </FormControl>
                </SimpleGrid>

                <FormControl>
                  <FormLabel>{t.gitServer.envVarsTitle}</FormLabel>
                  <Textarea
                    value={envText}
                    onChange={(event) => setEnvText(event.target.value)}
                    placeholder={t.gitServer.envVarsPlaceholder}
                    isDisabled={loading}
                    rows={4}
                  />
                </FormControl>
              </>
            )}

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
            isDisabled={isSubmitDisabled}
          >
            {t.gitServer.createApp}
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  )
}

export default CreateAppModal

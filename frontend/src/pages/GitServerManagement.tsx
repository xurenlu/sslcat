import React, { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Box,
  Heading,
  SimpleGrid,
  Card,
  CardBody,
  VStack,
  HStack,
  Button,
  Icon,
  Text,
  Flex,
  Badge,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  IconButton,
  useToast,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  FormControl,
  FormLabel,
  Input,
  Textarea,
  useDisclosure,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Code,
  Switch,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  NumberIncrementStepper,
  NumberDecrementStepper,
} from '@chakra-ui/react'
import {
  FiGitBranch,
  FiRefreshCw,
  FiPlus,
  FiEdit,
  FiTrash2,
  FiGithub,
  FiUpload,
  FiSettings,
  FiKey,
  FiFolder,
  FiCopy,
  FiTerminal,
  FiPackage,
  FiClock,
  FiSliders,
  FiGlobe,
} from 'react-icons/fi'
import { useConfig, buildPath, buildApiPath } from '../contexts/ConfigContext'
import RealtimeLogs from '../components/RealtimeLogs'
import DockerImageManager from '../components/DockerImageManager'
import DeployHistory from '../components/DeployHistory'
import PushHistory from '../components/PushHistory'
import SSHKeyBindings from '../components/SSHKeyBindings'

interface GitApp {
  id: string
  name: string
  git_url?: string
  status: 'active' | 'inactive' | 'deploying' | 'error'
  lastDeploy: string
  commits: number
  autoSSL: boolean
  domain?: string
  port?: number
  envVars?: Record<string, string>
  allowed_keys?: string[]
  push_history?: any[]
}

interface SSHKey {
  id: string
  name: string
  fingerprint: string
  type: string
  created: string
  lastUsed?: string
}

interface GitServerConfig {
  enabled: boolean
  port: number
  webhook: string
  defaultBranch: string
  autoSSL: boolean
  domainSuffix: string
  portRange: [number, number]
  welcomeMessage: string
  sslEmail: string
  defaultStrategy: string
  buildTimeout: number
  autoDomain: boolean
}

const GitServerManagement: React.FC = () => {
  const { t } = useTranslation()
  const { adminPrefix } = useConfig()
  const [apps, setApps] = useState<GitApp[]>([])
  const [sshKeys, setSSHKeys] = useState<SSHKey[]>([])
  const [config, setConfig] = useState<GitServerConfig>({
    enabled: true,
    port: 22,
    webhook: '',
    defaultBranch: 'main',
    autoSSL: true,
    domainSuffix: 'localhost',
    portRange: [8000, 9000],
    welcomeMessage: '欢迎使用 SSLcat Git 部署平台！',
    sslEmail: '',
    defaultStrategy: 'auto',
    buildTimeout: 300,
    autoDomain: true,
  })
  const [loading, setLoading] = useState(false)
  const { isOpen, onOpen, onClose } = useDisclosure()
  const {
    isOpen: isKeyOpen,
    onOpen: onKeyOpen,
    onClose: onKeyClose,
  } = useDisclosure()
  const {
    isOpen: isConfigOpen,
    onOpen: onConfigOpen,
    onClose: onConfigClose,
  } = useDisclosure()
  const toast = useToast()

  const [newApp, setNewApp] = useState({
    name: '',
    autoSSL: true,
  })

  const [newKey, setNewKey] = useState({
    name: '',
    publicKey: '',
  })
  
  const [selectedApp, setSelectedApp] = useState<string>('')
  const [isEnvModalOpen, setIsEnvModalOpen] = useState(false)
  const [envEditorApp, setEnvEditorApp] = useState<GitApp | null>(null)
  const [envVars, setEnvVars] = useState<Array<{ id: string; key: string; value: string }>>([
    { id: Date.now().toString(), key: '', value: '' },
  ])
  const [savingEnv, setSavingEnv] = useState(false)
  const [isRoutingModalOpen, setIsRoutingModalOpen] = useState(false)
  const [routingApp, setRoutingApp] = useState<GitApp | null>(null)
  const [routingDomain, setRoutingDomain] = useState('')
  const [routingPort, setRoutingPort] = useState<number>(0)
  const [savingRouting, setSavingRouting] = useState(false)
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false)
  const [deleteAppTarget, setDeleteAppTarget] = useState<GitApp | null>(null)
  const [deleteConfirmInput, setDeleteConfirmInput] = useState('')
  const [isDeleting, setIsDeleting] = useState(false)

  const openEnvModal = (app: GitApp) => {
    setEnvEditorApp(app)
    const existingVars = (app as any).envVars || {}
    const entries = Object.entries(existingVars).map(([key, value], index) => ({ 
      id: `${Date.now()}-${index}`, 
      key, 
      value: String(value ?? '') 
    }))
    setEnvVars(entries.length > 0 ? entries : [{ id: Date.now().toString(), key: '', value: '' }])
    setIsEnvModalOpen(true)
  }

  const closeEnvModal = () => {
    setIsEnvModalOpen(false)
    setEnvEditorApp(null)
    setEnvVars([{ id: Date.now().toString(), key: '', value: '' }])
    setSavingEnv(false)
  }

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

  const saveEnvVars = async () => {
    if (!envEditorApp) {
      return
    }

    const filteredVars = envVars
      .filter((item) => item.key.trim() !== '')
      .reduce<Record<string, string>>((acc, item) => {
        acc[item.key] = item.value
        return acc
      }, {})

    try {
      setSavingEnv(true)
      const response = await fetch(
        buildApiPath(adminPrefix, `/git-server/app/env?name=${encodeURIComponent(envEditorApp.name)}`),
        {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ env_vars: filteredVars }),
        }
      )

      if (!response.ok) {
        setSavingEnv(false)
        throw new Error('更新环境变量失败')
      }

      const responseData = await response.json().catch(() => ({}))
      
      toast({
        title: '环境变量已更新',
        description: responseData.message || '请重新部署应用以应用更改',
        status: 'success',
        duration: 5000,
        isClosable: true,
      })

      closeEnvModal()
      refreshData()
    } catch (error) {
      setSavingEnv(false)
      toast({
        title: '保存失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const openRoutingModal = (app: GitApp) => {
    setRoutingApp(app)
    setRoutingDomain(app.domain || '')
    setRoutingPort(app.port || 0)
    setIsRoutingModalOpen(true)
  }

  const closeRoutingModal = () => {
    setIsRoutingModalOpen(false)
    setRoutingApp(null)
    setSavingRouting(false)
  }

  const saveRouting = async () => {
    if (!routingApp) {
      return
    }

    try {
      setSavingRouting(true)
      const response = await fetch(
        buildApiPath(adminPrefix, `/git-server/app/routing?name=${encodeURIComponent(routingApp.name)}`),
        {
          method: 'PUT',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ domain: routingDomain, port: routingPort }),
        }
      )

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.error || '更新域名和端口失败')
      }

      toast({
        title: '域名与端口已更新',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })

      closeRoutingModal()
      refreshData()
    } catch (error) {
      setSavingRouting(false)
      toast({
        title: '保存失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const refreshData = async () => {
    setLoading(true)
    try {
      // 获取Git应用列表
      const appsResponse = await fetch(buildApiPath(adminPrefix, '/git-server/apps'))
      if (!appsResponse.ok) {
        throw new Error('获取Git应用列表失败')
      }
      const appsJson = await appsResponse.json()
      const apps = Array.isArray(appsJson?.data) ? appsJson.data : []
      setApps(apps)
      
      // 获取SSH密钥列表
      const keysResponse = await fetch(buildApiPath(adminPrefix, '/git-server/ssh-keys'))
      if (!keysResponse.ok) {
        throw new Error('获取SSH密钥失败')
      }
      const keysJson = await keysResponse.json()
      const sshKeys = Array.isArray(keysJson?.data) ? keysJson.data : []
      setSSHKeys(sshKeys)
      
      // 获取服务器配置
      const configResponse = await fetch(buildApiPath(adminPrefix, '/git-server/config'))
      if (!configResponse.ok) {
        throw new Error('获取服务器配置失败')
      }
      const configJson = await configResponse.json()
      if (configJson?.data) {
        // 转换后端返回的字段命名（下划线）为前端使用的驼峰命名
        const backendConfig = configJson.data
        setConfig({
          enabled: backendConfig.enabled,
          port: backendConfig.port,
          webhook: backendConfig.webhook,
          defaultBranch: backendConfig.defaultBranch || backendConfig.default_branch,
          autoSSL: backendConfig.autoSSL ?? backendConfig.auto_ssl,
          domainSuffix: backendConfig.domainSuffix || backendConfig.domain_suffix,
          portRange: backendConfig.portRange || backendConfig.port_range || [8000, 9000],
          welcomeMessage: backendConfig.welcomeMessage || backendConfig.welcome_message,
          sslEmail: backendConfig.sslEmail || backendConfig.ssl_email,
          defaultStrategy: backendConfig.defaultStrategy || backendConfig.default_strategy,
          buildTimeout: backendConfig.buildTimeout ?? backendConfig.build_timeout,
          autoDomain: backendConfig.autoDomain ?? backendConfig.auto_domain,
        })
      }
      
      setLoading(false)
    } catch (error) {
      console.error('获取Git服务器数据失败:', error)
      // 确保在错误情况下也设置空数组
      setApps([])
      setSSHKeys([])
      setLoading(false)
    }
  }

  const handleRestartSSHD = async () => {
    setLoading(true)
    try {
      const response = await fetch(`${adminPrefix}/api/git-server/restart-sshd`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
      })

      const data = await response.json()
      
      if (response.ok) {
        toast({
          title: 'SSH 服务重启成功',
          description: data.message || 'SSH 服务已成功重启',
          status: 'success',
          duration: 5000,
          isClosable: true,
        })
      } else {
        throw new Error(data.message || '重启失败')
      }
    } catch (error) {
      console.error('重启 SSH 服务失败:', error)
      toast({
        title: '重启 SSH 服务失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 5000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  const handleCreateApp = async () => {
    if (!newApp.name) {
      toast({
        title: '应用名称不能为空',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    try {
      const response = await fetch(buildApiPath(adminPrefix, '/git-server/apps'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: newApp.name,
          auto_ssl: newApp.autoSSL,
        }),
      })
      
      if (response.ok) {
        const result = await response.json()
        const appData = result.data
        
        toast({
          title: 'Git应用创建成功',
          description: `Git地址: git@${window.location.hostname}:${newApp.name}.git`,
          status: 'success',
          duration: 8000,
          isClosable: true,
        })
        
        onClose()
        await refreshData()
        resetAppForm()

        // 如果创建成功，显示Git推送指令提示
        setTimeout(() => {
          const gitCommands = `git remote add sslcat git@${window.location.hostname}:${newApp.name}.git
git push sslcat main`
          
          toast({
            title: '推送代码到应用',
            description: (
              <Box fontSize="sm">
                <Text mb={2}>在您的项目目录中执行：</Text>
                <HStack spacing={2} align="stretch">
                  <Code display="block" p={2} fontSize="xs" flex={1} whiteSpace="pre">
                    {gitCommands}
                  </Code>
                  <IconButton
                    aria-label={t('frontend.copy_command')}
                    icon={<Icon as={FiCopy} />}
                    size="sm"
                    onClick={() => {
                      navigator.clipboard.writeText(gitCommands)
                      toast({
                        title: '已复制到剪贴板',
                        status: 'success',
                        duration: 2000,
                        isClosable: true,
                      })
                    }}
                  />
                </HStack>
              </Box>
            ),
            status: 'info',
            duration: 15000,
            isClosable: true,
          })
        }, 1000)
      } else {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.error || '创建Git应用失败')
      }
    } catch (error) {
      toast({
        title: '创建失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const openDeleteModal = (app: GitApp) => {
    setDeleteAppTarget(app)
    setDeleteConfirmInput('')
    setIsDeleteModalOpen(true)
  }

  const closeDeleteModal = () => {
    setIsDeleteModalOpen(false)
    setDeleteAppTarget(null)
    setDeleteConfirmInput('')
    setIsDeleting(false)
  }

  const handleDeleteApp = async () => {
    if (!deleteAppTarget) return

    // 验证输入的应用名称
    if (deleteConfirmInput !== deleteAppTarget.name) {
      toast({
        title: t('frontend.delete_app_name_mismatch'),
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    try {
      setIsDeleting(true)
      const response = await fetch(
        buildApiPath(adminPrefix, `/git-server/app/delete?name=${encodeURIComponent(deleteAppTarget.name)}`),
        {
          method: 'DELETE',
        }
      )
      
      if (response.ok) {
        toast({
          title: 'Git应用删除成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        closeDeleteModal()
        refreshData()
      } else {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.error || '删除Git应用失败')
      }
    } catch (error) {
      toast({
        title: '删除失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setIsDeleting(false)
    }
  }

  const handleDeployApp = async (appName: string) => {
    try {
      const response = await fetch(
        buildApiPath(adminPrefix, `/git-server/app/redeploy?name=${encodeURIComponent(appName)}`),
        {
          method: 'POST',
        }
      )
      
      if (response.ok) {
        toast({
          title: '重新部署已启动',
          description: '应用正在重新部署中，请稍候...',
          status: 'info',
          duration: 5000,
          isClosable: true,
        })
        refreshData()
      } else {
        const errorData = await response.json().catch(() => ({}))
        throw new Error(errorData.error || '触发部署失败')
      }
    } catch (error) {
      toast({
        title: '部署失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const handleAddSSHKey = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/git-server/ssh-keys'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(newKey),
      })
      
      if (response.ok) {
        toast({
          title: 'SSH密钥添加成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        
        onKeyClose()
        refreshData()
        resetKeyForm()
      } else {
        throw new Error('添加SSH密钥失败')
      }
    } catch (error) {
      toast({
        title: '添加失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const handleDeleteSSHKey = async (id: string) => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, `/git-server/ssh-keys/${id}`), {
        method: 'DELETE',
      })
      
      if (response.ok) {
        toast({
          title: 'SSH密钥删除成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        refreshData()
      } else {
        throw new Error('删除SSH密钥失败')
      }
    } catch (error) {
      toast({
        title: '删除失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const handleUpdateConfig = async () => {
    try {
      // 转换前端的驼峰命名为后端需要的下划线命名
      const backendConfig = {
        enabled: config.enabled,
        port: config.port,
        webhook: config.webhook,
        default_branch: config.defaultBranch,
        auto_ssl: config.autoSSL,
        domain_suffix: config.domainSuffix,
        port_range: config.portRange,
        welcome_message: config.welcomeMessage,
        ssl_email: config.sslEmail,
        default_strategy: config.defaultStrategy,
        build_timeout: config.buildTimeout,
        auto_domain: config.autoDomain,
      }
      
      const response = await fetch(buildApiPath(adminPrefix, '/git-server/config'), {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(backendConfig),
      })
      
      if (response.ok) {
        toast({
          title: 'Git服务器配置更新成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        onConfigClose()
        await refreshData()
        
        // 如果启用了Git服务器但没有SSH密钥，提示用户添加
        if (config.enabled && sshKeys.length === 0) {
          setTimeout(() => {
            toast({
              title: '提示：添加SSH密钥',
              description: t('frontend.ssh_key_notice'),
              status: 'warning',
              duration: 8000,
              isClosable: true,
            })
          }, 500)
        }
      } else {
        throw new Error('更新配置失败')
      }
    } catch (error) {
      toast({
        title: '更新失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const resetAppForm = () => {
    setNewApp({
      name: '',
      autoSSL: true,
    })
  }

  const resetKeyForm = () => {
    setNewKey({
      name: '',
      publicKey: '',
    })
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'green'
      case 'deploying': return 'blue'
      case 'inactive': return 'gray'
      case 'error': return 'red'
      default: return 'gray'
    }
  }

  const getStatusText = (status: string) => {
    switch (status) {
      case 'active': return '运行中'
      case 'deploying': return '部署中'
      case 'inactive': return '未激活'
      case 'error': return '错误'
      default: return status
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast({
      title: '已复制到剪贴板',
      status: 'success',
      duration: 2000,
      isClosable: true,
    })
  }

  useEffect(() => {
    refreshData()
  }, [])

  // 获取需要重新部署的应用
  const pendingApps = apps.filter(app => (app as any).pending_restart === true)

  return (
    <>
      {/* 浮层提醒：有应用需要重新部署 */}
      {pendingApps.length > 0 && (
        <Box
          position="fixed"
          top="60px"
          right="20px"
          zIndex={9999}
          bg="orange.500"
          color="white"
          p={4}
          borderRadius="md"
          boxShadow="lg"
          maxW="400px"
        >
          <VStack align="stretch" spacing={2}>
            <HStack justify="space-between">
              <HStack>
                <Icon as={FiUpload} boxSize={5} />
                <Text fontWeight="bold">配置已更新</Text>
              </HStack>
              <IconButton
                aria-label="关闭"
                icon={<Icon as={FiRefreshCw} />}
                size="xs"
                variant="ghost"
                color="white"
                _hover={{ bg: 'orange.600' }}
                onClick={() => {
                  // 不做任何事，让用户自己点击重新部署按钮
                }}
              />
            </HStack>
            <Text fontSize="sm">
              以下应用的配置已更新，需要重新部署以应用更改：
            </Text>
            <VStack align="stretch" spacing={1} maxH="200px" overflowY="auto">
              {pendingApps.map(app => (
                <HStack key={app.name} justify="space-between" bg="orange.600" p={2} borderRadius="sm">
                  <Text fontSize="sm" fontWeight="medium">{app.name}</Text>
                  <Button
                    size="xs"
                    colorScheme="whiteAlpha"
                    leftIcon={<Icon as={FiUpload} />}
                    onClick={() => handleDeployApp(app.name)}
                  >
                    重新部署
                  </Button>
                </HStack>
              ))}
            </VStack>
          </VStack>
        </Box>
      )}

      <Modal isOpen={isEnvModalOpen} onClose={closeEnvModal} size="xl">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>{envEditorApp ? `环境变量：${envEditorApp.name}` : '环境变量'}</ModalHeader>
          <ModalCloseButton disabled={savingEnv} />
          <ModalBody>
            <VStack spacing={4} align="stretch">
              <Alert status="info" variant="left-accent">
                <AlertIcon />
                <Box>
                  <AlertTitle fontSize="sm">提示</AlertTitle>
                  <AlertDescription fontSize="sm">
                    环境变量将保存至Git部署配置中，在下一次部署时自动注入容器。未填写变量名的行会被忽略。
                  </AlertDescription>
                </Box>
              </Alert>
              <VStack spacing={3} align="stretch">
                {envVars.map((item, index) => (
                  <HStack key={item.id} spacing={3} align="flex-start">
                    <FormControl>
                      <FormLabel fontSize="sm">变量名</FormLabel>
                      <Input
                        placeholder={t('frontend.env_var_name')}
                        value={item.key}
                        onChange={(e) => updateEnvRow(index, 'key', e.target.value)}
                        isDisabled={savingEnv}
                      />
                    </FormControl>
                    <FormControl>
                      <FormLabel fontSize="sm">变量值</FormLabel>
                      <Input
                        placeholder={t('frontend.env_var_value')}
                        value={item.value}
                        onChange={(e) => updateEnvRow(index, 'value', e.target.value)}
                        isDisabled={savingEnv}
                      />
                    </FormControl>
                    <IconButton
                      aria-label={t('frontend.delete')}
                      icon={<Icon as={FiTrash2} />}
                      variant="ghost"
                      colorScheme="red"
                      mt={6}
                      onClick={() => removeEnvRow(index)}
                      isDisabled={savingEnv || envVars.length === 1}
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
                isDisabled={savingEnv}
              >
                新增变量
              </Button>
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button onClick={closeEnvModal} mr={3} variant="ghost" isDisabled={savingEnv}>
              取消
            </Button>
            <Button colorScheme="blue" onClick={saveEnvVars} isLoading={savingEnv}>
              保存
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      <Modal isOpen={isRoutingModalOpen} onClose={closeRoutingModal} size="md">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>{routingApp ? `域名与端口：${routingApp.name}` : '域名与端口'}</ModalHeader>
          <ModalCloseButton disabled={savingRouting} />
          <ModalBody>
            <VStack spacing={4} align="stretch">
              <Alert status="info" variant="left-accent">
                <AlertIcon />
                <Box>
                  <AlertTitle fontSize="sm">域名说明</AlertTitle>
                  <AlertDescription fontSize="sm">
                    留空表示使用系统自动分配的域名（如 app-name.{config.domainSuffix}）。保存后自动更新代理规则。
                  </AlertDescription>
                </Box>
              </Alert>

              <FormControl>
                <FormLabel>自定义域名</FormLabel>
                <Input
                  placeholder={config.domainSuffix ? `如 myapp.${config.domainSuffix}` : '请输入域名'}
                  value={routingDomain}
                  onChange={(e) => setRoutingDomain(e.target.value.trim())}
                  isDisabled={savingRouting}
                />
              </FormControl>

              <FormControl isRequired>
                <FormLabel>端口</FormLabel>
                <NumberInput
                  min={1}
                  max={65535}
                  value={routingPort || ''}
                  onChange={(_, value) => setRoutingPort(value)}
                  isDisabled={savingRouting}
                >
                  <NumberInputField placeholder={t('frontend.port_placeholder')} />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
              </FormControl>
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button onClick={closeRoutingModal} mr={3} variant="ghost" isDisabled={savingRouting}>
              取消
            </Button>
            <Button colorScheme="purple" onClick={saveRouting} isLoading={savingRouting}>
              保存
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
      <Box>
        <Flex justify="space-between" align="center" mb={6}>
          <HStack>
            <Icon as={FiGitBranch} boxSize={6} />
            <Heading size="lg">Git部署服务器</Heading>
          </HStack>
          <HStack>
            <Button
              leftIcon={<Icon as={FiRefreshCw} />}
              onClick={refreshData}
              isLoading={loading}
              variant="outline"
            >
              刷新
            </Button>
            <Button
              leftIcon={<Icon as={FiSettings} />}
              onClick={onConfigOpen}
              variant="outline"
            >
              服务器配置
            </Button>
            <Button
              leftIcon={<Icon as={FiPlus} />}
              colorScheme="blue"
              onClick={onOpen}
            >
              创建应用
            </Button>
          </HStack>
        </Flex>

        {/* 服务器状态 */}
        <Alert status={config.enabled ? 'success' : 'warning'} mb={6}>
          <AlertIcon />
          <AlertTitle>Git服务器状态:</AlertTitle>
          <AlertDescription>
            {config.enabled ? `服务器正在运行，端口 ${config.port}` : '服务器已禁用'}
          </AlertDescription>
        </Alert>

        {/* SSH 服务重启提示 */}
        {config.enabled && (
          <Alert status="info" mb={6}>
            <AlertIcon />
            <Box flex="1">
              <AlertTitle>需要重启 SSH 服务</AlertTitle>
              <AlertDescription>
                首次启用 Git Deploy 服务后，需要重启 SSH 服务以使配置生效。
                <br />
                <Text as="span" fontWeight="bold" color="blue.600">
                  Linux: sudo systemctl restart sshd
                </Text>
                <br />
                <Text as="span" fontWeight="bold" color="blue.600">
                  macOS: sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist && sudo launchctl load /System/Library/LaunchDaemons/ssh.plist
                </Text>
              </AlertDescription>
            </Box>
            <Button
              colorScheme="blue"
              size="sm"
              onClick={handleRestartSSHD}
              isLoading={loading}
            >
              自动重启 SSH
            </Button>
          </Alert>
        )}

        {/* 统计信息 */}
        <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={6} mb={8}>
          <Card>
            <CardBody>
              <Stat>
                <StatLabel>Git应用</StatLabel>
                <StatNumber>{apps.length}</StatNumber>
                <StatHelpText>
                  运行中: {Array.isArray(apps) ? apps.filter(app => app.status === 'active').length : 0}
                </StatHelpText>
              </Stat>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <Stat>
                <StatLabel>SSH密钥</StatLabel>
                <StatNumber>{sshKeys.length}</StatNumber>
                <StatHelpText>已配置的部署密钥</StatHelpText>
              </Stat>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <Stat>
                <StatLabel>总提交数</StatLabel>
                <StatNumber>{Array.isArray(apps) ? apps.reduce((sum, app) => sum + (app.commits || 0), 0) : 0}</StatNumber>
                <StatHelpText>所有应用的提交总数</StatHelpText>
              </Stat>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <Stat>
                <StatLabel>自动SSL</StatLabel>
                <StatNumber>{Array.isArray(apps) ? apps.filter(app => app.autoSSL).length : 0}</StatNumber>
                <StatHelpText>启用自动SSL的应用</StatHelpText>
              </Stat>
            </CardBody>
          </Card>
        </SimpleGrid>

        <Tabs variant="enclosed">
          <TabList>
            <Tab>
              <HStack>
                <Icon as={FiFolder} />
                <Text>Git应用</Text>
                <Badge colorScheme="blue">{apps.length}</Badge>
              </HStack>
            </Tab>
            <Tab>
              <HStack>
                <Icon as={FiKey} />
                <Text>SSH密钥</Text>
                <Badge colorScheme="green">{sshKeys.length}</Badge>
              </HStack>
            </Tab>
            
            <Tab>
              <HStack>
                <Icon as={FiTerminal} />
                <Text>实时日志</Text>
              </HStack>
            </Tab>
            
            <Tab>
              <HStack>
                <Icon as={FiPackage} />
                <Text>Docker镜像</Text>
              </HStack>
            </Tab>
            
            <Tab>
              <HStack>
                <Icon as={FiClock} />
                <Text>部署历史</Text>
              </HStack>
            </Tab>
            
            <Tab>
              <HStack>
                <Icon as={FiGitBranch} />
                <Text>推送记录</Text>
              </HStack>
            </Tab>
          </TabList>

          <TabPanels>
            {/* Git应用 */}
            <TabPanel>
              <Card>
                <CardBody>
                  {Array.isArray(apps) && apps.length > 0 ? (
                    <Table variant="simple">
                      <Thead>
                        <Tr>
                          <Th>选择</Th>
                          <Th>应用信息</Th>
                          <Th>Git推送地址</Th>
                          <Th>状态</Th>
                          <Th>最后部署</Th>
                          <Th>操作</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {apps.map((app) => (
                          <Tr 
                            key={app.id}
                            bg={selectedApp === app.name ? 'blue.50' : 'transparent'}
                            _hover={{ bg: 'gray.50' }}
                          >
                            <Td>
                              <Button
                                size="sm"
                                variant={selectedApp === app.name ? 'solid' : 'outline'}
                                colorScheme="blue"
                                onClick={() => setSelectedApp(selectedApp === app.name ? '' : app.name)}
                              >
                                {selectedApp === app.name ? '已选中' : '选择'}
                              </Button>
                            </Td>
                            <Td>
                              <VStack align="start" spacing={1}>
                                <HStack>
                                  <Icon as={FiGithub} />
                                  <Text fontWeight="medium">{app.name}</Text>
                                </HStack>
                                <HStack spacing={2}>
                                  <Badge colorScheme="gray">{app.commits || 0} commits</Badge>
                                  {app.autoSSL && (
                                    <Badge colorScheme="green">SSL</Badge>
                                  )}
                                </HStack>
                                {app.domain && (
                                  <Text fontSize="sm" color="gray.600">
                                    域名: {app.domain}
                                  </Text>
                                )}
                                <Text fontSize="sm" color="gray.600">
                                  端口: {app.port ?? '未分配'}
                                </Text>
                                {app.git_url && (
                                  <HStack spacing={1}>
                                    <Text fontSize="xs" color="gray.500">Git:</Text>
                                    <Code fontSize="xs" maxW="250px" isTruncated>
                                      {app.git_url}
                                    </Code>
                                    <IconButton
                                      aria-label={t('frontend.copy_git_url')}
                                      icon={<FiCopy />}
                                      size="xs"
                                      variant="ghost"
                                      onClick={() => copyToClipboard(app.git_url || '')}
                                    />
                                  </HStack>
                                )}
                                <Button
                                  size="xs"
                                  leftIcon={<Icon as={FiSliders} />}
                                  variant="ghost"
                                  colorScheme="blue"
                                  onClick={() => openEnvModal(app)}
                                >
                                  环境变量
                                </Button>
                                <Button
                                  size="xs"
                                  leftIcon={<Icon as={FiGlobe} />}
                                  variant="ghost"
                                  colorScheme="purple"
                                  onClick={() => openRoutingModal(app)}
                                >
                                  域名/端口
                                </Button>
                              </VStack>
                            </Td>
                            <Td>
                              {app.git_url ? (
                                <VStack align="start" spacing={1}>
                                  <Text fontSize="xs" color="gray.500">推送到此地址：</Text>
                                  <Code fontSize="xs" maxW="200px" isTruncated>
                                    {app.git_url}
                                  </Code>
                                </VStack>
                              ) : (
                                <Text fontSize="xs" color="gray.400">等待配置</Text>
                              )}
                            </Td>
                            <Td>
                              <Badge colorScheme={getStatusColor(app.status)}>
                                {getStatusText(app.status)}
                              </Badge>
                            </Td>
                            <Td>{app.lastDeploy || '未部署'}</Td>
                            <Td>
                              <HStack spacing={1}>
                                <IconButton
                                  aria-label={t('frontend.redeploy')}
                                  icon={<FiUpload />}
                                  size="sm"
                                  variant="ghost"
                                  colorScheme="green"
                                  onClick={() => handleDeployApp(app.name)}
                                  title={t('frontend.trigger_redeploy')}
                                />
                                <IconButton
                                  aria-label={t('frontend.delete_app')}
                                  icon={<FiTrash2 />}
                                  size="sm"
                                  variant="ghost"
                                  colorScheme="red"
                                  onClick={() => openDeleteModal(app)}
                                />
                              </HStack>
                            </Td>
                          </Tr>
                        ))}
                      </Tbody>
                    </Table>
                  ) : (
                    <Box textAlign="center" py={8}>
                      <Icon as={FiGitBranch} boxSize={12} color="gray.300" mb={4} />
                      <Text color="gray.500" mb={4}>暂无Git应用</Text>
                      <Button leftIcon={<Icon as={FiPlus} />} colorScheme="blue" onClick={onOpen}>
                        创建第一个应用
                      </Button>
                    </Box>
                  )}
                </CardBody>
              </Card>
            </TabPanel>

            {/* SSH密钥 */}
            <TabPanel>
              <VStack spacing={4} align="stretch">
                <Flex justify="space-between" align="center">
                  <Text fontSize="lg" fontWeight="medium">SSH部署密钥</Text>
                  <Button leftIcon={<Icon as={FiPlus} />} colorScheme="green" onClick={onKeyOpen}>
                    添加SSH密钥
                  </Button>
                </Flex>

                <Card>
                  <CardBody>
                    {Array.isArray(sshKeys) && sshKeys.length > 0 ? (
                      <Table variant="simple">
                        <Thead>
                          <Tr>
                            <Th>密钥名称</Th>
                            <Th>指纹</Th>
                            <Th>类型</Th>
                            <Th>创建时间</Th>
                            <Th>最后使用</Th>
                            <Th>操作</Th>
                          </Tr>
                        </Thead>
                        <Tbody>
                          {sshKeys.map((key) => (
                            <Tr key={key.id}>
                              <Td>
                                <HStack>
                                  <Icon as={FiKey} />
                                  <Text fontWeight="medium">{key.name}</Text>
                                </HStack>
                              </Td>
                              <Td>
                                <Code fontSize="xs" maxW="200px" isTruncated>
                                  {key.fingerprint}
                                </Code>
                              </Td>
                              <Td>
                                <Badge variant="outline">{key.type}</Badge>
                              </Td>
                              <Td>{key.created}</Td>
                              <Td>{key.lastUsed || '从未使用'}</Td>
                              <Td>
                                <HStack spacing={2}>
                                  <IconButton
                                    aria-label={t('frontend.copy_fingerprint')}
                                    icon={<FiCopy />}
                                    size="sm"
                                    variant="ghost"
                                    onClick={() => copyToClipboard(key.fingerprint)}
                                  />
                                  <IconButton
                                    aria-label={t('frontend.delete')}
                                    icon={<FiTrash2 />}
                                    size="sm"
                                    variant="ghost"
                                    colorScheme="red"
                                    onClick={() => handleDeleteSSHKey(key.id)}
                                  />
                                </HStack>
                              </Td>
                            </Tr>
                          ))}
                        </Tbody>
                      </Table>
                    ) : (
                      <Box textAlign="center" py={8}>
                        <Icon as={FiKey} boxSize={12} color="gray.300" mb={4} />
                        <Text color="gray.500" mb={4}>暂无SSH密钥</Text>
                        <Button leftIcon={<Icon as={FiPlus} />} colorScheme="green" onClick={onKeyOpen}>
                          添加第一个SSH密钥
                        </Button>
                      </Box>
                    )}
                  </CardBody>
                </Card>
              </VStack>
            </TabPanel>
            
            {/* 实时日志 */}
            <TabPanel>
              <VStack spacing={4} align="stretch">
                {selectedApp ? (
                  <RealtimeLogs 
                    appName={selectedApp} 
                    autoScroll={true}
                    maxLines={500}
                    showControls={true}
                  />
                ) : (
                  <Alert status="info">
                    <AlertIcon />
                    请先选择一个应用来查看实时日志
                  </Alert>
                )}
              </VStack>
            </TabPanel>
            
            {/* Docker镜像 */}
            <TabPanel>
              <VStack spacing={4} align="stretch">
                {selectedApp ? (
                  <DockerImageManager appName={selectedApp} />
                ) : (
                  <Alert status="info">
                    <AlertIcon />
                    请先选择一个应用来管理Docker镜像
                  </Alert>
                )}
              </VStack>
            </TabPanel>
            
            {/* 部署历史 */}
            <TabPanel>
              <VStack spacing={4} align="stretch">
                {selectedApp ? (
                  <DeployHistory appName={selectedApp} />
                ) : (
                  <Alert status="info">
                    <AlertIcon />
                    请先选择一个应用来查看部署历史
                  </Alert>
                )}
              </VStack>
            </TabPanel>
            
            {/* 推送记录 */}
            <TabPanel>
              <VStack spacing={4} align="stretch">
                {selectedApp ? (
                  <>
                    <Card>
                      <CardBody>
                        <VStack align="stretch" spacing={4}>
                          <Heading size="md">Git 推送历史</Heading>
                          <PushHistory appName={selectedApp} limit={50} />
                        </VStack>
                      </CardBody>
                    </Card>
                    
                    <Card>
                      <CardBody>
                        <VStack align="stretch" spacing={4}>
                          <Heading size="md">SSH 密钥绑定</Heading>
                          <SSHKeyBindings 
                            appName={selectedApp}
                            allowedKeys={apps.find(a => a.name === selectedApp)?.allowed_keys || []}
                            onUpdate={refreshData}
                          />
                        </VStack>
                      </CardBody>
                    </Card>
                  </>
                ) : (
                  <Alert status="info">
                    <AlertIcon />
                    请先选择一个应用来查看推送记录和管理SSH密钥绑定
                  </Alert>
                )}
              </VStack>
            </TabPanel>
          </TabPanels>
        </Tabs>

        {/* 创建应用模态框 */}
        <Modal isOpen={isOpen} onClose={onClose} size="lg">
          <ModalOverlay />
          <ModalContent>
            <ModalHeader>创建Git应用</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4} align="stretch">
                <Alert status="info" variant="left-accent">
                  <AlertIcon />
                  <Box>
                    <AlertTitle fontSize="sm">说明</AlertTitle>
                    <AlertDescription fontSize="sm">
                      创建应用后，系统会自动分配Git仓库地址、域名和端口。您只需要输入应用名称即可。
                    </AlertDescription>
                  </Box>
                </Alert>

                <FormControl isRequired>
                  <FormLabel>应用名称</FormLabel>
                  <Input
                    value={newApp.name}
                    onChange={(e) => setNewApp({ ...newApp, name: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, '') })}
                    placeholder="my-app"
                  />
                  <Text fontSize="sm" color="gray.500" mt={1}>
                    只能包含小写字母、数字和连字符，将用于生成Git仓库地址和域名
                  </Text>
                </FormControl>

                {newApp.name && config.domainSuffix && (
                  <Alert status="success" variant="subtle">
                    <AlertIcon />
                    <Box fontSize="sm">
                      <Text fontWeight="medium">预览信息：</Text>
                      <Text>Git地址: <Code fontSize="xs">git@{window.location.hostname}:{newApp.name}.git</Code></Text>
                      <Text>访问域名: <Code fontSize="xs">{newApp.name}.{config.domainSuffix}</Code></Text>
                      <Text>端口: 自动分配（{config.portRange[0]}-{config.portRange[1]}）</Text>
                    </Box>
                  </Alert>
                )}

                <FormControl display="flex" alignItems="center">
                  <FormLabel mb="0">启用自动SSL证书</FormLabel>
                  <Switch
                    isChecked={newApp.autoSSL}
                    onChange={(e) => setNewApp({ ...newApp, autoSSL: e.target.checked })}
                  />
                </FormControl>
              </VStack>
            </ModalBody>

            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onClose}>
                取消
              </Button>
              <Button colorScheme="blue" onClick={handleCreateApp}>
                创建应用
              </Button>
            </ModalFooter>
          </ModalContent>
        </Modal>

        {/* 添加SSH密钥模态框 */}
        <Modal isOpen={isKeyOpen} onClose={onKeyClose} size="lg">
          <ModalOverlay />
          <ModalContent>
            <ModalHeader>添加SSH密钥</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                <FormControl>
                  <FormLabel>密钥名称</FormLabel>
                  <Input
                    value={newKey.name}
                    onChange={(e) => setNewKey({ ...newKey, name: e.target.value })}
                    placeholder="deploy-key-1"
                  />
                </FormControl>

                <FormControl>
                  <FormLabel>公钥内容</FormLabel>
                  <Textarea
                    value={newKey.publicKey}
                    onChange={(e) => setNewKey({ ...newKey, publicKey: e.target.value })}
                    placeholder="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC..."
                    rows={6}
                  />
                </FormControl>
              </VStack>
            </ModalBody>

            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onKeyClose}>
                取消
              </Button>
              <Button colorScheme="green" onClick={handleAddSSHKey}>
                添加密钥
              </Button>
            </ModalFooter>
          </ModalContent>
        </Modal>

        {/* 删除应用确认对话框 */}
        <Modal isOpen={isDeleteModalOpen} onClose={closeDeleteModal} size="md">
          <ModalOverlay />
          <ModalContent>
            <ModalHeader>{t('frontend.delete_app_confirm')}</ModalHeader>
            <ModalCloseButton isDisabled={isDeleting} />
            <ModalBody>
              <VStack spacing={4} align="stretch">
                <Alert status="error" variant="left-accent">
                  <AlertIcon />
                  <Box>
                    <AlertTitle fontSize="sm">危险操作</AlertTitle>
                    <AlertDescription fontSize="sm">
                      {t('frontend.delete_app_warning')}
                    </AlertDescription>
                  </Box>
                </Alert>

                {deleteAppTarget && (
                  <>
                    <Box>
                      <Text fontSize="sm" mb={2}>
                        {t('frontend.delete_app_instruction').replace('{appName}', deleteAppTarget.name)}
                      </Text>
                      <Input
                        value={deleteConfirmInput}
                        onChange={(e) => setDeleteConfirmInput(e.target.value)}
                        placeholder={deleteAppTarget.name}
                        isDisabled={isDeleting}
                        autoFocus
                      />
                    </Box>

                    <Box bg="gray.50" p={3} borderRadius="md">
                      <Text fontSize="sm" fontWeight="medium" mb={1}>即将删除的应用信息：</Text>
                      <Text fontSize="sm">应用名称: {deleteAppTarget.name}</Text>
                      {deleteAppTarget.domain && (
                        <Text fontSize="sm">域名: {deleteAppTarget.domain}</Text>
                      )}
                      {deleteAppTarget.port && (
                        <Text fontSize="sm">端口: {deleteAppTarget.port}</Text>
                      )}
                    </Box>
                  </>
                )}
              </VStack>
            </ModalBody>

            <ModalFooter>
              <Button 
                variant="ghost" 
                mr={3} 
                onClick={closeDeleteModal}
                isDisabled={isDeleting}
              >
                取消
              </Button>
              <Button 
                colorScheme="red" 
                onClick={handleDeleteApp}
                isLoading={isDeleting}
                isDisabled={!deleteAppTarget || deleteConfirmInput !== deleteAppTarget.name}
              >
                确认删除
              </Button>
            </ModalFooter>
          </ModalContent>
        </Modal>

        {/* 服务器配置模态框 */}
        <Modal isOpen={isConfigOpen} onClose={onConfigClose} size="xl">
          <ModalOverlay />
          <ModalContent maxH="90vh" overflowY="auto">
            <ModalHeader>Git服务器配置</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                <FormControl display="flex" alignItems="center">
                  <FormLabel mb="0">启用Git服务器</FormLabel>
                  <Switch
                    isChecked={config.enabled}
                    onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
                  />
                </FormControl>

                <FormControl>
                  <FormLabel>SSH端口</FormLabel>
                  <Input
                    type="number"
                    value={config.port}
                    onChange={(e) => setConfig({ ...config, port: parseInt(e.target.value) })}
                  />
                </FormControl>

                <FormControl>
                  <FormLabel>Webhook基础URL</FormLabel>
                  <Input
                    value={config.webhook}
                    onChange={(e) => setConfig({ ...config, webhook: e.target.value })}
                    placeholder="https://your-domain.com/webhook"
                  />
                  <Text fontSize="sm" color="gray.500" mt={1}>
                    部署完成后的回调通知URL，支持企业微信、飞书、钉钉、Slack等平台
                  </Text>
                </FormControl>

                <FormControl>
                  <FormLabel>默认分支</FormLabel>
                  <Input
                    value={config.defaultBranch}
                    onChange={(e) => setConfig({ ...config, defaultBranch: e.target.value })}
                    placeholder="main"
                  />
                  <Text fontSize="sm" color="gray.500" mt={1}>
                    新Git应用创建时的默认分支名称
                  </Text>
                </FormControl>

                <FormControl display="flex" alignItems="center">
                  <FormLabel mb="0">默认启用自动SSL</FormLabel>
                  <Switch
                    isChecked={config.autoSSL}
                    onChange={(e) => setConfig({ ...config, autoSSL: e.target.checked })}
                  />
                </FormControl>

                <FormControl>
                  <FormLabel>域名后缀</FormLabel>
                  <Input
                    value={config.domainSuffix}
                    onChange={(e) => setConfig({ ...config, domainSuffix: e.target.value })}
                    placeholder="localhost"
                  />
                  <Text fontSize="sm" color="gray.500" mt={1}>
                    应用自动分配域名时使用的后缀，如 app-name.{config.domainSuffix}
                  </Text>
                </FormControl>

                <FormControl>
                  <FormLabel>端口范围</FormLabel>
                  <HStack>
                    <NumberInput
                      min={1000}
                      max={65535}
                      value={config.portRange[0]}
                      onChange={(_, value) => setConfig({ ...config, portRange: [value, config.portRange[1]] })}
                    >
                      <NumberInputField placeholder={t('frontend.start_port')} />
                      <NumberInputStepper>
                        <NumberIncrementStepper />
                        <NumberDecrementStepper />
                      </NumberInputStepper>
                    </NumberInput>
                    <Text>-</Text>
                    <NumberInput
                      min={1000}
                      max={65535}
                      value={config.portRange[1]}
                      onChange={(_, value) => setConfig({ ...config, portRange: [config.portRange[0], value] })}
                    >
                      <NumberInputField placeholder={t('frontend.end_port')} />
                      <NumberInputStepper>
                        <NumberIncrementStepper />
                        <NumberDecrementStepper />
                      </NumberInputStepper>
                    </NumberInput>
                  </HStack>
                  <Text fontSize="sm" color="gray.500" mt={1}>
                    应用自动分配端口的范围
                  </Text>
                </FormControl>

                <FormControl>
                  <FormLabel>欢迎消息</FormLabel>
                  <Textarea
                    value={config.welcomeMessage}
                    onChange={(e) => setConfig({ ...config, welcomeMessage: e.target.value })}
                    placeholder={t('frontend.welcome_message')}
                    rows={3}
                  />
                  <Text fontSize="sm" color="gray.500" mt={1}>
                    Git推送时显示的欢迎消息
                  </Text>
                </FormControl>

                <FormControl>
                  <FormLabel>SSL证书邮箱</FormLabel>
                  <Input
                    type="email"
                    value={config.sslEmail}
                    onChange={(e) => setConfig({ ...config, sslEmail: e.target.value })}
                    placeholder="admin@example.com"
                  />
                  <Text fontSize="sm" color="gray.500" mt={1}>
                    用于申请Let's Encrypt SSL证书的邮箱地址
                  </Text>
                </FormControl>

                <FormControl>
                  <FormLabel>默认部署策略</FormLabel>
                  <Input
                    value={config.defaultStrategy}
                    onChange={(e) => setConfig({ ...config, defaultStrategy: e.target.value })}
                    placeholder="auto"
                  />
                  <Text fontSize="sm" color="gray.500" mt={1}>
                    新应用的默认部署策略（auto、docker、static等）
                  </Text>
                </FormControl>

                <FormControl>
                  <FormLabel>构建超时时间（秒）</FormLabel>
                  <NumberInput
                    min={60}
                    max={3600}
                    value={config.buildTimeout}
                    onChange={(_, value) => setConfig({ ...config, buildTimeout: value })}
                  >
                    <NumberInputField placeholder="300" />
                    <NumberInputStepper>
                      <NumberIncrementStepper />
                      <NumberDecrementStepper />
                    </NumberInputStepper>
                  </NumberInput>
                  <Text fontSize="sm" color="gray.500" mt={1}>
                    应用构建的最大等待时间
                  </Text>
                </FormControl>

                <FormControl display="flex" alignItems="center">
                  <FormLabel mb="0">启用自动域名分配</FormLabel>
                  <Switch
                    isChecked={config.autoDomain}
                    onChange={(e) => setConfig({ ...config, autoDomain: e.target.checked })}
                  />
                </FormControl>
              </VStack>
            </ModalBody>

            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onConfigClose}>
                取消
              </Button>
              <Button colorScheme="blue" onClick={handleUpdateConfig}>
                保存配置
              </Button>
            </ModalFooter>
          </ModalContent>
        </Modal>
      </Box>
    </>
  )
}

export default GitServerManagement

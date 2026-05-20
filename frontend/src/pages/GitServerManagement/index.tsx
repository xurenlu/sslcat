import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  VStack,
  HStack,
  Button,
  Icon,
  Text,
  Flex,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  useDisclosure,
  SimpleGrid,
  Card,
  CardBody,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  useColorModeValue,
} from '@chakra-ui/react'
import {
  FiGitBranch,
  FiRefreshCw,
  FiSettings,
  FiFolder,
  FiActivity,
  FiServer,
  FiShield,
} from 'react-icons/fi'
import { useConfig } from '../../contexts/ConfigContext'
import { useTranslation } from '../../hooks/useLanguage'
import { useGitApps } from '../../hooks/useGitApps'
import { useSSHKeys } from '../../hooks/useSSHKeys'
import { useGitServerConfig } from '../../hooks/useGitServerConfig'
import SSHKeyList from './SSHKeyList'
import CreateAppModal from './CreateAppModal'
import AddSSHKeyModal from './AddSSHKeyModal'
import ConfigModal from './ConfigModal'
import EnvVarModal from './EnvVarModal'
import RoutingModal from './RoutingModal'
import DeleteAppModal from './DeleteAppModal'
import AppCardGrid from './AppCardGrid'
import { CreateAppRuntimeOptions, GitApp } from './types'

const GitServerManagement: React.FC = () => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()

  // 使用自定义 Hooks
  const {
    apps,
    loading: appsLoading,
    loadApps,
    createApp,
    deleteApp,
    deployApp,
    updateEnvVars,
    updateRouting,
  } = useGitApps({ adminPrefix })

  const {
    sshKeys,
    loading: keysLoading,
    loadSSHKeys,
    addSSHKey,
    deleteSSHKey,
  } = useSSHKeys({ adminPrefix })

  const {
    config,
    loading: configLoading,
    loadConfig,
    updateConfig,
    restartSSHD,
  } = useGitServerConfig({ adminPrefix })

  const [selectedAppForModal, setSelectedAppForModal] = useState<GitApp | null>(null)
  const [showSSHKeys, setShowSSHKeys] = useState(false)

  // Modal 状态
  const { isOpen: isCreateAppOpen, onOpen: onCreateAppOpen, onClose: onCreateAppClose } = useDisclosure()
  const { isOpen: isKeyOpen, onOpen: onKeyOpen, onClose: onKeyClose } = useDisclosure()
  const { isOpen: isConfigOpen, onOpen: onConfigOpen, onClose: onConfigClose } = useDisclosure()
  const { isOpen: isEnvModalOpen, onOpen: onEnvModalOpen, onClose: onEnvModalClose } = useDisclosure()
  const { isOpen: isRoutingModalOpen, onOpen: onRoutingModalOpen, onClose: onRoutingModalClose } = useDisclosure()
  const { isOpen: isDeleteModalOpen, onOpen: onDeleteModalOpen, onClose: onDeleteModalClose } = useDisclosure()

  // 刷新所有数据
  const refreshData = async () => {
    await Promise.all([loadApps(), loadSSHKeys(), loadConfig()])
  }

  // 初始化加载
  useEffect(() => {
    refreshData()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // 处理创建应用
  const handleCreateApp = async (name: string, autoSSL: boolean, options?: CreateAppRuntimeOptions) => {
    await createApp(name, autoSSL, options)
  }

  // 处理删除应用
  const handleDeleteApp = async (appName: string) => {
    await deleteApp(appName)
  }

  // 处理添加SSH密钥
  const handleAddSSHKey = async (name: string, publicKey: string) => {
    await addSSHKey(name, publicKey)
  }

  // 处理保存环境变量
  const handleSaveEnvVars = async (appName: string, envVars: Record<string, string>) => {
    await updateEnvVars(appName, envVars)
  }

  // 处理保存路由配置
  const handleSaveRouting = async (appName: string, domain: string, port: number) => {
    await updateRouting(appName, domain, port)
  }

  // 打开环境变量模态框
  const openEnvModal = (app: GitApp) => {
    setSelectedAppForModal(app)
    onEnvModalOpen()
  }

  // 打开路由配置模态框
  const openRoutingModal = (app: GitApp) => {
    setSelectedAppForModal(app)
    onRoutingModalOpen()
  }

  // 打开删除确认模态框
  const openDeleteModal = (app: GitApp) => {
    setSelectedAppForModal(app)
    onDeleteModalOpen()
  }

  const loading = appsLoading || keysLoading || configLoading

  // 获取需要重新部署的应用
  const pendingApps = apps.filter((app) => app.pending_restart === true)

  // 统计数据
  const activeAppsCount = apps.filter((app) => app.status === 'active').length
  const deployingAppsCount = apps.filter((app) => app.status === 'deploying').length
  const errorAppsCount = apps.filter((app) => app.status === 'error').length

  const bg = useColorModeValue('gray.50', 'gray.900')
  const cardBg = useColorModeValue('white', 'gray.800')

  return (
    <>
      {/* 浮层提醒：有应用需要重新部署 */}
      {pendingApps.length > 0 && (
        <Box
          position="fixed"
          top="80px"
          right="20px"
          zIndex={9999}
          bg="orange.500"
          color="white"
          p={4}
          borderRadius="12px"
          boxShadow="lg"
          maxW="400px"
          backdropFilter="blur(10px)"
        >
          <VStack align="stretch" spacing={3}>
            <HStack justify="space-between">
              <HStack>
                <Icon as={FiActivity} boxSize={5} />
                <Text fontWeight="bold">配置已更新</Text>
              </HStack>
            </HStack>
            <Text fontSize="sm">
              以下应用需要重新部署以应用新配置：
            </Text>
            <VStack align="stretch" spacing={2} maxH="200px" overflowY="auto">
              {pendingApps.map((app) => (
                <HStack
                  key={app.name}
                  justify="space-between"
                  bg="orange.600"
                  p={2}
                  borderRadius="8px"
                >
                  <Text fontSize="sm" fontWeight="medium">
                    {app.name}
                  </Text>
                  <Button
                    size="xs"
                    colorScheme="whiteAlpha"
                    leftIcon={<Icon as={FiRefreshCw} />}
                    onClick={() => deployApp(app.name)}
                  >
                    重新部署
                  </Button>
                </HStack>
              ))}
            </VStack>
          </VStack>
        </Box>
      )}

      <Box minH="100vh" bg={bg} py={8}>
        <VStack spacing={8} maxW="1600px" mx="auto" px={6}>
          {/* 页面头部 */}
          <Flex justify="space-between" align="center">
            <HStack spacing={4}>
              <Box
                p={3}
                bg="blue.500"
                borderRadius="12px"
                boxShadow="0 4px 12px rgba(59, 130, 246, 0.3)"
              >
                <Icon as={FiGitBranch} boxSize={8} color="white" />
              </Box>
              <VStack align="start" spacing={1}>
                <Heading size="lg" color="gray.800">
                  Git Server
                </Heading>
                <Text fontSize="sm" color="gray.500">
                  持续部署平台
                </Text>
              </VStack>
            </HStack>

            <HStack spacing={3}>
              <Button
                leftIcon={<Icon as={FiShield} />}
                onClick={() => setShowSSHKeys(!showSSHKeys)}
                variant={showSSHKeys ? 'solid' : 'outline'}
                colorScheme="green"
                borderRadius="8px"
              >
                SSH 密钥 ({sshKeys.length})
              </Button>
              <Button
                leftIcon={<Icon as={FiSettings} />}
                onClick={onConfigOpen}
                variant="outline"
                borderRadius="8px"
              >
                服务器配置
              </Button>
              <Button
                leftIcon={<Icon as={FiRefreshCw} />}
                onClick={refreshData}
                isLoading={loading}
                variant="outline"
                borderRadius="8px"
              >
                刷新
              </Button>
            </HStack>
          </Flex>

          {/* 统计卡片 */}
          <SimpleGrid columns={{ base: 2, md: 4 }} spacing={4}>
            <Card bg={cardBg} borderRadius="12px" boxShadow="sm">
              <CardBody>
                <Stat>
                  <StatLabel fontSize="sm" color="gray.500">总应用数</StatLabel>
                  <StatNumber fontSize="3xl">{apps.length}</StatNumber>
                  <StatHelpText fontSize="xs">已创建的应用</StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card bg={cardBg} borderRadius="12px" boxShadow="sm">
              <CardBody>
                <Stat>
                  <StatLabel fontSize="sm" color="gray.500">运行中</StatLabel>
                  <StatNumber fontSize="3xl" color="green.500">{activeAppsCount}</StatNumber>
                  <StatHelpText fontSize="xs">正常部署的应用</StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card bg={cardBg} borderRadius="12px" boxShadow="sm">
              <CardBody>
                <Stat>
                  <StatLabel fontSize="sm" color="gray.500">部署中</StatLabel>
                  <StatNumber fontSize="3xl" color="blue.500">{deployingAppsCount}</StatNumber>
                  <StatHelpText fontSize="xs">正在构建或部署</StatHelpText>
                </Stat>
              </CardBody>
            </Card>

            <Card bg={cardBg} borderRadius="12px" boxShadow="sm">
              <CardBody>
                <Stat>
                  <StatLabel fontSize="sm" color="gray.500">错误</StatLabel>
                  <StatNumber fontSize="3xl" color="red.500">{errorAppsCount}</StatNumber>
                  <StatHelpText fontSize="xs">部署失败的应用</StatHelpText>
                </Stat>
              </CardBody>
            </Card>
          </SimpleGrid>

          {/* 服务器状态 */}
          {!config.enabled && (
            <Alert status="warning" borderRadius="12px">
              <AlertIcon />
              <Box flex="1">
                <AlertTitle>Git Server 未启用</AlertTitle>
                <AlertDescription>
                  请在服务器配置中启用 Git Server 功能。
                </AlertDescription>
              </Box>
              <Button
                colorScheme="orange"
                size="sm"
                onClick={onConfigOpen}
              >
                前往配置
              </Button>
            </Alert>
          )}

          {/* SSH 密钥管理 */}
          {showSSHKeys && (
            <Card bg={cardBg} borderRadius="12px" boxShadow="sm">
              <CardBody>
                <VStack align="stretch" spacing={4}>
                  <Flex justify="space-between" align="center">
                    <HStack spacing={2}>
                      <Icon as={FiShield} boxSize={5} color="green.500" />
                      <Heading size="md">SSH 密钥</Heading>
                      <Text fontSize="sm" color="gray.500">
                    ({sshKeys.length} 个密钥)
                  </Text>
                    </HStack>
                    <Button
                      leftIcon={<Icon as={FiFolder} />}
                      size="sm"
                      colorScheme="green"
                      onClick={onKeyOpen}
                    >
                      添加密钥
                    </Button>
                  </Flex>

                  <SSHKeyList
                    sshKeys={sshKeys}
                    onAdd={onKeyOpen}
                    onDelete={deleteSSHKey}
                  />
                </VStack>
              </CardBody>
            </Card>
          )}

          {/* 应用卡片网格 */}
          <AppCardGrid
            apps={apps}
            loading={loading}
            onRefresh={loadApps}
            onDeploy={deployApp}
            onDelete={openDeleteModal}
            onOpenEnvModal={openEnvModal}
            onOpenRoutingModal={openRoutingModal}
            onCreateApp={onCreateAppOpen}
          />
        </VStack>
      </Box>

      {/* Modal 组件 */}
      <CreateAppModal
        isOpen={isCreateAppOpen}
        onClose={onCreateAppClose}
        onCreate={handleCreateApp}
        config={config}
      />

      <AddSSHKeyModal
        isOpen={isKeyOpen}
        onClose={onKeyClose}
        onAdd={handleAddSSHKey}
      />

      <ConfigModal
        isOpen={isConfigOpen}
        onClose={onConfigClose}
        config={config}
        onSave={updateConfig}
      />

      {selectedAppForModal && (
        <>
          <EnvVarModal
            isOpen={isEnvModalOpen}
            onClose={onEnvModalClose}
            app={selectedAppForModal}
            onSave={handleSaveEnvVars}
          />
          <RoutingModal
            isOpen={isRoutingModalOpen}
            onClose={onRoutingModalClose}
            app={selectedAppForModal}
            config={config}
            onSave={handleSaveRouting}
          />
          <DeleteAppModal
            isOpen={isDeleteModalOpen}
            onClose={onDeleteModalClose}
            app={selectedAppForModal}
            onDelete={handleDeleteApp}
          />
        </>
      )}
    </>
  )
}

export default GitServerManagement

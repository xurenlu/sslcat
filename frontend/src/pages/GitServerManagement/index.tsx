import React, { useState, useEffect } from 'react'
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
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  useDisclosure,
} from '@chakra-ui/react'
import {
  FiGitBranch,
  FiRefreshCw,
  FiPlus,
  FiUpload,
  FiSettings,
  FiKey,
  FiFolder,
  FiTerminal,
  FiPackage,
  FiClock,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../../contexts/ConfigContext'
import { useTranslation } from '../../hooks/useLanguage'
import RealtimeLogs from '../../components/RealtimeLogs'
import DockerImageManager from '../../components/DockerImageManager'
import DeployHistory from '../../components/DeployHistory'
import PushHistory from '../../components/PushHistory'
import SSHKeyBindings from '../../components/SSHKeyBindings'
import { useGitApps } from '../../hooks/useGitApps'
import { useSSHKeys } from '../../hooks/useSSHKeys'
import { useGitServerConfig } from '../../hooks/useGitServerConfig'
import AppList from './AppList'
import SSHKeyList from './SSHKeyList'
import CreateAppModal from './CreateAppModal'
import AddSSHKeyModal from './AddSSHKeyModal'
import ConfigModal from './ConfigModal'
import EnvVarModal from './EnvVarModal'
import RoutingModal from './RoutingModal'
import DeleteAppModal from './DeleteAppModal'
import DeployHistoryDialog from './DeployHistoryDialog'
import { GitApp } from './types'

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

  const [selectedApp, setSelectedApp] = useState<string>('')
  const [selectedAppForModal, setSelectedAppForModal] = useState<GitApp | null>(null)
  const [selectedAppForDeployHistory, setSelectedAppForDeployHistory] = useState<GitApp | null>(null)
  const [logsDeploymentId, setLogsDeploymentId] = useState<string | null>(null)

  // Modal 状态
  const { isOpen: isCreateAppOpen, onOpen: onCreateAppOpen, onClose: onCreateAppClose } = useDisclosure()
  const { isOpen: isKeyOpen, onOpen: onKeyOpen, onClose: onKeyClose } = useDisclosure()
  const { isOpen: isConfigOpen, onOpen: onConfigOpen, onClose: onConfigClose } = useDisclosure()
  const { isOpen: isEnvModalOpen, onOpen: onEnvModalOpen, onClose: onEnvModalClose } = useDisclosure()
  const { isOpen: isRoutingModalOpen, onOpen: onRoutingModalOpen, onClose: onRoutingModalClose } = useDisclosure()
  const { isOpen: isDeleteModalOpen, onOpen: onDeleteModalOpen, onClose: onDeleteModalClose } = useDisclosure()
  const { isOpen: isDeployHistoryOpen, onOpen: onDeployHistoryOpen, onClose: onDeployHistoryClose } = useDisclosure()

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
  const handleCreateApp = async (name: string, autoSSL: boolean) => {
    await createApp(name, autoSSL)
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

  // 打开部署历史模态框
  const openDeployHistoryModal = (app: GitApp) => {
    setSelectedAppForDeployHistory(app)
    onDeployHistoryOpen()
  }

  // 打开特定部署的日志
  const handleOpenDeploymentLogs = (appName: string, deploymentId: string) => {
    setSelectedApp(appName)
    setLogsDeploymentId(deploymentId)
    // 切换到日志标签页
    // 这里需要通过 state 或其他方式来切换 tab
    // 暂时简化处理，直接返回让用户手动切换
  }

  const loading = appsLoading || keysLoading || configLoading

  // 获取需要重新部署的应用
  const pendingApps = apps.filter((app) => app.pending_restart === true)

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
                <Text fontWeight="bold">{t.gitServer.configUpdated}</Text>
              </HStack>
            </HStack>
            <Text fontSize="sm">
              {t.gitServer.needRedeploy}
            </Text>
            <VStack align="stretch" spacing={1} maxH="200px" overflowY="auto">
              {pendingApps.map((app) => (
                <HStack
                  key={app.name}
                  justify="space-between"
                  bg="orange.600"
                  p={2}
                  borderRadius="sm"
                >
                  <Text fontSize="sm" fontWeight="medium">
                    {app.name}
                  </Text>
                  <Button
                    size="xs"
                    colorScheme="whiteAlpha"
                    leftIcon={<Icon as={FiUpload} />}
                    onClick={() => deployApp(app.name)}
                  >
                    {t.gitServer.redeploy}
                  </Button>
                </HStack>
              ))}
            </VStack>
          </VStack>
        </Box>
      )}

      <Box>
        <Flex justify="space-between" align="center" mb={6}>
          <HStack>
            <Icon as={FiGitBranch} boxSize={6} />
            <Heading size="lg">{t.gitServer.title}</Heading>
          </HStack>
          <HStack>
            <Button
              leftIcon={<Icon as={FiRefreshCw} />}
              onClick={refreshData}
              isLoading={loading}
              variant="outline"
            >
              {t.common.refresh}
            </Button>
            <Button
              leftIcon={<Icon as={FiSettings} />}
              onClick={onConfigOpen}
              variant="outline"
            >
              {t.gitServer.config}
            </Button>
            <Button leftIcon={<Icon as={FiPlus} />} colorScheme="blue" onClick={onCreateAppOpen}>
              {t.gitServer.addApp}
            </Button>
          </HStack>
        </Flex>

        {/* 服务器状态 */}
        <Alert status={config.enabled ? 'success' : 'warning'} mb={6}>
          <AlertIcon />
          <AlertTitle>{t.gitServer.serverStatus}</AlertTitle>
          <AlertDescription>
            {config.enabled
              ? t.gitServer.serverRunning.replace('{port}', String(config.port))
              : t.gitServer.serverDisabled}
          </AlertDescription>
        </Alert>

        {/* SSH 服务重启提示 */}
        {config.enabled && (
          <Alert status="info" mb={6}>
            <AlertIcon />
            <Box flex="1">
              <AlertTitle>{t.gitServer.needRestartSSH}</AlertTitle>
              <AlertDescription>
                {t.gitServer.restartSSHDescription}
                <br />
                <Text as="span" fontWeight="bold" color="blue.600">
                  Linux: sudo systemctl restart sshd
                </Text>
                <br />
                <Text as="span" fontWeight="bold" color="blue.600">
                  macOS: sudo launchctl unload /System/Library/LaunchDaemons/ssh.plist && sudo
                  launchctl load /System/Library/LaunchDaemons/ssh.plist
                </Text>
              </AlertDescription>
            </Box>
            <Button
              colorScheme="blue"
              size="sm"
              onClick={restartSSHD}
              isLoading={configLoading}
            >
              {t.gitServer.autoRestartSSH}
            </Button>
          </Alert>
        )}

        {/* 统计信息 */}
        <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={6} mb={8}>
          <Card>
            <CardBody>
              <Stat>
                <StatLabel>{t.gitServer.gitApps}</StatLabel>
                <StatNumber>{apps.length}</StatNumber>
                <StatHelpText>
                  {t.gitServer.runningApps}:{' '}
                  {Array.isArray(apps)
                    ? apps.filter((app) => app.status === 'active').length
                    : 0}
                </StatHelpText>
              </Stat>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <Stat>
                <StatLabel>{t.gitServer.sshKeys}</StatLabel>
                <StatNumber>{sshKeys.length}</StatNumber>
                <StatHelpText>{t.gitServer.configuredKeys}</StatHelpText>
              </Stat>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <Stat>
                <StatLabel>{t.gitServer.totalCommits}</StatLabel>
                <StatNumber>
                  {Array.isArray(apps)
                    ? apps.reduce((sum, app) => sum + (app.commits || 0), 0)
                    : 0}
                </StatNumber>
                <StatHelpText>{t.gitServer.allAppsCommits}</StatHelpText>
              </Stat>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <Stat>
                <StatLabel>{t.gitServer.autoSSL}</StatLabel>
                <StatNumber>
                  {Array.isArray(apps) ? apps.filter((app) => app.autoSSL).length : 0}
                </StatNumber>
                <StatHelpText>{t.gitServer.autoSSLApps}</StatHelpText>
              </Stat>
            </CardBody>
          </Card>
        </SimpleGrid>

        <Tabs variant="enclosed">
          <TabList>
            <Tab>
              <HStack>
                <Icon as={FiFolder} />
                <Text>{t.gitServer.gitApps}</Text>
                <Badge colorScheme="blue">{apps.length}</Badge>
              </HStack>
            </Tab>
            <Tab>
              <HStack>
                <Icon as={FiKey} />
                <Text>{t.gitServer.sshKeys}</Text>
                <Badge colorScheme="green">{sshKeys.length}</Badge>
              </HStack>
            </Tab>

            <Tab>
              <HStack>
                <Icon as={FiTerminal} />
                <Text>{t.gitServer.realtimeLogs}</Text>
              </HStack>
            </Tab>

            <Tab>
              <HStack>
                <Icon as={FiPackage} />
                <Text>{t.gitServer.dockerImages}</Text>
              </HStack>
            </Tab>

            <Tab>
              <HStack>
                <Icon as={FiClock} />
                <Text>{t.gitServer.deployHistory}</Text>
              </HStack>
            </Tab>

            <Tab>
              <HStack>
                <Icon as={FiGitBranch} />
                <Text>{t.gitServer.pushHistory}</Text>
              </HStack>
            </Tab>
          </TabList>

          <TabPanels>
            {/* Git应用 */}
            <TabPanel>
              <AppList
                apps={apps}
                selectedApp={selectedApp}
                onSelectApp={setSelectedApp}
                onDeploy={deployApp}
                onDelete={openDeleteModal}
                onOpenEnvModal={openEnvModal}
                onOpenRoutingModal={openRoutingModal}
                onOpenDeployHistory={openDeployHistoryModal}
                onCreateApp={onCreateAppOpen}
              />
            </TabPanel>

            {/* SSH密钥 */}
            <TabPanel>
              <SSHKeyList
                sshKeys={sshKeys}
                onAdd={onKeyOpen}
                onDelete={deleteSSHKey}
              />
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
                    {t.gitServer.selectAppFirst.replace('{feature}', t.gitServer.realtimeLogs)}
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
                    {t.gitServer.selectAppFirst.replace('{feature}', t.gitServer.manageDockerImages)}
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
                    {t.gitServer.selectAppFirst.replace('{feature}', t.gitServer.viewDeployHistory)}
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
                          <Heading size="md">{t.gitServer.pushHistory}</Heading>
                          <PushHistory appName={selectedApp} limit={50} />
                        </VStack>
                      </CardBody>
                    </Card>

                    <Card>
                      <CardBody>
                        <VStack align="stretch" spacing={4}>
                          <Heading size="md">{t.gitServer.sshKeys}</Heading>
                          <SSHKeyBindings
                            appName={selectedApp}
                            allowedKeys={
                              apps.find((a) => a.name === selectedApp)?.allowed_keys || []
                            }
                            onUpdate={refreshData}
                          />
                        </VStack>
                      </CardBody>
                    </Card>
                  </>
                ) : (
                  <Alert status="info">
                    <AlertIcon />
                    {t.gitServer.viewPushHistory}
                  </Alert>
                )}
              </VStack>
            </TabPanel>
          </TabPanels>
        </Tabs>

        {/* 模态框 */}
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
          onSave={updateConfig}
          config={config}
          loading={configLoading}
        />

        <EnvVarModal
          isOpen={isEnvModalOpen}
          onClose={onEnvModalClose}
          onSave={handleSaveEnvVars}
          app={selectedAppForModal}
        />

        <RoutingModal
          isOpen={isRoutingModalOpen}
          onClose={onRoutingModalClose}
          onSave={handleSaveRouting}
          app={selectedAppForModal}
          config={config}
        />

        <DeleteAppModal
          isOpen={isDeleteModalOpen}
          onClose={onDeleteModalClose}
          onDelete={handleDeleteApp}
          app={selectedAppForModal}
        />

        <DeployHistoryDialog
          isOpen={isDeployHistoryOpen}
          onClose={onDeployHistoryClose}
          appName={selectedAppForDeployHistory?.name || ''}
          onOpenLogs={handleOpenDeploymentLogs}
        />
      </Box>
    </>
  )
}

export default GitServerManagement


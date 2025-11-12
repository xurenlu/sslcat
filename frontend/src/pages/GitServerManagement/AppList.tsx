import React, { useState, useMemo } from 'react'
import {
  Box,
  Card,
  CardBody,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  VStack,
  HStack,
  Button,
  Icon,
  Text,
  Badge,
  Code,
  IconButton,
  Input,
  InputGroup,
  InputLeftElement,
  Select,
} from '@chakra-ui/react'
import {
  FiGithub,
  FiCopy,
  FiUpload,
  FiTrash2,
  FiSliders,
  FiGlobe,
  FiSearch,
  FiGitBranch,
  FiPlus,
} from 'react-icons/fi'
import { useTranslation } from '../../hooks/useLanguage'
import { GitApp } from './types'
import { TOAST_DURATION } from '../../constants'
import { useToast } from '@chakra-ui/react'

interface AppListProps {
  apps: GitApp[]
  selectedApp: string
  onSelectApp: (appName: string) => void
  onDeploy: (appName: string) => void
  onDelete: (app: GitApp) => void
  onOpenEnvModal: (app: GitApp) => void
  onOpenRoutingModal: (app: GitApp) => void
  onCreateApp: () => void
}

const AppList: React.FC<AppListProps> = ({
  apps,
  selectedApp,
  onSelectApp,
  onDeploy,
  onDelete,
  onOpenEnvModal,
  onOpenRoutingModal,
  onCreateApp,
}) => {
  const t = useTranslation()
  const toast = useToast()
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [sortField, setSortField] = useState<'name' | 'status' | 'lastDeploy'>('name')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('asc')

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active':
        return 'green'
      case 'deploying':
        return 'blue'
      case 'inactive':
        return 'gray'
      case 'error':
        return 'red'
      default:
        return 'gray'
    }
  }

  const getStatusText = (status: string) => {
    switch (status) {
      case 'active':
        return t.gitServer.statusActive
      case 'deploying':
        return t.gitServer.statusDeploying
      case 'inactive':
        return t.gitServer.statusInactive
      case 'error':
        return t.gitServer.statusError
      default:
        return status
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast({
      title: t.gitServer.copyToClipboard,
      status: 'success',
      duration: TOAST_DURATION.SHORT,
      isClosable: true,
    })
  }

  // 过滤和排序应用列表
  const filteredApps = useMemo(() => {
    let filtered = apps.filter((app) => {
      // 搜索过滤
      const matchesSearch =
        searchQuery === '' ||
        app.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        app.domain?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        app.git_url?.toLowerCase().includes(searchQuery.toLowerCase())

      // 状态过滤
      const matchesStatus = statusFilter === 'all' || app.status === statusFilter

      return matchesSearch && matchesStatus
    })

    // 排序
    filtered = [...filtered].sort((a, b) => {
      let aValue: any
      let bValue: any

      switch (sortField) {
        case 'name':
          aValue = a.name.toLowerCase()
          bValue = b.name.toLowerCase()
          break
        case 'status':
          aValue = a.status
          bValue = b.status
          break
        case 'lastDeploy':
          aValue = a.lastDeploy ? new Date(a.lastDeploy).getTime() : 0
          bValue = b.lastDeploy ? new Date(b.lastDeploy).getTime() : 0
          break
        default:
          return 0
      }

      if (aValue < bValue) return sortOrder === 'asc' ? -1 : 1
      if (aValue > bValue) return sortOrder === 'asc' ? 1 : -1
      return 0
    })

    return filtered
  }, [apps, searchQuery, statusFilter, sortField, sortOrder])

  return (
    <Card>
      <CardBody>
        {/* 搜索和过滤栏 */}
        <HStack spacing={4} mb={4}>
          <InputGroup flex={1} maxW="400px">
            <InputLeftElement pointerEvents="none">
              <Icon as={FiSearch} color="gray.400" />
            </InputLeftElement>
            <Input
              placeholder={t.gitServer.searchPlaceholder}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </InputGroup>
          <Select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            maxW="200px"
          >
            <option value="all">{t.gitServer.allStatuses}</option>
            <option value="active">{t.gitServer.statusActive}</option>
            <option value="deploying">{t.gitServer.statusDeploying}</option>
            <option value="inactive">{t.gitServer.statusInactive}</option>
            <option value="error">{t.gitServer.statusError}</option>
          </Select>
          <Select
            value={sortField}
            onChange={(e) => setSortField(e.target.value as 'name' | 'status' | 'lastDeploy')}
            maxW="150px"
          >
            <option value="name">{t.gitServer.sortByName || '按名称'}</option>
            <option value="status">{t.gitServer.sortByStatus || '按状态'}</option>
            <option value="lastDeploy">{t.gitServer.sortByLastDeploy || '按最后部署'}</option>
          </Select>
          <Button
            size="sm"
            onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
            variant="outline"
          >
            {sortOrder === 'asc' ? '↑' : '↓'}
          </Button>
        </HStack>

        {filteredApps.length === 0 ? (
          <Box textAlign="center" py={8}>
            <Icon as={FiGitBranch} boxSize={12} color="gray.300" mb={4} />
            <Text color="gray.500" mb={4}>
              {apps.length === 0
                ? t.gitServer.noGitApps
                : searchQuery || statusFilter !== 'all'
                ? t.gitServer.noAppsFound
                : t.gitServer.noGitApps}
            </Text>
            {apps.length === 0 && (
              <Button leftIcon={<Icon as={FiPlus} />} colorScheme="blue" onClick={onCreateApp}>
                {t.gitServer.createFirstApp}
              </Button>
            )}
          </Box>
        ) : (
          <Table variant="simple">
            <Thead>
              <Tr>
                <Th>{t.gitServer.select}</Th>
                <Th>{t.gitServer.appName}</Th>
                <Th>{t.gitServer.pushToAddress}</Th>
                <Th>{t.gitServer.status}</Th>
                <Th>{t.gitServer.lastDeploy}</Th>
                <Th>{t.gitServer.actions}</Th>
              </Tr>
            </Thead>
            <Tbody>
              {filteredApps.map((app) => (
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
                      onClick={() => onSelectApp(selectedApp === app.name ? '' : app.name)}
                    >
                      {selectedApp === app.name ? t.gitServer.selected : t.gitServer.select}
                    </Button>
                  </Td>
                  <Td>
                    <VStack align="start" spacing={1}>
                      <HStack>
                        <Icon as={FiGithub} />
                        <Text fontWeight="medium">{app.name}</Text>
                      </HStack>
                      <HStack spacing={2}>
                        <Badge colorScheme="gray">{app.commits || 0} {t.gitServer.commits}</Badge>
                        {app.autoSSL && <Badge colorScheme="green">SSL</Badge>}
                      </HStack>
                      {app.domain && (
                        <Text fontSize="sm" color="gray.600">
                          {t.gitServer.domain}: {app.domain}
                        </Text>
                      )}
                      <Text fontSize="sm" color="gray.600">
                        {t.gitServer.port}: {app.port ?? t.gitServer.unassigned}
                      </Text>
                      {app.git_url && (
                        <HStack spacing={1}>
                          <Text fontSize="xs" color="gray.500">
                            Git:
                          </Text>
                          <Code fontSize="xs" maxW="250px" isTruncated>
                            {app.git_url}
                          </Code>
                          <IconButton
                            aria-label={t.frontend.copy_git_url}
                            icon={<FiCopy />}
                            size="xs"
                            variant="ghost"
                            onClick={() => copyToClipboard(app.git_url || '')}
                          />
                        </HStack>
                      )}
                      <HStack spacing={2}>
                        <Button
                          size="xs"
                          leftIcon={<Icon as={FiSliders} />}
                          variant="ghost"
                          colorScheme="blue"
                          onClick={() => onOpenEnvModal(app)}
                        >
                          {t.gitServer.envVarsTitle}
                        </Button>
                        <Button
                          size="xs"
                          leftIcon={<Icon as={FiGlobe} />}
                          variant="ghost"
                          colorScheme="purple"
                          onClick={() => onOpenRoutingModal(app)}
                        >
                          {t.gitServer.routingTitle}
                        </Button>
                      </HStack>
                    </VStack>
                  </Td>
                  <Td>
                    {app.git_url ? (
                      <VStack align="start" spacing={1}>
                        <Text fontSize="xs" color="gray.500">
                          {t.gitServer.pushToAddress}
                        </Text>
                        <Code fontSize="xs" maxW="200px" isTruncated>
                          {app.git_url}
                        </Code>
                      </VStack>
                    ) : (
                      <Text fontSize="xs" color="gray.400">
                        {t.gitServer.waitingConfig}
                      </Text>
                    )}
                  </Td>
                  <Td>
                    <Badge colorScheme={getStatusColor(app.status)}>
                      {getStatusText(app.status)}
                    </Badge>
                  </Td>
                  <Td>{app.lastDeploy || t.gitServer.notDeployed}</Td>
                  <Td>
                    <HStack spacing={1}>
                      <IconButton
                        aria-label={t.frontend.redeploy}
                        icon={<FiUpload />}
                        size="sm"
                        variant="ghost"
                        colorScheme="green"
                        onClick={() => onDeploy(app.name)}
                        title={t.frontend.trigger_redeploy}
                      />
                      <IconButton
                        aria-label={t.frontend.delete_app}
                        icon={<FiTrash2 />}
                        size="sm"
                        variant="ghost"
                        colorScheme="red"
                        onClick={() => onDelete(app)}
                      />
                    </HStack>
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </CardBody>
    </Card>
  )
}

export default AppList


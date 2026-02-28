import React, { useState, useEffect } from 'react'
import {
  Box,
  Container,
  Heading,
  Text,
  Button,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  IconButton,
  Tooltip,
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
  Textarea,
  VStack,
  HStack,
  Divider,
  Alert,
  AlertIcon,
  Link,
  Spinner,
  Code,
  Flex,
  Input,
  SimpleGrid,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
} from '@chakra-ui/react'
import {
  ChevronLeftIcon,
  ChevronRightIcon,
  DownloadIcon,
  ViewIcon,
  DeleteIcon,
  EditIcon,
  RepeatIcon,
  TimeIcon,
  CheckCircleIcon,
} from '@chakra-ui/icons'
import { FaHistory, FaFileCode } from 'react-icons/fa'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'

interface ConfigVersion {
  id: string
  version: number
  timestamp: string
  hash: string
  file_path: string
  size: number
  author: string
  description: string
  is_auto: boolean
  is_daily: boolean
  date?: string
}

interface VersionStats {
  total_versions: number
  manual_versions: number
  auto_versions: number
  daily_versions: number
  total_size: number
  max_versions: number
  config_file: string
}

interface DiffChange {
  path: string
  old_value?: any
  new_value?: any
  change_type: 'added' | 'removed' | 'modified'
}

const ConfigHistory: React.FC = () => {
  const { adminPrefix } = useConfig()
  const [versions, setVersions] = useState<ConfigVersion[]>([])
  const [stats, setStats] = useState<VersionStats | null>(null)
  const [currentHash, setCurrentHash] = useState<string>('')
  const [loading, setLoading] = useState(true)
  const [selectedVersions, setSelectedVersions] = useState<Set<string>>(new Set())
  const [viewVersion, setViewVersion] = useState<ConfigVersion | null>(null)
  const [viewContent, setViewContent] = useState<any>(null)
  const [showDiff, setShowDiff] = useState(false)
  const [diffChanges, setDiffChanges] = useState<DiffChange[]>([])
  const [showRollbackConfirm, setShowRollbackConfirm] = useState(false)
  const [rollbackVersion, setRollbackVersion] = useState<ConfigVersion | null>(null)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [newVersionDesc, setNewVersionDesc] = useState('')
  const [showEditDescModal, setShowEditDescModal] = useState(false)
  const [editVersionId, setEditVersionId] = useState('')
  const [editVersionDesc, setEditVersionDesc] = useState('')

  const toast = useToast()

  useEffect(() => {
    loadVersions()
  }, [])

  const loadVersions = async () => {
    try {
      const effectivePrefix = adminPrefix || '/sslcat-panel'
      const response = await fetch(buildApiPath(effectivePrefix, '/api/config/versions'), {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          setVersions(data.versions || [])
          setStats(data.stats)
          setCurrentHash(data.current_hash || '')
        }
      }
    } catch (error) {
      toast({
        title: '加载失败',
        description: '无法加载配置版本列表',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  const handleCreateVersion = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix || '/sslcat-panel', '/api/config/versions/create'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          description: newVersionDesc || 'Manual backup',
        }),
      })

      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          toast({
            title: '备份创建成功',
            status: 'success',
            duration: 3000,
            isClosable: true,
          })
          setShowCreateModal(false)
          setNewVersionDesc('')
          loadVersions()
        }
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

  const handleRollback = async () => {
    if (!rollbackVersion) return

    try {
      const response = await fetch(buildApiPath(adminPrefix || '/sslcat-panel', '/api/config/versions/rollback'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ version_id: rollbackVersion.id }),
      })

      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          toast({
            title: '回滚成功',
            description: `配置已回滚到版本 ${rollbackVersion.version}`,
            status: 'success',
            duration: 3000,
            isClosable: true,
          })
          setShowRollbackConfirm(false)
          setRollbackVersion(null)
          loadVersions()
        }
      }
    } catch (error) {
      toast({
        title: '回滚失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const handleDeleteVersion = async (versionId: string) => {
    if (!confirm('确定要删除这个版本吗？此操作不可撤销。')) {
      return
    }

    try {
      const response = await fetch(buildApiPath(adminPrefix || '/sslcat-panel', `/api/config/versions/delete?id=${versionId}`), {
        method: 'DELETE',
        credentials: 'include',
      })

      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          toast({
            title: '删除成功',
            status: 'success',
            duration: 3000,
            isClosable: true,
          })
          loadVersions()
        }
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

  const handleViewVersion = async (version: ConfigVersion) => {
    try {
      const response = await fetch(buildApiPath(adminPrefix || '/sslcat-panel', `/api/config/versions/get?id=${version.id}`), {
        credentials: 'include',
      })

      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          setViewVersion(data.version)
          setViewContent(data.content)
        }
      }
    } catch (error) {
      toast({
        title: '加载失败',
        description: '无法加载版本内容',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const handleCompareVersions = async () => {
    const selectedArray = Array.from(selectedVersions)
    if (selectedArray.length !== 2) {
      toast({
        title: '请选择两个版本',
        description: '请选择两个版本进行比较',
        status: 'warning',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    try {
      const response = await fetch(
        buildApiPath(
          adminPrefix,
          `/api/config/versions/diff?v1=${selectedArray[0]}&v2=${selectedArray[1]}`
        ),
        { credentials: 'include' }
      )

      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          setDiffChanges(Object.values(data.changes || {}))
          setShowDiff(true)
        }
      }
    } catch (error) {
      toast({
        title: '比较失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const handleEditDescription = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix || '/sslcat-panel', '/api/config/versions/update'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          version_id: editVersionId,
          description: editVersionDesc,
        }),
      })

      if (response.ok) {
        const data = await response.json()
        if (data.success) {
          toast({
            title: '更新成功',
            status: 'success',
            duration: 3000,
            isClosable: true,
          })
          setShowEditDescModal(false)
          loadVersions()
        }
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

  const handleExport = (version: ConfigVersion) => {
    window.open(buildApiPath(adminPrefix || '/sslcat-panel', `/api/config/versions/export?id=${version.id}`), '_blank')
  }

  const toggleVersionSelection = (versionId: string) => {
    const newSelected = new Set(selectedVersions)
    if (newSelected.has(versionId)) {
      newSelected.delete(versionId)
    } else {
      newSelected.add(versionId)
      if (newSelected.size > 2) {
        const first = Array.from(newSelected)[0]
        newSelected.delete(first)
      }
    }
    setSelectedVersions(newSelected)
  }

  const formatDate = (timestamp: string) => {
    const date = new Date(timestamp)
    return date.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  }

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`
    return `${(bytes / 1024 / 1024).toFixed(2)} MB`
  }

  const getVersionTypeBadge = (version: ConfigVersion) => {
    if (version.is_daily) {
      return <Badge colorScheme="blue">每日备份</Badge>
    }
    if (version.is_auto) {
      return <Badge colorScheme="gray">自动备份</Badge>
    }
    return <Badge colorScheme="green">手动备份</Badge>
  }

  const getChangeTypeColor = (type: string) => {
    switch (type) {
      case 'added':
        return 'green'
      case 'removed':
        return 'red'
      case 'modified':
        return 'orange'
      default:
        return 'gray'
    }
  }

  const formatValue = (value: any): string => {
    if (value === null || value === undefined) return 'null'
    if (typeof value === 'object') return JSON.stringify(value, null, 2)
    return String(value)
  }

  if (loading) {
    return (
      <Flex h="100vh" align="center" justify="center">
        <Spinner size="xl" />
      </Flex>
    )
  }

  return (
    <Container maxW="container.xl" py={8}>
      <VStack spacing={6} align="stretch">
        {/* Header */}
        <Flex justify="space-between" align="center">
          <HStack spacing={3}>
            <Box as={FaHistory} boxSize={8} color="blue.500" />
            <Heading size="lg">配置历史管理</Heading>
          </HStack>
          <HStack spacing={3}>
            <Button
              leftIcon={<RepeatIcon />}
              onClick={loadVersions}
              variant="outline"
            >
              刷新
            </Button>
            <Button
              leftIcon={<CheckCircleIcon />}
              colorScheme="blue"
              onClick={() => setShowCreateModal(true)}
            >
              创建备份
            </Button>
          </HStack>
        </Flex>

        {/* Stats */}
        {stats && (
          <SimpleGrid columns={{ base: 2, md: 4 }} spacing={4}>
            <Stat>
              <StatLabel>总版本数</StatLabel>
              <StatNumber>{stats.total_versions}</StatNumber>
              <StatHelpText>最多保留 {stats.max_versions} 个版本</StatHelpText>
            </Stat>
            <Stat>
              <StatLabel>手动备份</StatLabel>
              <StatNumber>{stats.manual_versions}</StatNumber>
              <StatHelpText>您创建的备份</StatHelpText>
            </Stat>
            <Stat>
              <StatLabel>自动备份</StatLabel>
              <StatNumber>{stats.auto_versions}</StatNumber>
              <StatHelpText>系统自动创建</StatHelpText>
            </Stat>
            <Stat>
              <StatLabel>每日备份</StatLabel>
              <StatNumber>{stats.daily_versions}</StatNumber>
              <StatHelpText>每日定时备份</StatHelpText>
            </Stat>
          </SimpleGrid>
        )}

        {/* Compare Action */}
        {selectedVersions.size > 0 && (
          <Alert status="info">
            <AlertIcon />
            <Box flex="1">
              已选择 {selectedVersions.size} 个版本进行比较
            </Box>
            {selectedVersions.size === 2 && (
              <Button
                colorScheme="blue"
                size="sm"
                onClick={handleCompareVersions}
              >
                比较差异
              </Button>
            )}
          </Alert>
        )}

        {/* Versions Table */}
        <Box overflowX="auto">
          <Table variant="simple">
            <Thead>
              <Tr>
                <Th width="50px">选择</Th>
                <Th width="80px">版本</Th>
                <Th>描述</Th>
                <Th width="120px">类型</Th>
                <Th width="100px">大小</Th>
                <Th width="100px">作者</Th>
                <Th width="180px">创建时间</Th>
                <Th width="220px">操作</Th>
              </Tr>
            </Thead>
            <Tbody>
              {versions.map((version) => (
                <Tr key={version.id}>
                  <Td>
                    <input
                      type="checkbox"
                      checked={selectedVersions.has(version.id)}
                      onChange={() => toggleVersionSelection(version.id)}
                    />
                  </Td>
                  <Td>
                    <Badge colorScheme="blue">v{version.version}</Badge>
                  </Td>
                  <Td maxW="300px" noOfLines={2}>
                    {version.description || '-'}
                  </Td>
                  <Td>{getVersionTypeBadge(version)}</Td>
                  <Td>{formatSize(version.size)}</Td>
                  <Td>{version.author || '-'}</Td>
                  <Td>{formatDate(version.timestamp)}</Td>
                  <Td>
                    <HStack spacing={2}>
                      <Tooltip label="查看">
                        <IconButton
                          aria-label="查看"
                          icon={<ViewIcon />}
                          size="sm"
                          variant="ghost"
                          onClick={() => handleViewVersion(version)}
                        />
                      </Tooltip>
                      <Tooltip label="编辑描述">
                        <IconButton
                          aria-label="编辑描述"
                          icon={<EditIcon />}
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            setEditVersionId(version.id)
                            setEditVersionDesc(version.description || '')
                            setShowEditDescModal(true)
                          }}
                        />
                      </Tooltip>
                      <Tooltip label="导出">
                        <IconButton
                          aria-label="导出"
                          icon={<DownloadIcon />}
                          size="sm"
                          variant="ghost"
                          onClick={() => handleExport(version)}
                        />
                      </Tooltip>
                      <Tooltip label="回滚">
                        <IconButton
                          aria-label="回滚"
                          icon={<RepeatIcon />}
                          size="sm"
                          variant="ghost"
                          colorScheme="orange"
                          onClick={() => {
                            setRollbackVersion(version)
                            setShowRollbackConfirm(true)
                          }}
                        />
                      </Tooltip>
                      {!version.is_auto && (
                        <Tooltip label="删除">
                          <IconButton
                            aria-label="删除"
                            icon={<DeleteIcon />}
                            size="sm"
                            variant="ghost"
                            colorScheme="red"
                            onClick={() => handleDeleteVersion(version.id)}
                          />
                        </Tooltip>
                      )}
                    </HStack>
                  </Td>
                </Tr>
              ))}
              {versions.length === 0 && (
                <Tr>
                  <Td colSpan={8} textAlign="center" py={8}>
                    <Text color="gray.500">暂无配置版本</Text>
                  </Td>
                </Tr>
              )}
            </Tbody>
          </Table>
        </Box>

        {/* Info */}
        <Alert status="info">
          <AlertIcon />
          <Box>
            <Text fontWeight="bold">提示：</Text>
            <Text>
              • 选择两个版本可以查看配置差异
              <br />
              • 每次保存配置时会自动创建备份
              <br />
              • 手动创建的备份不会被自动清理
              <br />
              • 回滚前会自动备份当前配置
            </Text>
          </Box>
        </Alert>
      </VStack>

      {/* Create Version Modal */}
      <Modal isOpen={showCreateModal} onClose={() => setShowCreateModal(false)}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>创建配置备份</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <Alert status="info">
                <AlertIcon />
                <Text>创建当前配置的手动备份快照</Text>
              </Alert>
              <FormControl>
                <FormLabel>描述</FormLabel>
                <Textarea
                  value={newVersionDesc}
                  onChange={(e) => setNewVersionDesc(e.target.value)}
                  placeholder="为这个备份添加描述..."
                  rows={3}
                />
              </FormControl>
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button variant="ghost" onClick={() => setShowCreateModal(false)}>
              取消
            </Button>
            <Button colorScheme="blue" onClick={handleCreateVersion}>
              创建备份
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* Edit Description Modal */}
      <Modal isOpen={showEditDescModal} onClose={() => setShowEditDescModal(false)}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>编辑版本描述</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <FormControl>
              <FormLabel>描述</FormLabel>
              <Textarea
                value={editVersionDesc}
                onChange={(e) => setEditVersionDesc(e.target.value)}
                placeholder="为这个版本添加描述..."
                rows={3}
              />
            </FormControl>
          </ModalBody>
          <ModalFooter>
            <Button variant="ghost" onClick={() => setShowEditDescModal(false)}>
              取消
            </Button>
            <Button colorScheme="blue" onClick={handleEditDescription}>
              保存
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* Rollback Confirm Modal */}
      <Modal isOpen={showRollbackConfirm} onClose={() => setShowRollbackConfirm(false)}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>确认回滚</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <Alert status="warning">
                <AlertIcon />
                <Box>
                  <Text fontWeight="bold">警告：此操作将覆盖当前配置！</Text>
                  <Text mt={2}>
                    回滚前会自动创建当前配置的备份，以防需要恢复。
                  </Text>
                </Box>
              </Alert>
              {rollbackVersion && (
                <Box>
                  <Text fontWeight="bold">将回滚到：</Text>
                  <Text>版本 {rollbackVersion.version}</Text>
                  <Text>{rollbackVersion.description}</Text>
                  <Text fontSize="sm" color="gray.500">
                    {formatDate(rollbackVersion.timestamp)}
                  </Text>
                </Box>
              )}
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button variant="ghost" onClick={() => setShowRollbackConfirm(false)}>
              取消
            </Button>
            <Button colorScheme="red" onClick={handleRollback}>
              确认回滚
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* View Version Modal */}
      {viewVersion && (
        <Modal
          isOpen={!!viewVersion}
          onClose={() => {
            setViewVersion(null)
            setViewContent(null)
          }}
          size="6xl"
        >
          <ModalOverlay />
          <ModalContent maxW="90vw" maxH="90vh">
            <ModalHeader>
              版本 {viewVersion.version} - {viewVersion.description}
            </ModalHeader>
            <ModalCloseButton />
            <ModalBody overflowY="auto" maxH="70vh">
              <Code p={4} bg="gray.50" borderRadius="md" display="block" whiteSpace="pre">
                {JSON.stringify(viewContent, null, 2)}
              </Code>
            </ModalBody>
          </ModalContent>
        </Modal>
      )}

      {/* Diff Modal */}
      <Modal isOpen={showDiff} onClose={() => setShowDiff(false)} size="6xl">
        <ModalOverlay />
        <ModalContent maxW="90vw" maxH="90vh">
          <ModalHeader>配置差异比较</ModalHeader>
          <ModalCloseButton />
          <ModalBody overflowY="auto" maxH="70vh">
            <VStack spacing={4} align="stretch">
              {diffChanges.length === 0 ? (
                <Alert status="success">
                  <AlertIcon />
                  <Text>两个版本完全相同，没有差异</Text>
                </Alert>
              ) : (
                diffChanges.map((change, index) => (
                  <Box
                    key={index}
                    p={4}
                    borderWidth="1px"
                    borderRadius="md"
                    borderColor={`${getChangeTypeColor(change.change_type)}.200`}
                    bg={`${getChangeTypeColor(change.change_type)}.50`}
                  >
                    <HStack spacing={3} mb={2}>
                      <Badge colorScheme={getChangeTypeColor(change.change_type)}>
                        {change.change_type === 'added' && '新增'}
                        {change.change_type === 'removed' && '删除'}
                        {change.change_type === 'modified' && '修改'}
                      </Badge>
                      <Text fontWeight="bold" fontFamily="mono">
                        {change.path}
                      </Text>
                    </HStack>
                    <SimpleGrid columns={2} spacing={4}>
                      {change.change_type !== 'added' && (
                        <Box>
                          <Text fontSize="sm" color="gray.500" mb={1}>
                            旧值
                          </Text>
                          <Code
                            p={2}
                            bg="red.50"
                            borderRadius="md"
                            display="block"
                            whiteSpace="pre-wrap"
                            wordBreak="break-all"
                          >
                            {formatValue(change.old_value)}
                          </Code>
                        </Box>
                      )}
                      {change.change_type !== 'removed' && (
                        <Box>
                          <Text fontSize="sm" color="gray.500" mb={1}>
                            新值
                          </Text>
                          <Code
                            p={2}
                            bg="green.50"
                            borderRadius="md"
                            display="block"
                            whiteSpace="pre-wrap"
                            wordBreak="break-all"
                          >
                            {formatValue(change.new_value)}
                          </Code>
                        </Box>
                      )}
                    </SimpleGrid>
                  </Box>
                ))
              )}
            </VStack>
          </ModalBody>
        </ModalContent>
      </Modal>
    </Container>
  )
}

export default ConfigHistory

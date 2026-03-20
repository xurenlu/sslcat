import React, { useState, useMemo } from 'react'
import {
  Box,
  VStack,
  HStack,
  SimpleGrid,
  Input,
  InputGroup,
  InputLeftElement,
  Icon,
  Button,
  Select,
  Text,
  Flex,
  Card,
  CardBody,
  useColorModeValue,
} from '@chakra-ui/react'
import {
  FiSearch,
  FiFilter,
  FiPlus,
  FiRefreshCw,
  FiGithub,
} from 'react-icons/fi'
import { useTranslation } from '../../hooks/useLanguage'
import { GitApp } from './types'
import AppCard from './AppCard'

interface AppCardGridProps {
  apps: GitApp[]
  loading: boolean
  onRefresh: () => void
  onDeploy: (appName: string) => void
  onDelete: (app: GitApp) => void
  onOpenEnvModal: (app: GitApp) => void
  onOpenRoutingModal: (app: GitApp) => void
  onCreateApp: () => void
}

const AppCardGrid: React.FC<AppCardGridProps> = ({
  apps,
  loading,
  onRefresh,
  onDeploy,
  onDelete,
  onOpenEnvModal,
  onOpenRoutingModal,
  onCreateApp,
}) => {
  const t = useTranslation()
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')

  // 过滤和排序应用列表
  const filteredApps = useMemo(() => {
    let filtered = apps.filter((app) => {
      // 搜索过滤
      const matchesSearch =
        searchQuery === '' ||
        app.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        app.domain?.toLowerCase().includes(searchQuery.toLowerCase())

      // 状态过滤
      const matchesStatus = statusFilter === 'all' || app.status === statusFilter

      return matchesSearch && matchesStatus
    })

    return filtered
  }, [apps, searchQuery, statusFilter])

  const bg = useColorModeValue('white', 'gray.800')

  return (
    <VStack spacing={6} align="stretch">
      {/* 工具栏 */}
      <Card bg={bg} borderRadius="12px" boxShadow="sm">
        <CardBody>
          <Flex justify="space-between" align="center" flexWrap="wrap" gap={4}>
            {/* 搜索框 */}
            <InputGroup maxW="400px" flex={1}>
              <InputLeftElement pointerEvents="none">
                <Icon as={FiSearch} color="gray.400" />
              </InputLeftElement>
              <Input
                placeholder="搜索应用名称或域名..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                borderRadius="8px"
              />
            </InputGroup>

            {/* 过滤器和操作 */}
            <HStack spacing={3}>
              <Select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                w="180px"
                borderRadius="8px"
              >
                <option value="all">全部状态</option>
                <option value="active">{t.gitServer.statusActive}</option>
                <option value="deploying">{t.gitServer.statusDeploying}</option>
                <option value="inactive">{t.gitServer.statusInactive}</option>
                <option value="error">{t.gitServer.statusError}</option>
              </Select>

              <Button
                leftIcon={<Icon as={FiRefreshCw} />}
                onClick={onRefresh}
                isLoading={loading}
                variant="outline"
                borderRadius="8px"
              >
                刷新
              </Button>

              <Button
                leftIcon={<Icon as={FiPlus} />}
                colorScheme="blue"
                onClick={onCreateApp}
                borderRadius="8px"
              >
                新建应用
              </Button>
            </HStack>
          </Flex>

          {/* 统计信息 */}
          <HStack mt={4} spacing={6} fontSize="sm" color="gray.600">
            <Text>
              共 <Text as="strong" color="blue.500">{apps.length}</Text> 个应用
            </Text>
            <Text>•</Text>
            <Text>
              显示 <Text as="strong" color="green.500">{filteredApps.length}</Text> 个
            </Text>
            {statusFilter !== 'all' && (
              <>
                <Text>•</Text>
                <Text>筛选: {statusFilter}</Text>
              </>
            )}
            {searchQuery && (
              <>
                <Text>•</Text>
                <Text>搜索: "{searchQuery}"</Text>
              </>
            )}
          </HStack>
        </CardBody>
      </Card>

      {/* 应用卡片网格 */}
      {filteredApps.length === 0 ? (
        <Card bg={bg} borderRadius="16px" p={12} textAlign="center">
          <VStack spacing={4}>
            <Icon as={FiGithub} boxSize={16} color="gray.300" />
            <Text fontSize="xl" fontWeight="600" color="gray.500">
              {apps.length === 0 ? '还没有应用' : '没有找到匹配的应用'}
            </Text>
            {apps.length === 0 && (
              <Button leftIcon={<Icon as={FiPlus} />} colorScheme="blue" onClick={onCreateApp}>
                创建第一个应用
              </Button>
            )}
            {(searchQuery || statusFilter !== 'all') && (
              <Button variant="outline" onClick={() => { setSearchQuery(''); setStatusFilter('all') }}>
                清除筛选
              </Button>
            )}
          </VStack>
        </Card>
      ) : (
        <SimpleGrid columns={{ base: 1, lg: 2, xl: 2 }} spacing={6}>
          {filteredApps.map((app) => (
            <AppCard
              key={app.name}
              app={app}
              onDeploy={onDeploy}
              onDelete={onDelete}
              onOpenEnvModal={onOpenEnvModal}
              onOpenRoutingModal={onOpenRoutingModal}
            />
          ))}
        </SimpleGrid>
      )}
    </VStack>
  )
}

export default AppCardGrid

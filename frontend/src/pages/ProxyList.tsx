import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  Button,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Card,
  CardBody,
  HStack,
  Badge,
  Icon,
  Flex,
  Text,
  IconButton,
  useToast,
  Switch,
  Tooltip,
} from '@chakra-ui/react'
import {
  FiPlus,
  FiRefreshCw,
  FiEdit,
  FiTrash2,
  FiZap,
  FiGlobe,
} from 'react-icons/fi'

interface ProxyRule {
  id: string
  domain: string
  target: string
  enabled: boolean
  ssl: boolean
  created: string
}

const ProxyList: React.FC = () => {
  const [rules, setRules] = useState<ProxyRule[]>([])
  const [loading, setLoading] = useState(false)
  const toast = useToast()

  const refreshRules = async () => {
    setLoading(true)
    try {
      // TODO: 实际的 API 调用
      setTimeout(() => {
        setRules([
          {
            id: '1',
            domain: 'example.com',
            target: 'http://localhost:3000',
            enabled: true,
            ssl: true,
            created: '2024-01-15',
          },
          {
            id: '2',
            domain: 'api.example.com',
            target: 'http://localhost:8080',
            enabled: true,
            ssl: true,
            created: '2024-01-14',
          },
          {
            id: '3',
            domain: 'test.example.com',
            target: 'http://localhost:4000',
            enabled: false,
            ssl: false,
            created: '2024-01-13',
          },
        ])
        setLoading(false)
      }, 1000)
    } catch (error) {
      console.error('获取代理规则失败:', error)
      setLoading(false)
    }
  }

  const deleteRule = async (id: string) => {
    // 添加确认对话框
    if (!window.confirm('确定要删除这个代理规则吗？此操作不可撤销。')) {
      return
    }

    try {
      // TODO: 实际的 API 调用
      setRules(rules.filter(rule => rule.id !== id))
      toast({
        title: '删除成功',
        description: '代理规则已成功删除',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
    } catch (error) {
      toast({
        title: '删除失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 4000,
        isClosable: true,
      })
    }
  }

  const toggleRule = async (id: string, enabled: boolean) => {
    try {
      setRules(rules.map(rule => 
        rule.id === id ? { ...rule, enabled } : rule
      ))
      toast({
        title: enabled ? '代理规则已启用' : '代理规则已禁用',
        description: '规则状态更新成功',
        status: 'success',
        duration: 2000,
        isClosable: true,
      })
    } catch (error) {
      toast({
        title: '状态更新失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  useEffect(() => {
    refreshRules()
  }, [])

  return (
    <Box>
      <Flex justify="space-between" align="center" mb={6}>
        <HStack>
          <Icon as={FiZap} boxSize={6} />
          <Heading size="lg">代理配置</Heading>
        </HStack>
        <HStack>
          <Button
            leftIcon={<Icon as={FiRefreshCw} />}
            onClick={refreshRules}
            isLoading={loading}
            variant="outline"
          >
            刷新
          </Button>
          <Button
            leftIcon={<Icon as={FiPlus} />}
            colorScheme="blue"
          >
            新增规则
          </Button>
        </HStack>
      </Flex>

      <Card>
        <CardBody>
          {rules.length > 0 ? (
            <Table variant="simple">
              <Thead>
                <Tr>
                  <Th>域名</Th>
                  <Th>目标地址</Th>
                  <Th>状态</Th>
                  <Th>SSL</Th>
                  <Th>创建时间</Th>
                  <Th>操作</Th>
                </Tr>
              </Thead>
              <Tbody>
                {rules.map((rule) => (
                  <Tr key={rule.id}>
                    <Td>
                      <HStack>
                        <Icon as={FiGlobe} />
                        <Text fontFamily="mono">{rule.domain}</Text>
                      </HStack>
                    </Td>
                    <Td>
                      <Text fontFamily="mono" fontSize="sm">
                        {rule.target}
                      </Text>
                    </Td>
                            <Td>
                              <Tooltip label={rule.enabled ? '点击禁用' : '点击启用'}>
                                <Switch
                                  isChecked={rule.enabled}
                                  onChange={(e) => toggleRule(rule.id, e.target.checked)}
                                  colorScheme="green"
                                />
                              </Tooltip>
                            </Td>
                    <Td>
                      <Badge colorScheme={rule.ssl ? 'blue' : 'orange'}>
                        {rule.ssl ? 'HTTPS' : 'HTTP'}
                      </Badge>
                    </Td>
                    <Td>{rule.created}</Td>
                    <Td>
                      <HStack spacing={2}>
                        <IconButton
                          aria-label="编辑"
                          icon={<FiEdit />}
                          size="sm"
                          variant="ghost"
                        />
                        <IconButton
                          aria-label="删除"
                          icon={<FiTrash2 />}
                          size="sm"
                          variant="ghost"
                          colorScheme="red"
                          onClick={() => deleteRule(rule.id)}
                        />
                      </HStack>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          ) : (
            <Box textAlign="center" py={8}>
              <Icon as={FiZap} boxSize={12} color="gray.300" mb={4} />
              <Text color="gray.500" mb={4}>暂无代理规则</Text>
              <Button leftIcon={<Icon as={FiPlus} />} colorScheme="blue">
                创建第一个规则
              </Button>
            </Box>
          )}
        </CardBody>
      </Card>
    </Box>
  )
}

export default ProxyList

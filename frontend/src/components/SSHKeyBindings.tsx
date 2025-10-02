import React, { useState, useEffect } from 'react'
import {
  Box,
  VStack,
  HStack,
  Button,
  Text,
  Badge,
  Icon,
  IconButton,
  useToast,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalFooter,
  ModalCloseButton,
  useDisclosure,
  Select,
  Alert,
  AlertIcon,
  AlertDescription,
  Spinner,
  Flex,
  Code,
  Tooltip,
} from '@chakra-ui/react'
import {
  FiKey,
  FiPlus,
  FiTrash2,
  FiLock,
  FiUnlock,
  FiAlertCircle,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'

interface SSHKey {
  id: string
  name: string
  public_key: string
  fingerprint: string
  created_at: string
  last_used: string
  enabled: boolean
}

interface SSHKeyBindingsProps {
  appName: string
  allowedKeys: string[]
  onUpdate?: () => void
}

const SSHKeyBindings: React.FC<SSHKeyBindingsProps> = ({
  appName,
  allowedKeys = [],
  onUpdate,
}) => {
  const { adminPrefix } = useConfig()
  const [allKeys, setAllKeys] = useState<SSHKey[]>([])
  const [loading, setLoading] = useState(false)
  const [selectedKey, setSelectedKey] = useState('')
  const { isOpen, onOpen, onClose } = useDisclosure()
  const toast = useToast()

  const fetchAllKeys = async () => {
    setLoading(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/git-server/ssh-keys'))
      const data = await response.json()
      if (data.success) {
        setAllKeys(data.data || [])
      }
    } catch (error) {
      console.error('获取SSH密钥列表失败:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAllKeys()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const handleBindKey = async () => {
    if (!selectedKey) {
      toast({
        title: '请选择密钥',
        status: 'warning',
        duration: 2000,
      })
      return
    }

    try {
      const response = await fetch(buildApiPath(adminPrefix, '/git-server/app/bind-key'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          app_name: appName,
          key_fingerprint: selectedKey,
        }),
      })

      const data = await response.json()
      if (data.success) {
        toast({
          title: '绑定成功',
          status: 'success',
          duration: 2000,
        })
        onClose()
        setSelectedKey('')
        if (onUpdate) onUpdate()
      } else {
        toast({
          title: '绑定失败',
          description: data.error || '未知错误',
          status: 'error',
          duration: 3000,
        })
      }
    } catch (error) {
      toast({
        title: '网络错误',
        status: 'error',
        duration: 3000,
      })
    }
  }

  const handleUnbindKey = async (fingerprint: string) => {
    if (!confirm('确定要解绑此密钥吗？')) return

    try {
      const response = await fetch(buildApiPath(adminPrefix, '/git-server/app/unbind-key'), {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          app_name: appName,
          key_fingerprint: fingerprint,
        }),
      })

      const data = await response.json()
      if (data.success) {
        toast({
          title: '解绑成功',
          status: 'success',
          duration: 2000,
        })
        if (onUpdate) onUpdate()
      } else {
        toast({
          title: '解绑失败',
          description: data.error || '未知错误',
          status: 'error',
          duration: 3000,
        })
      }
    } catch (error) {
      toast({
        title: '网络错误',
        status: 'error',
        duration: 3000,
      })
    }
  }

  const getBoundKeys = () => {
    return allKeys.filter((key) => allowedKeys.includes(key.fingerprint))
  }

  const getUnboundKeys = () => {
    return allKeys.filter((key) => !allowedKeys.includes(key.fingerprint))
  }

  const boundKeys = getBoundKeys()
  const unboundKeys = getUnboundKeys()

  return (
    <Box>
      <VStack align="stretch" spacing={4}>
        {/* 权限说明 */}
        <Alert status="info" borderRadius="md">
          <AlertIcon />
          <Box flex="1">
            <AlertDescription fontSize="sm">
              {allowedKeys.length === 0 ? (
                <HStack>
                  <Icon as={FiUnlock} />
                  <Text>
                    当前应用未设置密钥限制，所有已添加的SSH密钥都可以推送到此应用。
                  </Text>
                </HStack>
              ) : (
                <HStack>
                  <Icon as={FiLock} />
                  <Text>
                    当前应用已设置密钥限制，只有绑定的 {allowedKeys.length} 个密钥可以推送。
                  </Text>
                </HStack>
              )}
            </AlertDescription>
          </Box>
        </Alert>

        {/* 操作按钮 */}
        <HStack justify="space-between">
          <Text fontWeight="bold">绑定的SSH密钥</Text>
          <Button
            leftIcon={<Icon as={FiPlus} />}
            onClick={onOpen}
            size="sm"
            colorScheme="blue"
            isDisabled={unboundKeys.length === 0}
          >
            绑定密钥
          </Button>
        </HStack>

        {/* 绑定的密钥列表 */}
        {loading ? (
          <Flex justify="center" py={8}>
            <Spinner />
          </Flex>
        ) : boundKeys.length === 0 ? (
          <Box textAlign="center" py={8} bg="gray.50" borderRadius="md">
            <Icon as={FiKey} boxSize={10} color="gray.400" mb={2} />
            <Text color="gray.500">暂无绑定的密钥</Text>
            <Text color="gray.400" fontSize="sm" mt={1}>
              所有SSH密钥都可以推送到此应用
            </Text>
          </Box>
        ) : (
          <Box overflowX="auto" borderWidth="1px" borderRadius="md">
            <Table variant="simple" size="sm">
              <Thead bg="gray.50">
                <Tr>
                  <Th>密钥名称</Th>
                  <Th>指纹</Th>
                  <Th>创建时间</Th>
                  <Th>状态</Th>
                  <Th>操作</Th>
                </Tr>
              </Thead>
              <Tbody>
                {boundKeys.map((key) => (
                  <Tr key={key.id}>
                    <Td>
                      <HStack>
                        <Icon as={FiKey} color="green.500" />
                        <Text fontWeight="medium">{key.name}</Text>
                      </HStack>
                    </Td>
                    <Td>
                      <Tooltip label={key.fingerprint}>
                        <Code fontSize="xs" maxW="200px" isTruncated>
                          {key.fingerprint}
                        </Code>
                      </Tooltip>
                    </Td>
                    <Td>
                      <Text fontSize="sm">
                        {new Date(key.created_at).toLocaleDateString('zh-CN')}
                      </Text>
                    </Td>
                    <Td>
                      {key.enabled ? (
                        <Badge colorScheme="green">已启用</Badge>
                      ) : (
                        <Badge colorScheme="gray">已禁用</Badge>
                      )}
                    </Td>
                    <Td>
                      <IconButton
                        aria-label="解绑密钥"
                        icon={<FiTrash2 />}
                        size="sm"
                        colorScheme="red"
                        variant="ghost"
                        onClick={() => handleUnbindKey(key.fingerprint)}
                      />
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </Box>
        )}

        {/* 未绑定的密钥提示 */}
        {unboundKeys.length > 0 && (
          <Alert status="warning" borderRadius="md">
            <AlertIcon as={FiAlertCircle} />
            <AlertDescription fontSize="sm">
              还有 {unboundKeys.length} 个SSH密钥未绑定到此应用。
            </AlertDescription>
          </Alert>
        )}
      </VStack>

      {/* 绑定密钥模态框 */}
      <Modal isOpen={isOpen} onClose={onClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>绑定SSH密钥</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack align="stretch" spacing={4}>
              <Text fontSize="sm" color="gray.600">
                选择要绑定到应用 <Code>{appName}</Code> 的SSH密钥：
              </Text>

              <Select
                placeholder="选择SSH密钥"
                value={selectedKey}
                onChange={(e) => setSelectedKey(e.target.value)}
              >
                {unboundKeys.map((key) => (
                  <option key={key.id} value={key.fingerprint}>
                    {key.name} - {key.fingerprint.substring(0, 20)}...
                  </option>
                ))}
              </Select>

              {selectedKey && (
                <Box p={3} bg="blue.50" borderRadius="md">
                  <Text fontSize="sm" color="blue.700">
                    <Icon as={FiAlertCircle} mr={2} />
                    绑定后，只有选中的密钥才能推送到此应用。
                  </Text>
                </Box>
              )}
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onClose}>
              取消
            </Button>
            <Button
              colorScheme="blue"
              onClick={handleBindKey}
              isDisabled={!selectedKey}
            >
              确认绑定
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default SSHKeyBindings


import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  Card,
  CardBody,
  CardHeader,
  VStack,
  HStack,
  Button,
  Icon,
  useToast,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  Text,
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
  Select,
  Switch,
  useDisclosure,
  Alert,
  AlertIcon,
  Spinner,
  Center,
  Tooltip,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  IconButton,
} from '@chakra-ui/react'
import {
  FiUsers,
  FiPlus,
  FiEdit,
  FiTrash2,
  FiMoreVertical,
  FiShield,
  FiUser,
  FiEye,
  FiEyeOff,
  FiRefreshCw,
} from 'react-icons/fi'
import { useConfig } from '../contexts/ConfigContext'
import { useAuth } from '../contexts/AuthContext'
import { useTranslation } from '../hooks/useLanguage'

interface User {
  id: number
  username: string
  role: string
  email: string
  is_active: boolean
  created_at: string
  last_login_at: string
  created_by: string
}

const UserManagement: React.FC = () => {
  const { adminPrefix } = useConfig()
  const { user } = useAuth()
  const toast = useToast()
  const t = useTranslation()
  const { isOpen: isAddOpen, onOpen: onAddOpen, onClose: onAddClose } = useDisclosure()
  const { isOpen: isEditOpen, onOpen: onEditOpen, onClose: onEditClose } = useDisclosure()
  const { isOpen: isDeleteOpen, onOpen: onDeleteOpen, onClose: onDeleteClose } = useDisclosure()

  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [selectedUser, setSelectedUser] = useState<User | null>(null)
  const [actionLoading, setActionLoading] = useState(false)

  // 添加用户表单
  const [addForm, setAddForm] = useState({
    username: '',
    password: '',
    confirmPassword: '',
    role: 'viewer',
    email: '',
  })

  // 编辑用户表单
  const [editForm, setEditForm] = useState({
    username: '',
    password: '',
    confirmPassword: '',
    role: 'viewer',
    email: '',
    is_active: true,
  })

  const roleLabels = {
    super_admin: t.userManagement.superAdmin,
    admin: t.userManagement.admin,
    operator: t.userManagement.operator,
    viewer: t.userManagement.readOnly,
  }

  const roleColors = {
    super_admin: 'red',
    admin: 'blue',
    operator: 'green',
    viewer: 'gray',
  }

  const canManageUsers = user?.role === 'super_admin' || user?.role === 'admin'

  // 获取用户列表
  const fetchUsers = async () => {
    try {
      setLoading(true)
      console.log('尝试获取用户列表，adminPrefix:', adminPrefix)
      const response = await fetch(`${adminPrefix}/api/users`, {
        credentials: 'include',
      })
      
      console.log('用户列表API响应状态:', response.status)
      
      if (response.ok) {
        const data = await response.json()
        console.log('用户列表数据:', data)
        setUsers(data.users || [])
      } else {
        const errorText = await response.text()
        console.error('获取用户列表失败:', response.status, errorText)
        toast({
          title: '获取用户列表失败',
          description: `状态码: ${response.status}${errorText ? ` - ${errorText}` : ''}`,
          status: 'error',
          duration: 5000,
          isClosable: true,
        })
      }
    } catch (error) {
      console.error('获取用户列表失败:', error)
      toast({
        title: '获取用户列表失败',
        description: error instanceof Error ? error.message : '网络连接错误',
        status: 'error',
        duration: 5000,
        isClosable: true,
      })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    // 检查用户权限
    if (!user) {
      console.warn('用户未登录，无法访问用户管理页面')
      return
    }
    
    if (!canManageUsers) {
      console.warn('当前用户权限不足，无法管理用户')
      toast({
        title: '权限不足',
        description: '您没有权限访问用户管理功能',
        status: 'warning',
        duration: 5000,
        isClosable: true,
      })
      return
    }
    
    console.log('当前用户信息:', user)
    fetchUsers()
  }, [user, canManageUsers])

  // 添加用户
  const handleAddUser = async () => {
    // 前端验证
    if (!addForm.username || addForm.username.trim().length < 3) {
      toast({
        title: '用户名长度至少3个字符',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    // 禁止使用 "admin" 作为用户名
    if (addForm.username.toLowerCase() === 'admin') {
      toast({
        title: '用户名不能为 "admin"',
        description: 'admin 是保留用户名，不能使用',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    if (!addForm.password || addForm.password.length < 6) {
      toast({
        title: '密码长度至少6个字符',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    if (addForm.password !== addForm.confirmPassword) {
      toast({
        title: '密码确认不匹配',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    if (!addForm.role) {
      toast({
        title: '请选择用户角色',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    setActionLoading(true)
    try {
      const response = await fetch(`${adminPrefix}/api/users`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          username: addForm.username,
          password: addForm.password,
          role: addForm.role,
          email: addForm.email,
        }),
      })

      if (response.ok) {
        toast({
          title: t.users.userCreated,
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        onAddClose()
        setAddForm({
          username: '',
          password: '',
          confirmPassword: '',
          role: 'viewer',
          email: '',
        })
        fetchUsers()
      } else {
        const error = await response.json()
        toast({
          title: t.users.userCreateFailed,
          description: error.error || t.common.unknownError,
          status: 'error',
          duration: 3000,
          isClosable: true,
        })
      }
    } catch (error) {
      console.error('创建用户失败:', error)
      toast({
        title: t.users.userCreateFailed,
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setActionLoading(false)
    }
  }

  // 编辑用户
  const handleEditUser = async () => {
    // 前端验证
    if (editForm.password && editForm.password.length < 6) {
      toast({
        title: '密码长度至少6个字符',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    if (editForm.password && editForm.password !== editForm.confirmPassword) {
      toast({
        title: '密码确认不匹配',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    if (!editForm.role) {
      toast({
        title: '请选择用户角色',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
      return
    }

    setActionLoading(true)
    try {
      const response = await fetch(`${adminPrefix}/api/users/${selectedUser?.username}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          password: editForm.password || undefined,
          role: editForm.role,
          email: editForm.email,
          is_active: editForm.is_active,
        }),
      })

      if (response.ok) {
        toast({
          title: '用户更新成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        onEditClose()
        setSelectedUser(null)
        fetchUsers()
      } else {
        const error = await response.json()
        toast({
          title: '更新用户失败',
          description: error.error || '未知错误',
          status: 'error',
          duration: 3000,
          isClosable: true,
        })
      }
    } catch (error) {
      console.error('更新用户失败:', error)
      toast({
        title: '更新用户失败',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setActionLoading(false)
    }
  }

  // 删除用户
  const handleDeleteUser = async () => {
    if (!selectedUser) return

    setActionLoading(true)
    try {
      const response = await fetch(`${adminPrefix}/api/users/${selectedUser.username}`, {
        method: 'DELETE',
        credentials: 'include',
      })

      if (response.ok) {
        toast({
          title: '用户删除成功',
          status: 'success',
          duration: 3000,
          isClosable: true,
        })
        onDeleteClose()
        setSelectedUser(null)
        fetchUsers()
      } else {
        const error = await response.json()
        toast({
          title: '删除用户失败',
          description: error.error || '未知错误',
          status: 'error',
          duration: 3000,
          isClosable: true,
        })
      }
    } catch (error) {
      console.error('删除用户失败:', error)
      toast({
        title: '删除用户失败',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    } finally {
      setActionLoading(false)
    }
  }

  const openEditModal = (user: User) => {
    setSelectedUser(user)
    setEditForm({
      username: user.username,
      password: '',
      confirmPassword: '',
      role: user.role,
      email: user.email,
      is_active: user.is_active,
    })
    onEditOpen()
  }

  const openDeleteModal = (user: User) => {
    setSelectedUser(user)
    onDeleteOpen()
  }

  const formatDate = (dateString: string) => {
    if (!dateString) return '从未登录'
    return new Date(dateString).toLocaleString('zh-CN')
  }
  const canDeleteUser = (targetUser: User) => {
    // 不能删除自己
    if (targetUser.username === user?.username) return false
    // 超级管理员可以删除任何人
    if (user?.role === 'super_admin') return true
    // 管理员不能删除超级管理员
    if (user?.role === 'admin' && targetUser.role === 'super_admin') return false
    return true
  }

  if (loading) {
    return (
      <Center h="400px">
        <Spinner size="xl" />
      </Center>
    )
  }

  return (
    <Box p={6}>
      <VStack spacing={6} align="stretch">
        {/* 页面标题 */}
        <HStack justify="space-between">
          <Heading size="lg" display="flex" alignItems="center" gap={2}>
            <Icon as={FiUsers} />
            {t.userManagement.title}
          </Heading>
          <HStack>
            <Button
              leftIcon={<Icon as={FiRefreshCw} />}
              variant="outline"
              onClick={fetchUsers}
            >
              {t.userManagement.refresh}
            </Button>
            {canManageUsers && (
              <Button
                leftIcon={<Icon as={FiPlus} />}
                colorScheme="brand"
                onClick={onAddOpen}
              >
                {t.userManagement.addUser}
              </Button>
            )}
          </HStack>
        </HStack>

        {/* 用户列表 */}
        <Card>
          <CardHeader>
            <Text fontSize="lg" fontWeight="medium">
              {t.userManagement.title} ({users.length})
            </Text>
          </CardHeader>
          <CardBody>
            <Table variant="simple">
              <Thead>
                <Tr>
                  <Th>{t.userManagement.username}</Th>
                  <Th>{t.userManagement.role}</Th>
                  <Th>{t.userManagement.email}</Th>
                  <Th>{t.userManagement.status}</Th>
                  <Th>{t.userManagement.created}</Th>
                  <Th>最后登录</Th>
                  <Th>{t.userManagement.actions}</Th>
                </Tr>
              </Thead>
              <Tbody>
                {users.map((userItem) => (
                  <Tr key={userItem.id}>
                    <Td>
                      <HStack>
                        <Text fontWeight="medium">{userItem.username}</Text>
                        {userItem.username === user?.username && (
                          <Badge colorScheme="blue" size="sm">当前用户</Badge>
                        )}
                      </HStack>
                    </Td>
                    <Td>
                      <Badge colorScheme={roleColors[userItem.role as keyof typeof roleColors]}>
                        {roleLabels[userItem.role as keyof typeof roleLabels]}
                      </Badge>
                    </Td>
                    <Td>{userItem.email || '-'}</Td>
                    <Td>
                      <Badge colorScheme={userItem.is_active ? 'green' : 'red'}>
                        {userItem.is_active ? '活跃' : '禁用'}
                      </Badge>
                    </Td>
                    <Td>{formatDate(userItem.created_at)}</Td>
                    <Td>{formatDate(userItem.last_login_at)}</Td>
                    <Td>
                      {canManageUsers && (
                        <Menu>
                          <MenuButton
                            as={IconButton}
                            icon={<FiMoreVertical />}
                            variant="ghost"
                            size="sm"
                          />
                          <MenuList>
                            <MenuItem
                              icon={<FiEdit />}
                              onClick={() => openEditModal(userItem)}
                            >
                              编辑
                            </MenuItem>
                            {canDeleteUser(userItem) && (
                              <MenuItem
                                icon={<FiTrash2 />}
                                color="red.500"
                                onClick={() => openDeleteModal(userItem)}
                              >
                                删除
                              </MenuItem>
                            )}
                          </MenuList>
                        </Menu>
                      )}
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </CardBody>
        </Card>

        {/* 添加用户模态框 */}
        <Modal isOpen={isAddOpen} onClose={onAddClose} size="md">
          <ModalOverlay />
          <ModalContent>
            <ModalHeader>{t.users.addUser}</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                <FormControl isRequired>
                  <FormLabel>{t.users.username}</FormLabel>
                  <Input
                    value={addForm.username}
                    onChange={(e) => setAddForm({ ...addForm, username: e.target.value })}
                    placeholder={t.users.usernamePlaceholder}
                  />
                </FormControl>
                <FormControl isRequired>
                  <FormLabel>{t.users.password}</FormLabel>
                  <Input
                    type="password"
                    value={addForm.password}
                    onChange={(e) => setAddForm({ ...addForm, password: e.target.value })}
                    placeholder={t.users.passwordPlaceholder}
                  />
                </FormControl>
                <FormControl isRequired>
                  <FormLabel>{t.users.confirmPassword}</FormLabel>
                  <Input
                    type="password"
                    value={addForm.confirmPassword}
                    onChange={(e) => setAddForm({ ...addForm, confirmPassword: e.target.value })}
                    placeholder={t.users.confirmPasswordPlaceholder}
                  />
                </FormControl>
                <FormControl isRequired>
                  <FormLabel>{t.users.role}</FormLabel>
                  <Select
                    value={addForm.role}
                    onChange={(e) => setAddForm({ ...addForm, role: e.target.value })}
                  >
                    <option value="viewer">{t.users.readOnly}</option>
                    <option value="operator">{t.users.operator}</option>
                    <option value="admin">{t.users.admin}</option>
                    {user?.role === 'super_admin' && (
                      <option value="super_admin">{t.users.superAdmin}</option>
                    )}
                  </Select>
                </FormControl>
                <FormControl>
                  <FormLabel>{t.users.email}</FormLabel>
                  <Input
                    type="email"
                    value={addForm.email}
                    onChange={(e) => setAddForm({ ...addForm, email: e.target.value })}
                    placeholder={t.users.emailPlaceholder}
                  />
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onAddClose}>
                {t.common.cancel}
              </Button>
              <Button
                colorScheme="brand"
                onClick={handleAddUser}
                isLoading={actionLoading}
              >
                {t.users.createUser}
              </Button>
            </ModalFooter>
          </ModalContent>
        </Modal>

        {/* 编辑用户模态框 */}
        <Modal isOpen={isEditOpen} onClose={onEditClose} size="md">
          <ModalOverlay />
          <ModalContent>
            <ModalHeader>编辑用户: {selectedUser?.username}</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <VStack spacing={4}>
                <FormControl>
                  <FormLabel>用户名</FormLabel>
                  <Input value={editForm.username} isDisabled />
                </FormControl>
                <FormControl>
                  <FormLabel>新密码（留空表示不修改）</FormLabel>
                  <Input
                    type="password"
                    value={editForm.password}
                    onChange={(e) => setEditForm({ ...editForm, password: e.target.value })}
                    placeholder={t.user.new_password_placeholder}
                  />
                </FormControl>
                {editForm.password && (
                  <FormControl>
                    <FormLabel>确认新密码</FormLabel>
                    <Input
                      type="password"
                      value={editForm.confirmPassword}
                      onChange={(e) => setEditForm({ ...editForm, confirmPassword: e.target.value })}
                      placeholder={t.user.confirm_password_placeholder}
                    />
                  </FormControl>
                )}
                <FormControl>
                  <FormLabel>角色</FormLabel>
                  <Select
                    value={editForm.role}
                    onChange={(e) => setEditForm({ ...editForm, role: e.target.value })}
                  >
                    <option value="viewer">只读用户</option>
                    <option value="operator">操作员</option>
                    <option value="admin">管理员</option>
                    {user?.role === 'super_admin' && (
                      <option value="super_admin">超级管理员</option>
                    )}
                  </Select>
                </FormControl>
                <FormControl>
                  <FormLabel>邮箱</FormLabel>
                  <Input
                    type="email"
                    value={editForm.email}
                    onChange={(e) => setEditForm({ ...editForm, email: e.target.value })}
                    placeholder={t.user.email_placeholder}
                  />
                </FormControl>
                <FormControl display="flex" alignItems="center">
                  <FormLabel mb="0">用户状态</FormLabel>
                  <Switch
                    isChecked={editForm.is_active}
                    onChange={(e) => setEditForm({ ...editForm, is_active: e.target.checked })}
                  />
                </FormControl>
              </VStack>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onEditClose}>
                取消
              </Button>
              <Button
                colorScheme="brand"
                onClick={handleEditUser}
                isLoading={actionLoading}
              >
                保存更改
              </Button>
            </ModalFooter>
          </ModalContent>
        </Modal>

        {/* 删除用户确认模态框 */}
        <Modal isOpen={isDeleteOpen} onClose={onDeleteClose}>
          <ModalOverlay />
          <ModalContent>
            <ModalHeader>确认删除用户</ModalHeader>
            <ModalCloseButton />
            <ModalBody>
              <Alert status="warning">
                <AlertIcon />
                您确定要删除用户 "{selectedUser?.username}" 吗？此操作无法撤销。
              </Alert>
            </ModalBody>
            <ModalFooter>
              <Button variant="ghost" mr={3} onClick={onDeleteClose}>
                取消
              </Button>
              <Button
                colorScheme="red"
                onClick={handleDeleteUser}
                isLoading={actionLoading}
              >
                删除用户
              </Button>
            </ModalFooter>
          </ModalContent>
        </Modal>
      </VStack>
    </Box>
  )
}

export default UserManagement

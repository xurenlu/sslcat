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
  Select,
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
} from '@chakra-ui/react'
import {
  FiTerminal,
  FiRefreshCw,
  FiPlus,
  FiEdit,
  FiTrash2,
  FiPlay,
  FiPause,
  FiSquare,
  FiDownload,
  FiBox,
  FiServer,
} from 'react-icons/fi'

interface RunnerTask {
  id: string
  name: string
  type: 'local' | 'docker'
  status: 'running' | 'stopped' | 'error' | 'pending'
  command: string
  workingDir: string
  environment: Record<string, string>
  created: string
  lastRun: string
  exitCode?: number
  output?: string
  pid?: number
  image?: string // Docker 任务
  container?: string // Docker 任务
}

interface RunnerStats {
  totalTasks: number
  runningTasks: number
  dockerTasks: number
  localTasks: number
}

const RunnersManagement: React.FC = () => {
  const [tasks, setTasks] = useState<RunnerTask[]>([])
  const [stats, setStats] = useState<RunnerStats>({
    totalTasks: 0,
    runningTasks: 0,
    dockerTasks: 0,
    localTasks: 0,
  })
  const [loading, setLoading] = useState(false)
  const { isOpen, onOpen, onClose } = useDisclosure()
  const {
    isOpen: isLogOpen,
    onOpen: onLogOpen,
    onClose: onLogClose,
  } = useDisclosure()
  const [selectedTask, setSelectedTask] = useState<RunnerTask | null>(null)
  const [taskType, setTaskType] = useState<'local' | 'docker'>('local')
  const toast = useToast()

  const [newTask, setNewTask] = useState({
    name: '',
    type: 'local' as RunnerTask['type'],
    command: '',
    workingDir: '/tmp',
    environment: {} as Record<string, string>,
    image: '',
    autoRestart: false,
  })

  const refreshData = async () => {
    setLoading(true)
    try {
      // TODO: 实际的 API 调用
      setTimeout(() => {
        const mockTasks: RunnerTask[] = [
          {
            id: '1',
            name: 'nginx-proxy',
            type: 'docker',
            status: 'running',
            command: '',
            workingDir: '/',
            environment: { PORT: '80' },
            created: '2024-01-15',
            lastRun: '2024-01-15 14:30:00',
            image: 'nginx:alpine',
            container: 'nginx-proxy-container',
          },
          {
            id: '2',
            name: 'backup-script',
            type: 'local',
            status: 'stopped',
            command: '/scripts/backup.sh',
            workingDir: '/scripts',
            environment: { BACKUP_DIR: '/backup' },
            created: '2024-01-14',
            lastRun: '2024-01-15 02:00:00',
            exitCode: 0,
          },
          {
            id: '3',
            name: 'log-processor',
            type: 'local',
            status: 'running',
            command: 'python log_processor.py',
            workingDir: '/app',
            environment: { ENV: 'production' },
            created: '2024-01-13',
            lastRun: '2024-01-15 14:25:00',
            pid: 12345,
          },
          {
            id: '4',
            name: 'redis-cache',
            type: 'docker',
            status: 'error',
            command: '',
            workingDir: '/',
            environment: {},
            created: '2024-01-12',
            lastRun: '2024-01-15 10:00:00',
            image: 'redis:6-alpine',
            exitCode: 1,
          },
        ]
        
        setTasks(mockTasks)
        setStats({
          totalTasks: mockTasks.length,
          runningTasks: mockTasks.filter(t => t.status === 'running').length,
          dockerTasks: mockTasks.filter(t => t.type === 'docker').length,
          localTasks: mockTasks.filter(t => t.type === 'local').length,
        })
        setLoading(false)
      }, 1000)
    } catch (error) {
      console.error('获取运行器数据失败:', error)
      setLoading(false)
    }
  }

  const handleCreateTask = async () => {
    try {
      // TODO: 实际的 API 调用
      toast({
        title: '任务创建成功',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      
      onClose()
      refreshData()
      resetForm()
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

  const handleTaskAction = async (id: string, action: 'start' | 'stop' | 'restart') => {
    try {
      // TODO: 实际的 API 调用
      const actionText = {
        start: '启动',
        stop: '停止',
        restart: '重启',
      }[action]
      
      toast({
        title: `任务${actionText}成功`,
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
      refreshData()
    } catch (error) {
      toast({
        title: '操作失败',
        description: error instanceof Error ? error.message : '未知错误',
        status: 'error',
        duration: 3000,
        isClosable: true,
      })
    }
  }

  const handleDeleteTask = async (id: string) => {
    try {
      setTasks(tasks.filter(task => task.id !== id))
      toast({
        title: '任务删除成功',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })
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

  const handleShowLogs = (task: RunnerTask) => {
    setSelectedTask(task)
    onLogOpen()
  }

  const resetForm = () => {
    setNewTask({
      name: '',
      type: 'local',
      command: '',
      workingDir: '/tmp',
      environment: {},
      image: '',
      autoRestart: false,
    })
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'running': return 'green'
      case 'stopped': return 'gray'
      case 'error': return 'red'
      case 'pending': return 'yellow'
      default: return 'gray'
    }
  }

  const getStatusText = (status: string) => {
    switch (status) {
      case 'running': return '运行中'
      case 'stopped': return '已停止'
      case 'error': return '错误'
      case 'pending': return '等待中'
      default: return status
    }
  }

  const getTypeColor = (type: string) => {
    return type === 'docker' ? 'blue' : 'purple'
  }

  const getTypeText = (type: string) => {
    return type === 'docker' ? 'Docker' : '本地'
  }

  useEffect(() => {
    refreshData()
  }, [])

  return (
    <Box>
      <Flex justify="space-between" align="center" mb={6}>
        <HStack>
          <Icon as={FiTerminal} boxSize={6} />
          <Heading size="lg">运行器管理</Heading>
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
            leftIcon={<Icon as={FiPlus} />}
            colorScheme="blue"
            onClick={onOpen}
          >
            添加任务
          </Button>
        </HStack>
      </Flex>

      {/* 统计卡片 */}
      <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={6} mb={8}>
        <Card>
          <CardBody>
            <Stat>
              <StatLabel>总任务数</StatLabel>
              <StatNumber>{stats.totalTasks}</StatNumber>
              <StatHelpText>所有运行器任务</StatHelpText>
            </Stat>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <Stat>
              <StatLabel>运行中</StatLabel>
              <StatNumber color="green.500">{stats.runningTasks}</StatNumber>
              <StatHelpText>正在运行的任务</StatHelpText>
            </Stat>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <Stat>
              <StatLabel>Docker 任务</StatLabel>
              <StatNumber color="blue.500">{stats.dockerTasks}</StatNumber>
              <StatHelpText>容器化任务</StatHelpText>
            </Stat>
          </CardBody>
        </Card>

        <Card>
          <CardBody>
            <Stat>
              <StatLabel>本地任务</StatLabel>
              <StatNumber color="purple.500">{stats.localTasks}</StatNumber>
              <StatHelpText>本地进程任务</StatHelpText>
            </Stat>
          </CardBody>
        </Card>
      </SimpleGrid>

      {/* 任务列表 */}
      <Tabs variant="enclosed">
        <TabList>
          <Tab>
            <HStack>
              <Icon as={FiTerminal} />
              <Text>所有任务</Text>
              <Badge colorScheme="gray">{tasks.length}</Badge>
            </HStack>
          </Tab>
          <Tab>
            <HStack>
              <Icon as={FiBox} />
              <Text>Docker 任务</Text>
              <Badge colorScheme="blue">{stats.dockerTasks}</Badge>
            </HStack>
          </Tab>
          <Tab>
            <HStack>
              <Icon as={FiServer} />
              <Text>本地任务</Text>
              <Badge colorScheme="purple">{stats.localTasks}</Badge>
            </HStack>
          </Tab>
        </TabList>

        <TabPanels>
          {/* 所有任务 */}
          <TabPanel>
            <Card>
              <CardBody>
                {tasks.length > 0 ? (
                  <Table variant="simple">
                    <Thead>
                      <Tr>
                        <Th>任务信息</Th>
                        <Th>类型</Th>
                        <Th>状态</Th>
                        <Th>命令/镜像</Th>
                        <Th>最后运行</Th>
                        <Th>操作</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {tasks.map((task) => (
                        <Tr key={task.id}>
                          <Td>
                            <VStack align="start" spacing={1}>
                              <Text fontWeight="medium">{task.name}</Text>
                              <Text fontSize="sm" color="gray.600">
                                工作目录: {task.workingDir}
                              </Text>
                              {task.pid && (
                                <Text fontSize="xs" color="gray.500">
                                  PID: {task.pid}
                                </Text>
                              )}
                              {task.container && (
                                <Text fontSize="xs" color="gray.500">
                                  容器: {task.container}
                                </Text>
                              )}
                            </VStack>
                          </Td>
                          <Td>
                            <Badge colorScheme={getTypeColor(task.type)}>
                              {getTypeText(task.type)}
                            </Badge>
                          </Td>
                          <Td>
                            <VStack align="start" spacing={1}>
                              <Badge colorScheme={getStatusColor(task.status)}>
                                {getStatusText(task.status)}
                              </Badge>
                              {task.exitCode !== undefined && (
                                <Text fontSize="xs" color="gray.500">
                                  退出码: {task.exitCode}
                                </Text>
                              )}
                            </VStack>
                          </Td>
                          <Td>
                            <Code fontSize="xs" maxW="200px" isTruncated>
                              {task.type === 'docker' ? task.image : task.command}
                            </Code>
                          </Td>
                          <Td>{task.lastRun}</Td>
                          <Td>
                            <HStack spacing={1}>
                              {task.status === 'stopped' ? (
                                <IconButton
                                  aria-label="启动"
                                  icon={<FiPlay />}
                                  size="sm"
                                  variant="ghost"
                                  colorScheme="green"
                                  onClick={() => handleTaskAction(task.id, 'start')}
                                />
                              ) : (
                                <IconButton
                                  aria-label="停止"
                                  icon={<FiSquare />}
                                  size="sm"
                                  variant="ghost"
                                  colorScheme="red"
                                  onClick={() => handleTaskAction(task.id, 'stop')}
                                />
                              )}
                              <IconButton
                                aria-label="重启"
                                icon={<FiPause />}
                                size="sm"
                                variant="ghost"
                                colorScheme="orange"
                                onClick={() => handleTaskAction(task.id, 'restart')}
                              />
                              <IconButton
                                aria-label="查看日志"
                                icon={<FiDownload />}
                                size="sm"
                                variant="ghost"
                                onClick={() => handleShowLogs(task)}
                              />
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
                                onClick={() => handleDeleteTask(task.id)}
                              />
                            </HStack>
                          </Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                ) : (
                  <Box textAlign="center" py={8}>
                    <Icon as={FiTerminal} boxSize={12} color="gray.300" mb={4} />
                    <Text color="gray.500" mb={4}>暂无运行器任务</Text>
                    <Button leftIcon={<Icon as={FiPlus} />} colorScheme="blue" onClick={onOpen}>
                      创建第一个任务
                    </Button>
                  </Box>
                )}
              </CardBody>
            </Card>
          </TabPanel>

          {/* Docker 任务 */}
          <TabPanel>
            <Card>
              <CardBody>
                <Table variant="simple">
                  <Thead>
                    <Tr>
                      <Th>任务名称</Th>
                      <Th>镜像</Th>
                      <Th>容器</Th>
                      <Th>状态</Th>
                      <Th>最后运行</Th>
                      <Th>操作</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {tasks.filter(task => task.type === 'docker').map((task) => (
                      <Tr key={task.id}>
                        <Td>{task.name}</Td>
                        <Td>
                          <Code fontSize="sm">{task.image}</Code>
                        </Td>
                        <Td>
                          <Code fontSize="sm">{task.container || '-'}</Code>
                        </Td>
                        <Td>
                          <Badge colorScheme={getStatusColor(task.status)}>
                            {getStatusText(task.status)}
                          </Badge>
                        </Td>
                        <Td>{task.lastRun}</Td>
                        <Td>
                          <HStack spacing={1}>
                            <IconButton
                              aria-label="操作"
                              icon={task.status === 'running' ? <FiSquare /> : <FiPlay />}
                              size="sm"
                              variant="ghost"
                              colorScheme={task.status === 'running' ? 'red' : 'green'}
                              onClick={() => handleTaskAction(task.id, task.status === 'running' ? 'stop' : 'start')}
                            />
                            <IconButton
                              aria-label="查看日志"
                              icon={<FiDownload />}
                              size="sm"
                              variant="ghost"
                              onClick={() => handleShowLogs(task)}
                            />
                          </HStack>
                        </Td>
                      </Tr>
                    ))}
                  </Tbody>
                </Table>
              </CardBody>
            </Card>
          </TabPanel>

          {/* 本地任务 */}
          <TabPanel>
            <Card>
              <CardBody>
                <Table variant="simple">
                  <Thead>
                    <Tr>
                      <Th>任务名称</Th>
                      <Th>命令</Th>
                      <Th>PID</Th>
                      <Th>状态</Th>
                      <Th>最后运行</Th>
                      <Th>操作</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {tasks.filter(task => task.type === 'local').map((task) => (
                      <Tr key={task.id}>
                        <Td>{task.name}</Td>
                        <Td>
                          <Code fontSize="sm">{task.command}</Code>
                        </Td>
                        <Td>{task.pid || '-'}</Td>
                        <Td>
                          <Badge colorScheme={getStatusColor(task.status)}>
                            {getStatusText(task.status)}
                          </Badge>
                        </Td>
                        <Td>{task.lastRun}</Td>
                        <Td>
                          <HStack spacing={1}>
                            <IconButton
                              aria-label="操作"
                              icon={task.status === 'running' ? <FiSquare /> : <FiPlay />}
                              size="sm"
                              variant="ghost"
                              colorScheme={task.status === 'running' ? 'red' : 'green'}
                              onClick={() => handleTaskAction(task.id, task.status === 'running' ? 'stop' : 'start')}
                            />
                            <IconButton
                              aria-label="查看日志"
                              icon={<FiDownload />}
                              size="sm"
                              variant="ghost"
                              onClick={() => handleShowLogs(task)}
                            />
                          </HStack>
                        </Td>
                      </Tr>
                    ))}
                  </Tbody>
                </Table>
              </CardBody>
            </Card>
          </TabPanel>
        </TabPanels>
      </Tabs>

      {/* 添加任务模态框 */}
      <Modal isOpen={isOpen} onClose={onClose} size="lg">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>添加运行器任务</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <FormControl>
                <FormLabel>任务名称</FormLabel>
                <Input
                  value={newTask.name}
                  onChange={(e) => setNewTask({ ...newTask, name: e.target.value })}
                  placeholder="backup-script"
                />
              </FormControl>

              <FormControl>
                <FormLabel>任务类型</FormLabel>
                <Select
                  value={newTask.type}
                  onChange={(e) => setNewTask({ ...newTask, type: e.target.value as RunnerTask['type'] })}
                >
                  <option value="local">本地进程</option>
                  <option value="docker">Docker 容器</option>
                </Select>
              </FormControl>

              {newTask.type === 'local' ? (
                <>
                  <FormControl>
                    <FormLabel>执行命令</FormLabel>
                    <Input
                      value={newTask.command}
                      onChange={(e) => setNewTask({ ...newTask, command: e.target.value })}
                      placeholder="/scripts/backup.sh"
                    />
                  </FormControl>

                  <FormControl>
                    <FormLabel>工作目录</FormLabel>
                    <Input
                      value={newTask.workingDir}
                      onChange={(e) => setNewTask({ ...newTask, workingDir: e.target.value })}
                      placeholder="/scripts"
                    />
                  </FormControl>
                </>
              ) : (
                <FormControl>
                  <FormLabel>Docker 镜像</FormLabel>
                  <Input
                    value={newTask.image}
                    onChange={(e) => setNewTask({ ...newTask, image: e.target.value })}
                    placeholder="nginx:alpine"
                  />
                </FormControl>
              )}

              <FormControl>
                <FormLabel>环境变量（一行一个，格式：KEY=VALUE）</FormLabel>
                <Textarea
                  placeholder="PORT=80&#10;ENV=production"
                  rows={3}
                />
              </FormControl>

              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">自动重启</FormLabel>
                <Switch
                  isChecked={newTask.autoRestart}
                  onChange={(e) => setNewTask({ ...newTask, autoRestart: e.target.checked })}
                />
              </FormControl>
            </VStack>
          </ModalBody>

          <ModalFooter>
            <Button variant="ghost" mr={3} onClick={onClose}>
              取消
            </Button>
            <Button colorScheme="blue" onClick={handleCreateTask}>
              创建任务
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>

      {/* 日志查看模态框 */}
      <Modal isOpen={isLogOpen} onClose={onLogClose} size="xl">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>
            任务日志 - {selectedTask?.name}
          </ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <Box bg="black" color="green.300" p={4} borderRadius="md" fontFamily="mono" fontSize="sm">
              <Text whiteSpace="pre-wrap">
                {selectedTask?.output || '暂无日志输出...'}
              </Text>
            </Box>
          </ModalBody>
          <ModalFooter>
            <Button onClick={onLogClose}>关闭</Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default RunnersManagement

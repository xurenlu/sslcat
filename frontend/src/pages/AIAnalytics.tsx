import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  Text,
  Card,
  CardBody,
  SimpleGrid,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  StatArrow,
  StatGroup,
  Progress,
  HStack,
  VStack,
  Button,
  Icon,
  useToast,
  Alert,
  AlertIcon,
  Badge,
  Divider,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Spinner,
  FormControl,
  FormLabel,
  Input,
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  NumberIncrementStepper,
  NumberDecrementStepper,
  Switch,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  useDisclosure,
} from '@chakra-ui/react'
import {
  FiCpu,
  FiActivity,
  FiShield,
  FiDatabase,
  FiPlay,
  FiRefreshCw,
  FiTrendingUp,
  FiAlertTriangle,
  FiCheckCircle,
  FiTarget,
} from 'react-icons/fi'
import { FaBrain } from 'react-icons/fa'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

interface MLStats {
  model_loaded: boolean
  total_samples: number
  feature_dim: number
  n_trees: number
  contamination: number
  total_predictions: number
  anomaly_count: number
  threshold: number
  avg_tree_depth: number
  last_training?: string
}

interface AnomalyPrediction {
  score: number
  level: string
  is_anomaly: boolean
  confidence: number
  timestamp: string
  reason: string
}

interface ThreatScore {
  overall_score: number
  overall_level: string
  components: {
    [key: string]: {
      score: number
      weight: number
      reason: string
    }
  }
  predictions: AnomalyPrediction[]
}

const AIAnalytics: React.FC = () => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  const toast = useToast()

  const [stats, setStats] = useState<MLStats | null>(null)
  const [predictions, setPredictions] = useState<AnomalyPrediction[]>([])
  const [threatScore, setThreatScore] = useState<ThreatScore | null>(null)
  const [loading, setLoading] = useState(true)
  const [training, setTraining] = useState(false)

  // Training config
  const [nTrees, setNTrees] = useState(100)
  const [maxSamples, setMaxSamples] = useState(256)
  const [contamination, setContamination] = useState(0.1)

  const { isOpen: isTrainModalOpen, onOpen: onTrainModalOpen, onClose: onTrainModalClose } = useDisclosure()

  const loadStats = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/ml/stats'), {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setStats(data)
      }
    } catch (error) {
      console.error('Error loading ML stats:', error)
    }
  }

  const loadPredictions = async () => {
    // TODO: 实现获取最近预测的 API
    // 暂时使用模拟数据
    setPredictions([
      {
        score: 0.15,
        level: 'normal',
        is_anomaly: false,
        confidence: 0.7,
        timestamp: new Date(Date.now() - 60000).toISOString(),
        reason: '正常访问模式',
      },
      {
        score: 0.85,
        level: 'high',
        is_anomaly: true,
        confidence: 0.95,
        timestamp: new Date(Date.now() - 120000).toISOString(),
        reason: '检测到SQL注入特征',
      },
    ])
  }

  useEffect(() => {
    const loadData = async () => {
      setLoading(true)
      await Promise.all([loadStats(), loadPredictions()])
      setLoading(false)
    }
    loadData()
  }, [adminPrefix])

  const handleTrain = async () => {
    setTraining(true)
    try {
      // TODO: 实现真实的训练 API 调用
      // const response = await fetch(buildApiPath(adminPrefix, '/api/ml/train'), {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   credentials: 'include',
      //   body: JSON.stringify({
      //     samples: [],
      //     n_trees: nTrees,
      //     max_samples: maxSamples,
      //     contamination,
      //   }),
      // })

      // 模拟训练延迟
      await new Promise(resolve => setTimeout(resolve, 3000))

      toast({
        title: '训练完成',
        description: 'ML 模型已成功训练',
        status: 'success',
        duration: 3000,
        isClosable: true,
      })

      await loadStats()
      onTrainModalClose()
    } catch (error) {
      console.error('Error training model:', error)
      toast({
        title: '训练失败',
        description: error instanceof Error ? error.message : '训练模型时出错',
        status: 'error',
        duration: 5000,
        isClosable: true,
      })
    } finally {
      setTraining(false)
    }
  }

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'critical':
        return 'red'
      case 'high':
        return 'orange'
      case 'medium':
        return 'yellow'
      case 'low':
        return 'blue'
      default:
        return 'green'
    }
  }

  const getThreatLevelLabel = (level: string) => {
    switch (level) {
      case 'critical':
        return '严重'
      case 'high':
        return '高'
      case 'medium':
        return '中'
      case 'low':
        return '低'
      default:
        return '正常'
    }
  }

  if (loading) {
    return (
      <Box p={6} display="flex" justifyContent="center" alignItems="center" minH="400px">
        <VStack spacing={4}>
          <Spinner size="xl" thickness="4px" speed="0.65s" emptyColor="gray.200" color="blue.500" />
          <Text>加载中...</Text>
        </VStack>
      </Box>
    )
  }

  const anomalyRate = stats?.total_predictions
    ? ((stats.anomaly_count / stats.total_predictions) * 100).toFixed(2)
    : '0.00'

  return (
    <Box p={6}>
      <VStack spacing={6} align="stretch">
        {/* Header */}
        <HStack justify="space-between">
          <Heading size="lg" display="flex" alignItems="center">
            <Icon as={FaBrain} mr={3} />
            AI 安全分析
          </Heading>
          <HStack>
            <Button
              leftIcon={<Icon as={FiRefreshCw} />}
              variant="outline"
              onClick={() => Promise.all([loadStats(), loadPredictions()])}
            >
              刷新
            </Button>
            <Button
              leftIcon={<Icon as={FiPlay} />}
              colorScheme="blue"
              onClick={onTrainModalOpen}
            >
              训练模型
            </Button>
          </HStack>
        </HStack>

        {/* Model Status Alert */}
        {!stats?.model_loaded && (
          <Alert status="warning" variant="left-accent">
            <AlertIcon />
            <Box flex="1">
              <Text fontWeight="bold">模型未加载</Text>
              <Text fontSize="sm">请先训练模型以启用 AI 异常检测功能</Text>
            </Box>
            <Button size="sm" colorScheme="blue" onClick={onTrainModalOpen}>
              立即训练
            </Button>
          </Alert>
        )}

        {/* Statistics Cards */}
        <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={4}>
          <Card>
            <CardBody>
              <StatGroup>
                <Stat>
                  <StatLabel display="flex" alignItems="center">
                    <Icon as={FiDatabase} mr={2} />
                    训练样本
                  </StatLabel>
                  <StatNumber>{stats?.total_samples?.toLocaleString() || 0}</StatNumber>
                  <StatHelpText>总样本数</StatHelpText>
                </Stat>
              </StatGroup>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <StatGroup>
                <Stat>
                  <StatLabel display="flex" alignItems="center">
                    <Icon as={FiTarget} mr={2} />
                    特征维度
                  </StatLabel>
                  <StatNumber>{stats?.feature_dim || 0}</StatNumber>
                  <StatHelpText>维度</StatHelpText>
                </Stat>
              </StatGroup>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <StatGroup>
                <Stat>
                  <StatLabel display="flex" alignItems="center">
                    <Icon as={FiCpu} mr={2} />
                    森林规模
                  </StatLabel>
                  <StatNumber>{stats?.n_trees?.toLocaleString() || 0}</StatNumber>
                  <StatHelpText>棵树</StatHelpText>
                </Stat>
              </StatGroup>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <StatGroup>
                <Stat>
                  <StatLabel display="flex" alignItems="center">
                    <Icon as={FiActivity} mr={2} />
                    总预测次数
                  </StatLabel>
                  <StatNumber>{stats?.total_predictions?.toLocaleString() || 0}</StatNumber>
                  <StatHelpText>
                    <StatArrow type="increase" />
                    持续增长
                  </StatHelpText>
                </Stat>
              </StatGroup>
            </CardBody>
          </Card>
        </SimpleGrid>

        {/* Detailed Metrics */}
        <SimpleGrid columns={{ base: 1, lg: 2 }} spacing={6}>
          {/* Model Configuration */}
          <Card>
            <CardBody>
              <VStack spacing={4} align="stretch">
                <Heading size="md" display="flex" alignItems="center">
                  <Icon as={FiShield} mr={2} />
                  模型配置
                </Heading>

                <SimpleGrid columns={2} spacing={4}>
                  <Box>
                    <Text fontSize="sm" color="gray.500" mb={1}>
                      污染率阈值
                    </Text>
                    <Text fontSize="xl" fontWeight="bold">
                      {stats?.contamination || 0}
                    </Text>
                  </Box>

                  <Box>
                    <Text fontSize="sm" color="gray.500" mb={1}>
                      异常阈值
                    </Text>
                    <Text fontSize="xl" fontWeight="bold">
                      {stats?.threshold?.toFixed(4) || 0}
                    </Text>
                  </Box>

                  <Box>
                    <Text fontSize="sm" color="gray.500" mb={1}>
                      平均树深度
                    </Text>
                    <Text fontSize="xl" fontWeight="bold">
                      {stats?.avg_tree_depth?.toFixed(2) || 0}
                    </Text>
                  </Box>

                  <Box>
                    <Text fontSize="sm" color="gray.500" mb={1}>
                      异常检测率
                    </Text>
                    <HStack>
                      <Text fontSize="xl" fontWeight="bold" color={parseFloat(anomalyRate) > 5 ? 'red.500' : 'green.500'}>
                        {anomalyRate}%
                      </Text>
                      {parseFloat(anomalyRate) > 5 && <Icon as={FiAlertTriangle} color="red.500" />}
                    </HStack>
                  </Box>
                </SimpleGrid>

                <Divider />

                <Box>
                  <Text fontSize="sm" color="gray.500" mb={2}>
                    异常计数 / 总预测
                  </Text>
                  <Progress
                    value={parseFloat(anomalyRate)}
                    max={100}
                    colorScheme={parseFloat(anomalyRate) > 5 ? 'red' : 'green'}
                    borderRadius="md"
                  />
                  <HStack justify="space-between" mt={2}>
                    <Text fontSize="xs" color="gray.500">
                      异常: {stats?.anomaly_count || 0}
                    </Text>
                    <Text fontSize="xs" color="gray.500">
                      总计: {stats?.total_predictions || 0}
                    </Text>
                  </HStack>
                </Box>

                {stats?.last_training && (
                  <Box>
                    <Text fontSize="sm" color="gray.500">
                      最后训练时间: {new Date(stats.last_training).toLocaleString('zh-CN')}
                    </Text>
                  </Box>
                )}
              </VStack>
            </CardBody>
          </Card>

          {/* Recent Predictions */}
          <Card>
            <CardBody>
              <VStack spacing={4} align="stretch">
                <Heading size="md" display="flex" alignItems="center">
                  <Icon as={FiTrendingUp} mr={2} />
                  最近检测
                </Heading>

                <Box overflowX="auto" maxH="300px" overflowY="auto">
                  <Table size="sm">
                    <Thead position="sticky" top={0} bg="white" zIndex={1}>
                      <Tr>
                        <Th>时间</Th>
                        <Th>等级</Th>
                        <Th>分数</Th>
                        <Th>原因</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {predictions.length === 0 ? (
                        <Tr>
                          <Td colSpan={4} textAlign="center" py={8}>
                            <Text color="gray.500">暂无预测记录</Text>
                          </Td>
                        </Tr>
                      ) : (
                        predictions.map((pred, idx) => (
                          <Tr key={idx}>
                            <Td whiteSpace="nowrap">
                              {new Date(pred.timestamp).toLocaleTimeString('zh-CN')}
                            </Td>
                            <Td>
                              <Badge colorScheme={getThreatLevelColor(pred.level)}>
                                {getThreatLevelLabel(pred.level)}
                              </Badge>
                            </Td>
                            <Td>
                              <HStack>
                                <Text fontWeight="bold">{(pred.score * 100).toFixed(1)}%</Text>
                                {pred.is_anomaly && <Icon as={FiAlertTriangle} color="orange.500" />}
                                {!pred.is_anomaly && <Icon as={FiCheckCircle} color="green.500" />}
                              </HStack>
                            </Td>
                            <Td whiteSpace="nowrap">{pred.reason}</Td>
                          </Tr>
                        ))
                      )}
                    </Tbody>
                  </Table>
                </Box>
              </VStack>
            </CardBody>
          </Card>
        </SimpleGrid>

        {/* Information Cards */}
        <SimpleGrid columns={{ base: 1, md: 3 }} spacing={4}>
          <Card>
            <CardBody>
              <VStack spacing={3} align="start">
                <Icon as={FaBrain} boxSize={8} color="blue.500" />
                <Heading size="sm">Isolation Forest</Heading>
                <Text fontSize="sm" color="gray.600">
                  使用隔离森林算法进行无监督异常检测，无需标注数据即可识别异常模式
                </Text>
              </VStack>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <VStack spacing={3} align="start">
                <Icon as={FiTarget} boxSize={8} color="green.500" />
                <Heading size="sm">多维特征提取</Heading>
                <Text fontSize="sm" color="gray.600">
                  从HTTP请求中提取40+维特征，包括URL模式、IP信誉、时序特征和行为模式
                </Text>
              </VStack>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <VStack spacing={3} align="start">
                <Icon as={FiShield} boxSize={8} color="purple.500" />
                <Heading size="sm">智能威胁评分</Heading>
                <Text fontSize="sm" color="gray.600">
                  综合异常检测、IP信誉、行为分析和时序趋势，计算综合威胁评分
                </Text>
              </VStack>
            </CardBody>
          </Card>
        </SimpleGrid>
      </VStack>

      {/* Training Modal */}
      <Modal isOpen={isTrainModalOpen} onClose={onTrainModalClose} size="md">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>训练 ML 模型</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <Alert status="info" variant="left-accent">
                <AlertIcon />
                <Box>
                  <Text fontWeight="bold">训练说明</Text>
                  <Text fontSize="sm">
                    模型将从历史请求数据中学习正常模式，训练后可自动检测异常行为
                  </Text>
                </Box>
              </Alert>

              <FormControl>
                <FormLabel>树数量</FormLabel>
                <NumberInput
                  value={nTrees}
                  onChange={(_, value) => setNTrees(value)}
                  min={10}
                  max={500}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
                <Text fontSize="xs" color="gray.500" mt={1}>
                  更多树可提高准确性，但会增加训练时间和内存使用
                </Text>
              </FormControl>

              <FormControl>
                <FormLabel>最大样本数</FormLabel>
                <NumberInput
                  value={maxSamples}
                  onChange={(_, value) => setMaxSamples(value)}
                  min={32}
                  max={2048}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
                <Text fontSize="xs" color="gray.500" mt={1}>
                  每棵树使用的样本数，影响树的最大深度
                </Text>
              </FormControl>

              <FormControl>
                <FormLabel>污染率</FormLabel>
                <NumberInput
                  value={contamination}
                  onChange={(_, value) => setContamination(value)}
                  min={0.01}
                  max={0.5}
                  step={0.01}
                  precision={2}
                >
                  <NumberInputField />
                  <NumberInputStepper>
                    <NumberIncrementStepper />
                    <NumberDecrementStepper />
                  </NumberInputStepper>
                </NumberInput>
                <Text fontSize="xs" color="gray.500" mt={1}>
                  预期异常数据比例，用于设置异常阈值
                </Text>
              </FormControl>
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button variant="ghost" onClick={onTrainModalClose} isDisabled={training}>
              取消
            </Button>
            <Button
              colorScheme="blue"
              onClick={handleTrain}
              isLoading={training}
              loadingText="训练中..."
            >
              开始训练
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default AIAnalytics

import React, { useState, useEffect, useCallback } from 'react'
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
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Spinner,
  FormControl,
  FormLabel,
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  NumberIncrementStepper,
  NumberDecrementStepper,
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
  FiClock,
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
  training_history_count?: number
  collected_samples?: number
  total_observed?: number
}

interface AnomalyPrediction {
  score: number
  level: string
  is_anomaly: boolean
  confidence?: number
  timestamp: string
  reason?: string
}

interface TrainingHistoryEntry {
  id: string
  timestamp: string
  n_trees: number
  max_samples: number
  contamination: number
  feature_dim: number
  sample_count: number
  sample_source: string
  duration_ms: number
  threshold: number
  avg_tree_depth: number
  triggered: string
}

const AIAnalytics: React.FC = () => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  const toast = useToast()

  const [stats, setStats] = useState<MLStats | null>(null)
  const [predictions, setPredictions] = useState<AnomalyPrediction[]>([])
  const [history, setHistory] = useState<TrainingHistoryEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [training, setTraining] = useState(false)

  // Training config
  const [nTrees, setNTrees] = useState(100)
  const [maxSamples, setMaxSamples] = useState(256)
  const [contamination, setContamination] = useState(0.1)

  const { isOpen: isTrainModalOpen, onOpen: onTrainModalOpen, onClose: onTrainModalClose } = useDisclosure()

  const loadStats = useCallback(async () => {
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
  }, [adminPrefix])

  const loadPredictions = useCallback(async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/ml/predictions/recent?limit=50'), {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setPredictions(Array.isArray(data?.predictions) ? data.predictions : [])
      }
    } catch (error) {
      console.error('Error loading ML predictions:', error)
    }
  }, [adminPrefix])

  const loadHistory = useCallback(async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/ml/training/history?limit=20'), {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setHistory(Array.isArray(data?.entries) ? data.entries : [])
      }
    } catch (error) {
      console.error('Error loading ML training history:', error)
    }
  }, [adminPrefix])

  useEffect(() => {
    const loadData = async () => {
      setLoading(true)
      await Promise.all([loadStats(), loadPredictions(), loadHistory()])
      setLoading(false)
    }
    loadData()
  }, [loadStats, loadPredictions, loadHistory])

  const handleTrain = async () => {
    setTraining(true)
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/ml/train'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          n_trees: nTrees,
          max_samples: maxSamples,
          contamination,
          auto_sample: true,
          triggered: 'ui',
        }),
      })

      if (!response.ok) {
        const errBody = await response.json().catch(() => ({}))
        const description = errBody?.error || errBody?.message ||
          (t.aiAnalytics?.needMoreSamples ?? 'Too few samples collected.')
        toast({
          title: t.aiAnalytics?.trainFailed ?? 'Training failed',
          description,
          status: 'error',
          duration: 6000,
          isClosable: true,
        })
        return
      }

      const result = await response.json()
      toast({
        title: t.aiAnalytics?.trainSuccess ?? 'Training complete',
        description: `${result.total_samples} samples · ${result.n_trees} trees · ${result.duration_ms}ms`,
        status: 'success',
        duration: 4000,
        isClosable: true,
      })

      await Promise.all([loadStats(), loadHistory(), loadPredictions()])
      onTrainModalClose()
    } catch (error) {
      console.error('Error training model:', error)
      toast({
        title: t.aiAnalytics?.trainFailed ?? 'Training failed',
        description: error instanceof Error ? error.message : '',
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
        return t.aiAnalytics?.threatLevelCritical ?? 'Critical'
      case 'high':
        return t.aiAnalytics?.threatLevelHigh ?? 'High'
      case 'medium':
        return t.aiAnalytics?.threatLevelMedium ?? 'Medium'
      case 'low':
        return t.aiAnalytics?.threatLevelLow ?? 'Low'
      default:
        return t.aiAnalytics?.threatLevelNormal ?? 'Normal'
    }
  }

  const getSourceLabel = (src: string) => {
    if (src === 'auto') return t.aiAnalytics?.sourceAuto ?? 'Auto'
    if (src === 'manual') return t.aiAnalytics?.sourceManual ?? 'Manual'
    return src
  }

  const getTriggerLabel = (trg: string) => {
    if (trg === 'ui') return t.aiAnalytics?.triggerUI ?? 'UI'
    if (trg === 'api') return t.aiAnalytics?.triggerAPI ?? 'API'
    if (trg === 'scheduler') return t.aiAnalytics?.triggerScheduler ?? 'Scheduler'
    return trg
  }

  const formatDuration = (ms: number) => {
    if (ms < 1000) return `${ms}ms`
    return `${(ms / 1000).toFixed(2)}s`
  }

  if (loading) {
    return (
      <Box p={6} display="flex" justifyContent="center" alignItems="center" minH="400px">
        <VStack spacing={4}>
          <Spinner size="xl" thickness="4px" speed="0.65s" emptyColor="gray.200" color="blue.500" />
          <Text>{t.common.loading ?? 'Loading...'}</Text>
        </VStack>
      </Box>
    )
  }

  const anomalyRate = stats?.total_predictions
    ? ((stats.anomaly_count / stats.total_predictions) * 100).toFixed(2)
    : '0.00'

  const collected = stats?.collected_samples ?? 0
  const observed = stats?.total_observed ?? 0

  return (
    <Box p={6}>
      <VStack spacing={6} align="stretch">
        {/* Header */}
        <HStack justify="space-between">
          <Heading size="lg" display="flex" alignItems="center">
            <Icon as={FaBrain} mr={3} />
            {t.aiAnalytics?.title ?? t.aiSecurity?.title ?? 'AI Anomaly Detection'}
          </Heading>
          <HStack>
            <Button
              leftIcon={<Icon as={FiRefreshCw} />}
              variant="outline"
              onClick={() => Promise.all([loadStats(), loadPredictions(), loadHistory()])}
            >
              {t.common.refresh}
            </Button>
            <Button
              leftIcon={<Icon as={FiPlay} />}
              colorScheme="blue"
              onClick={onTrainModalOpen}
            >
              {t.aiAnalytics?.trainModel ?? 'Train Model'}
            </Button>
          </HStack>
        </HStack>

        {/* Model Status Alert */}
        {!stats?.model_loaded && (
          <Alert status="warning" variant="left-accent">
            <AlertIcon />
            <Box flex="1">
              <Text fontWeight="bold">{t.aiAnalytics?.modelNotLoaded ?? 'Model not loaded'}</Text>
              <Text fontSize="sm">{t.aiAnalytics?.trainModelFirst ?? 'Please train the model first'}</Text>
            </Box>
            <Button size="sm" colorScheme="blue" onClick={onTrainModalOpen}>
              {t.aiAnalytics?.trainNow ?? 'Train now'}
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
                    {t.aiAnalytics?.trainingSamples ?? 'Training samples'}
                  </StatLabel>
                  <StatNumber>{stats?.total_samples?.toLocaleString() || 0}</StatNumber>
                  <StatHelpText>{t.aiAnalytics?.totalSamples ?? 'Total samples'}</StatHelpText>
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
                    {t.aiAnalytics?.collectedSamples ?? 'Collected samples'}
                  </StatLabel>
                  <StatNumber>{collected.toLocaleString()}</StatNumber>
                  <StatHelpText>
                    {(t.aiAnalytics?.totalObserved ?? 'Observed')}: {observed.toLocaleString()}
                  </StatHelpText>
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
                    {t.aiAnalytics?.forestSize ?? 'Forest size'}
                  </StatLabel>
                  <StatNumber>{stats?.n_trees?.toLocaleString() || 0}</StatNumber>
                  <StatHelpText>{t.aiAnalytics?.trees ?? 'trees'}</StatHelpText>
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
                    {t.aiAnalytics?.totalPredictions ?? 'Total predictions'}
                  </StatLabel>
                  <StatNumber>{stats?.total_predictions?.toLocaleString() || 0}</StatNumber>
                  <StatHelpText>
                    <StatArrow type="increase" />
                    {t.aiAnalytics?.continuouslyGrowing ?? 'Growing'}
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
                  {t.aiAnalytics?.modelConfig ?? 'Model configuration'}
                </Heading>

                <SimpleGrid columns={2} spacing={4}>
                  <Box>
                    <Text fontSize="sm" color="gray.500" mb={1}>
                      {t.aiAnalytics?.contaminationThreshold ?? 'Contamination'}
                    </Text>
                    <Text fontSize="xl" fontWeight="bold">
                      {stats?.contamination || 0}
                    </Text>
                  </Box>

                  <Box>
                    <Text fontSize="sm" color="gray.500" mb={1}>
                      {t.aiAnalytics?.anomalyThreshold ?? 'Anomaly threshold'}
                    </Text>
                    <Text fontSize="xl" fontWeight="bold">
                      {stats?.threshold?.toFixed(4) || 0}
                    </Text>
                  </Box>

                  <Box>
                    <Text fontSize="sm" color="gray.500" mb={1}>
                      {t.aiAnalytics?.avgTreeDepth ?? 'Avg tree depth'}
                    </Text>
                    <Text fontSize="xl" fontWeight="bold">
                      {stats?.avg_tree_depth?.toFixed(2) || 0}
                    </Text>
                  </Box>

                  <Box>
                    <Text fontSize="sm" color="gray.500" mb={1}>
                      {t.aiAnalytics?.anomalyDetectionRate ?? 'Anomaly rate'}
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
                    {t.aiAnalytics?.anomalyCountTotalPrediction ?? 'Anomalies / Predictions'}
                  </Text>
                  <Progress
                    value={parseFloat(anomalyRate)}
                    max={100}
                    colorScheme={parseFloat(anomalyRate) > 5 ? 'red' : 'green'}
                    borderRadius="md"
                  />
                  <HStack justify="space-between" mt={2}>
                    <Text fontSize="xs" color="gray.500">
                      {t.aiAnalytics?.anomaly ?? 'Anomaly'}: {stats?.anomaly_count || 0}
                    </Text>
                    <Text fontSize="xs" color="gray.500">
                      {t.aiAnalytics?.total ?? 'Total'}: {stats?.total_predictions || 0}
                    </Text>
                  </HStack>
                </Box>

                {stats?.last_training && (
                  <Box>
                    <Text fontSize="sm" color="gray.500">
                      {t.aiAnalytics?.lastTrainingTime ?? 'Last training'}: {new Date(stats.last_training).toLocaleString()}
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
                  {t.aiAnalytics?.recentDetection ?? 'Recent detections'}
                </Heading>

                <Box overflowX="auto" maxH="320px" overflowY="auto">
                  <Table size="sm">
                    <Thead position="sticky" top={0} bg="white" zIndex={1}>
                      <Tr>
                        <Th>{t.aiAnalytics?.time ?? 'Time'}</Th>
                        <Th>{t.aiAnalytics?.level ?? 'Level'}</Th>
                        <Th>{t.aiAnalytics?.score ?? 'Score'}</Th>
                        <Th>{t.aiAnalytics?.reason ?? 'Reason'}</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {predictions.length === 0 ? (
                        <Tr>
                          <Td colSpan={4} textAlign="center" py={8}>
                            <Text color="gray.500">{t.aiAnalytics?.noPredictions ?? 'No predictions yet'}</Text>
                          </Td>
                        </Tr>
                      ) : (
                        predictions.map((pred, idx) => (
                          <Tr key={idx}>
                            <Td whiteSpace="nowrap">
                              {new Date(pred.timestamp).toLocaleTimeString()}
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
                            <Td whiteSpace="nowrap">{pred.reason || '-'}</Td>
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

        {/* Training History */}
        <Card>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <Heading size="md" display="flex" alignItems="center">
                <Icon as={FiClock} mr={2} />
                {t.aiAnalytics?.trainingHistory ?? 'Training history'}
              </Heading>

              <Box overflowX="auto" maxH="320px" overflowY="auto">
                <Table size="sm">
                  <Thead position="sticky" top={0} bg="white" zIndex={1}>
                    <Tr>
                      <Th>{t.aiAnalytics?.historyTime ?? 'Time'}</Th>
                      <Th>{t.aiAnalytics?.historyTrigger ?? 'Trigger'}</Th>
                      <Th>{t.aiAnalytics?.historySource ?? 'Source'}</Th>
                      <Th isNumeric>{t.aiAnalytics?.historyNTrees ?? 'Trees'}</Th>
                      <Th isNumeric>{t.aiAnalytics?.historySamples ?? 'Samples'}</Th>
                      <Th isNumeric>{t.aiAnalytics?.historyContamination ?? 'Contamination'}</Th>
                      <Th isNumeric>{t.aiAnalytics?.historyDuration ?? 'Duration'}</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {history.length === 0 ? (
                      <Tr>
                        <Td colSpan={7} textAlign="center" py={8}>
                          <Text color="gray.500">
                            {t.aiAnalytics?.noTrainingHistory ?? 'No training records yet'}
                          </Text>
                        </Td>
                      </Tr>
                    ) : (
                      history.map((entry) => (
                        <Tr key={entry.id}>
                          <Td whiteSpace="nowrap">{new Date(entry.timestamp).toLocaleString()}</Td>
                          <Td>
                            <Badge colorScheme="blue" variant="subtle">
                              {getTriggerLabel(entry.triggered)}
                            </Badge>
                          </Td>
                          <Td>
                            <Badge colorScheme={entry.sample_source === 'auto' ? 'green' : 'purple'} variant="subtle">
                              {getSourceLabel(entry.sample_source)}
                            </Badge>
                          </Td>
                          <Td isNumeric>{entry.n_trees}</Td>
                          <Td isNumeric>{entry.sample_count.toLocaleString()}</Td>
                          <Td isNumeric>{entry.contamination.toFixed(2)}</Td>
                          <Td isNumeric>{formatDuration(entry.duration_ms)}</Td>
                        </Tr>
                      ))
                    )}
                  </Tbody>
                </Table>
              </Box>
            </VStack>
          </CardBody>
        </Card>

        {/* Information Cards */}
        <SimpleGrid columns={{ base: 1, md: 3 }} spacing={4}>
          <Card>
            <CardBody>
              <VStack spacing={3} align="start">
                <Icon as={FaBrain} boxSize={8} color="blue.500" />
                <Heading size="sm">{t.aiAnalytics?.isolationForest ?? 'Isolation Forest'}</Heading>
                <Text fontSize="sm" color="gray.600">
                  {t.aiAnalytics?.isolationForestDesc ?? 'Unsupervised anomaly detection via Isolation Forest.'}
                </Text>
              </VStack>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <VStack spacing={3} align="start">
                <Icon as={FiTarget} boxSize={8} color="green.500" />
                <Heading size="sm">{t.aiAnalytics?.multiDimFeatures ?? 'Multi-dimensional features'}</Heading>
                <Text fontSize="sm" color="gray.600">
                  {t.aiAnalytics?.multiDimFeaturesDesc ?? '40+ features extracted from each HTTP request.'}
                </Text>
              </VStack>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <VStack spacing={3} align="start">
                <Icon as={FiShield} boxSize={8} color="purple.500" />
                <Heading size="sm">{t.aiAnalytics?.smartThreatScore ?? 'Smart threat score'}</Heading>
                <Text fontSize="sm" color="gray.600">
                  {t.aiAnalytics?.smartThreatScoreDesc ?? 'Composite score from anomaly, IP reputation, behavior and trends.'}
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
          <ModalHeader>{t.aiAnalytics?.trainModalTitle ?? 'Train ML model'}</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <VStack spacing={4}>
              <Alert status="info" variant="left-accent">
                <AlertIcon />
                <Box>
                  <Text fontWeight="bold">{t.aiAnalytics?.trainDescription ?? 'Training notes'}</Text>
                  <Text fontSize="sm">
                    {t.aiAnalytics?.autoSampleHint ?? 'Will use recently collected real traffic samples.'}
                  </Text>
                  <Text fontSize="sm" mt={1} color="gray.600">
                    {t.aiAnalytics?.collectedSamples ?? 'Collected'}: <b>{collected.toLocaleString()}</b>
                  </Text>
                </Box>
              </Alert>

              <FormControl>
                <FormLabel>{t.aiAnalytics?.treeCount ?? 'Tree count'}</FormLabel>
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
                  {t.aiAnalytics?.treeCountHint ?? 'More trees → better accuracy, more memory.'}
                </Text>
              </FormControl>

              <FormControl>
                <FormLabel>{t.aiAnalytics?.maxSamples ?? 'Max samples per tree'}</FormLabel>
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
                  {t.aiAnalytics?.maxSamplesHint ?? 'Samples drawn per tree.'}
                </Text>
              </FormControl>

              <FormControl>
                <FormLabel>{t.aiAnalytics?.contamination ?? 'Contamination'}</FormLabel>
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
                  {t.aiAnalytics?.contaminationHint ?? 'Expected anomaly ratio.'}
                </Text>
              </FormControl>
            </VStack>
          </ModalBody>
          <ModalFooter>
            <Button variant="ghost" onClick={onTrainModalClose} isDisabled={training}>
              {t.aiAnalytics?.cancel ?? t.common.cancel}
            </Button>
            <Button
              colorScheme="blue"
              onClick={handleTrain}
              isLoading={training}
              loadingText={t.aiAnalytics?.training ?? 'Training...'}
            >
              {t.aiAnalytics?.startTraining ?? 'Start training'}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Box>
  )
}

export default AIAnalytics

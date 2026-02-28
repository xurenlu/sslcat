import React, { useState, useEffect } from 'react'
import {
  Box,
  Heading,
  Text,
  Card,
  CardBody,
  SimpleGrid,
  Button,
  Icon,
  useToast,
  HStack,
  VStack,
  Badge,
  Divider,
  Select,
  Input,
  FormControl,
  FormLabel,
  useColorModeValue,
  Spinner,
  Alert,
  AlertIcon,
  Tab,
  TabList,
  TabPanel,
  TabPanels,
  Tabs,
} from '@chakra-ui/react'
import {
  FiFileText,
  FiDownload,
  FiRefreshCw,
  FiCheckCircle,
} from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

interface ReportConfig {
  reportType: 'daily' | 'weekly' | 'monthly' | 'custom'
  startDate: string
  endDate: string
  includeCharts: boolean
  includeAttackDetails: boolean
  includeRecommendations: boolean
  format: 'pdf' | 'html' | 'json'
}

interface ReportStatus {
  id: string
  type: string
  status: 'pending' | 'generating' | 'completed' | 'failed'
  created: string
  completed?: string
  downloadUrl?: string
  error?: string
}

const SecurityReports: React.FC = () => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  const toast = useToast()

  const [config, setConfig] = useState<ReportConfig>({
    reportType: 'weekly',
    startDate: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
    endDate: new Date().toISOString().split('T')[0],
    includeCharts: true,
    includeAttackDetails: true,
    includeRecommendations: true,
    format: 'pdf',
  })

  const [generating, setGenerating] = useState(false)
  const [recentReports, setRecentReports] = useState<ReportStatus[]>([])
  const [loading, setLoading] = useState(true)

  const bgColor = useColorModeValue('white', 'gray.800')
  const borderColor = useColorModeValue('gray.200', 'gray.700')

  const loadRecentReports = async () => {
    try {
      const response = await fetch(buildApiPath(adminPrefix, '/api/security-reports/list'), {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json()
        setRecentReports(data.reports || [])
      }
    } catch (error) {
      console.error('Error loading reports:', error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadRecentReports()
  }, [adminPrefix])

  const handleGenerate = async () => {
    setGenerating(true)
    try {
      // 转换为后端期望的蛇形命名格式
      const requestBody = {
        report_type: config.reportType,
        start_date: config.startDate,
        end_date: config.endDate,
        include_charts: config.includeCharts,
        include_attack_details: config.includeAttackDetails,
        include_recommendations: config.includeRecommendations,
        format: config.format,
      }

      const response = await fetch(buildApiPath(adminPrefix, '/api/security-reports/generate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(requestBody),
      })

      if (response.ok) {
        const data = await response.json()

        // 如果是同步生成，直接下载
        if (data.download_url) {
          window.open(data.download_url, '_blank')
          toast({
            title: '报告生成成功',
            description: '报告已自动下载',
            status: 'success',
            duration: 3000,
            isClosable: true,
          })
        } else {
          // 异步生成
          toast({
            title: '报告已加入队列',
            description: '报告正在后台生成，请稍后在列表中查看',
            status: 'info',
            duration: 3000,
            isClosable: true,
          })
          loadRecentReports()
        }
      } else {
        const error = await response.json()
        throw new Error(error.error || '生成失败')
      }
    } catch (error) {
      console.error('Error generating report:', error)
      toast({
        title: '生成失败',
        description: error instanceof Error ? error.message : '生成报告时出错',
        status: 'error',
        duration: 5000,
        isClosable: true,
      })
    } finally {
      setGenerating(false)
    }
  }

  const handleDownload = (report: ReportStatus) => {
    if (report.downloadUrl) {
      window.open(report.downloadUrl, '_blank')
    }
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return <Badge colorScheme="green">已完成</Badge>
      case 'generating':
        return <Badge colorScheme="blue">生成中</Badge>
      case 'failed':
        return <Badge colorScheme="red">失败</Badge>
      default:
        return <Badge colorScheme="gray">等待中</Badge>
    }
  }

  return (
    <Box p={6}>
      <VStack spacing={6} align="stretch">
        {/* Header */}
        <Heading size="lg" display="flex" alignItems="center">
          <Icon as={FiFileText} mr={3} />
          安全报告
        </Heading>

        <SimpleGrid columns={{ base: 1, lg: 2 }} spacing={6}>
          {/* Report Configuration */}
          <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
            <CardBody>
              <VStack spacing={4} align="stretch">
                <Heading size="md">生成报告</Heading>

                <FormControl>
                  <FormLabel>报告类型</FormLabel>
                  <Select
                    value={config.reportType}
                    onChange={(e) => setConfig({ ...config, reportType: e.target.value as any })}
                  >
                    <option value="daily">每日报告</option>
                    <option value="weekly">每周报告</option>
                    <option value="monthly">每月报告</option>
                    <option value="custom">自定义</option>
                  </Select>
                </FormControl>

                <HStack>
                  <FormControl>
                    <FormLabel>开始日期</FormLabel>
                    <Input
                      type="date"
                      value={config.startDate}
                      onChange={(e) => setConfig({ ...config, startDate: e.target.value })}
                    />
                  </FormControl>

                  <FormControl>
                    <FormLabel>结束日期</FormLabel>
                    <Input
                      type="date"
                      value={config.endDate}
                      onChange={(e) => setConfig({ ...config, endDate: e.target.value })}
                    />
                  </FormControl>
                </HStack>

                <FormControl>
                  <FormLabel>导出格式</FormLabel>
                  <Select
                    value={config.format}
                    onChange={(e) => setConfig({ ...config, format: e.target.value as any })}
                  >
                    <option value="pdf">PDF 文档</option>
                    <option value="html">HTML 网页</option>
                    <option value="json">JSON 数据</option>
                  </Select>
                </FormControl>

                <Divider />

                <Heading size="sm">包含内容</Heading>

                <VStack align="start" spacing={2}>
                  <HStack justify="space-between" w="full">
                    <Text>图表和可视化</Text>
                    <input
                      type="checkbox"
                      checked={config.includeCharts}
                      onChange={(e) => setConfig({ ...config, includeCharts: e.target.checked })}
                    />
                  </HStack>
                  <HStack justify="space-between" w="full">
                    <Text>攻击详情列表</Text>
                    <input
                      type="checkbox"
                      checked={config.includeAttackDetails}
                      onChange={(e) => setConfig({ ...config, includeAttackDetails: e.target.checked })}
                    />
                  </HStack>
                  <HStack justify="space-between" w="full">
                    <Text>优化建议</Text>
                    <input
                      type="checkbox"
                      checked={config.includeRecommendations}
                      onChange={(e) => setConfig({ ...config, includeRecommendations: e.target.checked })}
                    />
                  </HStack>
                </VStack>

                <Button
                  leftIcon={<Icon as={FiDownload} />}
                  colorScheme="blue"
                  onClick={handleGenerate}
                  isLoading={generating}
                  loadingText="生成中..."
                  width="full"
                >
                  生成报告
                </Button>
              </VStack>
            </CardBody>
          </Card>

          {/* Recent Reports */}
          <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
            <CardBody>
              <VStack spacing={4} align="stretch">
                <HStack justify="space-between">
                  <Heading size="md">最近报告</Heading>
                  <Button
                    leftIcon={<Icon as={FiRefreshCw} />}
                    size="sm"
                    variant="outline"
                    onClick={loadRecentReports}
                  >
                    刷新
                  </Button>
                </HStack>

                {loading ? (
                  <Box py={8} textAlign="center">
                    <Spinner />
                  </Box>
                ) : recentReports.length === 0 ? (
                  <Alert status="info">
                    <AlertIcon />
                    <Box>
                      <Text fontWeight="bold">暂无报告</Text>
                      <Text fontSize="sm">生成第一份安全报告来查看系统安全状况</Text>
                    </Box>
                  </Alert>
                ) : (
                  <VStack spacing={3} align="stretch">
                    {recentReports.map((report) => (
                      <Card key={report.id} variant="outline" size="sm">
                        <CardBody p={3}>
                          <HStack justify="space-between">
                            <VStack align="start" spacing={1}>
                              <HStack>
                                <Icon as={FiFileText} color="blue.500" />
                                <Text fontWeight="bold">{report.type}</Text>
                                {getStatusBadge(report.status)}
                              </HStack>
                              <Text fontSize="xs" color="gray.500">
                                创建: {new Date(report.created).toLocaleString('zh-CN')}
                              </Text>
                            </VStack>

                            {report.status === 'completed' && (
                              <Button
                                leftIcon={<Icon as={FiDownload} />}
                                size="sm"
                                colorScheme="green"
                                onClick={() => handleDownload(report)}
                              >
                                下载
                              </Button>
                            )}

                            {report.status === 'generating' && (
                              <Spinner size="sm" />
                            )}

                            {report.status === 'failed' && (
                              <Text fontSize="xs" color="red.500">
                                {report.error || '生成失败'}
                              </Text>
                            )}
                          </HStack>
                        </CardBody>
                      </Card>
                    ))}
                  </VStack>
                )}
              </VStack>
            </CardBody>
          </Card>
        </SimpleGrid>

        {/* Report Templates */}
        <Card bg={bgColor} borderColor={borderColor} borderWidth="1px">
          <CardBody>
            <VStack spacing={4} align="stretch">
              <Heading size="md">报告模板说明</Heading>

              <Tabs>
                <TabList>
                  <Tab>每日报告</Tab>
                  <Tab>每周报告</Tab>
                  <Tab>每月报告</Tab>
                </TabList>

                <TabPanels>
                  <TabPanel>
                    <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                      <Box>
                        <Heading size="sm" mb={2}>包含内容</Heading>
                        <VStack align="start" spacing={2}>
                          <HStack><Icon as={FiCheckCircle} color="green.500" /><Text>24小时安全事件汇总</Text></HStack>
                          <HStack><Icon as={FiCheckCircle} color="green.500" /><Text>WAF拦截统计</Text></HStack>
                          <HStack><Icon as={FiCheckCircle} color="green.500" /><Text>流量异常分析</Text></HStack>
                          <HStack><Icon as={FiCheckCircle} color="green.500" /><Text>新增威胁IP列表</Text></HStack>
                        </VStack>
                      </Box>
                      <Box>
                        <Heading size="sm" mb={2}>适用场景</Heading>
                        <Text fontSize="sm" color="gray.600">
                          日常安全监控，快速了解过去24小时的安全状况。适合每日晨会使用。
                        </Text>
                      </Box>
                    </SimpleGrid>
                  </TabPanel>

                  <TabPanel>
                    <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                      <Box>
                        <Heading size="sm" mb={2}>包含内容</Heading>
                        <VStack align="start" spacing={2}>
                          <HStack><Icon as={FiCheckCircle} color="green.500" /><Text>7天趋势分析</Text></HStack>
                          <HStack><Icon as={FiCheckCircle} color="green.500" /><Text>攻击类型分布</Text></HStack>
                          <HStack><Icon as={FiCheckCircle} color="green.500" /><Text>地理来源统计</Text></HStack>
                          <HStack><Icon as={FiCheckCircle} color="green.500" /><Text>高危事件详情</Text></HStack>
                          <HStack><Icon as={FiCheckCircle} color="green.500" /><Text>安全建议</Text></HStack>
                        </VStack>
                      </Box>
                      <Box>
                        <Heading size="sm" mb={2}>适用场景</Heading>
                        <Text fontSize="sm" color="gray.600">
                          周度安全回顾，全面了解一周的安全态势。适合周报和安全团队讨论。
                        </Text>
                      </Box>
                    </SimpleGrid>
                  </TabPanel>

                  <TabPanel>
                    <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                      <Box>
                        <Heading size="sm" mb={2}>包含内容</Heading>
                        <VStack align="start" spacing={2}>
                          <HStack><Icon as={FiCheckCircle} color="green.500" /><Text>30天完整分析</Text></HStack>
                          <HStack><Icon as={FiCheckCircle} color="green.500" /><Text>月度趋势对比</Text></HStack>
                          <HStack><Icon as={FiCheckCircle} color="green.500" /><Text>威胁演变分析</Text></HStack>
                          <HStack><Icon as={FiCheckCircle} color="green.500" /><Text>防御效果评估</Text></HStack>
                          <HStack><Icon as={FiCheckCircle} color="green.500" /><Text>改进建议</Text></HStack>
                        </VStack>
                      </Box>
                      <Box>
                        <Heading size="sm" mb={2}>适用场景</Heading>
                        <Text fontSize="sm" color="gray.600">
                          月度安全报告，用于管理层汇报和长期安全策略规划。
                        </Text>
                      </Box>
                    </SimpleGrid>
                  </TabPanel>
                </TabPanels>
              </Tabs>
            </VStack>
          </CardBody>
        </Card>
      </VStack>
    </Box>
  )
}

export default SecurityReports

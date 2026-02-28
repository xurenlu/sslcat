import React, { useState } from 'react'
import {
  Box,
  VStack,
  HStack,
  Text,
  Button,
  FormControl,
  FormLabel,
  Input,
  Textarea,
  Select,
  Badge,
  Alert,
  AlertIcon,
  Code,
  useToast,
  Divider,
  SimpleGrid,
  Card,
  CardHeader,
  CardBody,
  Heading,
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
  Tag,
  Wrap,
  WrapItem,
} from '@chakra-ui/react'
import { FiPlay, FiRefreshCw, FiCopy, FiCheck } from 'react-icons/fi'
import axios from 'axios'

interface WAFRuleTestToolProps {
  existingRules?: Array<{ id: string; name: string; type: string }>
}

interface TestRequest {
  test_url: string
  test_method: string
  test_headers: Record<string, string>
  test_body: string
}

interface TestResult {
  success: boolean
  matched: boolean
  blocked?: boolean
  rule_name?: string
  rule_id?: string
  match_details?: string
  error?: string
}

const WAFRuleTestTool: React.FC<WAFRuleTestToolProps> = ({ existingRules = [] }) => {
  const toast = useToast()

  const [testMode, setTestMode] = useState<'existing' | 'custom'>('custom')
  const [selectedRuleId, setSelectedRuleId] = useState('')
  const [customRule, setCustomRule] = useState({
    name: '',
    type: 'xss',
    pattern: '',
    action: 'block',
  })

  const [testRequest, setTestRequest] = useState<TestRequest>({
    test_url: '/api/test?query=<script>alert(1)</script>',
    test_method: 'GET',
    test_headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    },
    test_body: '',
  })

  const [isLoading, setIsLoading] = useState(false)
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const [copied, setCopied] = useState(false)

  const commonTestCases = [
    {
      name: 'XSS 攻击',
      method: 'GET',
      url: '/search?q=<script>alert("XSS")</script>',
      body: '',
    },
    {
      name: 'SQL 注入',
      method: 'POST',
      url: '/api/login',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: "admin' OR '1'='1", password: 'test' }),
    },
    {
      name: '路径遍历',
      method: 'GET',
      url: '/files?path=../../../etc/passwd',
      body: '',
    },
    {
      name: '命令注入',
      method: 'GET',
      url: '/api/ping?ip=127.0.0.1;cat%20/etc/passwd',
      body: '',
    },
    {
      name: '正常请求',
      method: 'GET',
      url: '/api/users?page=1&limit=10',
      body: '',
    },
  ]

  const handleRunTest = async () => {
    // 验证输入
    if (testMode === 'existing' && !selectedRuleId) {
      toast({
        title: '验证失败',
        description: '请选择要测试的规则',
        status: 'error',
        duration: 3000,
      })
      return
    }

    if (testMode === 'custom' && !customRule.pattern.trim()) {
      toast({
        title: '验证失败',
        description: '请输入规则匹配模式',
        status: 'error',
        duration: 3000,
      })
      return
    }

    setIsLoading(true)
    setTestResult(null)

    try {
      const payload: any = {
        ...testRequest,
      }

      if (testMode === 'existing') {
        payload.rule_id = selectedRuleId
      } else {
        payload.rule = customRule
      }

      const response = await axios.post('/api/waf/rule/test', payload)
      setTestResult(response.data)

      toast({
        title: '测试完成',
        description: response.data.matched ? '规则匹配成功' : '规则未匹配',
        status: response.data.matched ? 'warning' : 'success',
        duration: 3000,
      })
    } catch (error: any) {
      const errorMsg = error.response?.data?.message || '测试请求失败'
      setTestResult({
        success: false,
        matched: false,
        error: errorMsg,
      })
      toast({
        title: '测试失败',
        description: errorMsg,
        status: 'error',
        duration: 5000,
      })
    } finally {
      setIsLoading(false)
    }
  }

  const handleLoadTestCase = (testCase: typeof commonTestCases[0]) => {
    setTestRequest({
      test_url: testCase.url,
      test_method: testCase.method,
      test_headers: testCase.headers || testRequest.test_headers,
      test_body: testCase.body,
    })
    setTestResult(null)
  }

  const handleCopyRequest = () => {
    const requestText = `${testRequest.test_method} ${testRequest.test_url}\n` +
      Object.entries(testRequest.test_headers)
        .map(([k, v]) => `${k}: ${v}`)
        .join('\n') +
      (testRequest.test_body ? `\n\n${testRequest.test_body}` : '')

    navigator.clipboard.writeText(requestText)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)

    toast({
      title: '已复制',
      description: '请求信息已复制到剪贴板',
      status: 'success',
      duration: 2000,
    })
  }

  const handleHeaderChange = (index: number, key: string, value: string) => {
    const newHeaders = { ...testRequest.test_headers }
    if (value) {
      newHeaders[key] = value
    } else {
      delete newHeaders[key]
    }
    setTestRequest({ ...testRequest, test_headers: newHeaders })
  }

  const addHeader = () => {
    const key = `X-Custom-${Object.keys(testRequest.test_headers).length + 1}`
    setTestRequest({
      ...testRequest,
      test_headers: { ...testRequest.test_headers, [key]: '' }
    })
  }

  const removeHeader = (key: string) => {
    const newHeaders = { ...testRequest.test_headers }
    delete newHeaders[key]
    setTestRequest({ ...testRequest, test_headers: newHeaders })
  }

  return (
    <VStack spacing={6} align="stretch">
      {/* 规则选择 */}
      <Card>
        <CardHeader>
          <Heading size="md">测试规则</Heading>
        </CardHeader>
        <CardBody>
          <VStack spacing={4} align="stretch">
            <FormControl>
              <FormLabel>测试模式</FormLabel>
              <Select value={testMode} onChange={(e) => setTestMode(e.target.value as any)}>
                <option value="custom">自定义规则</option>
                <option value="existing">现有规则</option>
              </Select>
            </FormControl>

            {testMode === 'existing' ? (
              <FormControl>
                <FormLabel>选择规则</FormLabel>
                <Select
                  placeholder="选择要测试的规则"
                  value={selectedRuleId}
                  onChange={(e) => setSelectedRuleId(e.target.value)}
                >
                  {existingRules.map((rule) => (
                    <option key={rule.id} value={rule.id}>
                      {rule.name} ({rule.type})
                    </option>
                  ))}
                </Select>
              </FormControl>
            ) : (
              <>
                <FormControl>
                  <FormLabel>规则名称</FormLabel>
                  <Input
                    value={customRule.name}
                    onChange={(e) => setCustomRule({ ...customRule, name: e.target.value })}
                    placeholder="测试规则名称"
                  />
                </FormControl>
                <SimpleGrid columns={2} spacing={3}>
                  <FormControl>
                    <FormLabel>规则类型</FormLabel>
                    <Select
                      value={customRule.type}
                      onChange={(e) => setCustomRule({ ...customRule, type: e.target.value })}
                    >
                      <option value="sql_injection">SQL 注入</option>
                      <option value="xss">XSS</option>
                      <option value="path_traversal">路径遍历</option>
                      <option value="command_injection">命令注入</option>
                      <option value="custom">自定义</option>
                    </Select>
                  </FormControl>
                  <FormControl>
                    <FormLabel>动作</FormLabel>
                    <Select
                      value={customRule.action}
                      onChange={(e) => setCustomRule({ ...customRule, action: e.target.value })}
                    >
                      <option value="block">拦截</option>
                      <option value="log">日志</option>
                      <option value="warn">警告</option>
                    </Select>
                  </FormControl>
                </SimpleGrid>
                <FormControl isRequired>
                  <FormLabel>匹配模式</FormLabel>
                  <Textarea
                    value={customRule.pattern}
                    onChange={(e) => setCustomRule({ ...customRule, pattern: e.target.value })}
                    placeholder="例如: &lt;script&gt;.*?&lt;/script&gt;"
                    fontFamily="monospace"
                    rows={3}
                  />
                </FormControl>
              </>
            )}
          </VStack>
        </CardBody>
      </Card>

      {/* 测试请求 */}
      <Card>
        <CardHeader>
          <HStack justify="space-between">
            <Heading size="md">测试请求</Heading>
            <HStack spacing={2}>
              <Button
                size="sm"
                variant="outline"
                leftIcon={<FiCopy />}
                onClick={handleCopyRequest}
              >
                {copied ? <FiCheck /> : '复制'}
              </Button>
            </HStack>
          </HStack>
        </CardHeader>
        <CardBody>
          <VStack spacing={4} align="stretch">
            {/* 预设测试用例 */}
            <Box>
              <Text fontSize="sm" fontWeight="medium" mb={2}>
                快速加载测试用例
              </Text>
              <Wrap>
                {commonTestCases.map((testCase) => (
                  <WrapItem key={testCase.name}>
                    <Tag
                      size="md"
                      variant="solid"
                      colorScheme={
                        testCase.name === '正常请求' ? 'green' : 'gray'
                      }
                      cursor="pointer"
                      onClick={() => handleLoadTestCase(testCase)}
                      _hover={{ bg: 'gray.300' }}
                    >
                      {testCase.name}
                    </Tag>
                  </WrapItem>
                ))}
              </Wrap>
            </Box>

            <Divider />

            {/* 请求行 */}
            <HStack spacing={2}>
              <Select
                w="140px"
                value={testRequest.test_method}
                onChange={(e) => setTestRequest({ ...testRequest, test_method: e.target.value })}
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
                <option value="PATCH">PATCH</option>
                <option value="HEAD">HEAD</option>
                <option value="OPTIONS">OPTIONS</option>
              </Select>
              <Input
                flex={1}
                value={testRequest.test_url}
                onChange={(e) => setTestRequest({ ...testRequest, test_url: e.target.value })}
                placeholder="/path?query=value"
                fontFamily="monospace"
              />
            </HStack>

            {/* 请求头 */}
            <Accordion allowMultiple>
              <AccordionItem>
                <AccordionButton>
                  <HStack flex="1" textAlign="left">
                    <Text fontSize="sm" fontWeight="medium">
                      请求头 ({Object.keys(testRequest.test_headers).length})
                    </Text>
                  </HStack>
                  <AccordionIcon />
                </AccordionButton>
                <AccordionPanel pb={4}>
                  <VStack spacing={2} align="stretch">
                    {Object.entries(testRequest.test_headers).map(([key, value], index) => (
                      <HStack key={key} spacing={2}>
                        <Input
                          size="sm"
                          value={key}
                          onChange={(e) => {
                            const newHeaders = { ...testRequest.test_headers }
                            delete newHeaders[key]
                            newHeaders[e.target.value] = value
                            setTestRequest({ ...testRequest, test_headers: newHeaders })
                          }}
                          placeholder="Header name"
                          flex={1}
                        />
                        <Input
                          size="sm"
                          value={value}
                          onChange={(e) => handleHeaderChange(index, key, e.target.value)}
                          placeholder="Header value"
                          flex={2}
                        />
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => removeHeader(key)}
                        >
                          删除
                        </Button>
                      </HStack>
                    ))}
                    <Button size="sm" variant="outline" onClick={addHeader}>
                      添加请求头
                    </Button>
                  </VStack>
                </AccordionPanel>
              </AccordionItem>
            </Accordion>

            {/* 请求体 */}
            {['POST', 'PUT', 'PATCH'].includes(testRequest.test_method) && (
              <FormControl>
                <FormLabel fontSize="sm">请求体</FormLabel>
                <Textarea
                  value={testRequest.test_body}
                  onChange={(e) => setTestRequest({ ...testRequest, test_body: e.target.value })}
                  placeholder='{"key": "value"}'
                  fontFamily="monospace"
                  rows={5}
                />
              </FormControl>
            )}

            {/* 运行测试按钮 */}
            <Button
              colorScheme="blue"
              size="lg"
              leftIcon={<FiPlay />}
              isLoading={isLoading}
              onClick={handleRunTest}
              w="full"
            >
              运行测试
            </Button>
          </VStack>
        </CardBody>
      </Card>

      {/* 测试结果 */}
      {testResult && (
        <Card>
          <CardHeader>
            <HStack justify="space-between">
              <Heading size="md">测试结果</Heading>
              {testResult.matched !== undefined && (
                <Badge
                  colorScheme={testResult.matched ? 'red' : 'green'}
                  fontSize="md"
                  px={3}
                  py={1}
                >
                  {testResult.matched ? '规则匹配' : '规则未匹配'}
                </Badge>
              )}
            </HStack>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              {testResult.error ? (
                <Alert status="error">
                  <AlertIcon />
                  <Text>{testResult.error}</Text>
                </Alert>
              ) : (
                <>
                  {testResult.matched && (
                    <Alert status="warning">
                      <AlertIcon />
                      <Box>
                        <Text fontWeight="bold">规则触发</Text>
                        <Text fontSize="sm">
                          匹配规则: {testResult.rule_name}
                        </Text>
                        {testResult.match_details && (
                          <Text fontSize="xs" color="gray.600" mt={1}>
                            {testResult.match_details}
                          </Text>
                        )}
                      </Box>
                    </Alert>
                  )}

                  {!testResult.matched && (
                    <Alert status="success">
                      <AlertIcon />
                      <Box>
                        <Text fontWeight="bold">规则未触发</Text>
                        <Text fontSize="sm">
                          请求未匹配任何 WAF 规则，请求将被正常处理
                        </Text>
                      </Box>
                    </Alert>
                  )}

                  {testResult.blocked !== undefined && (
                    <HStack spacing={2}>
                      <Text fontSize="sm" fontWeight="medium">
                        处理结果:
                      </Text>
                      <Badge colorScheme={testResult.blocked ? 'red' : 'green'}>
                        {testResult.blocked ? '已拦截' : '未拦截'}
                      </Badge>
                    </HStack>
                  )}

                  {testResult.rule_id && (
                    <Text fontSize="sm">
                      <Text as="span" fontWeight="medium">规则 ID: </Text>
                      <Code fontSize="xs">{testResult.rule_id}</Code>
                    </Text>
                  )}
                </>
              )}
            </VStack>
          </CardBody>
        </Card>
      )}
    </VStack>
  )
}

export default WAFRuleTestTool

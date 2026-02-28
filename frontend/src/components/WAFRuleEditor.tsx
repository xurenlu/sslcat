import React, { useState, useEffect } from 'react'
import {
  Box,
  VStack,
  HStack,
  Text,
  Button,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalFooter,
  ModalCloseButton,
  FormControl,
  FormLabel,
  Input,
  Textarea,
  Select,
  Switch,
  Badge,
  Divider,
  Alert,
  AlertIcon,
  Code,
  useToast,
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  NumberIncrementStepper,
  NumberDecrementStepper,
  SimpleGrid,
  IconButton,
  Tooltip,
  Tag,
  TagLabel,
  TagCloseButton,
  Wrap,
  WrapItem,
} from '@chakra-ui/react'
import { FiPlus, FiX, FiActivity, FiSave, FiUpload, FiDownload } from 'react-icons/fi'
import { useTranslation } from '../hooks/useLanguage'
import { WAFRule, RuleType, ActionType } from '../types/waf'
import axios from 'axios'

interface WAFRuleEditorProps {
  isOpen: boolean
  onClose: () => void
  onSave: () => void
  editRule?: WAFRule | null
}

interface RuleCondition {
  field: string
  operator: string
  value: string
}

interface RuleAction {
  type: string
  params?: Record<string, any>
}

const WAFRuleEditor: React.FC<WAFRuleEditorProps> = ({ isOpen, onClose, onSave, editRule }) => {
  const t = useTranslation()
  const toast = useToast()

  const [ruleId, setRuleId] = useState('')
  const [ruleName, setRuleName] = useState('')
  const [ruleType, setRuleType] = useState<string>(RuleType.Custom)
  const [pattern, setPattern] = useState('')
  const [action, setAction] = useState<string>(ActionType.Block)
  const [enabled, setEnabled] = useState(true)
  const [description, setDescription] = useState('')
  const [priority, setPriority] = useState(50)
  const [tags, setTags] = useState<string[]>([])
  const [tagInput, setTagInput] = useState('')
  const [severity, setSeverity] = useState('medium')
  const [category, setCategory] = useState('')

  // 高级规则条件
  const [conditions, setConditions] = useState<RuleCondition[]>([])
  const [actions, setActions] = useState<RuleAction[]>([{ type: 'block' }])

  const [isTesting, setIsTesting] = useState(false)
  const [testResult, setTestResult] = useState<any>(null)

  // 重置表单
  useEffect(() => {
    if (isOpen) {
      if (editRule) {
        setRuleId(editRule.id)
        setRuleName(editRule.name)
        setRuleType(editRule.type)
        setPattern(editRule.pattern)
        setAction(editRule.action)
        setEnabled(editRule.enabled)
        setDescription(editRule.description)
      } else {
        resetForm()
      }
    }
  }, [isOpen, editRule])

  const resetForm = () => {
    setRuleId('')
    setRuleName('')
    setRuleType(RuleType.Custom)
    setPattern('')
    setAction(ActionType.Block)
    setEnabled(true)
    setDescription('')
    setPriority(50)
    setTags([])
    setSeverity('medium')
    setCategory('')
    setConditions([])
    setActions([{ type: 'block' }])
    setTestResult(null)
  }

  const handleSave = async () => {
    // 验证必填字段
    if (!ruleName.trim()) {
      toast({
        title: '验证失败',
        description: '请输入规则名称',
        status: 'error',
        duration: 3000,
      })
      return
    }

    if (!pattern.trim()) {
      toast({
        title: '验证失败',
        description: '请输入规则匹配模式',
        status: 'error',
        duration: 3000,
      })
      return
    }

    try {
      const ruleData = {
        id: ruleId || undefined,
        name: ruleName,
        type: ruleType,
        pattern,
        action,
        enabled,
        description,
        priority,
        tags,
        severity,
        category,
        conditions: conditions.length > 0 ? conditions : undefined,
        actions: actions.length > 0 ? actions : undefined,
      }

      if (editRule) {
        await axios.post('/api/waf/rule/update?id=' + editRule.id, ruleData)
        toast({
          title: '成功',
          description: '规则已更新',
          status: 'success',
          duration: 3000,
        })
      } else {
        await axios.post('/api/waf/rule/create', ruleData)
        toast({
          title: '成功',
          description: '规则已创建',
          status: 'success',
          duration: 3000,
        })
      }

      onSave()
      onClose()
    } catch (error: any) {
      toast({
        title: '操作失败',
        description: error.response?.data?.message || '保存规则时出错',
        status: 'error',
        duration: 5000,
      })
    }
  }

  const handleTest = async () => {
    if (!pattern.trim()) {
      toast({
        title: '验证失败',
        description: '请先输入规则匹配模式',
        status: 'error',
        duration: 3000,
      })
      return
    }

    setIsTesting(true)
    setTestResult(null)

    try {
      const response = await axios.post('/api/waf/rule/test', {
        rule: {
          name: ruleName || 'Test Rule',
          type: ruleType,
          pattern,
          action,
        },
        test_url: '/test?query=<script>alert("xss")</script>',
        test_method: 'GET',
        test_headers: {
          'User-Agent': 'Mozilla/5.0',
        },
      })

      setTestResult(response.data)
      toast({
        title: '测试完成',
        description: response.data.matched ? '规则匹配成功' : '规则未匹配',
        status: response.data.matched ? 'success' : 'info',
        duration: 3000,
      })
    } catch (error: any) {
      toast({
        title: '测试失败',
        description: error.response?.data?.message || '测试规则时出错',
        status: 'error',
        duration: 5000,
      })
    } finally {
      setIsTesting(false)
    }
  }

  const handleAddTag = () => {
    if (tagInput.trim() && !tags.includes(tagInput.trim())) {
      setTags([...tags, tagInput.trim()])
      setTagInput('')
    }
  }

  const handleRemoveTag = (tagToRemove: string) => {
    setTags(tags.filter(tag => tag !== tagToRemove))
  }

  const handleAddCondition = () => {
    setConditions([...conditions, { field: 'url', operator: 'contains', value: '' }])
  }

  const handleRemoveCondition = (index: number) => {
    setConditions(conditions.filter((_, i) => i !== index))
  }

  const handleUpdateCondition = (index: number, field: keyof RuleCondition, value: string) => {
    const newConditions = [...conditions]
    newConditions[index][field] = value
    setConditions(newConditions)
  }

  const handleAddAction = () => {
    setActions([...actions, { type: 'log' }])
  }

  const handleRemoveAction = (index: number) => {
    setActions(actions.filter((_, i) => i !== index))
  }

  const handleUpdateAction = (index: number, field: keyof RuleAction, value: any) => {
    const newActions = [...actions]
    if (field === 'type') {
      newActions[index][field] = value
    } else if (field === 'params') {
      newActions[index].params = { ...newActions[index].params, ...value }
    }
    setActions(newActions)
  }

  const getRuleTypeLabel = (type: string): string => {
    const labels: Record<string, string> = {
      sql_injection: t.security.sqlInjection || 'SQL注入',
      xss: t.security.xss || 'XSS',
      path_traversal: t.security.pathTraversal || '路径遍历',
      command_injection: t.security.commandInjection || '命令注入',
      file_upload: t.security.fileUpload || '文件上传',
      sensitive_file: t.security.sensitiveFile || '敏感文件',
      scanner_detection: t.security.scannerDetection || '扫描器检测',
      custom: t.security.customRule || '自定义',
    }
    return labels[type] || type
  }

  const getActionLabel = (act: string): string => {
    const labels: Record<string, string> = {
      block: t.security.actionBlock || '拦截',
      log: t.security.actionLog || '日志',
      warn: t.security.actionWarn || '警告',
      allow: '允许',
      redirect: '重定向',
      rate_limit: '限流',
      captcha: '验证码',
    }
    return labels[act] || act
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} size="2xl" scrollBehavior="inside">
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>
          {editRule ? '编辑 WAF 规则' : '创建 WAF 规则'}
        </ModalHeader>
        <ModalCloseButton />

        <ModalBody pb={6}>
          <VStack spacing={4} align="stretch">
            {/* 基本信息 */}
            <Box>
              <Text fontSize="sm" fontWeight="bold" color="gray.700" mb={3}>
                基本信息
              </Text>
              <VStack spacing={3}>
                <FormControl isRequired>
                  <FormLabel fontSize="sm">规则名称</FormLabel>
                  <Input
                    value={ruleName}
                    onChange={(e) => setRuleName(e.target.value)}
                    placeholder="输入规则名称"
                  />
                </FormControl>

                <SimpleGrid columns={2} spacing={3}>
                  <FormControl isRequired>
                    <FormLabel fontSize="sm">规则类型</FormLabel>
                    <Select
                      value={ruleType}
                      onChange={(e) => setRuleType(e.target.value)}
                    >
                      {Object.values(RuleType).map((type) => (
                        <option key={type} value={type}>
                          {getRuleTypeLabel(type)}
                        </option>
                      ))}
                    </Select>
                  </FormControl>

                  <FormControl isRequired>
                    <FormLabel fontSize="sm">动作</FormLabel>
                    <Select
                      value={action}
                      onChange={(e) => setAction(e.target.value)}
                    >
                      <option value="block">拦截</option>
                      <option value="log">日志记录</option>
                      <option value="warn">警告</option>
                      <option value="allow">允许</option>
                      <option value="redirect">重定向</option>
                      <option value="rate_limit">限流</option>
                      <option value="captcha">验证码</option>
                    </Select>
                  </FormControl>
                </SimpleGrid>

                <FormControl isRequired>
                  <FormLabel fontSize="sm">匹配模式 (正则表达式)</FormLabel>
                  <Textarea
                    value={pattern}
                    onChange={(e) => setPattern(e.target.value)}
                    placeholder="例如: &lt;script&gt;.*?&lt;/script&gt;"
                    fontFamily="monospace"
                    rows={3}
                  />
                  <Text fontSize="xs" color="gray.500" mt={1}>
                    支持 Go 语言正则表达式语法
                  </Text>
                </FormControl>

                <FormControl>
                  <FormLabel fontSize="sm">描述</FormLabel>
                  <Textarea
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    placeholder="规则描述..."
                    rows={2}
                  />
                </FormControl>
              </VStack>
            </Box>

            <Divider />

            {/* 规则配置 */}
            <Box>
              <Text fontSize="sm" fontWeight="bold" color="gray.700" mb={3}>
                规则配置
              </Text>
              <VStack spacing={3}>
                <HStack justify="space-between">
                  <Text fontSize="sm">启用规则</Text>
                  <Switch isChecked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
                </HStack>

                <FormControl>
                  <FormLabel fontSize="sm">优先级 (1-100)</FormLabel>
                  <NumberInput
                    value={priority}
                    min={1}
                    max={100}
                    onChange={(value) => setPriority(parseInt(value) || 50)}
                  >
                    <NumberInputField />
                    <NumberInputStepper>
                      <NumberIncrementStepper />
                      <NumberDecrementStepper />
                    </NumberInputStepper>
                  </NumberInput>
                  <Text fontSize="xs" color="gray.500" mt={1}>
                    数值越大优先级越高
                  </Text>
                </FormControl>

                <SimpleGrid columns={2} spacing={3}>
                  <FormControl>
                    <FormLabel fontSize="sm">严重程度</FormLabel>
                    <Select
                      value={severity}
                      onChange={(e) => setSeverity(e.target.value)}
                    >
                      <option value="low">低</option>
                      <option value="medium">中</option>
                      <option value="high">高</option>
                      <option value="critical">严重</option>
                    </Select>
                  </FormControl>

                  <FormControl>
                    <FormLabel fontSize="sm">分类</FormLabel>
                    <Input
                      value={category}
                      onChange={(e) => setCategory(e.target.value)}
                      placeholder="例如: web_attack"
                    />
                  </FormControl>
                </SimpleGrid>

                <FormControl>
                  <FormLabel fontSize="sm">标签</FormLabel>
                  <HStack>
                    <Input
                      value={tagInput}
                      onChange={(e) => setTagInput(e.target.value)}
                      onKeyPress={(e) => e.key === 'Enter' && handleAddTag()}
                      placeholder="添加标签"
                    />
                    <Button size="sm" onClick={handleAddTag}>
                      <FiPlus />
                    </Button>
                  </HStack>
                  {tags.length > 0 && (
                    <Wrap mt={2}>
                      {tags.map((tag) => (
                        <WrapItem key={tag}>
                          <Tag size="md" variant="solid" colorScheme="blue">
                            <TagLabel>{tag}</TagLabel>
                            <TagCloseButton onClick={() => handleRemoveTag(tag)} />
                          </Tag>
                        </WrapItem>
                      ))}
                    </Wrap>
                  )}
                </FormControl>
              </VStack>
            </Box>

            <Divider />

            {/* 高级条件 */}
            <Box>
              <HStack justify="space-between" mb={3}>
                <Text fontSize="sm" fontWeight="bold" color="gray.700">
                  高级条件 (可选)
                </Text>
                <Button size="xs" leftIcon={<FiPlus />} onClick={handleAddCondition}>
                  添加条件
                </Button>
              </HStack>

              {conditions.length === 0 ? (
                <Text fontSize="sm" color="gray.500">
                  无额外条件，规则将仅基于匹配模式
                </Text>
              ) : (
                <VStack spacing={2}>
                  {conditions.map((condition, index) => (
                    <Box key={index} p={3} border="1px" borderColor="gray.200" borderRadius="md" w="full">
                      <HStack spacing={2}>
                        <Select
                          size="sm"
                          value={condition.field}
                          onChange={(e) => handleUpdateCondition(index, 'field', e.target.value)}
                          w="30%"
                        >
                          <option value="url">URL</option>
                          <option value="method">请求方法</option>
                          <option value="headers">请求头</option>
                          <option value="body">请求体</option>
                          <option value="query">查询参数</option>
                          <option value="ip">客户端IP</option>
                        </Select>

                        <Select
                          size="sm"
                          value={condition.operator}
                          onChange={(e) => handleUpdateCondition(index, 'operator', e.target.value)}
                          w="30%"
                        >
                          <option value="equals">等于</option>
                          <option value="contains">包含</option>
                          <option value="regex">正则匹配</option>
                          <option value="gt">大于</option>
                          <option value="lt">小于</option>
                          <option value="in">在列表中</option>
                        </Select>

                        <Input
                          size="sm"
                          value={condition.value}
                          onChange={(e) => handleUpdateCondition(index, 'value', e.target.value)}
                          placeholder="值"
                          flex={1}
                        />

                        <IconButton
                          size="sm"
                          aria-label="Remove condition"
                          icon={<FiX />}
                          onClick={() => handleRemoveCondition(index)}
                        />
                      </HStack>
                    </Box>
                  ))}
                </VStack>
              )}
            </Box>

            <Divider />

            {/* 测试结果 */}
            <Box>
              <HStack justify="space-between" mb={3}>
                <Text fontSize="sm" fontWeight="bold" color="gray.700">
                  测试规则
                </Text>
                <Button
                  size="sm"
                  leftIcon={<FiActivity />}
                  isLoading={isTesting}
                  onClick={handleTest}
                  colorScheme="blue"
                >
                  测试
                </Button>
              </HStack>

              {testResult && (
                <Alert status={testResult.matched ? 'success' : 'info'} mb={3}>
                  <AlertIcon />
                  <Box>
                    <Text fontSize="sm" fontWeight="bold">
                      {testResult.matched ? '规则匹配成功' : '规则未匹配'}
                    </Text>
                    {testResult.matched && (
                      <Text fontSize="xs">
                        匹配规则: {testResult.rule_name} | 动作: {getActionLabel(testResult.action || '')}
                        {testResult.blocked !== undefined && (
                          <Badge ml={2} colorScheme={testResult.blocked ? 'red' : 'green'}>
                            {testResult.blocked ? '已拦截' : '未拦截'}
                          </Badge>
                        )}
                      </Text>
                    )}
                  </Box>
                </Alert>
              )}

              <Text fontSize="xs" color="gray.500">
                点击测试按钮将使用示例请求测试当前规则配置
              </Text>
            </Box>
          </VStack>
        </ModalBody>

        <ModalFooter>
          <HStack spacing={3}>
            <Button variant="ghost" onClick={onClose}>
              取消
            </Button>
            <Button
              colorScheme="blue"
              leftIcon={<FiSave />}
              onClick={handleSave}
            >
              保存
            </Button>
          </HStack>
        </ModalFooter>
      </ModalContent>
    </Modal>
  )
}

export default WAFRuleEditor

import React, { useState } from 'react'
import {
  Box,
  VStack,
  HStack,
  Text,
  Badge,
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Icon,
  Tooltip,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalCloseButton,
  useDisclosure,
  Divider,
  Code,
  SimpleGrid,
} from '@chakra-ui/react'
import { FiShield, FiCheckCircle, FiXCircle } from 'react-icons/fi'
import { useTranslation } from '../hooks/useLanguage'
import { WAFRule } from '../types/waf'

interface WAFRulesListProps {
  rules: WAFRule[]
}

const WAFRulesList: React.FC<WAFRulesListProps> = ({ rules }) => {
  const t = useTranslation()
  const { isOpen, onOpen, onClose } = useDisclosure()
  const [selectedRule, setSelectedRule] = useState<WAFRule | null>(null)

  // 按类型分组规则
  const groupedRules = rules.reduce((acc, rule) => {
    if (!acc[rule.type]) {
      acc[rule.type] = []
    }
    acc[rule.type].push(rule)
    return acc
  }, {} as Record<string, WAFRule[]>)

  const handleRuleClick = (rule: WAFRule) => {
    setSelectedRule(rule)
    onOpen()
  }

  const formatDate = (dateString: string) => {
    try {
      const date = new Date(dateString)
      return date.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
      })
    } catch {
      return dateString
    }
  }

  const getRuleTypeName = (type: string): string => {
    const typeMap: Record<string, string> = {
      sql_injection: t.security.sqlInjection,
      xss: t.security.xss,
      path_traversal: t.security.pathTraversal,
      command_injection: t.security.commandInjection,
      file_upload: t.security.fileUpload,
      sensitive_file: t.security.sensitiveFile,
      scanner_detection: t.security.scannerDetection,
      custom: t.security.customRule,
    }
    return typeMap[type] || type
  }

  const getActionBadgeColor = (action: string): string => {
    switch (action) {
      case 'block':
        return 'red'
      case 'log':
        return 'blue'
      case 'warn':
        return 'orange'
      default:
        return 'gray'
    }
  }

  const getActionName = (action: string): string => {
    const actionMap: Record<string, string> = {
      block: t.security.actionBlock,
      log: t.security.actionLog,
      warn: t.security.actionWarn,
    }
    return actionMap[action] || action
  }

  if (rules.length === 0) {
    return (
      <Box textAlign="center" py={8} color="gray.500">
        <Icon as={FiShield} boxSize={12} mb={2} />
        <Text>{t.security.noRules}</Text>
      </Box>
    )
  }

  return (
    <>
      <Accordion allowMultiple defaultIndex={[0]}>
        {Object.entries(groupedRules).map(([type, typeRules]) => (
          <AccordionItem key={type}>
            <AccordionButton>
              <HStack flex="1" textAlign="left">
                <Icon as={FiShield} color="blue.500" />
                <Text fontWeight="medium">{getRuleTypeName(type)}</Text>
                <Badge colorScheme="blue">{typeRules.length}</Badge>
              </HStack>
              <AccordionIcon />
            </AccordionButton>
            <AccordionPanel pb={4}>
              <Table size="sm" variant="simple">
                <Thead>
                  <Tr>
                    <Th>{t.security.ruleName}</Th>
                    <Th>{t.security.ruleAction}</Th>
                    <Th>{t.security.status}</Th>
                    <Th>{t.security.ruleDescription}</Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {typeRules.map((rule) => (
                    <Tr key={rule.id}>
                      <Td>
                        <Text
                          fontSize="sm"
                          fontWeight="medium"
                          color="blue.500"
                          cursor="pointer"
                          _hover={{ textDecoration: 'underline' }}
                          onClick={() => handleRuleClick(rule)}
                        >
                          {rule.name}
                        </Text>
                      </Td>
                      <Td>
                        <Badge colorScheme={getActionBadgeColor(rule.action)}>
                          {getActionName(rule.action)}
                        </Badge>
                      </Td>
                      <Td>
                        <HStack>
                          <Icon
                            as={rule.enabled ? FiCheckCircle : FiXCircle}
                            color={rule.enabled ? 'green.500' : 'gray.400'}
                          />
                          <Text fontSize="sm" color={rule.enabled ? 'green.600' : 'gray.500'}>
                            {rule.enabled ? t.security.ruleEnabled : t.security.ruleDisabled}
                          </Text>
                        </HStack>
                      </Td>
                      <Td>
                        <Tooltip label={rule.pattern} placement="top">
                          <Text fontSize="sm" color="gray.600" noOfLines={1}>
                            {rule.description || rule.pattern}
                          </Text>
                        </Tooltip>
                      </Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            </AccordionPanel>
          </AccordionItem>
        ))}
      </Accordion>

      {/* 规则详情模态框 */}
      <Modal isOpen={isOpen} onClose={onClose} size="lg">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>{t.security.ruleName}: {selectedRule?.name}</ModalHeader>
          <ModalCloseButton />
          <ModalBody pb={6}>
            {selectedRule && (
              <VStack align="stretch" spacing={4}>
                <SimpleGrid columns={2} spacing={4}>
                  <Box>
                    <Text fontSize="sm" color="gray.600" mb={1}>
                      {t.security.ruleType}
                    </Text>
                    <Badge colorScheme="blue">
                      {getRuleTypeName(selectedRule.type)}
                    </Badge>
                  </Box>
                  <Box>
                    <Text fontSize="sm" color="gray.600" mb={1}>
                      {t.security.status}
                    </Text>
                    <HStack>
                      <Icon
                        as={selectedRule.enabled ? FiCheckCircle : FiXCircle}
                        color={selectedRule.enabled ? 'green.500' : 'gray.400'}
                      />
                      <Text fontSize="sm" color={selectedRule.enabled ? 'green.600' : 'gray.500'}>
                        {selectedRule.enabled ? t.security.ruleEnabled : t.security.ruleDisabled}
                      </Text>
                    </HStack>
                  </Box>
                  <Box>
                    <Text fontSize="sm" color="gray.600" mb={1}>
                      {t.security.ruleAction}
                    </Text>
                    <Badge colorScheme={getActionBadgeColor(selectedRule.action)}>
                      {getActionName(selectedRule.action)}
                    </Badge>
                  </Box>
                  <Box>
                    <Text fontSize="sm" color="gray.600" mb={1}>
                      {t.ssl.createdAt}
                    </Text>
                    <Text fontSize="sm">{formatDate(selectedRule.created_at)}</Text>
                  </Box>
                </SimpleGrid>

                <Divider />

                <Box>
                  <Text fontSize="sm" color="gray.600" mb={2}>
                    {t.security.ruleDescription}
                  </Text>
                  <Text fontSize="sm">{selectedRule.description || '-'}</Text>
                </Box>

                <Box>
                  <Text fontSize="sm" color="gray.600" mb={2}>
                    {t.security.rulePattern}
                  </Text>
                  <Code
                    p={2}
                    borderRadius="md"
                    fontSize="xs"
                    display="block"
                    whiteSpace="pre-wrap"
                    wordBreak="break-all"
                    bg="gray.50"
                    color="gray.800"
                  >
                    {selectedRule.pattern}
                  </Code>
                </Box>

              <Box>
                <Text fontSize="sm" color="gray.600" mb={2}>
                  ID
                </Text>
                <Code
                  p={2}
                  borderRadius="md"
                  fontSize="xs"
                  bg="gray.50"
                  color="gray.800"
                >
                  {selectedRule.id}
                </Code>
              </Box>
              </VStack>
            )}
          </ModalBody>
        </ModalContent>
      </Modal>
    </>
  )
}

export default WAFRulesList


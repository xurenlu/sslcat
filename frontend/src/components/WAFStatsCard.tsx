import React from 'react'
import {
  Card,
  CardBody,
  Stat,
  StatLabel,
  StatNumber,
  HStack,
  Box,
  Icon,
  Badge,
  VStack,
  Text,
} from '@chakra-ui/react'
import { FiShield, FiCheckCircle, FiAlertTriangle } from 'react-icons/fi'
import { useTranslation } from '../hooks/useLanguage'

interface WAFStatsCardProps {
  enabled: boolean
  totalBlocked: number
  activeRules: number
  detectionRate: number
  onClick?: () => void
}

const WAFStatsCard: React.FC<WAFStatsCardProps> = ({
  enabled,
  totalBlocked,
  activeRules,
  detectionRate,
  onClick,
}) => {
  const t = useTranslation()

  return (
    <Card
      cursor={onClick ? 'pointer' : 'default'}
      onClick={onClick}
      _hover={onClick ? { shadow: 'md', transform: 'translateY(-2px)' } : {}}
      transition="all 0.2s"
    >
      <CardBody>
        <VStack align="stretch" spacing={4}>
          <HStack justify="space-between">
            <HStack>
              <Icon
                as={FiShield}
                boxSize={8}
                color={enabled ? 'green.500' : 'gray.300'}
              />
              <Box>
                <Text fontSize="sm" fontWeight="medium" color="gray.600">
                  {t.security.wafProtection}
                </Text>
                <Badge colorScheme={enabled ? 'green' : 'gray'} mt={1}>
                  {enabled ? t.security.ruleEnabled : t.security.ruleDisabled}
                </Badge>
              </Box>
            </HStack>
          </HStack>

          <HStack spacing={6}>
            <Stat>
              <StatLabel fontSize="xs" color="gray.500">
                {t.security.totalBlocked}
              </StatLabel>
              <StatNumber fontSize="2xl" color="red.500">
                {totalBlocked.toLocaleString()}
              </StatNumber>
            </Stat>

            <Stat>
              <StatLabel fontSize="xs" color="gray.500">
                {t.security.wafRules}
              </StatLabel>
              <StatNumber fontSize="2xl" color="blue.500">
                {activeRules}
              </StatNumber>
            </Stat>

            <Stat>
              <StatLabel fontSize="xs" color="gray.500">
                {t.security.detectionRate}
              </StatLabel>
              <StatNumber fontSize="2xl" color="green.500">
                {detectionRate.toFixed(1)}%
              </StatNumber>
            </Stat>
          </HStack>

          {enabled && (
            <HStack fontSize="xs" color="green.600">
              <Icon as={FiCheckCircle} />
              <Text>{t.security.wafProtecting || 'WAF is protecting your application'}</Text>
            </HStack>
          )}

          {!enabled && (
            <HStack fontSize="xs" color="orange.600">
              <Icon as={FiAlertTriangle} />
              <Text>{t.security.wafDisabledWarning || 'WAF is disabled, it is recommended to enable it to enhance security'}</Text>
            </HStack>
          )}
        </VStack>
      </CardBody>
    </Card>
  )
}

export default WAFStatsCard


import React from 'react'
import {
  Box,
  Card,
  CardBody,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  VStack,
  HStack,
  Button,
  Icon,
  Text,
  Badge,
  Code,
  IconButton,
  Flex,
} from '@chakra-ui/react'
import { FiKey, FiCopy, FiTrash2, FiPlus } from 'react-icons/fi'
import { useTranslation } from '../../hooks/useLanguage'
import { SSHKey } from './types'
import { TOAST_DURATION } from '../../constants'
import { useToast } from '@chakra-ui/react'

interface SSHKeyListProps {
  sshKeys: SSHKey[]
  onAdd: () => void
  onDelete: (id: string) => void
}

const SSHKeyList: React.FC<SSHKeyListProps> = ({ sshKeys, onAdd, onDelete }) => {
  const t = useTranslation()
  const toast = useToast()

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast({
      title: t.gitServer.copyToClipboard,
      status: 'success',
      duration: TOAST_DURATION.SHORT,
      isClosable: true,
    })
  }

  return (
    <VStack spacing={4} align="stretch">
      <Flex justify="space-between" align="center">
        <Text fontSize="lg" fontWeight="medium">
          {t.gitServer.sshKeyTitle}
        </Text>
        <Button leftIcon={<Icon as={FiPlus} />} colorScheme="green" onClick={onAdd}>
          {t.gitServer.addSSHKey}
        </Button>
      </Flex>

      <Card>
        <CardBody>
          {Array.isArray(sshKeys) && sshKeys.length > 0 ? (
            <Table variant="simple">
              <Thead>
                <Tr>
                  <Th>{t.gitServer.keyName}</Th>
                  <Th>{t.gitServer.fingerprint}</Th>
                  <Th>{t.gitServer.status}</Th>
                  <Th>{t.gitServer.created}</Th>
                  <Th>{t.gitServer.lastUsed}</Th>
                  <Th>{t.gitServer.actions}</Th>
                </Tr>
              </Thead>
              <Tbody>
                {sshKeys.map((key) => (
                  <Tr key={key.id}>
                    <Td>
                      <HStack>
                        <Icon as={FiKey} />
                        <Text fontWeight="medium">{key.name}</Text>
                      </HStack>
                    </Td>
                    <Td>
                      <Code fontSize="xs" maxW="200px" isTruncated>
                        {key.fingerprint}
                      </Code>
                    </Td>
                    <Td>
                      <Badge variant="outline">{key.type}</Badge>
                    </Td>
                    <Td>{key.created}</Td>
                    <Td>{key.lastUsed || t.gitServer.neverUsed}</Td>
                    <Td>
                      <HStack spacing={2}>
                        <IconButton
                          aria-label={t.frontend.copy_fingerprint}
                          icon={<FiCopy />}
                          size="sm"
                          variant="ghost"
                          onClick={() => copyToClipboard(key.fingerprint)}
                        />
                        <IconButton
                          aria-label={t.frontend.delete}
                          icon={<FiTrash2 />}
                          size="sm"
                          variant="ghost"
                          colorScheme="red"
                          onClick={() => onDelete(key.id)}
                        />
                      </HStack>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          ) : (
            <Box textAlign="center" py={8}>
              <Icon as={FiKey} boxSize={12} color="gray.300" mb={4} />
              <Text color="gray.500" mb={4}>
                {t.gitServer.noSSHKeys}
              </Text>
              <Button leftIcon={<Icon as={FiPlus} />} colorScheme="green" onClick={onAdd}>
                {t.gitServer.addFirstSSHKey}
              </Button>
            </Box>
          )}
        </CardBody>
      </Card>
    </VStack>
  )
}

export default SSHKeyList


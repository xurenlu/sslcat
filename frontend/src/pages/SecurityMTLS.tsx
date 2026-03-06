import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Heading,
  Text,
  SimpleGrid,
  Card,
  CardHeader,
  CardBody,
  Button,
  Switch,
  FormControl,
  FormLabel,
  Input,
  Select,
  VStack,
  HStack,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  useToast,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  Alert,
  AlertIcon,
  IconButton,
  Badge,
  Code,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalFooter,
  ModalBody,
  ModalCloseButton,
  useDisclosure,
  Wrap,
} from '@chakra-ui/react';
import {
  FiShield,
  FiKey,
  FiUsers,
  FiLock,
  FiUnlock,
  FiRefreshCw,
  FiPlus,
  FiTrash2,
  FiCopy,
  FiDownload,
  FiUpload,
} from 'react-icons/fi';
import axios from 'axios';
import { useConfig, buildApiPath } from '../contexts/ConfigContext';
import { useTranslation } from '../hooks/useLanguage';

interface MTLSConfig {
  enabled: boolean;
  mode: string;
  client_cert_required: boolean;
  crl_check_enabled: boolean;
  cert_pinning_enabled: boolean;
}

interface Certificate {
  serial_number: string;
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  revoked: boolean;
  revoked_at?: string;
}

interface Role {
  name: string;
  description: string;
  permissions: string[];
  user_count: number;
}

interface Policy {
  id: string;
  name: string;
  resource: string;
  action: string;
  effect: string;
  priority: number;
}

interface AuditLog {
  timestamp: string;
  user: string;
  resource: string;
  action: string;
  allowed: boolean;
  reason: string;
}

const SecurityMTLS: React.FC = () => {
  const { adminPrefix } = useConfig();
  const t = useTranslation();
  const [mtlsConfig, setMtlsConfig] = useState<MTLSConfig | null>(null);
  const [whitelist, setWhitelist] = useState<string[]>([]);
  const [blacklist, setBlacklist] = useState<string[]>([]);
  const [issuedCerts, setIssuedCerts] = useState<Certificate[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const toast = useToast();

  const {
    isOpen: isCertModalOpen,
    onOpen: onCertModalOpen,
    onClose: onCertModalClose,
  } = useDisclosure();

  const fetchMTLSConfig = async () => {
    try {
      const response = await axios.get(buildApiPath(adminPrefix, '/api/mtls/config'));
      setMtlsConfig(response.data);
    } catch (error) {
      toast({
        title: t.securityMTLS?.loadFailed ?? t.common.error,
        description: t.securityMTLS?.loadConfigFailed ?? '无法加载 mTLS 配置',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const fetchWhitelist = async () => {
    try {
      const response = await axios.get(buildApiPath(adminPrefix, '/api/mtls/whitelist'));
      setWhitelist(response.data.certificates || []);
    } catch (error) {
      console.error('Failed to fetch whitelist:', error);
    }
  };

  const fetchBlacklist = async () => {
    try {
      const response = await axios.get(buildApiPath(adminPrefix, '/api/mtls/blacklist'));
      setBlacklist(response.data.certificates || []);
    } catch (error) {
      console.error('Failed to fetch blacklist:', error);
    }
  };

  const fetchIssuedCerts = async () => {
    try {
      const response = await axios.get(buildApiPath(adminPrefix, '/api/mtls/certificates'));
      setIssuedCerts(response.data.certificates || []);
    } catch (error) {
      console.error('Failed to fetch issued certificates:', error);
    }
  };

  const fetchRoles = async () => {
    try {
      const response = await axios.get(buildApiPath(adminPrefix, '/api/rbac/roles'));
      setRoles(response.data.roles || []);
    } catch (error) {
      console.error('Failed to fetch roles:', error);
    }
  };

  const fetchPolicies = async () => {
    try {
      const response = await axios.get(buildApiPath(adminPrefix, '/api/rbac/policies'));
      setPolicies(response.data.policies || []);
    } catch (error) {
      console.error('Failed to fetch policies:', error);
    }
  };

  const fetchAuditLogs = async () => {
    try {
      const response = await axios.get(buildApiPath(adminPrefix, '/api/rbac/audit'));
      setAuditLogs(response.data.logs || []);
    } catch (error) {
      console.error('Failed to fetch audit logs:', error);
    }
  };

  useEffect(() => {
    const loadData = async () => {
      await Promise.all([
        fetchMTLSConfig(),
        fetchWhitelist(),
        fetchBlacklist(),
        fetchIssuedCerts(),
        fetchRoles(),
        fetchPolicies(),
        fetchAuditLogs(),
      ]);
      setLoading(false);
    };
    loadData();
  }, []);

  const handleToggleMTLS = async () => {
    try {
      const response = await axios.post(buildApiPath(adminPrefix, '/api/mtls/config/update'), {
        ...mtlsConfig,
        enabled: !mtlsConfig?.enabled,
      });
      // 直接使用服务器返回的最新配置
      setMtlsConfig(response.data);
      toast({
        title: t.common.success,
        description: !mtlsConfig?.enabled ? (t.securityMTLS?.mtlsEnabled ?? 'mTLS 已启用') : (t.securityMTLS?.mtlsDisabled ?? 'mTLS 已禁用'),
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: t.common.operationFailed,
        description: t.securityMTLS?.mtlsUpdateFailed ?? '无法更新 mTLS 配置',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleAddToWhitelist = async (serialNumber: string) => {
    try {
      await axios.post(buildApiPath(adminPrefix, '/api/mtls/whitelist'), { serial_number: serialNumber });
      await fetchWhitelist();
      toast({
        title: t.common.success,
        description: t.securityMTLS?.certAddedToWhitelist ?? '证书已添加到白名单',
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: t.common.operationFailed,
        description: t.securityMTLS?.certAddFailed ?? '无法添加到白名单',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleRemoveFromWhitelist = async (serialNumber: string) => {
    try {
      await axios.delete(buildApiPath(adminPrefix, `/api/mtls/whitelist/${serialNumber}`));
      await fetchWhitelist();
      toast({
        title: t.common.success,
        description: t.securityMTLS?.certRemovedFromWhitelist ?? '证书已从白名单移除',
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: t.common.operationFailed,
        description: t.securityMTLS?.certRemoveFailed ?? '无法从白名单移除',
        status: 'error',
        duration: 3000,
      });
    }
  };

  const handleRevokeCert = async (serialNumber: string) => {
    try {
      await axios.post(buildApiPath(adminPrefix, '/api/mtls/revoke'), { serial_number: serialNumber });
      await fetchIssuedCerts();
      toast({
        title: t.common.success,
        description: t.securityMTLS?.certRevoked ?? '证书已吊销',
        status: 'success',
        duration: 3000,
      });
    } catch (error) {
      toast({
        title: t.common.operationFailed,
        description: t.securityMTLS?.certRevokeFailed ?? '无法吊销证书',
        status: 'error',
        duration: 3000,
      });
    }
  };

  if (loading) {
    return (
      <Container maxW="container.xl" py={8}>
        <Text>{t.common.loading}</Text>
      </Container>
    );
  }

  return (
    <Container maxW="container.xl" py={8}>
      <VStack spacing={6} align="stretch">
        {/* 实验性功能警告 */}
        <Alert status="warning" borderRadius="md">
          <AlertIcon />
          <Box>
            <Text fontWeight="bold">{t.securityMTLS?.experimentalFeature ?? '实验性功能'}</Text>
            <Text fontSize="sm">{t.securityMTLS?.notReadyDesc ?? '零信任安全（mTLS）功能尚未完全实现，有待生产环境测试。请在测试环境中谨慎使用。'}</Text>
          </Box>
        </Alert>

        {/* Header */}
        <Box display="flex" justifyContent="space-between" alignItems="center">
          <Box>
            <Heading size="lg" display="flex" alignItems="center" gap={2}>
              <FiShield />
              {t.securityMTLS?.title ?? '零信任安全中心'}
            </Heading>
            <Text color="gray.500" mt={2}>
              {t.securityMTLS?.manageMTLSDesc ?? '管理 mTLS、RBAC 和访问控制'}
            </Text>
          </Box>
        </Box>

        {/* Stats Cards */}
        <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={4}>
          <Card>
            <CardBody>
              <HStack spacing={4}>
                <Box color="blue.500" fontSize="3xl">
                  <FiKey />
                </Box>
                <Box>
                  <Text fontSize="sm" color="gray.500">
                    {t.securityMTLS?.certsIssued ?? '已颁发证书'}
                  </Text>
                  <Text fontSize="2xl" fontWeight="bold">
                    {issuedCerts.length}
                  </Text>
                </Box>
              </HStack>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <HStack spacing={4}>
                <Box color="green.500" fontSize="3xl">
                  <FiUsers />
                </Box>
                <Box>
                  <Text fontSize="sm" color="gray.500">
                    {t.securityMTLS?.roleCount ?? '角色数量'}
                  </Text>
                  <Text fontSize="2xl" fontWeight="bold">
                    {roles.length}
                  </Text>
                </Box>
              </HStack>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <HStack spacing={4}>
                <Box color="orange.500" fontSize="3xl">
                  <FiLock />
                </Box>
                <Box>
                  <Text fontSize="sm" color="gray.500">
                    {t.securityMTLS?.accessPolicies ?? '访问策略'}
                  </Text>
                  <Text fontSize="2xl" fontWeight="bold">
                    {policies.length}
                  </Text>
                </Box>
              </HStack>
            </CardBody>
          </Card>

          <Card>
            <CardBody>
              <HStack spacing={4}>
                <Box color="purple.500" fontSize="3xl">
                  <FiShield />
                </Box>
                <Box>
                  <Text fontSize="sm" color="gray.500">
                    {t.securityMTLS?.mtlsStatus ?? 'mTLS 状态'}
                  </Text>
                  <Badge colorScheme={mtlsConfig?.enabled ? 'green' : 'gray'} fontSize="lg">
                    {mtlsConfig?.enabled ? (t.securityMTLS?.enabled ?? '已启用') : (t.securityMTLS?.disabled ?? '已禁用')}
                  </Badge>
                </Box>
              </HStack>
            </CardBody>
          </Card>
        </SimpleGrid>

        {/* Main Tabs */}
        <Tabs>
          <TabList>
            <Tab>{t.securityMTLS?.mtlsConfig ?? 'mTLS 配置'}</Tab>
            <Tab>{t.securityMTLS?.rbacManagement ?? 'RBAC 管理'}</Tab>
            <Tab>{t.securityMTLS?.auditLogs ?? '审计日志'}</Tab>
          </TabList>

          <TabPanels>
            {/* mTLS Configuration Panel */}
            <TabPanel>
              <VStack spacing={6} align="stretch">
                <Card>
                  <CardHeader display="flex" justifyContent="space-between">
                    <Heading size="md">{t.securityMTLS?.mtlsSettings ?? 'mTLS 设置'}</Heading>
                    <HStack>
                      <Switch
                        isChecked={mtlsConfig?.enabled}
                        onChange={handleToggleMTLS}
                        colorScheme="green"
                      />
                      <IconButton
                        aria-label="刷新"
                        icon={<FiRefreshCw />}
                        onClick={() => {
                          fetchMTLSConfig();
                          fetchWhitelist();
                          fetchBlacklist();
                          fetchIssuedCerts();
                        }}
                      />
                    </HStack>
                  </CardHeader>
                  <CardBody>
                    <VStack spacing={4} align="stretch">
                      <FormControl>
                        <FormLabel>{t.securityMTLS?.verificationMode ?? '验证模式'}</FormLabel>
                        <Select value={mtlsConfig?.mode} isDisabled={!mtlsConfig?.enabled}>
                          <option value="strict">{t.securityMTLS?.strictMode ?? '严格模式 - 必须提供有效证书'}</option>
                          <option value="optional">{t.securityMTLS?.optionalMode ?? '可选模式 - 证书可选'}</option>
                          <option value="verify_client_if_given">
                            {t.securityMTLS?.verifyIfGiven ?? '验证模式 - 如果提供则验证'}
                          </option>
                        </Select>
                      </FormControl>

                      <HStack spacing={4}>
                        <FormControl display="flex" alignItems="center">
                          <Switch
                            isChecked={mtlsConfig?.client_cert_required}
                            isDisabled={!mtlsConfig?.enabled}
                          />
                          <FormLabel mb="0" ml={3}>
                            {t.securityMTLS?.requireClientCert ?? '要求客户端证书'}
                          </FormLabel>
                        </FormControl>

                        <FormControl display="flex" alignItems="center">
                          <Switch
                            isChecked={mtlsConfig?.crl_check_enabled}
                            isDisabled={!mtlsConfig?.enabled}
                          />
                          <FormLabel mb="0" ml={3}>
                            {t.securityMTLS?.enableCrlCheck ?? '启用 CRL 检查'}
                          </FormLabel>
                        </FormControl>

                        <FormControl display="flex" alignItems="center">
                          <Switch
                            isChecked={mtlsConfig?.cert_pinning_enabled}
                            isDisabled={!mtlsConfig?.enabled}
                          />
                          <FormLabel mb="0" ml={3}>
                            {t.securityMTLS?.enableCertPinning ?? '启用证书固定'}
                          </FormLabel>
                        </FormControl>
                      </HStack>
                    </VStack>
                  </CardBody>
                </Card>

                <SimpleGrid columns={{ base: 1, lg: 2 }} spacing={4}>
                  <Card>
                    <CardHeader display="flex" justifyContent="space-between">
                      <Heading size="md">{t.securityMTLS?.certWhitelist ?? '证书白名单'}</Heading>
                      <Button
                        leftIcon={<FiPlus />}
                        size="sm"
                        onClick={onCertModalOpen}
                      >
                        {t.securityMTLS?.add ?? t.common.add}
                      </Button>
                    </CardHeader>
                    <CardBody>
                      <VStack spacing={2} align="stretch">
                        {whitelist.length === 0 ? (
                          <Alert status="info">
                            <AlertIcon />
                            {t.securityMTLS?.whitelistEmpty ?? '白名单为空'}
                          </Alert>
                        ) : (
                          whitelist.map((serial) => (
                            <HStack
                              key={serial}
                              p={2}
                              bg="gray.50"
                              borderRadius="md"
                              justify="space-between"
                            >
                              <Code fontSize="xs">{serial}</Code>
                              <IconButton
                                aria-label="移除"
                                icon={<FiTrash2 />}
                                size="xs"
                                onClick={() => handleRemoveFromWhitelist(serial)}
                              />
                            </HStack>
                          ))
                        )}
                      </VStack>
                    </CardBody>
                  </Card>

                  <Card>
                    <CardHeader>
                      <Heading size="md">{t.securityMTLS?.certsIssued ?? '已颁发证书'}</Heading>
                    </CardHeader>
                    <CardBody>
                      <Table variant="simple" size="sm">
                        <Thead>
                          <Tr>
                            <Th>{t.securityMTLS?.subject ?? '主题'}</Th>
                            <Th>{t.securityMTLS?.expiryTime ?? '过期时间'}</Th>
                            <Th>{t.cluster?.status ?? '状态'}</Th>
                            <Th>{t.common.actions}</Th>
                          </Tr>
                        </Thead>
                        <Tbody>
                          {issuedCerts.slice(0, 5).map((cert) => (
                            <Tr key={cert.serial_number}>
                              <Td>
                                <Text fontSize="xs" noOfLines={1}>
                                  {cert.subject}
                                </Text>
                              </Td>
                              <Td fontSize="xs">
                                {new Date(cert.not_after).toLocaleDateString()}
                              </Td>
                              <Td>
                                {cert.revoked ? (
                                  <Badge colorScheme="red">{t.securityMTLS?.revoked ?? '已吊销'}</Badge>
                                ) : (
                                  <Badge colorScheme="green">{t.securityMTLS?.valid ?? '有效'}</Badge>
                                )}
                              </Td>
                              <Td>
                                {!cert.revoked && (
                                  <Button
                                    size="xs"
                                    colorScheme="red"
                                    onClick={() => handleRevokeCert(cert.serial_number)}
                                  >
                                    {t.securityMTLS?.revoke ?? '吊销'}
                                  </Button>
                                )}
                              </Td>
                            </Tr>
                          ))}
                        </Tbody>
                      </Table>
                    </CardBody>
                  </Card>
                </SimpleGrid>
              </VStack>
            </TabPanel>

            {/* RBAC Management Panel */}
            <TabPanel>
              <SimpleGrid columns={{ base: 1, lg: 2 }} spacing={6}>
                <Card>
                  <CardHeader display="flex" justifyContent="space-between">
                    <Heading size="md">{t.securityMTLS?.roleList ?? '角色列表'}</Heading>
                    <Button leftIcon={<FiPlus />} size="sm" colorScheme="blue">
                      {t.securityMTLS?.createRole ?? '创建角色'}
                    </Button>
                  </CardHeader>
                  <CardBody>
                    <VStack spacing={3} align="stretch">
                      {roles.map((role) => (
                        <Box
                          key={role.name}
                          p={4}
                          border="1px"
                          borderColor="gray.200"
                          borderRadius="md"
                        >
                          <HStack justify="space-between" mb={2}>
                            <Text fontWeight="bold">{role.name}</Text>
                            <Badge>{role.user_count} {t.securityMTLS?.users ?? '用户'}</Badge>
                          </HStack>
                          <Text fontSize="sm" color="gray.600" mb={2}>
                            {role.description}
                          </Text>
                          <Wrap>
                            {role.permissions.slice(0, 3).map((permission) => (
                              <Badge key={permission} mr={1} size="sm">
                                {permission}
                              </Badge>
                            ))}
                            {role.permissions.length > 3 && (
                              <Badge size="sm">
                                +{role.permissions.length - 3}
                              </Badge>
                            )}
                          </Wrap>
                        </Box>
                      ))}
                    </VStack>
                  </CardBody>
                </Card>

                <Card>
                  <CardHeader display="flex" justifyContent="space-between">
                    <Heading size="md">{t.securityMTLS?.accessPolicies ?? '访问策略'}</Heading>
                    <Button leftIcon={<FiPlus />} size="sm" colorScheme="green">
                      {t.securityMTLS?.addPolicy ?? '添加策略'}
                    </Button>
                  </CardHeader>
                  <CardBody>
                    <Table variant="simple" size="sm">
                      <Thead>
                        <Tr>
                          <Th>{t.securityMTLS?.name ?? '名称'}</Th>
                          <Th>{t.securityMTLS?.resource ?? '资源'}</Th>
                          <Th>{t.securityMTLS?.action ?? '操作'}</Th>
                          <Th>{t.securityMTLS?.effect ?? '效果'}</Th>
                        </Tr>
                      </Thead>
                      <Tbody>
                        {policies.map((policy) => (
                          <Tr key={policy.id}>
                            <Td>{policy.name}</Td>
                            <Td>
                              <Code fontSize="xs">{policy.resource}</Code>
                            </Td>
                            <Td>{policy.action}</Td>
                            <Td>
                              <Badge colorScheme={policy.effect === 'allow' ? 'green' : 'red'}>
                                {policy.effect}
                              </Badge>
                            </Td>
                          </Tr>
                        ))}
                      </Tbody>
                    </Table>
                  </CardBody>
                </Card>
              </SimpleGrid>
            </TabPanel>

            {/* Audit Logs Panel */}
            <TabPanel>
              <Card>
                <CardHeader display="flex" justifyContent="space-between">
                  <Heading size="md">{t.securityMTLS?.auditLogs ?? t.auditLogs?.title ?? '审计日志'}</Heading>
                  <HStack>
                    <Button leftIcon={<FiDownload />} size="sm" variant="outline">
                      {t.common.export}
                    </Button>
                    <IconButton
                      aria-label="刷新"
                      icon={<FiRefreshCw />}
                      onClick={fetchAuditLogs}
                    />
                  </HStack>
                </CardHeader>
                <CardBody>
                  <Table variant="simple" size="sm">
                    <Thead>
                      <Tr>
                        <Th>{t.securityMTLS?.time ?? t.common.time}</Th>
                        <Th>{t.securityMTLS?.users ?? t.common.user}</Th>
                        <Th>{t.securityMTLS?.resource ?? '资源'}</Th>
                        <Th>{t.securityMTLS?.action ?? '操作'}</Th>
                        <Th>{t.securityMTLS?.result ?? '结果'}</Th>
                        <Th>{t.securityMTLS?.reason ?? '原因'}</Th>
                      </Tr>
                    </Thead>
                    <Tbody>
                      {auditLogs.slice(0, 20).map((log, index) => (
                        <Tr key={index}>
                          <Td fontSize="xs">
                            {new Date(log.timestamp).toLocaleString()}
                          </Td>
                          <Td>{log.user}</Td>
                          <Td>
                            <Code fontSize="xs">{log.resource}</Code>
                          </Td>
                          <Td>{log.action}</Td>
                          <Td>
                            {log.allowed ? (
                              <Badge colorScheme="green">{t.securityMTLS?.allow ?? '允许'}</Badge>
                            ) : (
                              <Badge colorScheme="red">{t.securityMTLS?.deny ?? '拒绝'}</Badge>
                            )}
                          </Td>
                          <Td fontSize="xs">{log.reason}</Td>
                        </Tr>
                      ))}
                    </Tbody>
                  </Table>
                </CardBody>
              </Card>
            </TabPanel>
          </TabPanels>
        </Tabs>
      </VStack>

      {/* Add Certificate Modal */}
      <Modal isOpen={isCertModalOpen} onClose={onCertModalClose}>
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>{t.securityMTLS?.addCertToWhitelist ?? '添加证书到白名单'}</ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <FormControl>
              <FormLabel>{t.securityMTLS?.certSerialNumber ?? '证书序列号'}</FormLabel>
              <Input placeholder={t.securityMTLS?.certSerialPlaceholder ?? '输入证书序列号'} />
            </FormControl>
          </ModalBody>
          <ModalFooter>
            <Button onClick={onCertModalClose}>{t.common.cancel}</Button>
            <Button colorScheme="blue" ml={3}>
              {t.securityMTLS?.add ?? t.common.add}
            </Button>
          </ModalFooter>
        </ModalContent>
      </Modal>
    </Container>
  );
};

export default SecurityMTLS;

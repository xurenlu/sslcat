import React, { useState, useEffect } from 'react';
import {
  Box, VStack, HStack, Text, Button, Table, Thead, Tbody, Tr, Th, Td, Badge,
  Stat, StatLabel, StatNumber, StatHelpText, SimpleGrid, Card, CardBody, CardHeader,
  Heading, Select, Input, InputGroup, InputLeftElement, IconButton, Tooltip,
  useToast, Alert, AlertIcon, AlertTitle, AlertDescription,
  Modal, ModalOverlay, ModalContent, ModalHeader, ModalBody, ModalCloseButton,
  useDisclosure, Code, Divider,
} from '@chakra-ui/react';
// import { SearchIcon, DownloadIcon, DeleteIcon, ExternalLinkIcon } from '@chakra-ui/icons';
import { useTranslation } from '../hooks/useLanguage';
import api from '../utils/api';
import { FeatureGate } from '../components/FeatureGate';
import { RequestWaterfall } from '../components/RequestWaterfall';
import { VirtualList } from '../components/VirtualList';

interface SlowRequestRecord {
  id: string;
  timestamp: string;
  method: string;
  url: string;
  host: string;
  path: string;
  client_ip: string;
  user_agent: string;
  status_code: number;
  response_time: number;
  backend_id: string;
  backend_addr: string;
  target: string;
  rule_name: string;
  content_type: string;
  content_size: number;
  error?: string;
}

interface SlowRequestStats {
  total_slow_requests: number;
  average_response_time: number;
  slowest_response_time: number;
  slowest_request?: SlowRequestRecord;
  by_status_code: Record<string, number>;
  by_method: Record<string, number>;
  by_host: Record<string, number>;
  by_backend: Record<string, number>;
  recent_slow_requests: SlowRequestRecord[];
}

const SlowRequests: React.FC = () => {
  const t = useTranslation();
  const toast = useToast();
  const { isOpen, onOpen, onClose } = useDisclosure();

  const [stats, setStats] = useState<SlowRequestStats | null>(null);
  const [records, setRecords] = useState<SlowRequestRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [selectedRecord, setSelectedRecord] = useState<SlowRequestRecord | null>(null);
  const [limit, setLimit] = useState(50);
  const [searchTerm, setSearchTerm] = useState('');

  const loadStats = async () => {
    try {
      const response: any = await api.get('/slow-requests/stats');
      if (response.success) {
        setStats(response.data);
      }
    } catch (error) {
      console.error('Failed to load slow request stats:', error);
    }
  };

  const loadRecords = async () => {
    try {
      setLoading(true);
      const response: any = await api.get(`/slow-requests/records?limit=${limit}`);
      if (response.success) {
        setRecords(response.data.records);
      }
    } catch (error) {
      console.error('Failed to load slow request records:', error);
      toast({
        title: t.common.error,
        description: t.slowRequests.loadError,
        status: 'error',
        duration: 5000,
        isClosable: true,
      });
    } finally {
      setLoading(false);
    }
  };

  const clearRecords = async () => {
    try {
      setClearing(true);
      const response: any = await api.post('/slow-requests/clear');
      if (response.success) {
        toast({
          title: t.common.success,
          description: t.slowRequests.clearSuccess,
          status: 'success',
          duration: 3000,
          isClosable: true,
        });
        await loadStats();
        await loadRecords();
      }
    } catch (error) {
      console.error('Failed to clear slow request records:', error);
      toast({
        title: t.common.error,
        description: t.slowRequests.clearError,
        status: 'error',
        duration: 5000,
        isClosable: true,
      });
    } finally {
      setClearing(false);
    }
  };

  const exportRecords = async (format: 'json' | 'stats') => {
    try {
      setExporting(true);
      const response: any = await api.get(`/slow-requests/export?format=${format}`, {
        responseType: 'blob',
      });
      
      const blob = new Blob([response], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = format === 'json' ? 'slow_requests.json' : 'slow_request_stats.json';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      toast({
        title: t.common.success,
        description: t.slowRequests.exportSuccess,
        status: 'success',
        duration: 3000,
        isClosable: true,
      });
    } catch (error) {
      console.error('Failed to export slow request records:', error);
      toast({
        title: t.common.error,
        description: t.slowRequests.exportError,
        status: 'error',
        duration: 5000,
        isClosable: true,
      });
    } finally {
      setExporting(false);
    }
  };

  const viewRecord = (record: SlowRequestRecord) => {
    setSelectedRecord(record);
    onOpen();
  };

  const filteredRecords = records.filter(record => {
    if (!searchTerm) return true;
    const searchLower = searchTerm.toLowerCase();
    return (
      record.url.toLowerCase().includes(searchLower) ||
      record.host.toLowerCase().includes(searchLower) ||
      record.method.toLowerCase().includes(searchLower) ||
      record.client_ip.toLowerCase().includes(searchLower) ||
      record.rule_name.toLowerCase().includes(searchLower)
    );
  });

  const getStatusCodeColor = (statusCode: number) => {
    if (statusCode >= 200 && statusCode < 300) return 'green';
    if (statusCode >= 300 && statusCode < 400) return 'blue';
    if (statusCode >= 400 && statusCode < 500) return 'orange';
    if (statusCode >= 500) return 'red';
    return 'gray';
  };

  const formatResponseTime = (ms: number) => {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(2)}s`;
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  useEffect(() => {
    loadStats();
    loadRecords();
  }, [limit]);

  if (loading && !stats) {
    return (
      <Box display="flex" justifyContent="center" alignItems="center" minH="400px">
        <Text>{t.common.loading}</Text>
      </Box>
    );
  }

  return (
    <Box p={6}>
      <VStack spacing={6} align="stretch">
        <HStack justify="space-between">
          <Heading size="lg">{t.slowRequests.title}</Heading>
          <HStack>
            <Button onClick={() => exportRecords('json')} isLoading={exporting} variant="outline">📥 {t.slowRequests.exportRecords}</Button>
            <Button onClick={() => exportRecords('stats')} isLoading={exporting} variant="outline">📊 {t.slowRequests.exportStats}</Button>
            <Button onClick={clearRecords} isLoading={clearing} colorScheme="red" variant="outline">🗑️ {t.slowRequests.clearRecords}</Button>
          </HStack>
        </HStack>

        {stats && (
          <SimpleGrid columns={{ base: 1, md: 2, lg: 4 }} spacing={4}>
            <Card><CardBody><Stat><StatLabel>{t.slowRequests.totalSlowRequests}</StatLabel><StatNumber>{stats.total_slow_requests.toLocaleString()}</StatNumber></Stat></CardBody></Card>
            <Card><CardBody><Stat><StatLabel>{t.slowRequests.averageResponseTime}</StatLabel><StatNumber>{formatResponseTime(stats.average_response_time)}</StatNumber></Stat></CardBody></Card>
            <Card><CardBody><Stat><StatLabel>{t.slowRequests.slowestResponseTime}</StatLabel><StatNumber>{formatResponseTime(stats.slowest_response_time)}</StatNumber></Stat></CardBody></Card>
            <Card><CardBody><Stat><StatLabel>{t.slowRequests.threshold}</StatLabel><StatNumber>500ms</StatNumber><StatHelpText>{t.slowRequests.thresholdDescription}</StatHelpText></Stat></CardBody></Card>
          </SimpleGrid>
        )}

        <Card>
          <CardBody>
            <HStack spacing={4}>
              <InputGroup maxW="300px">
                <InputLeftElement pointerEvents="none"><Text color="gray.300">🔍</Text></InputLeftElement>
                <Input placeholder={t.slowRequests.searchPlaceholder} value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} />
              </InputGroup>
              <Select value={limit} onChange={(e) => setLimit(Number(e.target.value))} maxW="150px">
                <option value={20}>20 {t.slowRequests.records}</option>
                <option value={50}>50 {t.slowRequests.records}</option>
                <option value={100}>100 {t.slowRequests.records}</option>
                <option value={200}>200 {t.slowRequests.records}</option>
              </Select>
              <Button onClick={loadRecords} isLoading={loading}>{t.common.refresh}</Button>
            </HStack>
          </CardBody>
        </Card>

        {/* 请求瀑布图 */}
        {filteredRecords.length > 0 && (
          <Card>
            <CardHeader><Heading size="md">请求时间轴可视化</Heading></CardHeader>
            <CardBody>
              <FeatureGate
                require={['canvas2d']}
                fallback={
                  <Box p={4} textAlign="center" color="gray.500">
                    <Text>您的浏览器不支持 Canvas，请使用表格视图查看请求详情</Text>
                  </Box>
                }
                showFallbackNotice={false}
              >
                <RequestWaterfall
                  requests={filteredRecords.slice(0, 50)} // 限制显示数量
                />
              </FeatureGate>
            </CardBody>
          </Card>
        )}

        <Card>
          <CardHeader><Heading size="md">{t.slowRequests.recentRecords}</Heading></CardHeader>
          <CardBody>
            {loading ? (
              <Box display="flex" justifyContent="center" py={8}><Text>{t.common.loading}</Text></Box>
            ) : filteredRecords.length === 0 ? (
              <Alert status="info"><AlertIcon /><AlertTitle>{t.slowRequests.noRecords}</AlertTitle><AlertDescription>{t.slowRequests.noRecordsDescription}</AlertDescription></Alert>
            ) : (
              <Table variant="simple" size="sm">
                <Thead><Tr><Th>{t.slowRequests.timestamp}</Th><Th>{t.slowRequests.method}</Th><Th>{t.slowRequests.url}</Th><Th>{t.slowRequests.statusCode}</Th><Th>{t.slowRequests.responseTime}</Th><Th>{t.slowRequests.backend}</Th><Th>{t.slowRequests.actions}</Th></Tr></Thead>
                <Tbody>
                  {filteredRecords.map((record) => (
                    <Tr key={record.id}>
                      <Td><Text fontSize="sm">{new Date(record.timestamp).toLocaleString()}</Text></Td>
                      <Td><Badge colorScheme="blue" variant="outline">{record.method}</Badge></Td>
                      <Td><Text fontSize="sm" maxW="300px" isTruncated>{record.url}</Text></Td>
                      <Td><Badge colorScheme={getStatusCodeColor(record.status_code)}>{record.status_code}</Badge></Td>
                      <Td><Text fontSize="sm" fontWeight="bold" color="red.500">{formatResponseTime(record.response_time)}</Text></Td>
                      <Td><Text fontSize="sm" maxW="150px" isTruncated>{record.backend_id || '-'}</Text></Td>
                      <Td><Tooltip label={t.slowRequests.viewDetails}><IconButton aria-label={t.slowRequests.viewDetails} size="sm" variant="ghost" onClick={() => viewRecord(record)}>🔗</IconButton></Tooltip></Td>
                    </Tr>
                  ))}
                </Tbody>
              </Table>
            )}
          </CardBody>
        </Card>
      </VStack>

      <Modal isOpen={isOpen} onClose={onClose} size="xl">
        <ModalOverlay />
        <ModalContent>
          <ModalHeader>{t.slowRequests.recordDetails}</ModalHeader>
          <ModalCloseButton />
          <ModalBody pb={6}>
            {selectedRecord && (
              <VStack spacing={4} align="stretch">
                <SimpleGrid columns={2} spacing={4}>
                  <Box><Text fontWeight="bold">{t.slowRequests.timestamp}</Text><Text>{new Date(selectedRecord.timestamp).toLocaleString()}</Text></Box>
                  <Box><Text fontWeight="bold">{t.slowRequests.method}</Text><Badge colorScheme="blue">{selectedRecord.method}</Badge></Box>
                  <Box><Text fontWeight="bold">{t.slowRequests.url}</Text><Code fontSize="sm" wordBreak="break-all">{selectedRecord.url}</Code></Box>
                  <Box><Text fontWeight="bold">{t.slowRequests.host}</Text><Text>{selectedRecord.host}</Text></Box>
                  <Box><Text fontWeight="bold">{t.slowRequests.statusCode}</Text><Badge colorScheme={getStatusCodeColor(selectedRecord.status_code)}>{selectedRecord.status_code}</Badge></Box>
                  <Box><Text fontWeight="bold">{t.slowRequests.responseTime}</Text><Text color="red.500" fontWeight="bold">{formatResponseTime(selectedRecord.response_time)}</Text></Box>
                  <Box><Text fontWeight="bold">{t.slowRequests.clientIP}</Text><Text>{selectedRecord.client_ip}</Text></Box>
                  <Box><Text fontWeight="bold">{t.slowRequests.backend}</Text><Text>{selectedRecord.backend_id || '-'}</Text></Box>
                  <Box><Text fontWeight="bold">{t.slowRequests.backendAddr}</Text><Text>{selectedRecord.backend_addr || '-'}</Text></Box>
                  <Box><Text fontWeight="bold">{t.slowRequests.ruleName}</Text><Text>{selectedRecord.rule_name || '-'}</Text></Box>
                  <Box><Text fontWeight="bold">{t.slowRequests.contentType}</Text><Text>{selectedRecord.content_type || '-'}</Text></Box>
                  <Box><Text fontWeight="bold">{t.slowRequests.contentSize}</Text><Text>{formatFileSize(selectedRecord.content_size)}</Text></Box>
                </SimpleGrid>
                {selectedRecord.user_agent && (<><Divider /><Box><Text fontWeight="bold">{t.slowRequests.userAgent}</Text><Code fontSize="sm" wordBreak="break-all">{selectedRecord.user_agent}</Code></Box></>)}
                {selectedRecord.error && (<><Divider /><Box><Text fontWeight="bold" color="red.500">{t.slowRequests.error}</Text><Code fontSize="sm" colorScheme="red" wordBreak="break-all">{selectedRecord.error}</Code></Box></>)}
              </VStack>
            )}
          </ModalBody>
        </ModalContent>
      </Modal>
    </Box>
  );
};

export default SlowRequests;

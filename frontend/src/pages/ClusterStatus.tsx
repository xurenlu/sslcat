import React, { useEffect, useState } from 'react'
import { Box, Heading, SimpleGrid, Card, CardHeader, CardBody, Text, Badge, HStack, Button, Icon, useToast, VStack } from '@chakra-ui/react'
import { FiServer, FiShield, FiLink, FiRefreshCw } from 'react-icons/fi'
import { useConfig } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'
import { FeatureGate } from '../components/FeatureGate'
import { ClusterTopology } from '../components/ClusterTopology'
import { ClusterTopologySVG } from '../components/ClusterTopologySVG'

const Labeled: React.FC<{ label: string; value: string | number | React.ReactNode }> = ({ label, value }) => (
  <HStack justify="space-between">
    <Text color="gray.600">{label}</Text>
    <Text fontWeight="medium">{value}</Text>
  </HStack>
)

const ClusterStatus: React.FC = () => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  const toast = useToast()
  const [status, setStatus] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [testing, setTesting] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const resp = await fetch(`${adminPrefix}/api/cluster/status`, { credentials: 'include' })
      const data = await resp.json()
      if (resp.ok && data.success) {
        setStatus(data.data)
      }
    } finally {
      setLoading(false)
    }
  }

  const testMaster = async () => {
    setTesting(true)
    try {
      const resp = await fetch(`${adminPrefix}/api/cluster/test-master`, { method: 'POST', credentials: 'include' })
      const data = await resp.json()
      if (resp.ok && data.success) {
        toast({ title: data.data?.reachable ? t.clusterStatus.masterReachable : t.clusterStatus.masterUnreachable, status: data.data?.reachable ? 'success' : 'error', duration: 2000 })
      }
    } finally {
      setTesting(false)
    }
  }

  useEffect(() => { load() }, [adminPrefix])

  const modeBadge = (mode?: string) => {
    const color = mode === 'master' ? 'purple' : mode === 'slave' ? 'orange' : 'gray'
    const text = mode === 'master' ? t.cluster.modeMaster : mode === 'slave' ? t.cluster.modeSlave : t.cluster.modeStandalone
    return <Badge colorScheme={color}>{text}</Badge>
  }

  return (
    <Box>
      <HStack justify="space-between" mb={6}>
        <HStack>
          <Icon as={FiServer} />
          <Heading size="lg">{t.clusterStatus.title}</Heading>
        </HStack>
        <HStack>
          <Button leftIcon={<FiRefreshCw />} onClick={load} isLoading={loading} variant="outline">{t.common.refresh}</Button>
          <Button leftIcon={<FiLink />} onClick={testMaster} isLoading={testing} colorScheme="blue">{t.clusterStatus.testMaster}</Button>
        </HStack>
      </HStack>

      {/* 集群拓扑图 */}
      {status && (
        <Card mb={6}>
          <CardHeader>
            <Heading size="md">集群拓扑</Heading>
          </CardHeader>
          <CardBody>
            <FeatureGate
              require={['webgl']}
              fallback={
                <ClusterTopologySVG
                  currentNode={status}
                  masterNode={{
                    host: status?.master,
                    reachable: status?.master_last_reachable_at ? true : false,
                  }}
                  syncStatus={status?.sync}
                />
              }
              showFallbackNotice={true}
              fallbackMessage="您的浏览器不支持 WebGL，已切换到 SVG 简化视图"
            >
              <ClusterTopology
                currentNode={status}
                masterNode={{
                  host: status?.master,
                  reachable: status?.master_last_reachable_at ? true : false,
                }}
                syncStatus={status?.sync}
                width={800}
                height={500}
              />
            </FeatureGate>
          </CardBody>
        </Card>
      )}

      <SimpleGrid columns={{ base: 1, md: 3 }} spacing={6}>
        <Card>
          <CardHeader><HStack><Icon as={FiShield} /><Heading size="md">{t.clusterStatus.nodeInfo}</Heading></HStack></CardHeader>
          <CardBody>
            <VStack align="stretch" spacing={3}>
              <Labeled label={t.cluster.mode} value={modeBadge(status?.mode)} />
              <Labeled label={t.cluster.nodeName} value={status?.node_name || '-'} />
              <Labeled label="Node ID" value={status?.node_id || '-'} />
              <Labeled label={t.cluster.clusterPort} value={status?.port ?? '-'} />
              <Labeled label={t.clusterStatus.certCount} value={status?.cert_count ?? 0} />
            </VStack>
          </CardBody>
        </Card>

        <Card>
          <CardHeader><HStack><Icon as={FiLink} /><Heading size="md">{t.clusterStatus.masterInfo}</Heading></HStack></CardHeader>
          <CardBody>
            <VStack align="stretch" spacing={3}>
              <Labeled label={t.cluster.masterHost} value={status?.master || '-'} />
              <Labeled label={t.cluster.syncInterval} value={status?.sync?.interval ?? '-'} />
              <Labeled label={t.cluster.syncTimeout} value={status?.sync?.timeout ?? '-'} />
              <Labeled label={t.cluster.syncConfig} value={<Badge colorScheme={status?.sync?.config_enabled ? 'green' : 'gray'}>{status?.sync?.config_enabled ? t.common.enable : t.common.disable}</Badge>} />
              <Labeled label={t.cluster.syncCerts} value={<Badge colorScheme={status?.sync?.cert_enabled ? 'green' : 'gray'}>{status?.sync?.cert_enabled ? t.common.enable : t.common.disable}</Badge>} />
              <Labeled label={t.clusterStatus.lastCertSync} value={status?.last_cert_sync_at || '-'} />
              <Labeled label={t.clusterStatus.lastConfigSync} value={status?.last_config_sync_at || '-'} />
              <Labeled label={t.clusterStatus.masterLastReachable} value={status?.master_last_reachable_at || '-'} />
              {status?.last_sync_error && (
                <Labeled label={t.clusterStatus.lastError} value={<Text color="red.500">{status?.last_sync_error}</Text>} />
              )}
            </VStack>
          </CardBody>
        </Card>

        <Card>
          <CardHeader><HStack><Icon as={FiShield} /><Heading size="md">{t.clusterStatus.service}</Heading></HStack></CardHeader>
          <CardBody>
            <VStack align="stretch" spacing={3}>
              <Labeled label={t.clusterStatus.httpPort} value={status?.server_port ?? '-'} />
            </VStack>
          </CardBody>
        </Card>
      </SimpleGrid>
    </Box>
  )
}

export default ClusterStatus



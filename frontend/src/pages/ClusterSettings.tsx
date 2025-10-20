import React, { useEffect, useState } from 'react'
import {
  Box,
  Heading,
  Card,
  CardHeader,
  CardBody,
  VStack,
  HStack,
  FormControl,
  FormLabel,
  Input,
  Select,
  Switch,
  Button,
  Text,
  useToast,
  SimpleGrid,
  Alert,
  AlertIcon,
} from '@chakra-ui/react'
import { useConfig } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

const ClusterSettings: React.FC = () => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  const toast = useToast()

  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [cfg, setCfg] = useState<any>({
    mode: 'standalone',
    node_name: 'Node-1',
    master: { host: '', port: 8443, auth_key: '', timeout: 30, retry_interval: 10 },
    sync: { config_enabled: true, cert_enabled: true, interval: 30, timeout: 10, exclude_configs: [] },
    port: 8443,
    auth_key: '',
  })

  const load = async () => {
    try {
      setLoading(true)
      const resp = await fetch(`${adminPrefix}/api/cluster/settings`, { credentials: 'include' })
      if (!resp.ok) throw new Error('Failed to load')
      const data = await resp.json()
      if (data.success && data.data) {
        setCfg(data.data)
      }
    } catch (e) {
      // no-op
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (adminPrefix) load()
  }, [adminPrefix])

  const updateField = (path: string, value: any) => {
    setCfg((prev: any) => {
      const next = { ...prev }
      const keys = path.split('.')
      let obj: any = next
      for (let i = 0; i < keys.length - 1; i++) {
        obj[keys[i]] = obj[keys[i]] ?? {}
        obj = obj[keys[i]]
      }
      obj[keys[keys.length - 1]] = value
      return next
    })
  }

  const save = async () => {
    try {
      setSaving(true)
      const resp = await fetch(`${adminPrefix}/api/cluster/settings`, {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cfg),
      })
      const data = await resp.json()
      if (!resp.ok || !data.success) throw new Error(data.error || data.message || 'Save failed')
      toast({ title: t.common.success, status: 'success', duration: 2000 })
      load()
    } catch (e: any) {
      toast({ title: t.common.error, description: e.message, status: 'error' })
    } finally {
      setSaving(false)
    }
  }

  const syncACMEToDisk = async () => {
    try {
      const resp = await fetch(`${adminPrefix}/ssl/sync-acme`, { method: 'POST', credentials: 'include' })
      if (resp.ok) toast({ title: t.ssl.syncACMECertificates, status: 'success', duration: 2000 })
    } catch {}
  }

  const syncCertsFromMaster = async () => {
    try {
      const resp = await fetch(`${adminPrefix}/api/cluster/sync-certs`, { method: 'POST', credentials: 'include' })
      const data = await resp.json().catch(() => ({}))
      if (!resp.ok || data.success === false) throw new Error(data.error || data.message || 'Sync failed')
      toast({ title: t.cluster.syncCertsSuccess, status: 'success', duration: 2000 })
    } catch (e: any) {
      toast({ title: t.common.error, description: e.message, status: 'error' })
    }
  }

  return (
    <Box>
      <Heading size="lg" mb={6}>{t.cluster.title}</Heading>

      {cfg.mode === 'slave' && (
        <Alert status="info" mb={4} borderRadius="md">
          <AlertIcon />
          <Text>{t.cluster.slaveNotice}</Text>
        </Alert>
      )}

      <SimpleGrid columns={{ base: 1, md: 2 }} spacing={6}>
        <Card>
          <CardHeader>
            <Heading size="md">{t.cluster.basic}</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl>
                <FormLabel>{t.cluster.mode}</FormLabel>
                <Select value={cfg.mode} onChange={(e) => updateField('mode', e.target.value)} disabled={loading}>
                  <option value="standalone">{t.cluster.modeStandalone}</option>
                  <option value="master">{t.cluster.modeMaster}</option>
                  <option value="slave">{t.cluster.modeSlave}</option>
                </Select>
              </FormControl>
              <FormControl>
                <FormLabel>{t.cluster.nodeName}</FormLabel>
                <Input value={cfg.node_name || ''} onChange={(e) => updateField('node_name', e.target.value)} />
              </FormControl>
              <FormControl>
                <FormLabel>{t.cluster.clusterPort}</FormLabel>
                <Input type="number" value={cfg.port || 0} onChange={(e) => updateField('port', parseInt(e.target.value || '0'))} />
              </FormControl>
              <FormControl>
                <FormLabel>{t.cluster.clusterKey}</FormLabel>
                <Input value={cfg.auth_key || ''} onChange={(e) => updateField('auth_key', e.target.value)} placeholder="********" />
              </FormControl>
              <HStack>
                <Button colorScheme="blue" onClick={save} isLoading={saving}>{t.common.save}</Button>
                <Button onClick={load} isLoading={loading}>{t.common.refresh}</Button>
              </HStack>
            </VStack>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <Heading size="md">{t.cluster.masterConfig}</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl>
                <FormLabel>{t.cluster.masterHost}</FormLabel>
                <Input value={cfg.master?.host || ''} onChange={(e) => updateField('master.host', e.target.value)} />
              </FormControl>
              <FormControl>
                <FormLabel>{t.cluster.masterPort}</FormLabel>
                <Input type="number" value={cfg.master?.port || 0} onChange={(e) => updateField('master.port', parseInt(e.target.value || '0'))} />
              </FormControl>
              <FormControl>
                <FormLabel>{t.cluster.masterKey}</FormLabel>
                <Input value={cfg.master?.auth_key || ''} onChange={(e) => updateField('master.auth_key', e.target.value)} placeholder="********" />
              </FormControl>
              <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                <FormControl>
                  <FormLabel>{t.cluster.timeout}</FormLabel>
                  <Input type="number" value={cfg.master?.timeout || 0} onChange={(e) => updateField('master.timeout', parseInt(e.target.value || '0'))} />
                </FormControl>
                <FormControl>
                  <FormLabel>{t.cluster.retryInterval}</FormLabel>
                  <Input type="number" value={cfg.master?.retry_interval || 0} onChange={(e) => updateField('master.retry_interval', parseInt(e.target.value || '0'))} />
                </FormControl>
              </SimpleGrid>
              <HStack>
                <Button colorScheme="blue" onClick={save} isLoading={saving}>{t.common.save}</Button>
              </HStack>
            </VStack>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <Heading size="md">{t.cluster.sync}</Heading>
          </CardHeader>
          <CardBody>
            <VStack spacing={4} align="stretch">
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">{t.cluster.syncConfig}</FormLabel>
                <Switch isChecked={!!cfg.sync?.config_enabled} onChange={(e) => updateField('sync.config_enabled', e.target.checked)} />
              </FormControl>
              <FormControl display="flex" alignItems="center">
                <FormLabel mb="0">{t.cluster.syncCerts}</FormLabel>
                <Switch isChecked={!!cfg.sync?.cert_enabled} onChange={(e) => updateField('sync.cert_enabled', e.target.checked)} />
              </FormControl>
              <SimpleGrid columns={{ base: 1, md: 2 }} spacing={4}>
                <FormControl>
                  <FormLabel>{t.cluster.syncInterval}</FormLabel>
                  <Input type="number" value={cfg.sync?.interval || 0} onChange={(e) => updateField('sync.interval', parseInt(e.target.value || '0'))} />
                </FormControl>
                <FormControl>
                  <FormLabel>{t.cluster.syncTimeout}</FormLabel>
                  <Input type="number" value={cfg.sync?.timeout || 0} onChange={(e) => updateField('sync.timeout', parseInt(e.target.value || '0'))} />
                </FormControl>
              </SimpleGrid>
              <HStack>
                <Button colorScheme="blue" onClick={save} isLoading={saving}>{t.common.save}</Button>
                <Button variant="outline" onClick={syncACMEToDisk}>{t.ssl.syncACMECertificates}</Button>
                <Button variant="outline" onClick={syncCertsFromMaster}>{t.cluster.syncCertsFromMaster}</Button>
              </HStack>
            </VStack>
          </CardBody>
        </Card>
      </SimpleGrid>
    </Box>
  )
}

export default ClusterSettings



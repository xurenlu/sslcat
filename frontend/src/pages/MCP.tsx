import React, { useEffect, useMemo, useState } from 'react'
import {
  Box,
  Heading,
  Text,
  Card,
  CardBody,
  HStack,
  VStack,
  Badge,
  Button,
  Switch,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
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
  Checkbox,
  CheckboxGroup,
  Stack,
  Code,
  useToast,
  useDisclosure,
  Alert,
  AlertIcon,
  Select,
  Divider,
  Tooltip,
  IconButton,
} from '@chakra-ui/react'
import { FiRefreshCw, FiPlus, FiTrash2, FiCopy } from 'react-icons/fi'
import { useConfig, buildApiPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

type MCPStatus = {
  enabled: boolean
  path_prefix: string
  stream_url_path: string
  health_url_path: string
  token_count: number
  audit_enabled: boolean
  audit_file: string
  protocol_version: string
}

type MCPToken = {
  name: string
  scopes: string[]
  ip_allowlist?: string[]
  expires_at?: string
  rate_limit?: string
  created_at?: string
  description?: string
}

type AuditEntry = {
  time?: string
  token_name?: string
  ip?: string
  tool?: string
  args?: unknown
  status?: string
  latency_ms?: number
  raw?: string
}

type ScopeKey =
  | 'scopeRead'
  | 'scopeSiteWrite'
  | 'scopeCertWrite'
  | 'scopeProxyWrite'
  | 'scopeSecurityWrite'
  | 'scopeOpsWrite'
  | 'scopeAdmin'

const ALL_SCOPES: ScopeKey[] = [
  'scopeRead',
  'scopeSiteWrite',
  'scopeCertWrite',
  'scopeProxyWrite',
  'scopeSecurityWrite',
  'scopeOpsWrite',
  'scopeAdmin',
]
const SCOPE_VALUE: Record<string, string> = {
  scopeRead: 'read',
  scopeSiteWrite: 'site:write',
  scopeCertWrite: 'cert:write',
  scopeProxyWrite: 'proxy:write',
  scopeSecurityWrite: 'security:write',
  scopeOpsWrite: 'ops:write',
  scopeAdmin: 'admin',
}

const MCPPage: React.FC = () => {
  const { adminPrefix } = useConfig()
  const t = useTranslation()
  const tt = t.mcp!
  const toast = useToast()
  const createModal = useDisclosure()
  const plaintextModal = useDisclosure()

  const [status, setStatus] = useState<MCPStatus | null>(null)
  const [tokens, setTokens] = useState<MCPToken[]>([])
  const [loadingStatus, setLoadingStatus] = useState(false)
  const [loadingTokens, setLoadingTokens] = useState(false)
  const [lastPlain, setLastPlain] = useState<{ token: string; public: MCPToken | null }>({
    token: '',
    public: null,
  })

  const refreshStatus = async () => {
    setLoadingStatus(true)
    try {
      const r = await fetch(buildApiPath(adminPrefix, '/mcp/status'), { credentials: 'include' })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      setStatus(await r.json())
    } catch (e: any) {
      toast({ status: 'error', title: t.common.error, description: String(e) })
    } finally {
      setLoadingStatus(false)
    }
  }

  const refreshTokens = async () => {
    setLoadingTokens(true)
    try {
      const r = await fetch(buildApiPath(adminPrefix, '/mcp/tokens'), { credentials: 'include' })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const j = await r.json()
      setTokens(j.tokens || [])
    } catch (e: any) {
      toast({ status: 'error', title: t.common.error, description: String(e) })
    } finally {
      setLoadingTokens(false)
    }
  }

  useEffect(() => {
    refreshStatus()
    refreshTokens()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const toggleEnable = async (next: boolean) => {
    const confirmMsg = next ? tt.enableConfirm : tt.disableConfirm
    if (!window.confirm(confirmMsg)) return
    const r = await fetch(buildApiPath(adminPrefix, next ? '/mcp/enable' : '/mcp/disable'), {
      method: 'POST',
      credentials: 'include',
    })
    const j = await r.json().catch(() => ({}))
    if (!r.ok) {
      toast({ status: 'error', title: t.common.error, description: j.error || `HTTP ${r.status}` })
      return
    }
    toast({ status: 'success', title: t.common.success, description: tt.toggleApplied })
    refreshStatus()
  }

  const revokeToken = async (name: string) => {
    if (!window.confirm(tt.revokeConfirm)) return
    const r = await fetch(
      buildApiPath(adminPrefix, `/mcp/tokens?name=${encodeURIComponent(name)}`),
      { method: 'DELETE', credentials: 'include' },
    )
    const j = await r.json().catch(() => ({}))
    if (!r.ok) {
      toast({ status: 'error', title: t.common.error, description: j.error || `HTTP ${r.status}` })
      return
    }
    toast({ status: 'success', title: t.common.success })
    refreshTokens()
    refreshStatus()
  }

  return (
    <Box p={6}>
      <HStack justify="space-between" mb={4} align="start">
        <Box>
          <Heading size="lg">{tt.title}</Heading>
          <Text color="gray.500" mt={1}>
            {tt.subtitle}
          </Text>
        </Box>
        <HStack>
          <Badge colorScheme={status?.enabled ? 'green' : 'gray'} fontSize="0.9em" px={3} py={1}>
            {status?.enabled ? tt.statusEnabled : tt.statusDisabled}
          </Badge>
          <Switch
            isChecked={!!status?.enabled}
            isDisabled={loadingStatus || !status}
            onChange={(e) => toggleEnable(e.target.checked)}
            colorScheme="blue"
          />
        </HStack>
      </HStack>

      {/* 顶部信息卡 */}
      <Card mb={4}>
        <CardBody>
          <VStack align="stretch" spacing={2}>
            <InfoRow label={tt.protocolVersion} value={status?.protocol_version || '-'} />
            <InfoRow label={tt.pathPrefix} value={status?.path_prefix || '-'} />
            <InfoRow label={tt.streamUrl} value={status?.stream_url_path || '-'} code />
            <InfoRow label={tt.healthUrl} value={status?.health_url_path || '-'} code />
            <InfoRow label={tt.tokenCount} value={String(status?.token_count ?? 0)} />
          </VStack>
        </CardBody>
      </Card>

      <Tabs colorScheme="blue" variant="enclosed">
        <TabList>
          <Tab>{tt.tokensTab}</Tab>
          <Tab>{tt.auditTab}</Tab>
          <Tab>{tt.aboutTab}</Tab>
        </TabList>
        <TabPanels>
          <TabPanel px={0}>
            <HStack mb={3}>
              <Button leftIcon={<FiPlus />} colorScheme="blue" onClick={createModal.onOpen}>
                {tt.createToken}
              </Button>
              <Button
                leftIcon={<FiRefreshCw />}
                onClick={refreshTokens}
                isLoading={loadingTokens}
                variant="outline"
              >
                {tt.refresh}
              </Button>
            </HStack>
            <TokensTable tokens={tokens} onRevoke={revokeToken} tt={tt} neverLabel={tt.never} />
          </TabPanel>
          <TabPanel px={0}>
            <AuditPanel tt={tt} adminPrefix={adminPrefix} />
          </TabPanel>
          <TabPanel px={0}>
            <AboutPanel tt={tt} status={status} />
          </TabPanel>
        </TabPanels>
      </Tabs>

      {/* 创建 token */}
      <CreateTokenDialog
        isOpen={createModal.isOpen}
        onClose={createModal.onClose}
        onCreated={(plain, tk) => {
          plaintextModal.onOpen()
          setLastPlain({ token: plain, public: tk })
          refreshTokens()
          refreshStatus()
        }}
        tt={tt}
        commonT={t.common}
      />

      {/* 明文 token 弹窗 */}
      <PlaintextDialog
        isOpen={plaintextModal.isOpen}
        onClose={plaintextModal.onClose}
        plain={lastPlain}
        tt={tt}
        toast={toast}
        adminPrefix={adminPrefix}
        streamPath={status?.stream_url_path || ''}
      />
    </Box>
  )
}

// =====================
// 子组件：信息行
// =====================
const InfoRow: React.FC<{ label: string; value: string; code?: boolean }> = ({
  label,
  value,
  code,
}) => (
  <HStack>
    <Text fontWeight="bold" minW="200px" color="gray.600">
      {label}
    </Text>
    {code ? <Code fontSize="sm">{value}</Code> : <Text>{value}</Text>}
  </HStack>
)

// =====================
// 子组件：Token 表
// =====================
const TokensTable: React.FC<{
  tokens: MCPToken[]
  onRevoke: (name: string) => void
  tt: any
  neverLabel: string
}> = ({ tokens, onRevoke, tt, neverLabel }) => {
  if (tokens.length === 0) {
    return (
      <Alert status="info">
        <AlertIcon />
        {tt.noTokens}
      </Alert>
    )
  }
  return (
    <Table size="sm" variant="simple">
      <Thead>
        <Tr>
          <Th>{tt.columnName}</Th>
          <Th>{tt.columnScopes}</Th>
          <Th>{tt.columnExpires}</Th>
          <Th>{tt.columnCreated}</Th>
          <Th width="80px">{tt.columnActions}</Th>
        </Tr>
      </Thead>
      <Tbody>
        {tokens.map((tk) => (
          <Tr key={tk.name}>
            <Td>
              <VStack align="start" spacing={0}>
                <Text fontWeight="bold">{tk.name}</Text>
                {tk.description && (
                  <Text fontSize="xs" color="gray.500">
                    {tk.description}
                  </Text>
                )}
              </VStack>
            </Td>
            <Td>
              <HStack spacing={1} flexWrap="wrap">
                {tk.scopes.map((s) => (
                  <Badge key={s} colorScheme={s === 'admin' ? 'red' : 'blue'} fontSize="0.7em">
                    {s}
                  </Badge>
                ))}
              </HStack>
            </Td>
            <Td>
              <Text fontSize="sm">{tk.expires_at || neverLabel}</Text>
            </Td>
            <Td>
              <Text fontSize="sm">{tk.created_at || '-'}</Text>
            </Td>
            <Td>
              <Tooltip label={tt.revoke}>
                <IconButton
                  aria-label={tt.revoke}
                  icon={<FiTrash2 />}
                  size="sm"
                  colorScheme="red"
                  variant="ghost"
                  onClick={() => onRevoke(tk.name)}
                />
              </Tooltip>
            </Td>
          </Tr>
        ))}
      </Tbody>
    </Table>
  )
}

// =====================
// 子组件：创建 Token 对话框
// =====================
const CreateTokenDialog: React.FC<{
  isOpen: boolean
  onClose: () => void
  onCreated: (plain: string, tk: MCPToken) => void
  tt: any
  commonT: any
}> = ({ isOpen, onClose, onCreated, tt, commonT }) => {
  const { adminPrefix } = useConfig()
  const toast = useToast()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [scopes, setScopes] = useState<string[]>(['read'])
  const [ipAllowlist, setIPAllowlist] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [rateLimit, setRateLimit] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const reset = () => {
    setName('')
    setDescription('')
    setScopes(['read'])
    setIPAllowlist('')
    setExpiresAt('')
    setRateLimit('')
  }

  const submit = async () => {
    if (!name.trim()) {
      toast({ status: 'warning', title: tt.tokenName, description: 'required' })
      return
    }
    setSubmitting(true)
    try {
      const body = {
        name: name.trim(),
        description: description.trim(),
        scopes,
        ip_allowlist: ipAllowlist
          .split(',')
          .map((s) => s.trim())
          .filter((s) => s.length > 0),
        expires_at: expiresAt.trim() || undefined,
        rate_limit: rateLimit.trim() || undefined,
      }
      const r = await fetch(buildApiPath(adminPrefix, '/mcp/tokens'), {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const j = await r.json().catch(() => ({}))
      if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`)
      onCreated(j.token, j.public)
      reset()
      onClose()
    } catch (e: any) {
      toast({ status: 'error', title: commonT.error, description: String(e) })
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} size="2xl">
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>{tt.createToken}</ModalHeader>
        <ModalCloseButton />
        <ModalBody>
          <VStack spacing={3} align="stretch">
            <FormControl isRequired>
              <FormLabel>{tt.tokenName}</FormLabel>
              <Input
                placeholder={tt.tokenNamePlaceholder}
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </FormControl>
            <FormControl>
              <FormLabel>{tt.description}</FormLabel>
              <Input
                placeholder={tt.descriptionPlaceholder}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </FormControl>
            <FormControl>
              <FormLabel>{tt.scopes}</FormLabel>
              <CheckboxGroup
                value={scopes}
                onChange={(v) => setScopes(v as string[])}
                colorScheme="blue"
              >
                <Stack spacing={1}>
                  {ALL_SCOPES.map((k) => (
                    <Checkbox key={k} value={SCOPE_VALUE[k]}>
                      <Text fontSize="sm">{tt[k]}</Text>
                    </Checkbox>
                  ))}
                </Stack>
              </CheckboxGroup>
            </FormControl>
            <HStack align="start">
              <FormControl>
                <FormLabel>{tt.ipAllowlist}</FormLabel>
                <Input
                  placeholder={tt.ipAllowlistPlaceholder}
                  value={ipAllowlist}
                  onChange={(e) => setIPAllowlist(e.target.value)}
                />
              </FormControl>
              <FormControl>
                <FormLabel>{tt.rateLimit}</FormLabel>
                <Input
                  placeholder={tt.rateLimitPlaceholder}
                  value={rateLimit}
                  onChange={(e) => setRateLimit(e.target.value)}
                />
              </FormControl>
            </HStack>
            <FormControl>
              <FormLabel>{tt.expiresAt}</FormLabel>
              <Input
                placeholder={tt.expiresAtPlaceholder}
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
              />
            </FormControl>
          </VStack>
        </ModalBody>
        <ModalFooter>
          <Button variant="ghost" mr={2} onClick={onClose}>
            {tt.cancel}
          </Button>
          <Button colorScheme="blue" onClick={submit} isLoading={submitting}>
            {tt.create}
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  )
}

// =====================
// 子组件：明文 Token 弹窗
// =====================
const PlaintextDialog: React.FC<{
  isOpen: boolean
  onClose: () => void
  plain: { token: string; public: MCPToken | null }
  tt: any
  toast: ReturnType<typeof useToast>
  adminPrefix: string
  streamPath: string
}> = ({ isOpen, onClose, plain, tt, toast, adminPrefix, streamPath }) => {
  const fullURL = useMemo(() => {
    if (typeof window === 'undefined') return streamPath
    return window.location.origin + streamPath
  }, [streamPath])
  const clientJSON = JSON.stringify(
    {
      mcpServers: {
        sslcat: {
          type: 'http',
          url: fullURL,
          headers: { Authorization: `Bearer ${plain.token}` },
        },
      },
    },
    null,
    2,
  )

  const copy = (text: string) => {
    navigator.clipboard?.writeText(text).then(
      () => toast({ status: 'success', title: tt.tokenCopied }),
      () => toast({ status: 'error', title: 'Copy failed' }),
    )
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} size="2xl" closeOnOverlayClick={false}>
      <ModalOverlay />
      <ModalContent>
        <ModalHeader>{tt.tokenCreatedTitle}</ModalHeader>
        <ModalBody>
          <Alert status="warning" mb={3}>
            <AlertIcon />
            <Text fontSize="sm">{tt.tokenCreatedWarning}</Text>
          </Alert>
          <FormControl mb={3}>
            <FormLabel>{tt.plaintextLabel}</FormLabel>
            <HStack>
              <Code flex="1" p={2} fontSize="sm" wordBreak="break-all">
                {plain.token}
              </Code>
              <IconButton
                aria-label={tt.copyToken}
                icon={<FiCopy />}
                onClick={() => copy(plain.token)}
              />
            </HStack>
          </FormControl>
          <Divider my={3} />
          <FormControl>
            <FormLabel>{tt.quickStart}</FormLabel>
            <Text fontSize="sm" color="gray.500" mb={2}>
              {tt.quickStartHint}
            </Text>
            <Box position="relative">
              <Textarea
                value={clientJSON}
                readOnly
                rows={10}
                fontFamily="mono"
                fontSize="xs"
              />
              <IconButton
                aria-label={tt.copyToken}
                icon={<FiCopy />}
                size="sm"
                position="absolute"
                top={2}
                right={2}
                onClick={() => copy(clientJSON)}
              />
            </Box>
          </FormControl>
        </ModalBody>
        <ModalFooter>
          <Button colorScheme="blue" onClick={onClose}>
            {tt.iSavedIt}
          </Button>
        </ModalFooter>
      </ModalContent>
    </Modal>
  )
}

// =====================
// 子组件：审计日志面板
// =====================
const AuditPanel: React.FC<{ tt: any; adminPrefix: string }> = ({ tt, adminPrefix }) => {
  const toast = useToast()
  const today = () => {
    const d = new Date()
    const yyyy = d.getFullYear()
    const mm = String(d.getMonth() + 1).padStart(2, '0')
    const dd = String(d.getDate()).padStart(2, '0')
    return `${yyyy}${mm}${dd}`
  }
  const [date, setDate] = useState(today())
  const [tail, setTail] = useState(200)
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [exists, setExists] = useState(true)
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const r = await fetch(
        buildApiPath(adminPrefix, `/mcp/audit?date=${date}&tail=${tail}`),
        { credentials: 'include' },
      )
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const j = await r.json()
      setEntries(j.entries || [])
      setExists(j.exists !== false)
    } catch (e: any) {
      toast({ status: 'error', title: 'Error', description: String(e) })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <Box>
      <HStack mb={3}>
        <FormControl maxW="180px">
          <FormLabel fontSize="xs">{tt.auditDate}</FormLabel>
          <Input
            type="text"
            value={date}
            onChange={(e) => setDate(e.target.value.replace(/[^0-9]/g, '').slice(0, 8))}
            placeholder="YYYYMMDD"
          />
        </FormControl>
        <FormControl maxW="150px">
          <FormLabel fontSize="xs">{tt.auditTailLabel}</FormLabel>
          <Select value={tail} onChange={(e) => setTail(Number(e.target.value))}>
            <option value={50}>50</option>
            <option value={200}>200</option>
            <option value={500}>500</option>
            <option value={1000}>1000</option>
          </Select>
        </FormControl>
        <Button mt="22px" leftIcon={<FiRefreshCw />} onClick={load} isLoading={loading}>
          {tt.refresh}
        </Button>
      </HStack>

      {!exists && (
        <Alert status="info" mb={3}>
          <AlertIcon />
          {tt.auditNotExist}
        </Alert>
      )}
      {exists && entries.length === 0 && (
        <Alert status="info" mb={3}>
          <AlertIcon />
          {tt.auditEmpty}
        </Alert>
      )}
      {entries.length > 0 && (
        <Table size="sm" variant="striped">
          <Thead>
            <Tr>
              <Th>Time</Th>
              <Th>Token</Th>
              <Th>IP</Th>
              <Th>Tool</Th>
              <Th>Status</Th>
              <Th isNumeric>Latency (ms)</Th>
            </Tr>
          </Thead>
          <Tbody>
            {entries.map((e, i) => (
              <Tr key={i}>
                <Td fontSize="xs">{e.time || '-'}</Td>
                <Td fontSize="xs">{e.token_name || '-'}</Td>
                <Td fontSize="xs">{e.ip || '-'}</Td>
                <Td fontSize="xs">
                  <Code fontSize="xs">{e.tool || '-'}</Code>
                </Td>
                <Td>
                  <Badge
                    colorScheme={
                      e.status === 'ok'
                        ? 'green'
                        : e.status === 'forbidden'
                        ? 'red'
                        : e.status === 'pending_confirm'
                        ? 'yellow'
                        : 'gray'
                    }
                    fontSize="0.7em"
                  >
                    {e.status || '-'}
                  </Badge>
                </Td>
                <Td isNumeric fontSize="xs">
                  {e.latency_ms ?? '-'}
                </Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
      )}
    </Box>
  )
}

// =====================
// 子组件：关于面板
// =====================
const AboutPanel: React.FC<{ tt: any; status: MCPStatus | null }> = ({ tt, status }) => (
  <VStack align="stretch" spacing={3}>
    <Text>{tt.aboutLine1}</Text>
    <Text>{tt.aboutLine2}</Text>
    {status && (
      <Card>
        <CardBody>
          <Text fontSize="sm" color="gray.500" mb={2}>
            {tt.streamUrl}
          </Text>
          <Code fontSize="sm">{status.stream_url_path}</Code>
          <Text fontSize="sm" color="gray.500" mt={3} mb={2}>
            {tt.protocolVersion}
          </Text>
          <Code fontSize="sm">{status.protocol_version}</Code>
        </CardBody>
      </Card>
    )}
  </VStack>
)

export default MCPPage

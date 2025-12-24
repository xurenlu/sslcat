import React, { useCallback, useEffect, useMemo, useState } from 'react'
import {
	Badge,
	Box,
	Button,
	Card,
	CardBody,
	CardHeader,
	Divider,
	FormControl,
	FormLabel,
	Heading,
	HStack,
	IconButton,
	Input,
	Modal,
	ModalBody,
	ModalCloseButton,
	ModalContent,
	ModalFooter,
	ModalHeader,
	ModalOverlay,
	NumberInput,
	NumberInputField,
	Select,
	SimpleGrid,
	Spinner,
	Stack,
	Switch,
	Table,
	Tbody,
	Td,
	Text,
	Textarea,
	Th,
	Thead,
	Tooltip,
	Tr,
	useToast,
	VStack,
} from '@chakra-ui/react'
import {
	FiCopy,
	FiEdit,
	FiPlay,
	FiPlus,
	FiRefreshCw,
	FiStopCircle,
	FiTrash2,
} from 'react-icons/fi'

import { useTranslation } from '../hooks/useLanguage'
import { apiService } from '../utils/api'
import {
	TunnelDefinitionPayload,
	TunnelProviderPayload,
	TunnelProviderSummary,
	TunnelWithStatus,
} from '../types/tunnels'

const preserveCredentialValue = '__PRESERVE__'

type TunnelStatus = TunnelWithStatus['status']

interface KeyValueRow {
	id: string
	key: string
	value: string
	hasExisting?: boolean
}

interface ProviderFormState {
	id?: string
	name: string
	type: string
	description: string
	enabled: boolean
	autoStart: boolean
	credentials: KeyValueRow[]
	options: KeyValueRow[]
}

interface TunnelFormState {
	id?: string
	name: string
	protocol: string
	localAddress: string
	localPort: number
	publicHostname: string
	publicPort?: number
	edgeRegion: string
	autoStart: boolean
	notes: string
}

interface TunnelsResponse {
	success: boolean
	providers?: TunnelProviderSummary[]
	supported_providers?: string[]
	supported_protocols?: string[]
}

const fallbackTexts = {
	title: 'Dynamic Domain / Tunneling',
	description: 'Manage Cloudflare Tunnel, ngrok, frp and PeanutHull to publish internal services securely.',
	addProvider: 'Add Service',
	editProvider: 'Edit Service',
	deleteProvider: 'Delete Service',
	confirmDeleteProvider: 'Delete this service? All tunnels underneath will be removed.',
	addTunnel: 'Add Tunnel',
	editTunnel: 'Edit Tunnel',
	deleteTunnel: 'Delete Tunnel',
	confirmDeleteTunnel: 'Delete this tunnel?',
	providerType: 'Service Type',
	providerName: 'Service Name',
	descriptionLabel: 'Description',
	enabled: 'Enable Service',
	autoStart: 'Auto-start All Tunnels',
	credentials: 'Credentials',
	options: 'Advanced Options',
	notes: 'Notes',
	key: 'Key',
	value: 'Value',
	addRow: 'Add Entry',
	removeRow: 'Remove',
	credentialPlaceholder: 'e.g. token, tunnel_id',
	optionPlaceholder: 'e.g. region, entrypoint',
	secretStored: 'Stored',
	protocol: 'Protocol',
	localAddress: 'Local Address',
	localPort: 'Local Port',
	publicHostname: 'Public Hostname',
	publicPort: 'Public Port',
	edgeRegion: 'Edge Region',
	status: 'Status',
	lastError: 'Last Error',
	lastUpdated: 'Last Updated',
	actions: 'Actions',
  logFile: 'Log File',
  pid: 'Process PID',
  restartCount: 'Restart Count',
  lastStarted: 'Last Started',
  lastStopped: 'Last Stopped',
  copyLogPath: 'Copy Path',
  copyLogPathSuccess: 'Log path copied',
  copyLogPathFailed: 'Failed to copy log path',
	startTunnel: 'Start',
	stopTunnel: 'Stop',
	refresh: 'Refresh',
	save: 'Save',
	cancel: 'Cancel',
	noProviders: 'No tunneling services configured yet.',
	createFirstProvider: 'Create a service to integrate Cloudflare Tunnel, ngrok, frp or PeanutHull.',
	statusConnected: 'Connected',
	statusDisconnected: 'Disconnected',
	statusError: 'Error',
	statusUnknown: 'Unknown',
	statusConnecting: 'Connecting',
	providerBadgeAutoStart: 'Auto-start',
	providerBadgeDisabled: 'Disabled',
}

const providerLabels: Record<string, string> = {
	cloudflare: 'Cloudflare Tunnel',
	ngrok: 'ngrok',
	frp: 'frp',
	phddns: 'PeanutHull',
}

const statusColor: Record<TunnelStatus, string> = {
	connected: 'green',
	disconnected: 'gray',
	error: 'red',
	unknown: 'gray',
	connecting: 'orange',
}

const defaultProviderTypes = ['cloudflare', 'ngrok', 'frp', 'phddns']
const defaultProtocols = ['http', 'https', 'tcp', 'udp']

const createRow = (key = '', value = '', hasExisting = false): KeyValueRow => ({
	id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
	key,
	value,
	hasExisting,
})

const buildRecordFromRows = (rows: KeyValueRow[]): Record<string, string> | undefined => {
	const record: Record<string, string> = {}
	rows.forEach((row) => {
		const trimmedKey = row.key.trim()
		if (!trimmedKey) return
		record[trimmedKey] = row.value.trim()
	})
	return Object.keys(record).length ? record : undefined
}

const tunnelSummaryToPayload = (tunnel: TunnelWithStatus): TunnelDefinitionPayload => ({
	id: tunnel.id,
	name: tunnel.name,
	protocol: tunnel.protocol,
	local_address: tunnel.local_address,
	local_port: tunnel.local_port,
	public_hostname: tunnel.public_hostname,
	public_port: tunnel.public_port,
	edge_region: tunnel.edge_region,
	auto_start: tunnel.auto_start,
	notes: tunnel.notes,
})

const buildCredentialPreserveMap = (
	provider?: TunnelProviderSummary | null,
): Record<string, string> | undefined => {
	if (!provider) return undefined
	const result: Record<string, string> = {}
	provider.credentials.forEach((credential) => {
		if (credential.has_value) {
			result[credential.key] = preserveCredentialValue
		}
	})
	return Object.keys(result).length ? result : undefined
}

const formatDateTime = (value?: string): string => {
	if (!value) return '--'
	try {
		return new Date(value).toLocaleString()
	} catch {
		return value
	}
}

const extractFileName = (path?: string): string => {
	if (!path) return ''
	const segments = path.split(/[/\\]/)
	return segments[segments.length - 1] || path
}

const Tunnels: React.FC = () => {
	const t = useTranslation()
	const toast = useToast()
	const texts = t.tunnels ?? fallbackTexts

	const [providers, setProviders] = useState<TunnelProviderSummary[]>([])
	const [supportedProviders, setSupportedProviders] = useState<string[]>(defaultProviderTypes)
	const [supportedProtocols, setSupportedProtocols] = useState<string[]>(defaultProtocols)
	const [loading, setLoading] = useState(true)
	const [saving, setSaving] = useState(false)
	const [actioningTunnel, setActioningTunnel] = useState<string | null>(null)
	const [deletingTarget, setDeletingTarget] = useState<string | null>(null)
	const [providerModalOpen, setProviderModalOpen] = useState(false)
	const [tunnelModalOpen, setTunnelModalOpen] = useState(false)
	const [editingProvider, setEditingProvider] = useState<TunnelProviderSummary | null>(null)
	const [tunnelProvider, setTunnelProvider] = useState<TunnelProviderSummary | null>(null)
	const [providerForm, setProviderForm] = useState<ProviderFormState>({
		name: '',
		type: defaultProviderTypes[0],
		description: '',
		enabled: true,
		autoStart: true,
		credentials: [],
		options: [],
	})
	const [tunnelForm, setTunnelForm] = useState<TunnelFormState>({
		name: '',
		protocol: defaultProtocols[0],
		localAddress: '127.0.0.1',
		localPort: 8080,
		publicHostname: '',
		publicPort: undefined,
		edgeRegion: '',
		autoStart: true,
		notes: '',
	})

	const refreshProviders = useCallback(async () => {
		setLoading(true)
		try {
			const response = (await apiService.getTunnels()) as TunnelsResponse
			if (response?.providers) {
				setProviders(response.providers)
			}
			if (response?.supported_providers?.length) {
				setSupportedProviders(response.supported_providers)
			}
			if (response?.supported_protocols?.length) {
				setSupportedProtocols(response.supported_protocols)
			}
		} catch (error: any) {
			console.error('Failed to load tunneling data', error)
			toast({
				title: texts.refresh,
				description: error?.message || 'Failed to load data',
				status: 'error',
				duration: 5000,
				isClosable: true,
			})
		} finally {
			setLoading(false)
		}
	}, [toast, texts.refresh])

	useEffect(() => {
		refreshProviders()
	}, [refreshProviders])

	const handleCopyLogPath = useCallback(
		async (path: string) => {
			try {
				if (!navigator?.clipboard?.writeText) {
					throw new Error('Clipboard API unavailable')
				}
				await navigator.clipboard.writeText(path)
				toast({
					title: texts.copyLogPathSuccess,
					status: 'success',
					duration: 2000,
					isClosable: true,
				})
			} catch (error: any) {
				console.error('Failed to copy log path', error)
				toast({
					title: texts.copyLogPathFailed,
					description: error?.message,
					status: 'error',
					duration: 4000,
					isClosable: true,
				})
			}
		},
		[toast, texts.copyLogPathFailed, texts.copyLogPathSuccess],
	)

	const resetProviderForm = useCallback(
		(defaultType?: string) => {
			setProviderForm({
				name: '',
				type: defaultType || supportedProviders[0] || defaultProviderTypes[0],
				description: '',
				enabled: true,
				autoStart: true,
				credentials: [],
				options: [],
			})
		},
		[supportedProviders],
	)

	const resetTunnelForm = useCallback(
		(defaultProtocol?: string) => {
			setTunnelForm({
				name: '',
				protocol: defaultProtocol || supportedProtocols[0] || defaultProtocols[0],
				localAddress: '127.0.0.1',
				localPort: 8080,
				publicHostname: '',
				publicPort: undefined,
				edgeRegion: '',
				autoStart: true,
				notes: '',
			})
		},
		[supportedProtocols],
	)

	const handleAddProvider = () => {
		resetProviderForm()
		setEditingProvider(null)
		setProviderModalOpen(true)
	}

	const handleEditProvider = (provider: TunnelProviderSummary) => {
		setEditingProvider(provider)
		setProviderForm({
			id: provider.id,
			name: provider.name,
			type: provider.type,
			description: provider.description ?? '',
			enabled: provider.enabled,
			autoStart: provider.auto_start,
			credentials: provider.credentials.map((c) => createRow(c.key, '', c.has_value)),
			options: provider.options
				? Object.entries(provider.options).map(([key, value]) => createRow(key, value))
				: [],
		})
		setProviderModalOpen(true)
	}

	const handleAddTunnel = (provider: TunnelProviderSummary) => {
		setTunnelProvider(provider)
		resetTunnelForm()
		setTunnelModalOpen(true)
	}

	const handleEditTunnel = (provider: TunnelProviderSummary, tunnel: TunnelWithStatus) => {
		setTunnelProvider(provider)
		setTunnelForm({
			id: tunnel.id,
			name: tunnel.name,
			protocol: tunnel.protocol,
			localAddress: tunnel.local_address,
			localPort: tunnel.local_port,
			publicHostname: tunnel.public_hostname ?? '',
			publicPort: tunnel.public_port,
			edgeRegion: tunnel.edge_region ?? '',
			autoStart: tunnel.auto_start,
			notes: tunnel.notes ?? '',
		})
		setTunnelModalOpen(true)
	}

	const updateCredentialRows = (updater: (rows: KeyValueRow[]) => KeyValueRow[]) => {
		setProviderForm((prev) => ({
			...prev,
			credentials: updater(prev.credentials),
		}))
	}

	const updateOptionRows = (updater: (rows: KeyValueRow[]) => KeyValueRow[]) => {
		setProviderForm((prev) => ({
			...prev,
			options: updater(prev.options),
		}))
	}

	const collectCredentialPayload = (
		rows: KeyValueRow[],
		baseProvider?: TunnelProviderSummary | null,
	): Record<string, string> | undefined => {
		const payload: Record<string, string> = {}
		const activeKeys = new Set<string>()

		rows.forEach((row) => {
			const key = row.key.trim()
			if (!key) return
			activeKeys.add(key)
			if (row.value.trim()) {
				payload[key] = row.value.trim()
			} else if (row.hasExisting) {
				payload[key] = preserveCredentialValue
			}
		})

		if (baseProvider) {
			baseProvider.credentials.forEach((credential) => {
				if (!activeKeys.has(credential.key) && credential.has_value) {
					payload[credential.key] = ''
				}
			})
		}

		return Object.keys(payload).length ? payload : undefined
	}

	const buildProviderPayload = (
		baseProvider: TunnelProviderSummary | null,
		form: ProviderFormState,
		tunnels: TunnelDefinitionPayload[],
	): TunnelProviderPayload => ({
		id: form.id || baseProvider?.id,
		name: form.name.trim(),
		type: form.type,
		enabled: form.enabled,
		description: form.description.trim(),
		auto_start: form.autoStart,
		credentials:
			collectCredentialPayload(form.credentials, baseProvider) ||
			buildCredentialPreserveMap(baseProvider),
		options: buildRecordFromRows(form.options),
		tunnels,
	})

	const handleSaveProvider = async () => {
		if (!providerForm.name.trim()) {
			toast({
				title: texts.providerName,
				description: 'Name is required',
				status: 'warning',
				duration: 3000,
				isClosable: true,
			})
			return
		}

		setSaving(true)
		try {
			const tunnels = editingProvider
				? editingProvider.tunnels.map(tunnelSummaryToPayload)
				: []
			const payload = buildProviderPayload(editingProvider, providerForm, tunnels)
			await apiService.saveTunnelProvider(payload)
			toast({
				title: texts.save,
				description: editingProvider ? texts.editProvider : texts.addProvider,
				status: 'success',
				duration: 3000,
				isClosable: true,
			})
			setProviderModalOpen(false)
			resetProviderForm()
			refreshProviders()
		} catch (error: any) {
			console.error('Failed to save provider', error)
			toast({
				title: texts.save,
				description: error?.message || 'Failed to save provider',
				status: 'error',
				duration: 5000,
				isClosable: true,
			})
		} finally {
			setSaving(false)
		}
	}

	const handleDeleteProvider = async (provider: TunnelProviderSummary) => {
		setDeletingTarget(provider.id)
		try {
			await apiService.deleteTunnelProvider(provider.id)
			toast({
				title: texts.deleteProvider,
				description: `${provider.name} removed`,
				status: 'success',
				duration: 3000,
				isClosable: true,
			})
			refreshProviders()
		} catch (error: any) {
			console.error('Failed to delete provider', error)
			toast({
				title: texts.deleteProvider,
				description: error?.message || 'Failed to delete provider',
				status: 'error',
				duration: 5000,
				isClosable: true,
			})
		} finally {
			setDeletingTarget(null)
		}
	}

	const handleDeleteTunnel = async (provider: TunnelProviderSummary, tunnel: TunnelWithStatus) => {
		setDeletingTarget(tunnel.id)
		try {
			await apiService.deleteTunnel(provider.id, tunnel.id)
			toast({
				title: texts.deleteTunnel,
				description: `${tunnel.name} removed`,
				status: 'success',
				duration: 3000,
				isClosable: true,
			})
			refreshProviders()
		} catch (error: any) {
			console.error('Failed to delete tunnel', error)
			toast({
				title: texts.deleteTunnel,
				description: error?.message || 'Failed to delete tunnel',
				status: 'error',
				duration: 5000,
				isClosable: true,
			})
		} finally {
			setDeletingTarget(null)
		}
	}

	const handleSaveTunnel = async () => {
		if (!tunnelProvider) return
		if (!tunnelForm.name.trim()) {
			toast({
				title: texts.editTunnel,
				description: 'Tunnel name is required',
				status: 'warning',
				duration: 3000,
				isClosable: true,
			})
			return
		}
		if (!Number.isInteger(tunnelForm.localPort) || tunnelForm.localPort < 1 || tunnelForm.localPort > 65535) {
			toast({
				title: texts.localPort,
				description: 'Local port must be between 1 and 65535',
				status: 'warning',
				duration: 3000,
				isClosable: true,
			})
			return
		}
		if (tunnelForm.publicPort !== undefined && tunnelForm.publicPort !== null) {
			const port = tunnelForm.publicPort
			if (!Number.isInteger(port) || port < 0 || port > 65535) {
				toast({
					title: texts.publicPort,
					description: 'Public port must be between 0 and 65535',
					status: 'warning',
					duration: 3000,
					isClosable: true,
				})
				return
			}
		}

		setSaving(true)
		try {
			const payloadTunnel: TunnelDefinitionPayload = {
				id: tunnelForm.id,
				name: tunnelForm.name.trim(),
				protocol: tunnelForm.protocol,
				local_address: tunnelForm.localAddress.trim(),
				local_port: tunnelForm.localPort,
				public_hostname: tunnelForm.publicHostname.trim() || undefined,
				public_port:
					tunnelForm.publicPort === undefined || tunnelForm.publicPort === null
						? undefined
						: tunnelForm.publicPort,
				edge_region: tunnelForm.edgeRegion.trim() || undefined,
				auto_start: tunnelForm.autoStart,
				notes: tunnelForm.notes.trim() || undefined,
			}

			const tunnelsPayload = tunnelProvider.tunnels
				.map(tunnelSummaryToPayload)
				.filter((existing) => existing.id !== payloadTunnel.id)

			if (payloadTunnel.id) {
				tunnelsPayload.push(payloadTunnel)
			} else {
				tunnelsPayload.push({ ...payloadTunnel, id: undefined })
			}

			const payload: TunnelProviderPayload = {
				id: tunnelProvider.id,
				name: tunnelProvider.name,
				type: tunnelProvider.type,
				enabled: tunnelProvider.enabled,
				description: tunnelProvider.description ?? '',
				auto_start: tunnelProvider.auto_start,
				credentials: buildCredentialPreserveMap(tunnelProvider),
				options: tunnelProvider.options,
				tunnels: tunnelsPayload,
			}

			await apiService.saveTunnelProvider(payload)
			toast({
				title: texts.save,
				description: texts.editTunnel,
				status: 'success',
				duration: 3000,
				isClosable: true,
			})
			setTunnelModalOpen(false)
			resetTunnelForm()
			refreshProviders()
		} catch (error: any) {
			console.error('Failed to save tunnel', error)
			toast({
				title: texts.save,
				description: error?.message || 'Failed to save tunnel',
				status: 'error',
				duration: 5000,
				isClosable: true,
			})
		} finally {
			setSaving(false)
		}
	}

	const handleTunnelAction = async (
		action: 'start' | 'stop',
		provider: TunnelProviderSummary,
		tunnel: TunnelWithStatus,
	) => {
		setActioningTunnel(tunnel.id)
		try {
			if (action === 'start') {
				await apiService.startTunnel(provider.id, tunnel.id)
			} else {
				await apiService.stopTunnel(provider.id, tunnel.id)
			}
			toast({
				title: action === 'start' ? texts.startTunnel : texts.stopTunnel,
				description: `${tunnel.name} ${action === 'start' ? 'started' : 'stopped'}`,
				status: 'success',
				duration: 3000,
				isClosable: true,
			})
			refreshProviders()
		} catch (error: any) {
			console.error('Failed to control tunnel', error)
			toast({
				title: action === 'start' ? texts.startTunnel : texts.stopTunnel,
				description: error?.message || 'Operation failed',
				status: 'error',
				duration: 5000,
				isClosable: true,
			})
		} finally {
			setActioningTunnel(null)
		}
	}

	const renderStatusBadge = (status: TunnelStatus) => {
		const textMap: Record<TunnelStatus, string> = {
			connected: texts.statusConnected,
			disconnected: texts.statusDisconnected,
			error: texts.statusError,
			unknown: texts.statusUnknown,
			connecting: texts.statusConnecting,
		}
		return <Badge colorScheme={statusColor[status]}>{textMap[status] ?? status}</Badge>
	}

	const providerCards = useMemo(() => {
		if (!providers.length) {
			return (
				<Card>
					<CardBody textAlign="center">
						<VStack spacing={3}>
							<Text>{texts.noProviders}</Text>
							<Text fontSize="sm" color="gray.500">
								{texts.createFirstProvider}
							</Text>
							<Button leftIcon={<FiPlus />} colorScheme="brand" onClick={handleAddProvider}>
								{texts.addProvider}
							</Button>
						</VStack>
					</CardBody>
				</Card>
			)
		}

		return (
			<SimpleGrid columns={{ base: 1, xl: 2 }} spacing={6}>
				{providers.map((provider) => (
					<Card key={provider.id} variant="outline">
						<CardHeader>
							<Stack direction={{ base: 'column', md: 'row' }} justify="space-between" spacing={3}>
								<Box>
									<HStack spacing={3}>
										<Heading size="md">{provider.name}</Heading>
										<Badge colorScheme="purple">
											{providerLabels[provider.type] ?? provider.type}
										</Badge>
										{provider.auto_start && (
											<Badge colorScheme="green">{texts.providerBadgeAutoStart}</Badge>
										)}
										{!provider.enabled && (
											<Badge colorScheme="gray">{texts.providerBadgeDisabled}</Badge>
										)}
									</HStack>
									<Text mt={2} color="gray.600" fontSize="sm">
										{provider.description || '--'}
									</Text>
								</Box>
								<HStack spacing={2}>
									<Button size="sm" leftIcon={<FiPlus />} variant="outline" onClick={() => handleAddTunnel(provider)}>
										{texts.addTunnel}
									</Button>
									<IconButton
										size="sm"
										aria-label="edit-provider"
										icon={<FiEdit />}
										onClick={() => handleEditProvider(provider)}
									/>
									<IconButton
										size="sm"
										aria-label="delete-provider"
										icon={<FiTrash2 />}
										colorScheme="red"
										isLoading={deletingTarget === provider.id}
										onClick={() => handleDeleteProvider(provider)}
									/>
								</HStack>
							</Stack>
						</CardHeader>
						<CardBody>
							<VStack align="stretch" spacing={4}>
								<Text fontSize="sm" color="gray.500">
									{provider.tunnels.length} tunnels
								</Text>
								<Divider />
								<Box overflowX="auto" w="100%">
									<Table variant="simple" size="sm" minW="1000px">
										<Thead>
											<Tr>
												<Th minW="120px">{texts.providerName}</Th>
												<Th minW="80px">{texts.protocol}</Th>
												<Th minW="140px">{texts.localAddress}</Th>
												<Th minW="180px">{texts.publicHostname}</Th>
												<Th minW="280px">{texts.status}</Th>
												<Th minW="160px">{texts.lastUpdated}</Th>
												<Th textAlign="right" minW="140px">{texts.actions}</Th>
											</Tr>
										</Thead>
									<Tbody>
										{provider.tunnels.map((tunnel) => (
											<Tr key={tunnel.id}>
												<Td>{tunnel.name}</Td>
												<Td textTransform="uppercase">{tunnel.protocol}</Td>
												<Td>{`${tunnel.local_address}:${tunnel.local_port}`}</Td>
												<Td>
													{tunnel.public_hostname ? `${tunnel.public_hostname}${tunnel.public_port ? `:${tunnel.public_port}` : ''}` : '--'}
												</Td>
												<Td>
													<VStack align="start" spacing={1}>
														{renderStatusBadge(tunnel.status)}
														{tunnel.last_error && (
															<Tooltip label={tunnel.last_error} placement="top-start">
																<Text fontSize="xs" color="red.500" maxW="240px" isTruncated>
																	{texts.lastError}: {tunnel.last_error}
																</Text>
															</Tooltip>
														)}
														{typeof tunnel.pid === 'number' && tunnel.pid > 0 && (
															<Text fontSize="xs" color="gray.500">
																{texts.pid}: {tunnel.pid}
															</Text>
														)}
														<Text fontSize="xs" color="gray.500">
															{texts.restartCount}: {tunnel.restart_count ?? 0}
														</Text>
														{tunnel.last_started_at && (
															<Text fontSize="xs" color="gray.500">
																{texts.lastStarted}: {formatDateTime(tunnel.last_started_at)}
															</Text>
														)}
														{tunnel.last_stopped_at && (
															<Text fontSize="xs" color="gray.500">
																{texts.lastStopped}: {formatDateTime(tunnel.last_stopped_at)}
															</Text>
														)}
														{tunnel.log_path && (
															<HStack spacing={1} maxW="240px">
																<Tooltip label={tunnel.log_path} placement="top-start">
																	<Text fontSize="xs" color="gray.500" flex="1" isTruncated>
																		{texts.logFile}: {extractFileName(tunnel.log_path)}
																	</Text>
																</Tooltip>
																<IconButton
																	aria-label={texts.copyLogPath}
																	icon={<FiCopy />}
																	size="xs"
																	variant="ghost"
																	onClick={() => handleCopyLogPath(tunnel.log_path!)}
																/>
															</HStack>
														)}
													</VStack>
												</Td>
												<Td>{formatDateTime(tunnel.updated_at)}</Td>
												<Td textAlign="right">
													<HStack justify="flex-end" spacing={2}>
														<IconButton
															aria-label={tunnel.status === 'connected' ? texts.stopTunnel : texts.startTunnel}
															icon={tunnel.status === 'connected' ? <FiStopCircle /> : <FiPlay />}
															colorScheme={tunnel.status === 'connected' ? 'red' : 'green'}
															size="sm"
															isLoading={actioningTunnel === tunnel.id}
															onClick={() => handleTunnelAction(tunnel.status === 'connected' ? 'stop' : 'start', provider, tunnel)}
														/>
														<IconButton
															aria-label="edit-tunnel"
															icon={<FiEdit />}
															size="sm"
															onClick={() => handleEditTunnel(provider, tunnel)}
														/>
														<IconButton
															aria-label="delete-tunnel"
															icon={<FiTrash2 />}
															size="sm"
															colorScheme="red"
															isLoading={deletingTarget === tunnel.id}
															onClick={() => handleDeleteTunnel(provider, tunnel)}
														/>
													</HStack>
												</Td>
											</Tr>
										))}
									</Tbody>
									</Table>
								</Box>
							</VStack>
						</CardBody>
					</Card>
				))}
			</SimpleGrid>
		)
	}, [providers, texts, deletingTarget, actioningTunnel, handleCopyLogPath, renderStatusBadge])

	const providerCredentialEditor = (
		<VStack align="stretch" spacing={3}>
			{providerForm.credentials.map((row) => (
				<HStack key={row.id} align="flex-start">
					<Input
						placeholder={texts.key}
						value={row.key}
						onChange={(event) =>
							updateCredentialRows((rows) =>
								rows.map((item) =>
									item.id === row.id ? { ...item, key: event.target.value } : item,
								),
							)
						}
					/>
					<Input
						placeholder={row.hasExisting && !row.value ? texts.secretStored : texts.credentialPlaceholder}
						value={row.value}
						onChange={(event) =>
							updateCredentialRows((rows) =>
								rows.map((item) =>
									item.id === row.id ? { ...item, value: event.target.value } : item,
								),
							)
						}
					/>
					{row.hasExisting && !row.value && (
						<Tooltip label={texts.secretStored}>
							<Badge colorScheme="purple">{texts.secretStored}</Badge>
						</Tooltip>
					)}
					<IconButton
						aria-label="remove-credential"
						icon={<FiTrash2 />}
						size="sm"
						onClick={() =>
							updateCredentialRows((rows) => rows.filter((item) => item.id !== row.id))
						}
					/>
				</HStack>
			))}
			<Button
				leftIcon={<FiPlus />}
				size="sm"
				variant="ghost"
				onClick={() => updateCredentialRows((rows) => [...rows, createRow()])}
			>
				{texts.addRow}
			</Button>
		</VStack>
	)

	const providerOptionsEditor = (
		<VStack align="stretch" spacing={3}>
			{providerForm.options.map((row) => (
				<HStack key={row.id} align="flex-start">
					<Input
						placeholder={texts.key}
						value={row.key}
						onChange={(event) =>
							updateOptionRows((rows) =>
								rows.map((item) =>
									item.id === row.id ? { ...item, key: event.target.value } : item,
								),
							)
						}
					/>
					<Input
						placeholder={texts.optionPlaceholder}
						value={row.value}
						onChange={(event) =>
							updateOptionRows((rows) =>
								rows.map((item) =>
									item.id === row.id ? { ...item, value: event.target.value } : item,
								),
							)
						}
					/>
					<IconButton
						aria-label="remove-option"
						icon={<FiTrash2 />}
						size="sm"
						onClick={() =>
							updateOptionRows((rows) => rows.filter((item) => item.id !== row.id))
						}
					/>
				</HStack>
			))}
			<Button
				leftIcon={<FiPlus />}
				size="sm"
				variant="ghost"
				onClick={() => updateOptionRows((rows) => [...rows, createRow()])}
			>
				{texts.addRow}
			</Button>
		</VStack>
	)

	return (
		<Box>
			<Stack spacing={4} mb={6}>
				<Stack direction={{ base: 'column', md: 'row' }} justify="space-between" align={{ md: 'center' }} spacing={4}>
					<Box>
						<Heading size="lg">{texts.title}</Heading>
						<Text color="gray.600" mt={2} maxW="3xl">
							{texts.description}
						</Text>
					</Box>
					<HStack spacing={3}>
						<Button leftIcon={<FiRefreshCw />} variant="outline" onClick={refreshProviders}>
							{texts.refresh}
						</Button>
						<Button leftIcon={<FiPlus />} colorScheme="brand" onClick={handleAddProvider}>
							{texts.addProvider}
						</Button>
					</HStack>
				</Stack>
			</Stack>

			{loading ? (
				<Box textAlign="center" py={20}>
					<Spinner size="xl" />
				</Box>
			) : (
				providerCards
			)}

			<Modal isOpen={providerModalOpen} onClose={() => setProviderModalOpen(false)} size="xl">
				<ModalOverlay />
				<ModalContent>
					<ModalHeader>{editingProvider ? texts.editProvider : texts.addProvider}</ModalHeader>
					<ModalCloseButton isDisabled={saving} />
					<ModalBody>
						<VStack spacing={4} align="stretch">
							<FormControl isRequired>
								<FormLabel>{texts.providerName}</FormLabel>
								<Input
									value={providerForm.name}
									onChange={(event) => setProviderForm((prev) => ({ ...prev, name: event.target.value }))}
								/>
							</FormControl>
							<FormControl>
								<FormLabel>{texts.providerType}</FormLabel>
								<Select
									value={providerForm.type}
									onChange={(event) => setProviderForm((prev) => ({ ...prev, type: event.target.value }))}
								>
									{supportedProviders.map((type) => (
										<option key={type} value={type}>
											{providerLabels[type] ?? type}
										</option>
									))}
								</Select>
							</FormControl>
							<FormControl>
								<FormLabel>{texts.descriptionLabel}</FormLabel>
								<Textarea
									value={providerForm.description}
									onChange={(event) => setProviderForm((prev) => ({ ...prev, description: event.target.value }))}
								/>
							</FormControl>
							<HStack spacing={6}>
								<FormControl display="flex" alignItems="center">
									<FormLabel mb="0">{texts.enabled}</FormLabel>
									<Switch
										isChecked={providerForm.enabled}
										onChange={(event) => setProviderForm((prev) => ({ ...prev, enabled: event.target.checked }))}
									/>
								</FormControl>
								<FormControl display="flex" alignItems="center">
									<FormLabel mb="0">{texts.autoStart}</FormLabel>
									<Switch
										isChecked={providerForm.autoStart}
										onChange={(event) => setProviderForm((prev) => ({ ...prev, autoStart: event.target.checked }))}
									/>
								</FormControl>
							</HStack>
							<FormControl>
								<FormLabel>{texts.credentials}</FormLabel>
								{providerCredentialEditor}
							</FormControl>
							<FormControl>
								<FormLabel>{texts.options}</FormLabel>
								{providerOptionsEditor}
							</FormControl>
						</VStack>
					</ModalBody>
					<ModalFooter>
						<Button mr={3} onClick={() => setProviderModalOpen(false)} isDisabled={saving}>
							{texts.cancel}
						</Button>
						<Button colorScheme="brand" isLoading={saving} onClick={handleSaveProvider}>
							{texts.save}
						</Button>
					</ModalFooter>
				</ModalContent>
			</Modal>

			<Modal isOpen={tunnelModalOpen} onClose={() => setTunnelModalOpen(false)} size="lg">
				<ModalOverlay />
				<ModalContent>
					<ModalHeader>{tunnelForm.id ? texts.editTunnel : texts.addTunnel}</ModalHeader>
					<ModalCloseButton isDisabled={saving} />
					<ModalBody>
						<VStack spacing={4} align="stretch">
							<FormControl isRequired>
								<FormLabel>{texts.providerName}</FormLabel>
								<Input
									value={tunnelForm.name}
									onChange={(event) => setTunnelForm((prev) => ({ ...prev, name: event.target.value }))}
								/>
							</FormControl>
							<FormControl>
								<FormLabel>{texts.protocol}</FormLabel>
								<Select
									value={tunnelForm.protocol}
									onChange={(event) => setTunnelForm((prev) => ({ ...prev, protocol: event.target.value }))}
								>
									{supportedProtocols.map((protocol) => (
										<option key={protocol} value={protocol}>
											{protocol.toUpperCase()}
										</option>
									))}
								</Select>
							</FormControl>
							<FormControl>
								<FormLabel>{texts.localAddress}</FormLabel>
								<Input
									value={tunnelForm.localAddress}
									onChange={(event) => setTunnelForm((prev) => ({ ...prev, localAddress: event.target.value }))}
								/>
							</FormControl>
							<FormControl>
								<FormLabel>{texts.localPort}</FormLabel>
								<NumberInput
									min={1}
									max={65535}
									value={tunnelForm.localPort}
									onChange={(_, value) =>
										setTunnelForm((prev) => ({ ...prev, localPort: Number.isNaN(value) ? prev.localPort : value }))
									}
								>
									<NumberInputField />
								</NumberInput>
							</FormControl>
							<FormControl>
								<FormLabel>{texts.publicHostname}</FormLabel>
								<Input
									value={tunnelForm.publicHostname}
									onChange={(event) => setTunnelForm((prev) => ({ ...prev, publicHostname: event.target.value }))}
								/>
							</FormControl>
							<FormControl>
								<FormLabel>{texts.publicPort}</FormLabel>
								<NumberInput
									min={0}
									max={65535}
									value={tunnelForm.publicPort ?? undefined}
									onChange={(valueString, valueNumber) => {
										if (valueString === '') {
											setTunnelForm((prev) => ({ ...prev, publicPort: undefined }))
										} else {
											setTunnelForm((prev) => ({ ...prev, publicPort: Number.isNaN(valueNumber) ? prev.publicPort : valueNumber }))
										}
									}}
								>
									<NumberInputField />
								</NumberInput>
							</FormControl>
							<FormControl>
								<FormLabel>{texts.edgeRegion}</FormLabel>
								<Input
									value={tunnelForm.edgeRegion}
									onChange={(event) => setTunnelForm((prev) => ({ ...prev, edgeRegion: event.target.value }))}
								/>
							</FormControl>
							<FormControl>
								<FormLabel>{texts.notes}</FormLabel>
								<Textarea
									value={tunnelForm.notes}
									onChange={(event) => setTunnelForm((prev) => ({ ...prev, notes: event.target.value }))}
								/>
							</FormControl>
							<FormControl display="flex" alignItems="center">
								<FormLabel mb="0">{texts.autoStart}</FormLabel>
								<Switch
									isChecked={tunnelForm.autoStart}
									onChange={(event) => setTunnelForm((prev) => ({ ...prev, autoStart: event.target.checked }))}
								/>
							</FormControl>
						</VStack>
					</ModalBody>
					<ModalFooter>
						<Button mr={3} onClick={() => setTunnelModalOpen(false)} isDisabled={saving}>
							{texts.cancel}
						</Button>
						<Button colorScheme="brand" isLoading={saving} onClick={handleSaveTunnel}>
							{texts.save}
						</Button>
					</ModalFooter>
				</ModalContent>
			</Modal>
		</Box>
	)
}

export default Tunnels


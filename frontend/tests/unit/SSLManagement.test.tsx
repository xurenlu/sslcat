import { ChakraProvider } from '@chakra-ui/react'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import SSLManagement from '../../src/pages/SSLManagement'
import theme from '../../src/theme'

vi.mock('../../src/contexts/ConfigContext', () => ({
  useConfig: () => ({
    adminPrefix: '/admin',
    isLoading: false,
    error: null,
    refreshConfig: vi.fn(),
    updatePrefix: vi.fn(),
    changeAdminPrefix: vi.fn(),
  }),
  buildApiPath: (prefix: string, path: string) =>
    `${prefix}${path.startsWith('/api') ? path : `/api${path}`}`,
}))

vi.mock('../../src/hooks/useLanguage', () => ({
  useTranslation: () => ({
    ssl: {
      title: 'SSL 证书管理',
      refresh: '刷新',
      applyCertificate: '申请证书',
      uploadCertificate: '上传证书',
      downloadAllCertificates: '下载全部证书',
      syncACMECertificates: '同步 ACME 证书',
      domain: '域名',
      issuer: '颁发机构',
      status: '状态',
      expiresAt: '过期时间',
      autoRenew: '自动续期',
      createdAt: '创建时间',
      actions: '操作',
      wildcard: '通配符',
      updateCertificate: '更新证书',
      downloadCertificate: '下载证书',
      deleteCertificate: '删除证书',
      noCertificates: '暂无证书',
      createFirst: '创建第一个证书',
      cancel: '取消',
      applying: '申请中',
      domainPlaceholder: 'example.com',
      wildcardSupport: '支持通配符',
      valid: '有效',
      expiringSoon: '即将过期',
      expired: '已过期',
      daysUntilExpiry: '天后过期',
      expiredDays: '天前过期',
    },
  }),
}))

const renderPage = () =>
  render(
    <ChakraProvider theme={theme}>
      <SSLManagement />
    </ChakraProvider>
  )

describe('SSLManagement 删除证书', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('删除时应调用后端删除 API', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => [
          {
            domain: 'example.com',
            issued_at: '2026-01-01T00:00:00Z',
            expires_at: '2026-12-31T00:00:00Z',
            status: '有效',
            is_wildcard: false,
            self_signed: false,
            issuer: 'Let\'s Encrypt',
          },
        ],
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => [],
      })

    vi.stubGlobal('fetch', fetchMock)
    vi.spyOn(window, 'confirm').mockReturnValue(true)

    const user = userEvent.setup()
    renderPage()

    await screen.findByText('example.com')

    await user.click(screen.getByLabelText('删除证书'))

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/admin/api/ssl/delete?domain=example.com',
        expect.objectContaining({
          method: 'DELETE',
          credentials: 'include',
        })
      )
    })
  })
})

import { ChakraProvider } from '@chakra-ui/react'
import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import SitesManagement from '../../src/pages/SitesManagement'
import theme from '../../src/theme'

const toastMessages = {
  siteDataLoadPartialFailed: vi.fn(),
  siteDataLoadFailed: vi.fn(),
  siteDeleteSuccess: vi.fn(),
  siteDeleteFailed: vi.fn(),
}

vi.mock('../../src/contexts/ConfigContext', () => ({
  useConfig: () => ({
    adminPrefix: '/admin',
    version: '2.3.0-rc3',
    isLoading: false,
    error: null,
    refreshConfig: vi.fn(),
    updatePrefix: vi.fn(),
    changeAdminPrefix: vi.fn(),
  }),
  buildPath: (prefix: string, path: string) => `${prefix}${path}`,
  buildApiPath: (prefix: string, path: string) =>
    `${prefix}${path.startsWith('/api') ? path : `/api${path}`}`,
}))

vi.mock('../../src/hooks/useLanguage', () => ({
  useTranslation: () => ({
    common: {
      enable: '启用',
      disable: '禁用',
    },
    sites: {
      title: '站点管理',
      staticSites: '静态站点',
      phpSites: 'PHP 站点',
      refresh: '刷新',
      updateSite: '更新站点',
      createSite: '创建站点',
      edit: '编辑',
      delete: '删除',
      staticSiteList: '静态站点列表',
      addStaticSite: '+ 添加静态站点',
      addFirstStaticSite: '+ 添加第一个静态站点',
      noStaticSites: '暂无静态站点',
      noPHPSites: '暂无 PHP 站点',
      addFirstPHPSite: '+ 添加第一个 PHP 站点',
      domain: '域名',
      rootDirectory: '根目录',
      status: '状态',
      indexFile: '入口文件',
      pathPrefixRules: '路径前缀规则',
      actions: '操作',
      rules: '个规则',
      phpVersion: 'PHP 版本',
      connectionAddress: '连接地址',
      memoryLimit: '内存限制',
      executionTime: '执行时间',
      defaultPhpVersion: '默认版本',
      defaultMemoryLimit: '默认限制',
      defaultExecutionTime: '默认',
    },
  }),
}))

vi.mock('../../src/hooks/useToastMessages', () => ({
  useToastMessages: () => toastMessages,
}))

const renderPage = () =>
  render(
    <MemoryRouter>
      <ChakraProvider theme={theme}>
        <SitesManagement />
      </ChakraProvider>
    </MemoryRouter>
  )

describe('SitesManagement 删除站点', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    Object.values(toastMessages).forEach((mock) => mock.mockClear())
  })

  it('删除静态站点时应调用后端删除 API 并刷新列表', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          sites: [
            {
              domain: 'row1.17push.com',
              root: '/srv/row1',
              index: 'index.html',
              enabled: true,
              path_prefix_rules: [],
            },
          ],
        }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sites: [] }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ success: true }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sites: [] }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ sites: [] }),
      })

    vi.stubGlobal('fetch', fetchMock)

    const user = userEvent.setup()
    renderPage()

    await screen.findByText('row1.17push.com')
    await act(async () => {
      await user.click(screen.getByLabelText('删除'))
    })

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        '/admin/api/static-sites/delete?domain=row1.17push.com',
        expect.objectContaining({
          method: 'DELETE',
          credentials: 'include',
        })
      )
    })

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledTimes(5)
    })
    await waitFor(() => {
      expect(screen.queryByText('row1.17push.com')).not.toBeInTheDocument()
    })
    await waitFor(() => {
      expect(toastMessages.siteDeleteSuccess).toHaveBeenCalledTimes(1)
    })
  })
})

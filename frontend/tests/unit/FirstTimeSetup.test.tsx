import { render, screen, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ChakraProvider } from '@chakra-ui/react'
import FirstTimeSetup from '../../src/pages/FirstTimeSetup'
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
    setup: {
      password_placeholder: '请输入密码',
      confirm_password_placeholder: '请确认密码',
      loading: '提交中...',
    },
  }),
}))

const renderComponent = () =>
  render(
    <ChakraProvider theme={theme}>
      <FirstTimeSetup />
    </ChakraProvider>
  )

describe('FirstTimeSetup', () => {
  afterEach(() => {
    vi.clearAllMocks()
  })

  it('保持提交按钮禁用直到必填项通过校验', async () => {
    const user = userEvent.setup()
    await act(async () => {
      renderComponent()
    })

    const submitButton = screen.getByRole('button', { name: '完成设置' })
    expect(submitButton).toBeDisabled()

    const passwordInput = screen.getByPlaceholderText('请输入密码')
    await user.type(passwordInput, 'Short1!')
    await user.tab()

    const confirmInput = screen.getByPlaceholderText('请确认密码')
    await user.type(confirmInput, 'Short1!')
    await user.tab()

    const emailInput = screen.getByPlaceholderText('admin@example.com')
    await user.type(emailInput, 'adminexample.com')
    await user.tab()

    expect(submitButton).toBeDisabled()
    expect(await screen.findByText('邮箱格式不正确')).toBeInTheDocument()
  })

  it('在表单有效时允许提交', async () => {
    const user = userEvent.setup()
    await act(async () => {
      renderComponent()
    })

    const passwordInput = screen.getByPlaceholderText('请输入密码')
    const confirmInput = screen.getByPlaceholderText('请确认密码')
    const emailInput = screen.getByPlaceholderText('admin@example.com')

    await user.type(passwordInput, 'StrongPassw0rd!')
    await user.tab()
    await user.type(confirmInput, 'StrongPassw0rd!')
    await user.tab()
    await user.type(emailInput, 'admin@example.com')
    await user.tab()

    const submitButton = screen.getByRole('button', { name: '完成设置' })
    expect(submitButton).not.toBeDisabled()
  })

  it('域名与目标地址不成对时提示错误', async () => {
    const user = userEvent.setup()
    await act(async () => {
      renderComponent()
    })

    await user.type(screen.getByPlaceholderText('请输入密码'), 'ValidPassw0rd!')
    await user.tab()
    await user.type(screen.getByPlaceholderText('请确认密码'), 'ValidPassw0rd!')
    await user.tab()
    await user.type(screen.getByPlaceholderText('admin@example.com'), 'admin@example.com')
    await user.tab()

    await user.type(screen.getByLabelText('域名'), 'example.com')
    await user.tab()

    expect(
      await screen.findByText('域名和目标地址需要同时填写或都留空')
    ).toBeInTheDocument()
  })
})


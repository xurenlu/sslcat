import { ChakraProvider } from '@chakra-ui/react'
import { render, screen } from '@testing-library/react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import AuthGuard from '../../src/components/AuthGuard'

const auth = vi.hoisted(() => ({ isAuthenticated: false, isLoading: false }))

vi.mock('../../src/contexts/AuthContext', () => ({ useAuth: () => auth }))
vi.mock('../../src/contexts/ConfigContext', () => ({
  useConfig: () => ({ adminPrefix: '/custom-admin' }),
}))
vi.mock('../../src/hooks/useLanguage', () => ({
  useTranslation: () => ({ common: { redirectingToLogin: 'redirecting' } }),
}))

const renderProtectedRoute = () => render(
  <ChakraProvider>
    <BrowserRouter>
      <Routes>
        <Route path="/custom-admin/sites" element={
          <AuthGuard><div data-testid="protected" /></AuthGuard>
        } />
        <Route path="/custom-admin/login" element={<div data-testid="login" />} />
      </Routes>
    </BrowserRouter>
  </ChakraProvider>
)

describe('AuthGuard 路由兼容性', () => {
  beforeEach(() => {
    auth.isAuthenticated = false
    auth.isLoading = false
    window.history.replaceState(null, '', '/custom-admin/sites')
  })

  afterEach(() => {
    window.history.replaceState(null, '', '/')
  })

  it('未登录时通过 BrowserRouter 跳转到当前管理前缀的登录页', async () => {
    renderProtectedRoute()
    expect(await screen.findByTestId('login')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/custom-admin/login')
    expect(screen.queryByTestId('protected')).not.toBeInTheDocument()
  })

  it('已登录时保留当前路由并显示受保护内容', () => {
    auth.isAuthenticated = true
    renderProtectedRoute()
    expect(screen.getByTestId('protected')).toBeInTheDocument()
    expect(window.location.pathname).toBe('/custom-admin/sites')
  })

  it('认证状态加载期间不触发登录跳转', () => {
    auth.isLoading = true
    renderProtectedRoute()
    expect(window.location.pathname).toBe('/custom-admin/sites')
    expect(screen.queryByTestId('protected')).not.toBeInTheDocument()
    expect(screen.queryByTestId('login')).not.toBeInTheDocument()
  })
})

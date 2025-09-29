import { Routes, Route } from 'react-router-dom'
import { Box, Spinner, Center, Text } from '@chakra-ui/react'
import { LanguageProvider } from './hooks/useLanguage'
import { ConfigProvider, useConfig } from './contexts/ConfigContext'
import { AuthProvider } from './contexts/AuthContext'
import Layout from './components/Layout'
import AuthGuard from './components/AuthGuard'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import ProxyList from './pages/ProxyList'
import ProxyAdd from './pages/ProxyAdd'
import ProxyEdit from './pages/ProxyEdit'
import SSLManagement from './pages/SSLManagement'
import Settings from './pages/Settings'
import Notifications from './pages/Notifications'
import Security from './pages/Security'
import SitesManagement from './pages/SitesManagement'
import DNSManagement from './pages/DNSManagement'
import GitServerManagement from './pages/GitServerManagement'
import UserManagement from './pages/UserManagement'
import ChangePassword from './pages/ChangePassword'
import CDNManagement from './pages/CDNManagement'
import Statistics from './pages/Statistics'

const AppRoutes: React.FC = () => {
  const { adminPrefix, isLoading, error } = useConfig()

  if (isLoading) {
    return (
      <Center h="100vh">
        <Spinner size="xl" />
      </Center>
    )
  }

  if (error) {
    return (
      <Center h="100vh">
        <Text color="red.500">配置加载失败: {error}</Text>
      </Center>
    )
  }

  return (
    <Routes>
      {/* 登录页面不需要认证 */}
      <Route path={`${adminPrefix}/login`} element={<Login />} />
      
      {/* 所有其他页面都需要认证 */}
      <Route path={`${adminPrefix}/`} element={
        <AuthGuard>
          <Dashboard />
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/dashboard`} element={
        <AuthGuard>
          <Dashboard />
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/proxy`} element={
        <AuthGuard>
          <ProxyList />
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/proxy/add`} element={
        <AuthGuard>
          <ProxyAdd />
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/proxy/edit`} element={
        <AuthGuard>
          <ProxyEdit />
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/sites`} element={
        <AuthGuard>
          <SitesManagement />
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/ssl`} element={
        <AuthGuard>
          <SSLManagement />
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/settings`} element={
        <AuthGuard>
          <Settings />
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/dns`} element={
        <AuthGuard>
          <DNSManagement />
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/security`} element={
        <AuthGuard>
          <Security />
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/git-server`} element={
        <AuthGuard>
          <GitServerManagement />
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/notifications`} element={
        <AuthGuard>
          <Notifications />
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/users`} element={
        <AuthGuard>
          <UserManagement />
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/change-password`} element={
        <AuthGuard>
          <ChangePassword />
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/cdn`} element={
        <AuthGuard>
          <CDNManagement />
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/statistics`} element={
        <AuthGuard>
          <Statistics />
        </AuthGuard>
      } />
    </Routes>
  )
}

function App() {
  return (
    <LanguageProvider>
      <ConfigProvider>
        <AuthProvider>
          <Box minH="100vh">
            <Layout>
              <AppRoutes />
            </Layout>
          </Box>
        </AuthProvider>
      </ConfigProvider>
    </LanguageProvider>
  )
}

export default App

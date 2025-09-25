import { Routes, Route } from 'react-router-dom'
import { Box, Spinner, Center, Text } from '@chakra-ui/react'
import { LanguageProvider } from './hooks/useLanguage'
import { ConfigProvider, useConfig } from './contexts/ConfigContext'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import ProxyList from './pages/ProxyList'
import ProxyAdd from './pages/ProxyAdd'
import SSLManagement from './pages/SSLManagement'
import Settings from './pages/Settings'
import Notifications from './pages/Notifications'
import Security from './pages/Security'
import SitesManagement from './pages/SitesManagement'
import DNSManagement from './pages/DNSManagement'
import ClusterManagement from './pages/ClusterManagement'
import RunnersManagement from './pages/RunnersManagement'
import GitServerManagement from './pages/GitServerManagement'

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
      <Route path={`${adminPrefix}/`} element={<Dashboard />} />
      <Route path={`${adminPrefix}/dashboard`} element={<Dashboard />} />
      <Route path={`${adminPrefix}/proxy`} element={<ProxyList />} />
      <Route path={`${adminPrefix}/proxy/add`} element={<ProxyAdd />} />
      <Route path={`${adminPrefix}/sites`} element={<SitesManagement />} />
      <Route path={`${adminPrefix}/ssl`} element={<SSLManagement />} />
      <Route path={`${adminPrefix}/settings`} element={<Settings />} />
      <Route path={`${adminPrefix}/dns`} element={<DNSManagement />} />
      <Route path={`${adminPrefix}/security`} element={<Security />} />
      <Route path={`${adminPrefix}/cluster`} element={<ClusterManagement />} />
      <Route path={`${adminPrefix}/runners`} element={<RunnersManagement />} />
      <Route path={`${adminPrefix}/git-server`} element={<GitServerManagement />} />
      <Route path={`${adminPrefix}/notifications`} element={<Notifications />} />
    </Routes>
  )
}

function App() {
  return (
    <LanguageProvider>
      <ConfigProvider>
        <Box minH="100vh">
          <Layout>
            <AppRoutes />
          </Layout>
        </Box>
      </ConfigProvider>
    </LanguageProvider>
  )
}

export default App

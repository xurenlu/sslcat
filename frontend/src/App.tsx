import { Routes, Route, Navigate } from 'react-router-dom'
import { Box, Spinner, Center, Text, Button, VStack, Heading } from '@chakra-ui/react'
import * as Sentry from '@sentry/react'
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
import ProxyDomainDetail from './pages/ProxyDomainDetail'
import SSLManagement from './pages/SSLManagement'
import Settings from './pages/Settings'
import Notifications from './pages/Notifications'
import Security from './pages/Security'
import SitesManagement from './pages/SitesManagement'
import StaticSiteEdit from './pages/StaticSiteEdit'
import PHPSiteEdit from './pages/PHPSiteEdit'
import DNSManagement from './pages/DNSManagement'
import GitServerManagement from './pages/GitServerManagement'
import UserManagement from './pages/UserManagement'
import ChangePassword from './pages/ChangePassword'
import CDNManagement from './pages/CDNManagement'
import Statistics from './pages/Statistics'
import SlowRequests from './pages/SlowRequests'
import AISecurityAnalysis from './pages/AISecurityAnalysis'
import ImageOptimization from './pages/ImageOptimization'
import FirstTimeSetup from './pages/FirstTimeSetup'
import ClusterSettings from './pages/ClusterSettings'
import Monitoring from './pages/Monitoring'
import ClusterStatus from './pages/ClusterStatus'
import TemplateMarket from './pages/TemplateMarket'
import TemplateDeploy from './pages/TemplateDeploy'
import BlockManagement from './pages/BlockManagement'
import ConfigHistory from './pages/ConfigHistory'

// 辅助组件：为需要 Layout 的页面添加 Layout
const LayoutRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <Layout>{children}</Layout>
)

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
      {/* 根路径重定向到 admin prefix */}
      <Route path="/" element={<Navigate to={`${adminPrefix}/dashboard`} replace />} />
      
      {/* 登录和首次设置页面不需要认证 */}
      <Route path={`${adminPrefix}/login`} element={<Login />} />
      {/* 首次设置页面：后端已检查认证，前端直接渲染 */}
      <Route path={`${adminPrefix}/settings/first-setup`} element={<FirstTimeSetup />} />
      
      {/* 所有其他页面都需要认证和 Layout */}
      <Route path={`${adminPrefix}/`} element={
        <AuthGuard>
          <LayoutRoute>
            <Dashboard />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/dashboard`} element={
        <AuthGuard>
          <LayoutRoute>
            <Dashboard />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/proxy`} element={
        <AuthGuard>
          <LayoutRoute>
            <ProxyList />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/proxy/add`} element={
        <AuthGuard>
          <LayoutRoute>
            <ProxyAdd />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/proxy/edit`} element={
        <AuthGuard>
          <LayoutRoute>
            <ProxyEdit />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/proxy/view`} element={
        <AuthGuard>
          <LayoutRoute>
            <ProxyDomainDetail />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/sites`} element={
        <AuthGuard>
          <LayoutRoute>
            <SitesManagement />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/static-site-edit`} element={
        <AuthGuard>
          <LayoutRoute>
            <StaticSiteEdit />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/static-site-add`} element={
        <AuthGuard>
          <LayoutRoute>
            <StaticSiteEdit />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/php-site-edit`} element={
        <AuthGuard>
          <LayoutRoute>
            <PHPSiteEdit />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/php-site-add`} element={
        <AuthGuard>
          <LayoutRoute>
            <PHPSiteEdit />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/ssl`} element={
        <AuthGuard>
          <LayoutRoute>
            <SSLManagement />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/settings`} element={
        <AuthGuard>
          <LayoutRoute>
            <Settings />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/dns`} element={
        <AuthGuard>
          <LayoutRoute>
            <DNSManagement />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/security`} element={
        <AuthGuard>
          <LayoutRoute>
            <Security />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/block-management`} element={
        <AuthGuard>
          <LayoutRoute>
            <BlockManagement />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/git-server`} element={
        <AuthGuard>
          <LayoutRoute>
            <GitServerManagement />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/templates`} element={
        <AuthGuard>
          <LayoutRoute>
            <TemplateMarket />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/templates/deploy/:templateId`} element={
        <AuthGuard>
          <LayoutRoute>
            <TemplateDeploy />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/notifications`} element={
        <AuthGuard>
          <LayoutRoute>
            <Notifications />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/users`} element={
        <AuthGuard>
          <LayoutRoute>
            <UserManagement />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/change-password`} element={
        <AuthGuard>
          <LayoutRoute>
            <ChangePassword />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/cdn`} element={
        <AuthGuard>
          <LayoutRoute>
            <CDNManagement />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/statistics`} element={
        <AuthGuard>
          <LayoutRoute>
            <Statistics />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/monitoring`} element={
        <AuthGuard>
          <LayoutRoute>
            <Monitoring />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/slow-requests`} element={
        <AuthGuard>
          <LayoutRoute>
            <SlowRequests />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/cluster`} element={
        <AuthGuard>
          <LayoutRoute>
            <ClusterSettings />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/cluster/status`} element={
        <AuthGuard>
          <LayoutRoute>
            <ClusterStatus />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/ai-security`} element={
        <AuthGuard>
          <LayoutRoute>
            <AISecurityAnalysis />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/image-optimization`} element={
        <AuthGuard>
          <LayoutRoute>
            <ImageOptimization />
          </LayoutRoute>
        </AuthGuard>
      } />
      <Route path={`${adminPrefix}/config-history`} element={
        <AuthGuard>
          <LayoutRoute>
            <ConfigHistory />
          </LayoutRoute>
        </AuthGuard>
      } />
    </Routes>
  )
}

// 错误回退组件
const ErrorFallback = ({ error, resetError }: { error: unknown; resetError: () => void }) => {
  const errorMessage = error instanceof Error ? error.message : String(error)
  return (
    <Center h="100vh" bg="gray.50">
      <VStack spacing={6} maxW="600px" p={8} textAlign="center">
        <Box fontSize="6xl">😅</Box>
        <Heading size="lg" color="gray.700">
          抱歉，页面出错了
        </Heading>
        <Text color="gray.600">
          我们已经收到错误报告，开发团队会尽快处理。
        </Text>
        <Box 
          p={4} 
          bg="red.50" 
          borderRadius="md" 
          w="100%" 
          fontSize="sm" 
          fontFamily="mono"
          textAlign="left"
          color="red.700"
        >
          <Text fontWeight="bold" mb={2}>错误信息：</Text>
          <Text>{errorMessage}</Text>
        </Box>
        <VStack spacing={3} w="100%">
          <Button 
            colorScheme="blue" 
            size="lg"
            onClick={resetError}
            w="100%"
          >
            重试
          </Button>
          <Button 
            variant="outline"
            size="lg"
            onClick={() => window.location.href = '/'}
            w="100%"
          >
            返回首页
          </Button>
        </VStack>
      </VStack>
    </Center>
  )
}

function App() {
  return (
    <Sentry.ErrorBoundary 
      fallback={ErrorFallback}
      showDialog={false}
    >
      <LanguageProvider>
        <ConfigProvider>
          <AuthProvider>
            <AppRoutes />
          </AuthProvider>
        </ConfigProvider>
      </LanguageProvider>
    </Sentry.ErrorBoundary>
  )
}

export default App

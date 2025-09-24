import React from 'react'
import { Routes, Route } from 'react-router-dom'
import { Box } from '@chakra-ui/react'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import ProxyList from './pages/ProxyList'
import SSLManagement from './pages/SSLManagement'
import Settings from './pages/Settings'
import Notifications from './pages/Notifications'
import Security from './pages/Security'
import SitesManagement from './pages/SitesManagement'
import DNSManagement from './pages/DNSManagement'
import ClusterManagement from './pages/ClusterManagement'
import RunnersManagement from './pages/RunnersManagement'
import GitServerManagement from './pages/GitServerManagement'

function App() {
  return (
    <Box minH="100vh">
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/proxy" element={<ProxyList />} />
          <Route path="/sites" element={<SitesManagement />} />
          <Route path="/ssl" element={<SSLManagement />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/dns" element={<DNSManagement />} />
          <Route path="/security" element={<Security />} />
          <Route path="/cluster" element={<ClusterManagement />} />
          <Route path="/runners" element={<RunnersManagement />} />
          <Route path="/git-server" element={<GitServerManagement />} />
          <Route path="/notifications" element={<Notifications />} />
        </Routes>
      </Layout>
    </Box>
  )
}

export default App

import React from 'react'
import {
  Box,
  Drawer,
  DrawerContent,
  DrawerOverlay,
  VStack,
  HStack,
  Text,
  Icon,
  Link,
  Divider,
  Button,
  Image,
  useBreakpointValue,
} from '@chakra-ui/react'
import { Link as RouterLink, useLocation } from 'react-router-dom'
import { useTranslation } from '../hooks/useLanguage'
import { useConfig, buildPath } from '../contexts/ConfigContext'
import logoImage from '../logo.png'
import {
  FiHome,
  FiSettings,
  FiShield,
  FiGlobe,
  FiZap,
  FiBell,
  FiTerminal,
  FiGitBranch,
  FiUsers,
  FiLogOut,
  FiHardDrive,
  FiKey,
  FiBarChart2,
} from 'react-icons/fi'
import { FaRobot } from 'react-icons/fa'

interface SidebarProps {
  isOpen: boolean
  onClose: () => void
  width?: string
}

interface NavItemProps {
  icon: any
  children: string
  to: string
  isActive?: boolean
  badge?: string
}

const NavItem: React.FC<NavItemProps> = ({ icon, children, to, isActive, badge }) => {
  return (
    <Link
      as={RouterLink}
      to={to}
      style={{ textDecoration: 'none' }}
      _focus={{ boxShadow: 'none' }}
    >
      <HStack
        px={4}
        py={3}
        borderRadius="md"
        bg={isActive ? 'brand.500' : 'transparent'}
        color={isActive ? 'white' : 'gray.700'}
        _hover={{
          bg: isActive ? 'brand.600' : 'gray.100',
          color: isActive ? 'white' : 'gray.900',
        }}
        transition="all 0.2s"
        justify="space-between"
      >
        <HStack>
          <Icon as={icon} boxSize={5} />
          <Text fontSize="sm" fontWeight="medium">
            {children}
          </Text>
        </HStack>
        {badge && (
          <Box
            px={2}
            py={0.5}
            fontSize="xs"
            fontWeight="bold"
            borderRadius="md"
            bgGradient="linear(to-r, purple.400, purple.600)"
            color="white"
          >
            {badge}
          </Box>
        )}
      </HStack>
    </Link>
  )
}

const SidebarContent = () => {
  const location = useLocation()
  const t = useTranslation()
  const { adminPrefix } = useConfig()
  
  // 构建带有 adminPrefix 的 logo 路径
  const logoSrc = `${adminPrefix}${logoImage}`

  const menuItems = [
    { name: t.navigation.dashboard, icon: FiHome, path: buildPath(adminPrefix, '/dashboard') },
    { name: t.navigation.proxy, icon: FiZap, path: buildPath(adminPrefix, '/proxy') },
    { name: t.navigation.sites, icon: FiGlobe, path: buildPath(adminPrefix, '/sites') },
    { name: t.navigation.ssl, icon: FiShield, path: buildPath(adminPrefix, '/ssl') },
    { name: t.navigation.cdnCache, icon: FiHardDrive, path: buildPath(adminPrefix, '/cdn') },
    { name: '访问统计', icon: FiBarChart2, path: buildPath(adminPrefix, '/statistics') },
    { name: t.navigation.settings, icon: FiSettings, path: buildPath(adminPrefix, '/settings') },
    { name: t.navigation.dns, icon: FiGlobe, path: buildPath(adminPrefix, '/dns') },
    { name: t.navigation.security, icon: FiShield, path: buildPath(adminPrefix, '/security') },
    { name: t.navigation.gitServer, icon: FiGitBranch, path: buildPath(adminPrefix, '/git-server') },
    { name: t.navigation.notifications, icon: FiBell, path: buildPath(adminPrefix, '/notifications') },
    { name: t.navigation.aiSecurity || '🤖 AI 安全分析', icon: FaRobot, path: buildPath(adminPrefix, '/ai-security'), badge: 'AI' },
    { name: t.navigation.userManagement, icon: FiUsers, path: buildPath(adminPrefix, '/users') },
    { name: t.navigation.changePassword, icon: FiKey, path: buildPath(adminPrefix, '/change-password') },
  ]

  return (
    <Box h="full" bg="white" borderRight="1px" borderColor="gray.200" display="flex" flexDirection="column">
      {/* Logo - 固定顶部 */}
      <Box p={6} borderBottom="1px" borderColor="gray.200" flexShrink={0}>
        <VStack spacing={3}>
          {/* Logo 图片 */}
          <Box
            position="relative"
            transition="all 0.3s ease"
            _hover={{
              transform: 'scale(1.05)',
            }}
          >
            <Image
              src={logoSrc}
              alt="SSLcat Logo"
              boxSize="60px"
              objectFit="contain"
              filter="blur(2px)"
              transition="filter 0.3s ease"
              _hover={{
                filter: 'blur(0px)',
              }}
            />
          </Box>
          
          {/* 品牌名称 */}
          <Text fontSize="2xl" fontWeight="bold" color="brand.500">
            SSLcat
          </Text>
          <Text fontSize="sm" color="gray.500" textAlign="center">
            {t.sidebar.sslProxyServer}
          </Text>
          <Button
            as="a"
            href="https://sslcat.com"
            target="_blank"
            size="sm"
            variant="outline"
            colorScheme="brand"
          >
            {t.sidebar.officialWebsite}
          </Button>
        </VStack>
      </Box>


      {/* 可滚动的内容区域 */}
      <Box flex={1} overflowY="auto" p={4}>
        <VStack spacing={1} align="stretch">
          {menuItems.map((item) => (
            <NavItem
              key={item.path}
              icon={item.icon}
              to={item.path}
              isActive={location.pathname === item.path}
              badge={item.badge}
            >
              {item.name}
            </NavItem>
          ))}
        </VStack>
      </Box>

      {/* Logout - 固定底部 */}
      <Box p={4} borderTop="1px" borderColor="gray.200" flexShrink={0}>
        <Button
          variant="outline"
          colorScheme="red"
          size="sm"
          leftIcon={<Icon as={FiLogOut} />}
          w="full"
        >
          {t.navigation.logout}
        </Button>
      </Box>
    </Box>
  )
}

const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose, width }) => {
  const isDesktop = useBreakpointValue({ base: false, md: true })

  if (isDesktop) {
    return (
      <Box
        position="fixed"
        left={0}
        top={0}
        w={width}
        h="full"
        zIndex="sticky"
      >
        <SidebarContent />
      </Box>
    )
  }

  return (
    <Drawer isOpen={isOpen} placement="left" onClose={onClose}>
      <DrawerOverlay />
      <DrawerContent>
        <SidebarContent />
      </DrawerContent>
    </Drawer>
  )
}

export default Sidebar

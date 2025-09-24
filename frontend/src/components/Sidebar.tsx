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
  Collapse,
  useDisclosure,
  Button,
  useBreakpointValue,
} from '@chakra-ui/react'
import { Link as RouterLink, useLocation } from 'react-router-dom'
import {
  FiHome,
  FiSettings,
  FiShield,
  FiGlobe,
  FiZap,
  FiBell,
  FiChevronDown,
  FiChevronRight,
  FiTerminal,
  FiGitBranch,
  FiUsers,
  FiLogOut,
} from 'react-icons/fi'

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
}

const NavItem: React.FC<NavItemProps> = ({ icon, children, to, isActive }) => {
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
      >
        <Icon as={icon} boxSize={5} />
        <Text fontSize="sm" fontWeight="medium">
          {children}
        </Text>
      </HStack>
    </Link>
  )
}

const SidebarContent = () => {
  const location = useLocation()
  const { isOpen: isAdvancedOpen, onToggle: onAdvancedToggle } = useDisclosure()

  const mainMenuItems = [
    { name: '仪表板', icon: FiHome, path: '/dashboard' },
    { name: '代理配置', icon: FiZap, path: '/proxy' },
    { name: '站点管理', icon: FiGlobe, path: '/sites' },
    { name: 'SSL证书', icon: FiShield, path: '/ssl' },
    { name: '系统设置', icon: FiSettings, path: '/settings' },
  ]

  const advancedMenuItems = [
    { name: 'DNS配置', icon: FiGlobe, path: '/dns' },
    { name: '安全设置', icon: FiShield, path: '/security' },
    { name: '集群管理', icon: FiUsers, path: '/cluster' },
    { name: '运行器', icon: FiTerminal, path: '/runners' },
    { name: 'Git部署服务器', icon: FiGitBranch, path: '/git-server' },
    { name: '通知管理', icon: FiBell, path: '/notifications' },
  ]

  return (
    <Box h="full" bg="white" borderRight="1px" borderColor="gray.200">
      <VStack spacing={0} align="stretch" h="full">
        {/* Logo */}
        <Box p={6} borderBottom="1px" borderColor="gray.200">
          <VStack spacing={2}>
            <Text fontSize="2xl" fontWeight="bold" color="brand.500">
              SSLcat
            </Text>
            <Text fontSize="sm" color="gray.500" textAlign="center">
              SSL 代理服务器
            </Text>
            <Button
              as="a"
              href="https://sslcat.com"
              target="_blank"
              size="sm"
              variant="outline"
              colorScheme="brand"
            >
              官方网站
            </Button>
          </VStack>
        </Box>

        {/* Language Selector */}
        <Box p={4} borderBottom="1px" borderColor="gray.200">
          <Text fontSize="sm" color="gray.600" mb={2}>
            语言 Language
          </Text>
          {/* TODO: 实现语言选择器 */}
        </Box>

        {/* Main Navigation */}
        <Box p={4} flex={1}>
          <VStack spacing={1} align="stretch">
            {mainMenuItems.map((item) => (
              <NavItem
                key={item.path}
                icon={item.icon}
                to={item.path}
                isActive={location.pathname === item.path}
              >
                {item.name}
              </NavItem>
            ))}
          </VStack>

          <Divider my={4} />

          {/* Advanced Options */}
          <VStack spacing={1} align="stretch">
            <Button
              variant="outline"
              size="sm"
              onClick={onAdvancedToggle}
              leftIcon={<Icon as={isAdvancedOpen ? FiChevronDown : FiChevronRight} />}
              justifyContent="flex-start"
            >
              高级选项
            </Button>
            <Collapse in={isAdvancedOpen}>
              <VStack spacing={1} align="stretch" mt={2}>
                {advancedMenuItems.map((item) => (
                  <NavItem
                    key={item.path}
                    icon={item.icon}
                    to={item.path}
                    isActive={location.pathname === item.path}
                  >
                    {item.name}
                  </NavItem>
                ))}
              </VStack>
            </Collapse>
          </VStack>
        </Box>

        {/* Logout */}
        <Box p={4} borderTop="1px" borderColor="gray.200">
          <Button
            variant="outline"
            colorScheme="red"
            size="sm"
            leftIcon={<Icon as={FiLogOut} />}
            w="full"
          >
            退出登录
          </Button>
        </Box>
      </VStack>
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

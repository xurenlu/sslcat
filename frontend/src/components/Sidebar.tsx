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
  Select,
} from '@chakra-ui/react'
import { Link as RouterLink, useLocation } from 'react-router-dom'
import { useLanguage } from '../hooks/useLanguage'
import { useTranslation } from '../hooks/useLanguage'
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
  const { currentLanguage, changeLanguage, getCurrentLanguage, supportedLanguages } = useLanguage()
  const t = useTranslation()

  const mainMenuItems = [
    { name: t.navigation.dashboard, icon: FiHome, path: '/dashboard' },
    { name: t.navigation.proxy, icon: FiZap, path: '/proxy' },
    { name: t.navigation.sites, icon: FiGlobe, path: '/sites' },
    { name: t.navigation.ssl, icon: FiShield, path: '/ssl' },
    { name: t.navigation.settings, icon: FiSettings, path: '/settings' },
  ]

  const advancedMenuItems = [
    { name: t.navigation.dns, icon: FiGlobe, path: '/dns' },
    { name: t.navigation.security, icon: FiShield, path: '/security' },
    { name: t.navigation.cluster, icon: FiUsers, path: '/cluster' },
    { name: t.navigation.runners, icon: FiTerminal, path: '/runners' },
    { name: t.navigation.gitServer, icon: FiGitBranch, path: '/git-server' },
    { name: t.navigation.notifications, icon: FiBell, path: '/notifications' },
  ]

  return (
    <Box h="full" bg="white" borderRight="1px" borderColor="gray.200" display="flex" flexDirection="column">
      {/* Logo - 固定顶部 */}
      <Box p={6} borderBottom="1px" borderColor="gray.200" flexShrink={0}>
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

      {/* Language Selector - 固定 */}
      <Box p={4} borderBottom="1px" borderColor="gray.200" flexShrink={0}>
        <Text fontSize="sm" color="gray.600" mb={2}>
          语言 Language
        </Text>
        <Select
          size="sm"
          value={currentLanguage}
          onChange={(e) => changeLanguage(e.target.value)}
        >
          {supportedLanguages.map((language) => (
            <option key={language.code} value={language.code}>
              {language.flag} {language.nativeName}
            </option>
          ))}
        </Select>
      </Box>

      {/* 可滚动的内容区域 */}
      <Box flex={1} overflowY="auto" p={4}>
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
              {t.navigation.advanced}
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

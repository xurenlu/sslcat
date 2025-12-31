import React from 'react'
import {
  Box,
  Flex,
  IconButton,
  useBreakpointValue,
  Spacer,
  HStack,
  VStack,
  Text,
  Button,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  Avatar,
  Select,
  Tag,
  TagLabel,
  Icon,
} from '@chakra-ui/react'
import { FiMenu, FiUser, FiLogOut, FiLock, FiChevronDown } from 'react-icons/fi'
import { useAuth } from '../contexts/AuthContext'
import { useConfig, buildPath } from '../contexts/ConfigContext'
import { Link as RouterLink, useLocation } from 'react-router-dom'
import { useLanguage, supportedLanguages, useTranslation } from '../hooks/useLanguage'

interface HeaderProps {
  onMenuClick: () => void
}

const Header: React.FC<HeaderProps> = ({ onMenuClick }) => {
  const showMobileMenu = useBreakpointValue({ base: true, md: false })
  const { user, logout } = useAuth()
  const { adminPrefix } = useConfig()
  const { currentLanguage, changeLanguage } = useLanguage()
  const t = useTranslation()
  const location = useLocation()

  // 根据当前路径获取页面标题
  const getPageTitle = (): string => {
    const path = location.pathname
    // 移除 adminPrefix 前缀，获取相对路径
    let relativePath = path
    if (adminPrefix && path.startsWith(adminPrefix)) {
      relativePath = path.slice(adminPrefix.length)
    }
    // 标准化路径：移除尾部斜杠，如果为空则使用 /dashboard
    const normalizedPath = relativePath.endsWith('/') && relativePath.length > 1 
      ? relativePath.slice(0, -1) 
      : relativePath || '/dashboard'

    // 路径到标题的映射
    const pathToTitleMap: Record<string, () => string> = {
      '/': () => t.dashboard.title,
      '/dashboard': () => t.dashboard.title,
      '/proxy': () => t.proxy.title,
      '/proxy/add': () => t.proxy.addRule,
      '/proxy/edit': () => t.proxy.editRule,
      '/sites': () => t.sites.title,
      '/static-site-edit': () => t.sites.updateSite,
      '/static-site-add': () => t.sites.createSite,
      '/php-site-edit': () => t.sites.updateSite,
      '/php-site-add': () => t.sites.createSite,
      '/ssl': () => t.ssl.title,
      '/settings': () => t.settings.title,
      '/dns': () => t.dns.title,
      '/security': () => t.security.title,
      '/git-server': () => t.gitServer.title,
      '/notifications': () => t.notifications.title,
      '/users': () => t.userManagement.title,
      '/change-password': () => t.navigation.changePassword,
      '/cdn': () => t.cdn.title,
      '/statistics': () => t.statistics.title,
      '/monitoring': () => t.monitoring.title,
      '/slow-requests': () => t.slowRequests.title,
      '/cluster': () => t.clusterSettings.title,
      '/cluster/status': () => t.clusterStatus.title,
      '/ai-security': () => t.aiSecurity.title,
      '/image-optimization': () => t.imageOptimization.title,
    }

    // 检查是否有精确匹配
    if (pathToTitleMap[normalizedPath]) {
      return pathToTitleMap[normalizedPath]()
    }

    // 检查模板部署路径
    if (normalizedPath.startsWith('/templates/deploy/')) {
      return '模板部署'
    }
    if (normalizedPath === '/templates') {
      return '模板市场'
    }

    // 如果没有匹配，返回默认值
    return t.dashboard.title
  }

  return (
    <Box
      bg="rgba(255, 255, 255, 0.8)"
      backdropFilter="blur(10px)"
      borderBottom="1px"
      borderColor="gray.100"
      px={6}
      py={3}
      position="sticky"
      top={0}
      zIndex="sticky"
      boxShadow="sm"
    >
      <Flex align="center">
        {showMobileMenu && (
          <IconButton
            aria-label={t.header.open_menu}
            icon={<FiMenu />}
            variant="ghost"
            onClick={onMenuClick}
            mr={2}
          />
        )}
        
        <Box>
          <Text fontSize="lg" fontWeight="bold" color="gray.800" display={{ base: 'none', md: 'block' }}>
            {getPageTitle()}
          </Text>
        </Box>

        <Spacer />
        
        {/* 用户菜单和语言选择器 */}
        {user && (
          <HStack spacing={4}>
            {/* 语言选择器 */}
            <Select
              size="sm"
              variant="filled"
              bg="gray.50"
              borderRadius="lg"
              value={currentLanguage}
              onChange={(e) => changeLanguage(e.target.value)}
              width="130px"
              cursor="pointer"
              _hover={{ bg: 'gray.100' }}
            >
              {supportedLanguages.map((language) => (
                <option key={language.code} value={language.code}>
                  {language.flag} {language.nativeName}
                </option>
              ))}
            </Select>
            
            <Menu gutter={8}>
              <MenuButton
                as={Button}
                variant="ghost"
                size="md"
                borderRadius="full"
                px={2}
                _hover={{ bg: 'gray.50' }}
                _active={{ bg: 'gray.100' }}
              >
                <HStack spacing={3}>
                  <Avatar 
                    size="sm" 
                    name={user.username} 
                    bg="brand.500"
                    boxShadow="0 2px 4px rgba(33, 150, 243, 0.3)"
                  />
                  <VStack align="start" spacing={0} display={{ base: 'none', md: 'flex' }}>
                    <Text fontSize="sm" fontWeight="bold" color="gray.700">{user.username}</Text>
                    <Tag size="sm" variant="subtle" colorScheme="brand" borderRadius="full" height="18px">
                      <TagLabel fontSize="10px" fontWeight="800">{user.role.toUpperCase()}</TagLabel>
                    </Tag>
                  </VStack>
                  <Icon as={FiChevronDown} color="gray.400" display={{ base: 'none', md: 'block' }} />
                </HStack>
              </MenuButton>
              <MenuList borderRadius="xl" p={2} boxShadow="xl" border="none">
                <MenuItem 
                  icon={<FiLock />}
                  as={RouterLink}
                  to={buildPath(adminPrefix, '/change-password')}
                  borderRadius="lg"
                  py={2}
                >
                  {t.navigation.changePassword}
                </MenuItem>
                <Box h="1px" bg="gray.50" my={1} />
                <MenuItem 
                  icon={<FiLogOut />} 
                  onClick={logout}
                  borderRadius="lg"
                  py={2}
                  color="red.500"
                  _hover={{ bg: 'red.50' }}
                >
                  {t.navigation.logout}
                </MenuItem>
              </MenuList>
            </Menu>
          </HStack>
        )}
      </Flex>
    </Box>
  )
}

export default Header

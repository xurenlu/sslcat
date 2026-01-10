import React, { useState, useMemo } from 'react'
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
  Input,
  InputGroup,
  InputLeftElement,
  Tooltip,
  Badge,
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
  FiImage,
  FiServer,
  FiClock,
  FiPackage,
  FiActivity,
  FiSearch,
  FiX,
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
      w="full"
    >
      <HStack
        px={3}
        py={2}
        borderRadius="lg"
        bg={isActive ? 'brand.500' : 'transparent'}
        color={isActive ? 'white' : 'gray.600'}
        _hover={{
          bg: isActive ? 'brand.600' : 'gray.50',
          color: isActive ? 'white' : 'brand.600',
          transform: isActive ? 'none' : 'translateX(4px)',
        }}
        transition="all 0.2s cubic-bezier(.08,.52,.52,1)"
        justify="space-between"
        cursor="pointer"
        role="group"
      >
        <HStack spacing={2.5}>
          <Icon 
            as={icon} 
            boxSize={4.5} 
            color={isActive ? 'white' : 'gray.400'}
            _groupHover={{ color: isActive ? 'white' : 'brand.500' }}
          />
          <Text fontSize="sm" fontWeight={isActive ? "bold" : "medium"}>
            {children}
          </Text>
        </HStack>
        {badge && (
          <Badge
            px={2}
            py={0.5}
            fontSize="2xs"
            fontWeight="bold"
            borderRadius="full"
            bgGradient="linear(to-r, purple.400, purple.600)"
            color="white"
            boxShadow="0 2px 4px rgba(128, 90, 213, 0.3)"
          >
            {badge}
          </Badge>
        )}
      </HStack>
    </Link>
  )
}

const SidebarContent = () => {
  const location = useLocation()
  const t = useTranslation()
  const { adminPrefix, version } = useConfig()
  const [searchQuery, setSearchQuery] = useState('')
  
  // 构建带有 adminPrefix 的 logo 路径
  const logoSrc = `${adminPrefix}${logoImage}`

  const categories = useMemo(() => [
    {
      title: t.sidebar.console,
      items: [
        { name: t.navigation.dashboard, icon: FiHome, path: buildPath(adminPrefix, '/dashboard'), keywords: 'home stats 首页 概览' },
        { name: t.navigation.statistics, icon: FiBarChart2, path: buildPath(adminPrefix, '/statistics'), keywords: 'stats requests traffic 流量 统计' },
        { name: t.navigation.monitoring || 'System Monitoring', icon: FiActivity, path: buildPath(adminPrefix, '/monitoring'), keywords: 'cpu memory watchdog 监控 性能' },
        { name: t.navigation.slowRequests, icon: FiClock, path: buildPath(adminPrefix, '/slow-requests'), keywords: 'performance slow delay 慢日志 延迟' },
      ]
    },
    {
      title: t.sidebar.coreServices,
      items: [
        { name: t.navigation.proxy, icon: FiZap, path: buildPath(adminPrefix, '/proxy'), keywords: 'proxy rules reverse 反代 规则' },
        { name: t.navigation.sites, icon: FiGlobe, path: buildPath(adminPrefix, '/sites'), keywords: 'static php website 网站 站点' },
        { name: t.navigation.ssl, icon: FiShield, path: buildPath(adminPrefix, '/ssl'), keywords: 'cert letsencrypt 证书 安全' },
        { name: t.navigation.dns, icon: FiGlobe, path: buildPath(adminPrefix, '/dns'), keywords: 'cloudflare aliyun tencent 域名 解析' },
      ]
    },
    {
      title: t.sidebar.advancedFeatures,
      items: [
        { name: t.navigation.cdnCache, icon: FiHardDrive, path: buildPath(adminPrefix, '/cdn'), keywords: 'cache speed cdn 缓存 加速' },
        { name: t.navigation.imageOptimization, icon: FiImage, path: buildPath(adminPrefix, '/image-optimization'), keywords: 'webp compression resize 图片 压缩' },
        { name: t.navigation.gitServer, icon: FiGitBranch, path: buildPath(adminPrefix, '/git-server'), keywords: 'deploy auto ci/cd 部署 自动化' },
        { name: t.sidebar.templateMarket, icon: FiPackage, path: buildPath(adminPrefix, '/templates'), keywords: 'market apps docker 模板 应用' },
      ]
    },
    {
      title: t.sidebar.securityProtection,
      items: [
        { name: t.navigation.security, icon: FiShield, path: buildPath(adminPrefix, '/security'), keywords: 'waf ddos block 防火墙 拦截' },
        { name: t.sidebar.blockManagement, icon: FiX, path: buildPath(adminPrefix, '/block-management'), keywords: 'block unblock ip tls fingerprint user agent 封禁 解封' },
        { name: t.navigation.aiSecurity || '🤖 AI 安全分析', icon: FaRobot, path: buildPath(adminPrefix, '/ai-security'), badge: 'AI', keywords: 'ai robot threat analysis 智能 分析' },
      ]
    },
    {
      title: t.sidebar.clusterDeployment,
      items: [
        { name: t.navigation.cluster || 'Cluster', icon: FiServer, path: buildPath(adminPrefix, '/cluster'), keywords: 'master slave sync 集群 同步' },
        { name: t.navigation.clusterStatus || 'Cluster Status', icon: FiServer, path: buildPath(adminPrefix, '/cluster/status'), keywords: 'nodes health status 节点 健康' },
      ]
    },
    {
      title: t.sidebar.systemManagement,
      items: [
        { name: t.navigation.settings, icon: FiSettings, path: buildPath(adminPrefix, '/settings'), keywords: 'config basic notification 配置 通知' },
        { name: t.navigation.userManagement, icon: FiUsers, path: buildPath(adminPrefix, '/users'), keywords: 'admin members roles 用户 权限' },
        { name: t.navigation.changePassword, icon: FiKey, path: buildPath(adminPrefix, '/change-password'), keywords: 'security auth password 密码 安全' },
      ]
    }
  ], [t, adminPrefix])

  const filteredCategories = useMemo(() => {
    if (!searchQuery) return categories

    const query = searchQuery.toLowerCase()
    return categories.map(category => ({
      ...category,
      items: category.items.filter(item => 
        item.name.toLowerCase().includes(query) || 
        item.keywords.toLowerCase().includes(query)
      )
    })).filter(category => category.items.length > 0)
  }, [categories, searchQuery])

  return (
    <Box h="full" bg="white" borderRight="1px" borderColor="gray.100" display="flex" flexDirection="column" boxShadow="sm">
      {/* Logo - 固定顶部 */}
      <Box p={4} borderBottom="1px" borderColor="gray.50" flexShrink={0} bgGradient="linear(to-br, white, gray.50)">
        <VStack spacing={2}>
          {/* Logo 图片 */}
          <Box
            position="relative"
            transition="all 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275)"
            _hover={{
              transform: 'scale(1.1) rotate(5deg)',
            }}
            cursor="pointer"
          >
            <Image
              src={logoSrc}
              alt="SSLcat Logo"
              boxSize="40px"
              objectFit="contain"
              filter="drop-shadow(0 4px 6px rgba(33, 150, 243, 0.2))"
            />
          </Box>
          
          {/* 品牌名称 */}
          <VStack spacing={0}>
            <Text fontSize="lg" fontWeight="800" letterSpacing="tight" bgGradient="linear(to-r, brand.500, brand.700)" bgClip="text">
              SSLcat
            </Text>
            <Text fontSize="2xs" color="gray.400" fontWeight="medium" textTransform="uppercase" letterSpacing="wide">
              Gateway
            </Text>
          </VStack>
        </VStack>
      </Box>

      {/* 搜索框 */}
      <Box px={3} py={2}>
        <InputGroup size="sm">
          <InputLeftElement pointerEvents="none">
            <Icon as={FiSearch} color="gray.400" />
          </InputLeftElement>
          <Input
            placeholder={t.sidebar.searchPlaceholder || 'Search...'}
            variant="filled"
            bg="gray.50"
            _focus={{
              bg: 'white',
              borderColor: 'brand.300',
              boxShadow: '0 0 0 1px brand.300'
            }}
            borderRadius="lg"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </InputGroup>
      </Box>

      {/* 可滚动的内容区域 */}
      <Box flex={1} overflowY="auto" px={2} py={2} css={{
        '&::-webkit-scrollbar': { width: '4px' },
        '&::-webkit-scrollbar-track': { background: 'transparent' },
        '&::-webkit-scrollbar-thumb': { background: '#E2E8F0', borderRadius: '10px' },
      }}>
        <VStack spacing={6} align="stretch">
          {filteredCategories.map((category) => (
            <Box key={category.title}>
              <Text
                px={3}
                mb={1.5}
                fontSize="2xs"
                fontWeight="bold"
                color="gray.400"
                textTransform="uppercase"
                letterSpacing="wide"
              >
                {category.title}
              </Text>
              <VStack spacing={0.5} align="stretch">
                {category.items.map((item) => (
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
          ))}
          {filteredCategories.length === 0 && (
            <Box py={10} textAlign="center">
              <Text fontSize="sm" color="gray.500">未找到匹配功能</Text>
            </Box>
          )}
        </VStack>
      </Box>

      {/* 底部区域 */}
      <Box p={3} borderTop="1px" borderColor="gray.50" flexShrink={0} bg="gray.50">
        <VStack spacing={2}>
          <HStack w="full" justify="space-between" px={1}>
            <VStack align="start" spacing={0}>
              <Text fontSize="xs" color="gray.400" fontWeight="bold">VERSION</Text>
              <Text fontSize="sm" fontWeight="mono" color="brand.600">{version || 'v1.3.32-rc6'}</Text>
            </VStack>
            <Tooltip label={t.navigation.logout} placement="top">
              <Button
                variant="ghost"
                colorScheme="red"
                size="sm"
                px={2}
                onClick={() => {
                  // 这里应该调用登出逻辑
                  window.location.href = buildPath(adminPrefix, '/login')
                }}
              >
                <Icon as={FiLogOut} boxSize={5} />
              </Button>
            </Tooltip>
          </HStack>
          
          <Button
            as="a"
            href="https://sslcat.com"
            target="_blank"
            size="xs"
            variant="ghost"
            color="gray.400"
            _hover={{ color: 'brand.500', bg: 'transparent' }}
            w="full"
            fontWeight="normal"
          >
            {t.sidebar.officialWebsite}
          </Button>
        </VStack>
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

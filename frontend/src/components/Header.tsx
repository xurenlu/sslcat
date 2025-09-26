import React from 'react'
import {
  Box,
  Flex,
  IconButton,
  useBreakpointValue,
  Spacer,
  HStack,
  Text,
  Button,
  Menu,
  MenuButton,
  MenuList,
  MenuItem,
  Avatar,
} from '@chakra-ui/react'
import { FiMenu, FiUser, FiLogOut, FiLock } from 'react-icons/fi'
import { useAuth } from '../contexts/AuthContext'
import { useConfig, buildPath } from '../contexts/ConfigContext'
import { Link as RouterLink } from 'react-router-dom'

interface HeaderProps {
  onMenuClick: () => void
}

const Header: React.FC<HeaderProps> = ({ onMenuClick }) => {
  const showMobileMenu = useBreakpointValue({ base: true, md: false })
  const { user, logout } = useAuth()
  const { adminPrefix } = useConfig()

  return (
    <Box
      bg="white"
      borderBottom="1px"
      borderColor="gray.200"
      px={4}
      py={3}
      position="sticky"
      top={0}
      zIndex="sticky"
    >
      <Flex align="center">
        {showMobileMenu && (
          <IconButton
            aria-label="打开菜单"
            icon={<FiMenu />}
            variant="ghost"
            onClick={onMenuClick}
            mr={2}
          />
        )}
        <Spacer />
        
        {/* 用户菜单 */}
        {user && (
          <HStack spacing={3}>
            <Text fontSize="sm" color="gray.600">
              {user.username}
            </Text>
            <Menu>
              <MenuButton
                as={Button}
                variant="ghost"
                size="sm"
                leftIcon={<Avatar size="xs" name={user.username} />}
              >
                {user.role}
              </MenuButton>
              <MenuList>
                <MenuItem 
                  icon={<FiLock />}
                  as={RouterLink}
                  to={buildPath(adminPrefix, '/change-password')}
                >
                  修改密码
                </MenuItem>
                <MenuItem icon={<FiLogOut />} onClick={logout}>
                  退出登录
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

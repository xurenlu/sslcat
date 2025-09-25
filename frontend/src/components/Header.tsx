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
import { FiMenu, FiUser, FiLogOut } from 'react-icons/fi'
import { useAuth } from '../contexts/AuthContext'

interface HeaderProps {
  onMenuClick: () => void
}

const Header: React.FC<HeaderProps> = ({ onMenuClick }) => {
  const showMobileMenu = useBreakpointValue({ base: true, md: false })
  const { user, logout } = useAuth()

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
                <MenuItem icon={<FiUser />}>
                  个人设置
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

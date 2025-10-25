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
  Select,
} from '@chakra-ui/react'
import { FiMenu, FiUser, FiLogOut, FiLock } from 'react-icons/fi'
import { useAuth } from '../contexts/AuthContext'
import { useConfig, buildPath } from '../contexts/ConfigContext'
import { Link as RouterLink } from 'react-router-dom'
import { useLanguage, supportedLanguages } from '../hooks/useLanguage'

interface HeaderProps {
  onMenuClick: () => void
}

const Header: React.FC<HeaderProps> = ({ onMenuClick }) => {
  const showMobileMenu = useBreakpointValue({ base: true, md: false })
  const { user, logout } = useAuth()
  const { adminPrefix } = useConfig()
  const { currentLanguage, changeLanguage } = useLanguage()

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
            aria-label={t.header.open_menu}
            icon={<FiMenu />}
            variant="ghost"
            onClick={onMenuClick}
            mr={2}
          />
        )}
        <Spacer />
        
        {/* 用户菜单和语言选择器 */}
        {user && (
          <HStack spacing={3}>
            {/* 语言选择器 */}
            <Select
              size="sm"
              value={currentLanguage}
              onChange={(e) => changeLanguage(e.target.value)}
              width="120px"
            >
              {supportedLanguages.map((language) => (
                <option key={language.code} value={language.code}>
                  {language.flag} {language.nativeName}
                </option>
              ))}
            </Select>
            
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

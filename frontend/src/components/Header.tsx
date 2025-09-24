import React from 'react'
import {
  Box,
  Flex,
  IconButton,
  useBreakpointValue,
  Spacer,
} from '@chakra-ui/react'
import { FiMenu } from 'react-icons/fi'

interface HeaderProps {
  onMenuClick: () => void
}

const Header: React.FC<HeaderProps> = ({ onMenuClick }) => {
  const showMobileMenu = useBreakpointValue({ base: true, md: false })

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
        {/* 这里可以添加用户信息、通知等 */}
      </Flex>
    </Box>
  )
}

export default Header

import React from 'react'
import {
  Box,
  useDisclosure,
  useBreakpointValue,
} from '@chakra-ui/react'
import Sidebar from './Sidebar'
import Header from './Header'

interface LayoutProps {
  children: React.ReactNode
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const { isOpen, onOpen, onClose } = useDisclosure()
  const sidebarWidth = useBreakpointValue({ base: 'full', md: '240px' })

  return (
    <Box minH="100vh" bg="gray.50" position="relative" overflow="hidden">
      {/* 装饰性背景 */}
      <Box
        position="absolute"
        top="-10%"
        right="-5%"
        w="40%"
        h="40%"
        bgGradient="radial(brand.100, transparent)"
        borderRadius="full"
        filter="blur(80px)"
        opacity="0.4"
        zIndex="0"
      />
      <Box
        position="absolute"
        bottom="-10%"
        left="-5%"
        w="30%"
        h="30%"
        bgGradient="radial(purple.100, transparent)"
        borderRadius="full"
        filter="blur(60px)"
        opacity="0.3"
        zIndex="0"
      />

      <Sidebar
        isOpen={isOpen}
        onClose={onClose}
        width={sidebarWidth}
      />
      <Box 
        ml={{ base: 0, md: sidebarWidth }} 
        transition="all 0.3s cubic-bezier(0.4, 0, 0.2, 1)" 
        position="relative" 
        zIndex="1"
      >
        <Header onMenuClick={onOpen} />
        <Box p={{ base: 4, md: 8 }} maxW="1600px" mx="auto">
          {children}
        </Box>
      </Box>
    </Box>
  )
}

export default Layout

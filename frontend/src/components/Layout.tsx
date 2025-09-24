import React from 'react'
import {
  Box,
  Flex,
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
  const sidebarWidth = useBreakpointValue({ base: 'full', md: '280px' })

  return (
    <Box minH="100vh" bg="gray.50">
      <Sidebar
        isOpen={isOpen}
        onClose={onClose}
        width={sidebarWidth}
      />
      <Box ml={{ base: 0, md: sidebarWidth }} transition="margin-left 0.3s">
        <Header onMenuClick={onOpen} />
        <Box p={6}>
          {children}
        </Box>
      </Box>
    </Box>
  )
}

export default Layout

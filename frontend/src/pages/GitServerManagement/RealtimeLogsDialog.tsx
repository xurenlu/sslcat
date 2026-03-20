import React, { useState } from 'react'
import {
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalCloseButton,
  IconButton,
  Icon,
  Button,
  useDisclosure,
} from '@chakra-ui/react'
import { FiTerminal } from 'react-icons/fi'
import { useTranslation } from '../../hooks/useLanguage'
import RealtimeLogs from '../../components/RealtimeLogs'

interface RealtimeLogsDialogProps {
  appName: string
  trigger?: React.ReactNode
}

const RealtimeLogsDialog: React.FC<RealtimeLogsDialogProps> = ({ appName, trigger }) => {
  const t = useTranslation()
  const { isOpen, onOpen, onClose } = useDisclosure()

  const defaultTrigger = (
    <IconButton
      aria-label={t.gitServer.viewLogs || '查看日志'}
      icon={<Icon as={FiTerminal} />}
      size="sm"
      variant="ghost"
      colorScheme="blue"
      onClick={onOpen}
    />
  )

  const TriggerWrapper = ({ children }: { children: React.ReactNode }) => {
    if (React.isValidElement(children)) {
      return React.cloneElement(children as React.ReactElement<any>, {
        onClick: onOpen,
      })
    }
    return <>{children}</>
  }

  return (
    <>
      {trigger ? <TriggerWrapper>{trigger}</TriggerWrapper> : defaultTrigger}

      <Modal isOpen={isOpen} onClose={onClose} size="full" scrollBehavior="inside">
        <ModalOverlay />
        <ModalContent maxW="container.xl" maxH="80vh">
          <ModalHeader>
            {t.gitServer.viewLogs} - {appName}
          </ModalHeader>
          <ModalCloseButton />
          <ModalBody>
            <RealtimeLogs
              appName={appName}
              autoScroll={true}
              maxLines={500}
              showControls={true}
            />
          </ModalBody>
        </ModalContent>
      </Modal>
    </>
  )
}

export default RealtimeLogsDialog

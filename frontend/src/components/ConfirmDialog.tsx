import React from 'react'
import {
  AlertDialog,
  AlertDialogOverlay,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogBody,
  AlertDialogFooter,
  Button,
  useDisclosure,
} from '@chakra-ui/react'
import { useTranslation } from '../hooks/useLanguage'

interface ConfirmDialogProps {
  isOpen: boolean
  onClose: () => void
  onConfirm: () => void
  title: string
  message: string
  confirmButtonText?: string
  cancelButtonText?: string
  confirmButtonColor?: string
  isLoading?: boolean
}

const ConfirmDialog: React.FC<ConfirmDialogProps> = ({
  isOpen,
  onClose,
  onConfirm,
  title,
  message,
  confirmButtonText,
  cancelButtonText,
  confirmButtonColor = 'red',
  isLoading = false,
}) => {
  const t = useTranslation()
  const cancelRef = React.useRef<HTMLButtonElement>(null)

  const handleConfirm = () => {
    onConfirm()
    onClose()
  }

  return (
    <AlertDialog
      isOpen={isOpen}
      leastDestructiveRef={cancelRef}
      onClose={onClose}
    >
      <AlertDialogOverlay>
        <AlertDialogContent>
          <AlertDialogHeader fontSize="lg" fontWeight="bold">
            {title}
          </AlertDialogHeader>

          <AlertDialogBody>
            {message}
          </AlertDialogBody>

          <AlertDialogFooter>
            <Button ref={cancelRef} onClick={onClose} disabled={isLoading}>
              {cancelButtonText || t.common.cancel}
            </Button>
            <Button
              colorScheme={confirmButtonColor}
              onClick={handleConfirm}
              ml={3}
              isLoading={isLoading}
              loadingText={t.dialog.processing}
            >
              {confirmButtonText || t.common.confirm}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialogOverlay>
    </AlertDialog>
  )
}

// Hook for using confirm dialog
export const useConfirmDialog = () => {
  const { isOpen, onOpen, onClose } = useDisclosure()
  const [dialogProps, setDialogProps] = React.useState<{
    title: string
    message: string
    onConfirm: () => void
    confirmButtonText?: string
    confirmButtonColor?: string
  }>({
    title: '',
    message: '',
    onConfirm: () => {},
  })

  const showConfirm = (props: {
    title: string
    message: string
    onConfirm: () => void
    confirmButtonText?: string
    confirmButtonColor?: string
  }) => {
    setDialogProps(props)
    onOpen()
  }

  const ConfirmDialogComponent = () => (
    <ConfirmDialog
      isOpen={isOpen}
      onClose={onClose}
      {...dialogProps}
    />
  )

  return {
    showConfirm,
    ConfirmDialog: ConfirmDialogComponent,
  }
}

export default ConfirmDialog

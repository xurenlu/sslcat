import React from 'react'
import { VStack, HStack, Input, IconButton, Button, Text } from '@chakra-ui/react'
import { FiTrash2, FiPlus } from 'react-icons/fi'

interface HeaderEditorProps {
  value: Record<string, string>
  onChange: (headers: Record<string, string>) => void
  placeholderKey?: string
  placeholderValue?: string
}

const HeaderEditor: React.FC<HeaderEditorProps> = ({ value, onChange, placeholderKey, placeholderValue }) => {
  const currentEntries = Object.entries(value || {})

  const updateEntry = (oldKey: string, newKey: string, newValue: string) => {
    const next: Record<string, string> = {}
    currentEntries.forEach(([k, v]) => {
      if (k !== oldKey) {
        next[k] = v
      }
    })

    const trimmedKey = newKey.trim()
    if (trimmedKey) {
      next[trimmedKey] = newValue
    }

    onChange(next)
  }

  const removeEntry = (oldKey: string) => {
    const next: Record<string, string> = {}
    currentEntries.forEach(([k, v]) => {
      if (k !== oldKey) {
        next[k] = v
      }
    })
    onChange(next)
  }

  const addEmpty = () => {
    const next = { ...value }
    // 添加一个临时的空条目，使用特殊键名
    next['__temp__' + Date.now()] = ''
    onChange(next)
  }

  return (
    <VStack spacing={3} align="stretch">
      {currentEntries.length === 0 && (
        <Text fontSize="sm" color="gray.500">暂无自定义头，可手动添加或使用预设。</Text>
      )}
      {currentEntries.map(([key, val], index) => (
        <HStack key={`${key}-${index}`} spacing={2} align="center">
          <Input
            placeholder={placeholderKey}
            value={key}
            onChange={(e) => updateEntry(key, e.target.value, val)}
          />
          <Input
            placeholder={placeholderValue}
            value={val}
            onChange={(e) => updateEntry(key, key, e.target.value)}
          />
          <IconButton
            aria-label={t.header.delete_header}
            icon={<FiTrash2 />}
            variant="ghost"
            colorScheme="red"
            onClick={() => removeEntry(key)}
          />
        </HStack>
      ))}
      <Button
        leftIcon={<FiPlus />}
        size="sm"
        onClick={addEmpty}
        alignSelf="flex-start"
      >
        添加头部
      </Button>
    </VStack>
  )
}

export default HeaderEditor


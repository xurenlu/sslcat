import React, { useState, useEffect } from 'react'
import {
  Box,
  Grid,
  Card,
  CardBody,
  CardHeader,
  Heading,
  Text,
  Button,
  Input,
  InputGroup,
  InputLeftElement,
  Select,
  Badge,
  VStack,
  HStack,
  Spinner,
  Center,
  useToast,
  Icon,
  Flex,
} from '@chakra-ui/react'
import { SearchIcon, StarIcon } from '@chakra-ui/icons'
import { useNavigate } from 'react-router-dom'
import api from '../utils/api'
import { useConfig, buildPath } from '../contexts/ConfigContext'
import { useTranslation } from '../hooks/useLanguage'

interface Template {
  id: string
  name: string
  category: string
  subcategory?: string
  tags: string[]
  description: string
  icon?: string
  version?: string
  author?: string
  website?: string
  source: 'builtin' | 'custom'
}

const TemplateMarket: React.FC = () => {
  const [templates, setTemplates] = useState<Template[]>([])
  const [filteredTemplates, setFilteredTemplates] = useState<Template[]>([])
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('')
  const [tagFilter, setTagFilter] = useState('')
  const navigate = useNavigate()
  const toast = useToast()
  const { adminPrefix } = useConfig()
  const t = useTranslation()

  useEffect(() => {
    loadTemplates()
  }, [])

  useEffect(() => {
    filterTemplates()
  }, [templates, searchQuery, categoryFilter, tagFilter])

  const loadTemplates = async () => {
    try {
      setLoading(true)
      const response: any = await api.get('/git-server/templates')
      if (response && response.success && response.data) {
        setTemplates(response.data)
      } else if (response && Array.isArray(response)) {
        // 如果直接返回数组
        setTemplates(response)
      }
    } catch (error: any) {
      toast({
        title: t.templates?.loadFailed || 'Failed to load templates',
        description: error.message || (t.templates?.loadFailedDesc || 'Unable to load template list'),
        status: 'error',
        duration: 3000,
      })
    } finally {
      setLoading(false)
    }
  }

  const filterTemplates = () => {
    let filtered = [...templates]

    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      filtered = filtered.filter(
        (t) =>
          t.name.toLowerCase().includes(query) ||
          t.description.toLowerCase().includes(query) ||
          t.tags.some((tag) => tag.toLowerCase().includes(query))
      )
    }

    if (categoryFilter) {
      filtered = filtered.filter((t) => t.category === categoryFilter)
    }

    if (tagFilter) {
      filtered = filtered.filter((t) => t.tags.includes(tagFilter))
    }

    setFilteredTemplates(filtered)
  }

  const categories = Array.from(new Set(templates.map((t) => t.category)))
  const tags = Array.from(new Set(templates.flatMap((t) => t.tags)))

  const handleDeploy = (templateId: string) => {
    navigate(buildPath(adminPrefix, `/templates/deploy/${templateId}`))
  }

  if (loading) {
    return (
      <Center h="400px">
        <Spinner size="xl" />
      </Center>
    )
  }

  return (
    <Box p={6}>
      <VStack spacing={6} align="stretch">
        <Heading size="lg">{t.templates?.title || t.sidebar.templateMarket || 'Template Market'}</Heading>

        {/* 搜索和筛选 */}
        <HStack spacing={4}>
          <InputGroup>
            <InputLeftElement pointerEvents="none">
              <SearchIcon color="gray.400" />
            </InputLeftElement>
            <Input
              placeholder={t.templates?.searchPlaceholder || 'Search templates...'}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </InputGroup>
          <Select
            placeholder={t.templates?.selectCategory || 'Select category'}
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            maxW="200px"
          >
            {categories.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </Select>
          <Select
            placeholder={t.templates?.selectTag || 'Select tags'}
            value={tagFilter}
            onChange={(e) => setTagFilter(e.target.value)}
            maxW="200px"
          >
            {tags.slice(0, 20).map((tag) => (
              <option key={tag} value={tag}>
                {tag}
              </option>
            ))}
          </Select>
          {(categoryFilter || tagFilter || searchQuery) && (
            <Button onClick={() => {
              setCategoryFilter('')
              setTagFilter('')
              setSearchQuery('')
            }}>
              {t.templates?.clearFilters || 'Clear Filters'}
            </Button>
          )}
        </HStack>

        {/* 模板列表 */}
        <Text color="gray.500">
          {t.templates?.foundTemplates?.replace('{count}', filteredTemplates.length.toString()) || `Found ${filteredTemplates.length} templates`}
        </Text>

        <Grid templateColumns="repeat(auto-fill, minmax(300px, 1fr))" gap={4}>
          {filteredTemplates.map((template) => (
            <Card key={template.id} _hover={{ shadow: 'lg' }}>
              <CardHeader>
                <Flex justify="space-between" align="start">
                  <VStack align="start" spacing={2}>
                    <Heading size="md">{template.name}</Heading>
                    <HStack>
                      <Badge colorScheme="blue">{template.category}</Badge>
                      {template.source === 'builtin' && (
                        <Badge colorScheme="green">{t.templates?.builtin || 'Built-in'}</Badge>
                      )}
                    </HStack>
                  </VStack>
                </Flex>
              </CardHeader>
              <CardBody>
                <VStack align="stretch" spacing={4}>
                  <Text fontSize="sm" color="gray.600" noOfLines={3}>
                    {template.description}
                  </Text>
                  {template.tags.length > 0 && (
                    <HStack flexWrap="wrap">
                      {template.tags.slice(0, 5).map((tag) => (
                        <Badge key={tag} fontSize="xs" colorScheme="gray">
                          {tag}
                        </Badge>
                      ))}
                    </HStack>
                  )}
                  <Button
                    colorScheme="blue"
                    onClick={() => handleDeploy(template.id)}
                    width="full"
                  >
                    {t.templates?.oneClickDeploy || 'One-Click Deploy'}
                  </Button>
                </VStack>
              </CardBody>
            </Card>
          ))}
        </Grid>

        {filteredTemplates.length === 0 && (
          <Center py={10}>
            <Text color="gray.500">{t.templates?.noMatchingTemplates || 'No matching templates found'}</Text>
          </Center>
        )}
      </VStack>
    </Box>
  )
}

export default TemplateMarket


import React from 'react'
import {
  Box,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Text,
  Badge,
  VStack,
} from '@chakra-ui/react'

interface GeoDataPoint {
  country: string
  countryCode: string
  count: number
}

interface GeoTableProps {
  data: GeoDataPoint[]
}

export const GeoTable: React.FC<GeoTableProps> = ({ data }) => {
  if (!data || data.length === 0) {
    return (
      <Box p={8} textAlign="center">
        <Text color="gray.500">暂无地理位置数据</Text>
      </Box>
    )
  }

  // 按请求数排序
  const sortedData = [...data].sort((a, b) => b.count - a.count)

  return (
    <VStack align="stretch" spacing={4}>
      <Text fontWeight="semibold">请求地理位置分布（表格视图）</Text>
      <Box overflowX="auto">
        <Table variant="simple" size="sm">
          <Thead>
            <Tr>
              <Th>排名</Th>
              <Th>国家/地区</Th>
              <Th>请求数</Th>
              <Th>占比</Th>
            </Tr>
          </Thead>
          <Tbody>
            {sortedData.map((point, idx) => {
              const total = sortedData.reduce((sum, p) => sum + p.count, 0)
              const percentage = ((point.count / total) * 100).toFixed(2)

              return (
                <Tr key={idx}>
                  <Td>
                    <Badge colorScheme={idx < 3 ? 'blue' : 'gray'}>
                      #{idx + 1}
                    </Badge>
                  </Td>
                  <Td fontWeight="medium">{point.country}</Td>
                  <Td fontFamily="mono">{point.count.toLocaleString()}</Td>
                  <Td>
                    <Box>
                      <Text fontSize="sm">{percentage}%</Text>
                      <Box
                        mt={1}
                        h="4px"
                        bg="blue.200"
                        borderRadius="full"
                        overflow="hidden"
                      >
                        <Box
                          h="100%"
                          bg="blue.500"
                          width={`${percentage}%`}
                          transition="width 0.3s ease"
                        />
                      </Box>
                    </Box>
                  </Td>
                </Tr>
              )
            })}
          </Tbody>
        </Table>
      </Box>
    </VStack>
  )
}

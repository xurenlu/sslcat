import React from 'react'
import {
  Box,
  Card,
  CardBody,
  CardHeader,
  Heading,
  VStack,
  HStack,
  Text,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  Code,
  OrderedList,
  ListItem,
  Button,
  Icon,
  Badge,
  Divider,
  UnorderedList,
  Link,
} from '@chakra-ui/react'
import {
  FiDownload,
  FiDatabase,
  FiFolder,
  FiCheckCircle,
  FiExternalLink,
  FiInfo,
  FiTerminal,
} from 'react-icons/fi'

const GeoIPSetupGuide: React.FC = () => {
  return (
    <VStack spacing={6} align="stretch">
      {/* 概述 */}
      <Card>
        <CardHeader>
          <HStack>
            <Icon as={FiInfo} color="blue.500" />
            <Heading size="md">GeoIP数据库设置指南</Heading>
          </HStack>
        </CardHeader>
        <CardBody>
          <Text>
            地理位置过滤功能需要MaxMind的GeoLite2数据库文件。本指南将帮助您正确设置这些数据库文件。
          </Text>
        </CardBody>
      </Card>

      {/* 所需文件 */}
      <Card>
        <CardHeader>
          <Heading size="md">所需文件</Heading>
        </CardHeader>
        <CardBody>
          <VStack spacing={4} align="stretch">
            <HStack>
              <Icon as={FiDatabase} color="green.500" />
              <Box>
                <Text fontWeight="bold">GeoLite2-City.mmdb</Text>
                <Text fontSize="sm" color="gray.600">
                  <Badge colorScheme="green" mr={2}>必需</Badge>
                  城市级地理位置数据库，包含国家、城市、坐标等信息
                </Text>
              </Box>
            </HStack>
            
            <HStack>
              <Icon as={FiDatabase} color="orange.500" />
              <Box>
                <Text fontWeight="bold">GeoLite2-ASN.mmdb</Text>
                <Text fontSize="sm" color="gray.600">
                  <Badge colorScheme="orange" mr={2}>可选</Badge>
                  自治系统号数据库，提供ISP和组织信息
                </Text>
              </Box>
            </HStack>
          </VStack>
        </CardBody>
      </Card>

      {/* 获取数据库文件 */}
      <Card>
        <CardHeader>
          <Heading size="md">获取数据库文件</Heading>
        </CardHeader>
        <CardBody>
          <VStack spacing={4} align="stretch">
            <Alert status="info">
              <AlertIcon />
              <Box>
                <AlertTitle>免费账户注册</AlertTitle>
                <AlertDescription>
                  MaxMind GeoLite2数据库需要免费注册账户才能下载
                </AlertDescription>
              </Box>
            </Alert>

            <OrderedList spacing={3}>
              <ListItem>
                <Text>
                  访问MaxMind官网：
                  <Link 
                    href="https://www.maxmind.com/" 
                    color="blue.500" 
                    isExternal
                    ml={2}
                  >
                    https://www.maxmind.com/
                    <Icon as={FiExternalLink} ml={1} />
                  </Link>
                </Text>
              </ListItem>
              
              <ListItem>
                <Text>点击 "Sign Up for GeoLite2" 注册免费账户</Text>
              </ListItem>
              
              <ListItem>
                <Text>登录后进入 "My License Key" 页面，生成License Key</Text>
              </ListItem>
              
              <ListItem>
                <Text>下载以下数据库文件：</Text>
                <UnorderedList mt={2} ml={4}>
                  <ListItem>
                    <Code>GeoLite2-City.mmdb</Code> (必需)
                  </ListItem>
                  <ListItem>
                    <Code>GeoLite2-ASN.mmdb</Code> (可选)
                  </ListItem>
                </UnorderedList>
              </ListItem>
            </OrderedList>
          </VStack>
        </CardBody>
      </Card>

      {/* 文件放置 */}
      <Card>
        <CardHeader>
          <Heading size="md">文件放置位置</Heading>
        </CardHeader>
        <CardBody>
          <VStack spacing={4} align="stretch">
            <Alert status="warning">
              <AlertIcon />
              <Box>
                <AlertTitle>重要提示</AlertTitle>
                <AlertDescription>
                  请将下载的数据库文件解压后，放置到指定目录
                </AlertDescription>
              </Box>
            </Alert>

            <Box>
              <Text fontWeight="bold" mb={2}>
                <Icon as={FiFolder} mr={2} />
                目标目录：
              </Text>
              <Code p={3} display="block" bg="gray.50" borderRadius="md">
                ./data/geoip/
              </Code>
            </Box>

            <Box>
              <Text fontWeight="bold" mb={2}>完整文件路径：</Text>
              <VStack spacing={2} align="stretch">
                <HStack>
                  <Icon as={FiCheckCircle} color="green.500" />
                  <Code>./data/geoip/GeoLite2-City.mmdb</Code>
                </HStack>
                <HStack>
                  <Icon as={FiCheckCircle} color="orange.500" />
                  <Code>./data/geoip/GeoLite2-ASN.mmdb</Code>
                </HStack>
              </VStack>
            </Box>

            <Divider />

            <Box>
              <Text fontWeight="bold" mb={2}>
                <Icon as={FiTerminal} mr={2} />
                使用命令行创建目录：
              </Text>
              <Code p={3} display="block" bg="gray.900" color="green.300" borderRadius="md">
                mkdir -p ./data/geoip
              </Code>
            </Box>
          </VStack>
        </CardBody>
      </Card>

      {/* 验证安装 */}
      <Card>
        <CardHeader>
          <Heading size="md">验证安装</Heading>
        </CardHeader>
        <CardBody>
          <VStack spacing={4} align="stretch">
            <Text>
              文件放置完成后，您可以通过以下方式验证安装：
            </Text>

            <OrderedList spacing={3}>
              <ListItem>
                <Text>重新启动SSLcat服务</Text>
              </ListItem>
              
              <ListItem>
                <Text>查看服务日志，确认数据库加载成功：</Text>
                <Code p={3} display="block" bg="gray.50" borderRadius="md" mt={2}>
                  GeoIP city database loaded successfully from: ./data/geoip/GeoLite2-City.mmdb
                </Code>
              </ListItem>
              
              <ListItem>
                <Text>在安全中心的地理位置过滤页面查看状态</Text>
              </ListItem>
              
              <ListItem>
                <Text>{t.geoipSetup.test_function}</Text>
              </ListItem>
            </OrderedList>

            <Alert status="success">
              <AlertIcon />
              <Box>
                <AlertTitle>自动检测</AlertTitle>
                <AlertDescription>
                  SSLcat会自动检测数据库文件，如果文件不存在，地理位置过滤功能将自动禁用，不会影响其他功能
                </AlertDescription>
              </Box>
            </Alert>
          </VStack>
        </CardBody>
      </Card>

      {/* 故障排除 */}
      <Card>
        <CardHeader>
          <Heading size="md">故障排除</Heading>
        </CardHeader>
        <CardBody>
          <VStack spacing={4} align="stretch">
            <Box>
              <Text fontWeight="bold" color="red.500" mb={2}>
                问题：数据库文件无法加载
              </Text>
              <UnorderedList spacing={2} ml={4}>
                <ListItem>检查文件路径是否正确</ListItem>
                <ListItem>确认文件权限允许读取</ListItem>
                <ListItem>验证下载的文件完整性</ListItem>
                <ListItem>确认文件已正确解压</ListItem>
              </UnorderedList>
            </Box>

            <Box>
              <Text fontWeight="bold" color="red.500" mb={2}>
                问题：地理位置识别不准确
              </Text>
              <UnorderedList spacing={2} ml={4}>
                <ListItem>更新到最新的GeoLite2数据库</ListItem>
                <ListItem>清空地理位置缓存</ListItem>
                <ListItem>检查客户端IP获取是否正确</ListItem>
              </UnorderedList>
            </Box>

            <Box>
              <Text fontWeight="bold" color="red.500" mb={2}>
                问题：功能无法启用
              </Text>
              <UnorderedList spacing={2} ml={4}>
                <ListItem>确认城市数据库文件存在</ListItem>
                <ListItem>检查配置文件中的数据库路径</ListItem>
                <ListItem>查看系统日志获取详细错误信息</ListItem>
              </UnorderedList>
            </Box>
          </VStack>
        </CardBody>
      </Card>

      {/* 操作按钮 */}
      <Card>
        <CardBody>
          <HStack spacing={4}>
            <Button
              as={Link}
              href="https://www.maxmind.com/"
              isExternal
              colorScheme="blue"
              leftIcon={<FiDownload />}
            >
              下载GeoLite2数据库
            </Button>
            
            <Button
              as={Link}
              href="https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
              isExternal
              variant="outline"
              leftIcon={<FiExternalLink />}
            >
              查看官方文档
            </Button>
          </HStack>
        </CardBody>
      </Card>
    </VStack>
  )
}

export default GeoIPSetupGuide

# SSLcat 端口配置设计方案

## 🎯 设计目标

1. **简化用户体验**：默认监听 80 和 443 端口
2. **明确功能选择**：用户需要主动开启"自定义端口"才能修改
3. **功能说明清晰**：告知用户选择的影响
4. **向后兼容**：保持现有配置的兼容性

## 📋 当前问题分析

### 配置不一致
- **前端显示**：`httpPort: '80'`, `httpsPort: '443'`
- **后端实际**：只有一个 `server.port` 配置项
- **潜规则**：443 端口时自动监听 80 端口

### 用户体验混乱
- 用户看到两个端口设置，但实际只控制一个
- 没有明确说明端口配置的规则和限制
- 用户不知道修改端口会失去 HTTPS 功能

## 🎨 新设计方案

### 1. 配置结构变更

```json
{
  "server": {
    "host": "0.0.0.0",
    "port_mode": "standard",  // "standard" | "custom"
    "custom_port": 18080,     // 仅在 port_mode="custom" 时生效
    "enable_https": true,     // 是否启用 HTTPS（仅在 standard 模式下）
    "debug": false
  }
}
```

### 2. 端口模式说明

#### Standard 模式（默认）
- **监听端口**：80 (HTTP) + 443 (HTTPS)
- **功能**：完整的 HTTP/HTTPS 支持
- **SSL 证书**：自动申请和管理
- **重定向**：HTTP → HTTPS 自动重定向
- **适用场景**：生产环境，需要 SSL 证书

#### Custom 模式
- **监听端口**：用户指定的单个端口
- **功能**：仅 HTTP 支持
- **SSL 证书**：不支持自动申请
- **重定向**：无
- **适用场景**：开发环境，内网部署，反向代理后端

### 3. 前端界面设计

```tsx
// 端口配置组件
const PortConfiguration = () => {
  const [portMode, setPortMode] = useState<'standard' | 'custom'>('standard')
  const [customPort, setCustomPort] = useState(8080)
  const [enableHttps, setEnableHttps] = useState(true)

  return (
    <Card>
      <CardHeader>
        <Heading size="md">端口配置</Heading>
      </CardHeader>
      <CardBody>
        <VStack spacing={4} align="stretch">
          {/* 端口模式选择 */}
          <FormControl>
            <FormLabel>端口模式</FormLabel>
            <RadioGroup value={portMode} onChange={setPortMode}>
              <VStack align="start" spacing={2}>
                <Radio value="standard">
                  <VStack align="start" spacing={1}>
                    <Text fontWeight="bold">标准模式（推荐）</Text>
                    <Text fontSize="sm" color="gray.600">
                      监听 80 和 443 端口，支持完整的 HTTP/HTTPS 功能
                    </Text>
                    <Text fontSize="sm" color="green.600">
                      ✓ 自动 SSL 证书申请和管理
                      ✓ HTTP 到 HTTPS 自动重定向
                      ✓ 适合生产环境
                    </Text>
                  </VStack>
                </Radio>
                <Radio value="custom">
                  <VStack align="start" spacing={1}>
                    <Text fontWeight="bold">自定义端口</Text>
                    <Text fontSize="sm" color="gray.600">
                      监听单个自定义端口，仅支持 HTTP
                    </Text>
                    <Text fontSize="sm" color="orange.600">
                      ⚠️ 不支持 SSL 证书自动申请
                      ⚠️ 不支持 HTTPS 功能
                      ⚠️ 适合开发环境或内网部署
                    </Text>
                  </VStack>
                </Radio>
              </VStack>
            </RadioGroup>
          </FormControl>

          {/* 标准模式配置 */}
          {portMode === 'standard' && (
            <Box p={4} bg="green.50" borderRadius="md">
              <VStack spacing={3} align="stretch">
                <Text fontWeight="bold" color="green.700">
                  标准模式配置
                </Text>
                <HStack>
                  <Text>HTTP 端口：</Text>
                  <Badge colorScheme="blue">80</Badge>
                </HStack>
                <HStack>
                  <Text>HTTPS 端口：</Text>
                  <Badge colorScheme="green">443</Badge>
                </HStack>
                <FormControl>
                  <FormLabel>启用 HTTPS</FormLabel>
                  <Switch
                    isChecked={enableHttps}
                    onChange={(e) => setEnableHttps(e.target.checked)}
                  />
                  <Text fontSize="sm" color="gray.600">
                    启用后会自动申请和管理 SSL 证书
                  </Text>
                </FormControl>
              </VStack>
            </Box>
          )}

          {/* 自定义模式配置 */}
          {portMode === 'custom' && (
            <Box p={4} bg="orange.50" borderRadius="md">
              <VStack spacing={3} align="stretch">
                <Text fontWeight="bold" color="orange.700">
                  自定义端口配置
                </Text>
                <Alert status="warning" borderRadius="md">
                  <AlertIcon />
                  <AlertDescription>
                    自定义端口模式下，SSLcat 将仅监听指定端口，不支持 HTTPS 功能。
                    如需 HTTPS，请使用标准模式或配置反向代理。
                  </AlertDescription>
                </Alert>
                <FormControl>
                  <FormLabel>监听端口</FormLabel>
                  <Input
                    type="number"
                    value={customPort}
                    onChange={(e) => setCustomPort(parseInt(e.target.value))}
                    placeholder="8080"
                    min="1024"
                    max="65535"
                  />
                  <Text fontSize="sm" color="gray.600">
                    建议使用 8080、3000、8000 等非特权端口
                  </Text>
                </FormControl>
              </VStack>
            </Box>
          )}
        </VStack>
      </CardBody>
    </Card>
  )
}
```

### 4. 后端实现逻辑

```go
// 端口配置结构
type PortConfig struct {
    Mode       string `json:"mode"`        // "standard" | "custom"
    CustomPort int    `json:"custom_port"` // 自定义端口
    EnableHTTPS bool  `json:"enable_https"` // 是否启用 HTTPS
}

// 启动逻辑
func (s *Server) Start() error {
    switch s.config.PortMode {
    case "standard":
        return s.startStandardMode()
    case "custom":
        return s.startCustomMode()
    default:
        return s.startStandardMode() // 默认标准模式
    }
}

// 标准模式：监听 80 和 443
func (s *Server) startStandardMode() error {
    // 启动 HTTPS 服务器 (443)
    if s.config.EnableHTTPS {
        go s.startHTTPSServer()
    }
    
    // 启动 HTTP 重定向服务器 (80)
    go s.startHTTPRedirectServer()
    
    return nil
}

// 自定义模式：监听单个端口
func (s *Server) startCustomMode() error {
    return s.startHTTPServer(s.config.CustomPort)
}
```

### 5. 配置迁移策略

#### 向后兼容
```go
func (c *Config) LoadFromFile(filename string) error {
    // 加载现有配置
    if err := json.Unmarshal(data, c); err != nil {
        return err
    }
    
    // 迁移旧配置
    if c.Server.PortMode == "" {
        if c.Server.Port == 443 {
            c.Server.PortMode = "standard"
            c.Server.EnableHTTPS = true
        } else {
            c.Server.PortMode = "custom"
            c.Server.CustomPort = c.Server.Port
            c.Server.EnableHTTPS = false
        }
    }
    
    return nil
}
```

## 🚀 实施计划

### 阶段 1：后端配置结构
1. 修改 `ServerConfig` 结构体
2. 实现端口模式逻辑
3. 添加配置迁移逻辑

### 阶段 2：前端界面
1. 重新设计端口配置界面
2. 添加模式选择和说明
3. 实现配置保存逻辑

### 阶段 3：测试和文档
1. 测试各种配置场景
2. 更新用户文档
3. 添加配置示例

## 📊 用户场景示例

### 场景 1：生产环境（推荐）
```json
{
  "server": {
    "port_mode": "standard",
    "enable_https": true
  }
}
```
- 监听 80 和 443
- 自动 SSL 证书管理
- HTTP → HTTPS 重定向

### 场景 2：开发环境
```json
{
  "server": {
    "port_mode": "custom",
    "custom_port": 18080
  }
}
```
- 仅监听 8080 端口
- 仅 HTTP 支持
- 适合本地开发

### 场景 3：内网部署
```json
{
  "server": {
    "port_mode": "custom",
    "custom_port": 3000
  }
}
```
- 仅监听 3000 端口
- 通过 Nginx 反向代理提供 HTTPS

## ✅ 优势总结

1. **用户体验**：清晰的模式选择，明确的功能说明
2. **功能完整**：标准模式提供完整的 HTTP/HTTPS 支持
3. **灵活配置**：自定义模式满足特殊需求
4. **向后兼容**：现有配置自动迁移
5. **文档完善**：详细的配置说明和示例

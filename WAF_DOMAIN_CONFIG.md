# WAF 按域名配置功能

## 功能概述

为 sslcat 添加了按域名/站点配置 WAF 开关的功能。现在用户可以在以下页面中为每个域名、静态站点或 PHP 站点单独配置 WAF 防护：

- 代理规则编辑页面（ProxyEdit）
- 代理规则添加页面（ProxyAdd）
- 静态站点编辑页面（StaticSiteEdit）
- PHP 站点编辑页面（PHPSiteEdit）

## 配置选项

每个域名/站点都有三个 WAF 配置选项：

1. **全局（默认）**: `waf_enabled = null`
   - 使用全局 WAF 配置
   - 这是默认选项，适用于大多数场景

2. **启用**: `waf_enabled = true`
   - 强制为此域名/站点启用 WAF
   - 即使全局 WAF 被禁用，此域名/站点仍会受到保护

3. **禁用**: `waf_enabled = false`
   - 强制为此域名/站点禁用 WAF
   - 即使全局 WAF 被启用，此域名/站点也不会受到保护
   - 适用于某些特殊场景（如内部 API、测试环境等）

## 前端修改

### 1. 数据结构修改

在所有相关页面的 Form 接口中添加了 `waf_enabled` 字段：

```typescript
interface ProxyRuleForm {
  // ... 其他字段
  waf_enabled?: boolean | null  // null 表示使用全局配置
}
```

### 2. UI 组件

在所有编辑页面中添加了统一的 WAF 配置 UI：

```tsx
<FormControl>
  <FormLabel>
    <HStack>
      <Icon as={FiShield} />
      <Text>WAF 防护</Text>
    </HStack>
  </FormLabel>
  <VStack align="stretch" spacing={2}>
    <Text fontSize="sm" color="gray.500">
      {formData.waf_enabled === null 
        ? '使用全局 WAF 配置（默认）' 
        : formData.waf_enabled 
          ? '已为此域名启用 WAF' 
          : '已为此域名禁用 WAF'}
    </Text>
    <HStack>
      <Button
        size="sm"
        variant={formData.waf_enabled === null ? 'solid' : 'outline'}
        colorScheme={formData.waf_enabled === null ? 'blue' : 'gray'}
        onClick={() => handleInputChange('waf_enabled', null)}
      >
        全局
      </Button>
      <Button
        size="sm"
        variant={formData.waf_enabled === true ? 'solid' : 'outline'}
        colorScheme={formData.waf_enabled === true ? 'green' : 'gray'}
        onClick={() => handleInputChange('waf_enabled', true)}
      >
        启用
      </Button>
      <Button
        size="sm"
        variant={formData.waf_enabled === false ? 'solid' : 'outline'}
        colorScheme={formData.waf_enabled === false ? 'red' : 'gray'}
        onClick={() => handleInputChange('waf_enabled', false)}
      >
        禁用
      </Button>
    </HStack>
  </VStack>
</FormControl>
```

### 3. 修改的文件列表

- `frontend/src/pages/ProxyEdit.tsx` - 代理规则编辑页面
- `frontend/src/pages/ProxyAdd.tsx` - 代理规则添加页面
- `frontend/src/pages/StaticSiteEdit.tsx` - 静态站点编辑页面
- `frontend/src/pages/PHPSiteEdit.tsx` - PHP 站点编辑页面

## 后端支持

后端已经支持 `waf_enabled` 字段的存储和读取：

- 在 `internal/config/config.go` 中，`ProxyRule`、`StaticSite` 和 `PHPSite` 结构体都已包含 `WAFEnabled *bool` 字段
- 在 `internal/web/server.go` 中，`handleRequest` 方法会根据域名的 `waf_enabled` 配置决定是否启用 WAF 检查
- 在 `internal/proxy/manager.go` 中，代理管理器会正确处理 WAF 配置

## 使用场景

### 场景 1：为特定域名禁用 WAF

某些内部 API 或测试环境可能需要禁用 WAF 以避免误拦截：

1. 进入代理规则编辑页面
2. 找到 "WAF 防护" 配置区域
3. 点击 "禁用" 按钮
4. 保存配置

### 场景 2：为特定域名强制启用 WAF

即使全局 WAF 被禁用，某些重要的公开域名仍需要 WAF 保护：

1. 进入代理规则编辑页面
2. 找到 "WAF 防护" 配置区域
3. 点击 "启用" 按钮
4. 保存配置

### 场景 3：使用全局配置（推荐）

大多数情况下，使用全局 WAF 配置即可：

1. 进入代理规则编辑页面
2. 找到 "WAF 防护" 配置区域
3. 点击 "全局" 按钮（默认选项）
4. 保存配置

## 默认行为

- 新创建的代理规则、静态站点和 PHP 站点默认使用全局 WAF 配置（`waf_enabled = null`）
- 如果全局 WAF 启用，则默认所有站点都受保护
- 如果全局 WAF 禁用，则默认所有站点都不受保护
- 用户可以随时为特定域名/站点覆盖全局配置

## 技术细节

### 三态逻辑

使用 `*bool` 类型（Go）和 `boolean | null`（TypeScript）实现三态逻辑：

- `null`: 使用全局配置
- `true`: 强制启用
- `false`: 强制禁用

### 配置优先级

```
域名级别配置 > 全局配置
```

即：如果域名设置了 `waf_enabled = true` 或 `false`，则使用域名级别的配置；否则使用全局配置。

## 测试建议

1. 创建一个新的代理规则，验证默认为"全局"配置
2. 修改为"启用"，保存后刷新页面，验证配置是否保存成功
3. 修改为"禁用"，保存后刷新页面，验证配置是否保存成功
4. 修改回"全局"，保存后刷新页面，验证配置是否保存成功
5. 对静态站点和 PHP 站点重复上述测试

## 兼容性

- 向后兼容：现有配置中没有 `waf_enabled` 字段的域名/站点会自动使用全局配置
- 数据库迁移：不需要额外的数据库迁移，配置文件会自动升级


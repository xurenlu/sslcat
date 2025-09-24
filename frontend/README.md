# WithSSL 现代化前端

基于 Vite + React + TypeScript + Chakra UI 构建的现代化管理界面。

## 技术栈

- **构建工具**: Vite 5.x
- **框架**: React 18 + TypeScript
- **UI 库**: Chakra UI 2.x (基于用户偏好配置)
- **路由**: React Router DOM 6.x
- **图标**: React Icons (Feather Icons)
- **HTTP 客户端**: Axios
- **状态管理**: React Hooks

## 快速开始

### 开发环境

1. 确保已安装 Node.js (推荐 18.x 或更高版本)
2. 安装依赖：
   ```bash
   npm install
   ```
3. 启动开发服务器：
   ```bash
   npm run dev
   # 或者从项目根目录运行
   make dev-frontend
   ```
4. 在浏览器中访问 http://localhost:3000

### 生产构建

```bash
# 构建前端
npm run build

# 或者从项目根目录运行
make build-frontend

# 完整构建（前端 + 后端）
make build-all
```

## 项目结构

```
frontend/
├── public/                 # 静态资源
├── src/
│   ├── components/        # 通用组件
│   │   ├── Layout.tsx     # 布局组件
│   │   ├── Sidebar.tsx    # 侧边栏
│   │   └── Header.tsx     # 头部
│   ├── pages/             # 页面组件
│   │   ├── Dashboard.tsx  # 仪表板
│   │   ├── ProxyList.tsx  # 代理管理
│   │   ├── SSLManagement.tsx # SSL证书管理
│   │   ├── Settings.tsx   # 系统设置
│   │   ├── Security.tsx   # 安全中心
│   │   └── Notifications.tsx # 通知管理
│   ├── hooks/             # 自定义 Hooks
│   │   └── useApi.ts      # API 请求 Hook
│   ├── utils/             # 工具函数
│   │   └── api.ts         # API 服务
│   ├── types/             # TypeScript 类型定义
│   │   └── index.ts       # 通用类型
│   ├── App.tsx            # 主应用组件
│   ├── main.tsx           # 应用入口点
│   ├── theme.ts           # Chakra UI 主题配置
│   └── index.css          # 全局样式
├── package.json           # 项目配置
├── tsconfig.json          # TypeScript 配置
├── vite.config.ts         # Vite 配置
└── README.md              # 项目说明
```

## 开发指南

### API 集成

前端通过 `/api` 路径与后端通信，Vite 开发服务器配置了代理：

```typescript
// vite.config.ts
server: {
  port: 3000,
  proxy: {
    '/api': {
      target: 'http://localhost:8443',
      changeOrigin: true,
    },
  },
}
```

### 添加新页面

1. 在 `src/pages/` 目录创建新组件
2. 在 `src/App.tsx` 中添加路由
3. 在 `src/components/Sidebar.tsx` 中添加导航链接

### 主题定制

修改 `src/theme.ts` 文件来自定义 Chakra UI 主题：

```typescript
const theme = extendTheme({
  colors: {
    brand: {
      // 自定义品牌颜色
    },
  },
  // 其他主题配置
})
```

### API 请求

使用 `src/hooks/useApi.ts` 简化 API 请求：

```typescript
import { useApi } from '../hooks/useApi'
import { apiService } from '../utils/api'

function MyComponent() {
  const { data, loading, error, refetch } = useApi(
    () => apiService.getStats(),
    { immediate: true }
  )
  
  return (
    // 组件内容
  )
}
```

## 构建部署

### 嵌入式部署

前端文件会被嵌入到 Go 二进制文件中：

1. `make build` 会自动构建前端并嵌入到 Go 程序
2. 生产环境中，所有静态资源都从内存中提供服务
3. 无需单独部署前端文件

### 访问路径

- 管理界面：`/admin/spa/` (SPA 路由)
- 静态资源：`/admin/assets/` (CSS, JS, 图片等)
- API 接口：`/admin/api/` (后端 API)

## 开发最佳实践

1. **组件设计**: 使用 Chakra UI 组件，保持一致的设计语言
2. **类型安全**: 充分利用 TypeScript 的类型检查
3. **错误处理**: 使用统一的错误处理机制
4. **性能优化**: 使用 React.memo, useMemo, useCallback 优化性能
5. **可访问性**: 遵循 WCAG 指南，确保界面可访问

## 故障排除

### 常见问题

1. **Node.js 版本问题**: 确保使用 Node.js 18 或更高版本
2. **依赖安装失败**: 删除 `node_modules` 和 `package-lock.json`，重新安装
3. **构建失败**: 检查 TypeScript 错误和 ESLint 警告
4. **开发服务器无法启动**: 确保端口 3000 未被占用

### 调试技巧

1. 使用浏览器开发者工具
2. 检查网络请求和响应
3. 查看控制台错误信息
4. 使用 React Developer Tools 扩展

## 贡献指南

1. 遵循现有的代码风格
2. 添加必要的类型定义
3. 编写清晰的组件文档
4. 测试新功能的兼容性

## 许可证

与主项目保持一致。

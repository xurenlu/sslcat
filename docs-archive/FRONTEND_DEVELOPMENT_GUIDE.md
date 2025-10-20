# SSLcat 前端开发指南

## 🚨 Node.js 环境问题解决方案

### 问题描述
当前系统存在 Node.js 依赖库问题：
```
dyld[88520]: Library not loaded: /opt/homebrew/opt/icu4c/lib/libicui18n.74.dylib
```

### 🔧 解决方案

#### 方案 1: 修复 Node.js 环境（推荐）
```bash
# 自动修复
make fix-node

# 或手动修复
brew reinstall icu4c node
npm install -g pnpm
```

#### 方案 2: 使用简单开发模式（临时）
```bash
# 启动简单开发模式（绕过 Node.js 问题）
make dev-frontend-simple
```

#### 方案 3: 使用完整前端（修复后）
```bash
# 修复环境后使用完整前端
make dev-frontend
```

## 🎯 开发模式对比

### 简单开发模式
- ✅ **优点**: 绕过 Node.js 环境问题，快速启动
- ✅ **功能**: 显示管理面板概览和功能说明
- ❌ **限制**: 无完整 React 交互功能
- 🎯 **适用**: 快速预览和演示

### 完整开发模式
- ✅ **优点**: 完整的 React + TypeScript 开发环境
- ✅ **功能**: 热重载、完整交互、组件开发
- ❌ **要求**: 需要修复 Node.js 环境
- 🎯 **适用**: 前端开发和功能实现

## 🚀 快速开始

### 1. 启动后端服务
```bash
# 开发模式启动后端
make dev

# 或直接运行
go run main.go --config sslcat.conf --log-level debug
```

### 2. 启动前端服务

#### 简单模式（推荐先试这个）
```bash
make dev-frontend-simple
```

#### 完整模式（需要修复环境）
```bash
# 先修复环境
make fix-node

# 然后启动完整前端
make dev-frontend
```

### 3. 访问管理面板
- **简单模式**: http://localhost:8443/admin/spa
- **完整模式**: http://localhost:3000 (前端) + http://localhost:8443 (后端API)
- **传统界面**: http://localhost:8443/admin

## 🛠️ 开发工作流

### 前端开发（完整模式）
```bash
# 1. 修复 Node.js 环境
make fix-node

# 2. 启动后端服务（终端1）
make dev

# 3. 启动前端服务（终端2）
make dev-frontend

# 4. 开始开发
# - 前端代码在 frontend/src/ 目录
# - 支持热重载
# - TypeScript 类型检查
# - Chakra UI 组件库
```

### 后端开发（简单模式）
```bash
# 1. 启动后端服务
make dev

# 2. 启动简单前端（可选）
make dev-frontend-simple

# 3. 访问管理界面
# - 传统界面: http://localhost:8443/admin
# - 简单前端: http://localhost:8443/admin/spa
```

## 📁 项目结构

```
sslcat/
├── frontend/                 # React 前端项目
│   ├── src/
│   │   ├── components/       # 通用组件
│   │   ├── pages/           # 页面组件
│   │   ├── hooks/           # 自定义 Hooks
│   │   └── utils/           # 工具函数
│   ├── package.json         # 依赖配置
│   └── vite.config.ts       # Vite 配置
├── internal/
│   ├── assets/
│   │   └── frontend/        # 嵌入的前端文件
│   └── web/
│       └── frontend_routes.go # 前端路由
├── scripts/
│   ├── build-frontend.sh    # 前端构建脚本
│   ├── dev-frontend.sh      # 完整开发服务器
│   ├── start-frontend-dev.sh # 简单开发服务器
│   └── fix-node-env.sh      # 环境修复脚本
└── Makefile                 # 构建配置
```

## 🔧 环境要求

### 完整开发模式
- **Node.js**: 18+ (需要修复环境问题)
- **pnpm**: 包管理器
- **Go**: 1.21+

### 简单开发模式
- **Go**: 1.21+ (仅后端)

## 🎨 前端技术栈

- **框架**: React 18 + TypeScript
- **构建工具**: Vite
- **UI库**: Chakra UI
- **路由**: React Router v6
- **状态管理**: React Hooks
- **HTTP客户端**: Axios
- **图标**: React Icons

## 📋 可用命令

```bash
# 环境修复
make fix-node                 # 修复 Node.js 环境

# 前端开发
make dev-frontend             # 完整前端开发服务器
make dev-frontend-simple      # 简单前端开发服务器

# 构建
make build-frontend           # 构建前端
make build                    # 构建完整项目

# 后端开发
make dev                      # 启动后端开发服务器
make build                    # 构建后端
```

## 🚨 故障排除

### Node.js 环境问题
```bash
# 检查 Node.js 版本
node --version

# 检查 pnpm 安装
pnpm --version

# 修复环境
make fix-node
```

### 端口冲突
- **后端**: 8443 (可在配置文件中修改)
- **前端**: 3000 (可在 vite.config.ts 中修改)

### 依赖问题
```bash
# 清理并重新安装
cd frontend
rm -rf node_modules package-lock.json
pnpm install
```

## 🎉 开发建议

1. **先使用简单模式**: 快速验证后端功能
2. **修复环境后使用完整模式**: 进行前端开发
3. **使用热重载**: 提高开发效率
4. **遵循组件化**: 保持代码结构清晰
5. **使用 TypeScript**: 提高代码质量

## 📞 技术支持

如果遇到问题，请检查：
1. Node.js 和 pnpm 是否正确安装
2. 端口是否被占用
3. 防火墙设置
4. 依赖版本兼容性

---

**注意**: 当前推荐使用简单开发模式来快速启动项目，完整的前端开发需要先修复 Node.js 环境问题。

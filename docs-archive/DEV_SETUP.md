# SSLcat 开发环境设置

## 概述

此开发环境配置允许您同时运行 Go 后端服务和 Vite 前端开发服务器，实现前后端分离开发。

## 架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   浏览器访问     │    │   Vite 前端     │    │   Go 后端       │
│  localhost:9980 │───▶│   localhost:9980│───▶│  localhost:80   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                │  /api/* 代理转发        │
                                └────────────────────────┘
```

## 端口配置

- **前端开发服务器**: `localhost:9980` (Vite)
- **Go 后端服务**: `localhost:80` (HTTP) 和 `localhost:443` (HTTPS)
- **API 请求**: 自动从 9980 端口代理到 80 端口

## 快速启动

### 方法 1: 使用简化脚本 (推荐)

```bash
# 同时启动前后端
./dev.sh

# 只启动后端
./dev.sh backend

# 只启动前端
./dev.sh frontend
```

### 方法 2: 使用完整脚本

```bash
./dev-start.sh
```

### 方法 3: 手动启动

```bash
# 终端 1: 启动 Go 后端
go run main.go -config sslcat-dev.conf -port 443 -host 0.0.0.0

# 终端 2: 启动 Vite 前端
cd frontend
npm run dev
```

## 开发配置说明

### Vite 配置 (frontend/vite.config.ts)

```typescript
server: {
  port: 9980,
  host: '0.0.0.0',
  proxy: {
    '/api': {
      target: 'http://localhost:80',
      changeOrigin: true,
      secure: false,
    },
    '/sslcat-panel': {
      target: 'http://localhost:80',
      changeOrigin: true,
      secure: false,
    },
  },
}
```

### Go 开发配置 (sslcat-dev.conf)

- **调试模式**: `debug: true`
- **访问日志**: 启用
- **SSL 测试环境**: `staging: true`
- **自签名证书**: 允许
- **Vite User-Agent**: 已添加到允许列表

## 访问地址

- **前端开发**: http://localhost:9980
- **后端 API**: http://localhost:80/api/
- **管理面板**: http://localhost:80/sslcat-panel/
- **HTTPS**: https://localhost:443 (需要接受自签名证书)

## 开发工作流

1. **前端开发**: 在 `frontend/` 目录下修改 React 代码
2. **API 开发**: 在 Go 代码中修改 API 接口
3. **热重载**: 前端代码修改后自动刷新，后端需要重启
4. **调试**: 使用浏览器开发者工具调试前端，查看 Go 日志调试后端

## 生产部署

开发完成后，使用以下命令构建生产版本：

```bash
# 构建前端
cd frontend
npm run build

# 启动生产服务 (前端已嵌入 Go 服务)
go run main.go -config sslcat.conf -port 443 -host 0.0.0.0
```

## 故障排除

### 端口被占用

```bash
# 查看端口占用
lsof -i :80
lsof -i :443
lsof -i :9980

# 停止占用进程
kill -9 <PID>
```

### 代理不工作

1. 检查 Go 服务是否在 80 端口运行
2. 检查 Vite 代理配置
3. 查看浏览器网络面板中的请求

### SSL 证书问题

开发环境使用自签名证书，浏览器会显示安全警告，点击"高级"→"继续访问"即可。

## 注意事项

1. **权限问题**: 80 和 443 端口需要 root 权限，建议使用 `sudo` 运行
2. **防火墙**: 确保防火墙允许相关端口
3. **缓存**: 开发时建议禁用浏览器缓存
4. **日志**: 开发配置启用了详细日志，便于调试

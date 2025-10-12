import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  base: '/',  // 使用根路径，后端会动态重写为正确的 adminPrefix
  
  // 定义全局变量
  define: {
    __APP_VERSION__: JSON.stringify(process.env.npm_package_version || '1.0.0'),
  },
  
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    // 生成 source maps（用于 Sentry 错误追踪）
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: undefined,
        // Source map 文件名（可选，方便管理）
        sourcemapBaseUrl: undefined,
      },
    },
  },
  server: {
    port: 9980,
    host: '0.0.0.0',
    proxy: {
      // 只代理 API 请求，不代理前端路由
      '^/sslcat-panel2/api': {
        target: 'http://localhost:80',
        changeOrigin: true,
        secure: false,
        ws: true, // 启用 WebSocket 代理
      },
      // 备用：直接匹配 /api 路径（如果前端直接调用 /api）
      '^/api': {
        target: 'http://localhost:80',
        changeOrigin: true,
        secure: false,
        ws: true, // 启用 WebSocket 代理
        rewrite: (path) => `/sslcat-panel2${path}`,
      },
    },
  },
})

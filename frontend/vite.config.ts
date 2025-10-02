import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        manualChunks: undefined,
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

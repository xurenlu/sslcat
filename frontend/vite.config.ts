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
    // 生产环境不生成 source maps，减少文件大小
    sourcemap: false,
    // 启用代码压缩（使用 esbuild，更快）
    minify: 'esbuild',
    // 设置 chunk 大小警告阈值
    chunkSizeWarningLimit: 1000,
    rollupOptions: {
      output: {
        // 启用代码分割
        manualChunks: {
          // 将 React 相关库分离
          'react-vendor': ['react', 'react-dom'],
          // 将 Chakra UI 分离
          'chakra-vendor': ['@chakra-ui/react', '@emotion/react', '@emotion/styled', 'framer-motion'],
          // 将路由相关分离
          'router-vendor': ['react-router-dom'],
          // 将工具库分离
          'utils-vendor': ['axios', 'i18next', 'react-i18next'],
          // 将图标库分离
          'icons-vendor': ['react-icons'],
        },
      },
    },
  },
  server: {
    port: 9980,
    host: '0.0.0.0',
    proxy: {
      // 代理所有 API 请求到后端 (端口 8080)
      '^/sslcat-panel/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      // 备用：直接匹配 /api 路径
      '^/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
    },
  },
})

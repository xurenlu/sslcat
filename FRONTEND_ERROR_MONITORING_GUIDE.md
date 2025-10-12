# 前端错误监控集成指南

本指南介绍如何在 SSLCat 前端项目中集成错误监控方案，帮助你及时发现和解决生产环境中的问题。

## 目录

1. [方案对比](#方案对比)
2. [方案一：Sentry（推荐）](#方案一sentry推荐)
3. [方案二：自建错误收集系统](#方案二自建错误收集系统)
4. [方案三：开源替代方案](#方案三开源替代方案)
5. [通用最佳实践](#通用最佳实践)

---

## 方案对比

| 方案 | 优点 | 缺点 | 适用场景 |
|------|------|------|----------|
| **Sentry** | 功能强大、易用、社区活跃 | 免费额度有限，需要外部服务 | 中小型项目，快速上线 |
| **自建系统** | 完全可控、无外部依赖、数据私密 | 需要开发和维护成本 | 对数据安全要求高的项目 |
| **GlitchTip** | 开源、可自托管、兼容 Sentry SDK | 功能相对简单 | 想要开源且自托管的场景 |
| **Rollbar** | 性能好、AI 辅助分析 | 价格较高 | 企业级应用 |

---

## 方案一：Sentry（推荐）

Sentry 是目前最流行的错误监控平台，提供免费版本，功能强大且易于集成。

### 1.1 安装依赖

```bash
cd frontend
yarn add @sentry/react @sentry/tracing
```

### 1.2 配置 Sentry

创建文件 `frontend/src/utils/sentry.ts`:

```typescript
import * as Sentry from "@sentry/react";
import { BrowserTracing } from "@sentry/tracing";

// 初始化 Sentry
export function initSentry() {
  // 只在生产环境启用
  if (import.meta.env.MODE !== 'production') {
    return;
  }

  Sentry.init({
    // 替换为你的 Sentry DSN
    dsn: "https://your-dsn@sentry.io/project-id",
    
    // 集成追踪
    integrations: [
      new BrowserTracing(),
      new Sentry.Replay({
        maskAllText: false,
        blockAllMedia: false,
      }),
    ],

    // 性能监控采样率（0-1）
    tracesSampleRate: 0.1,

    // Session 重放采样率
    replaysSessionSampleRate: 0.1,
    replaysOnErrorSampleRate: 1.0,

    // 环境标识
    environment: import.meta.env.MODE,

    // 版本号（从 package.json 获取）
    release: `sslcat-frontend@${__APP_VERSION__}`,

    // 忽略的错误
    ignoreErrors: [
      // 浏览器扩展导致的错误
      'top.GLOBALS',
      'ResizeObserver loop limit exceeded',
      // 网络错误
      'Network request failed',
      'NetworkError',
    ],

    // 请求前处理（可以过滤敏感信息）
    beforeSend(event, hint) {
      // 过滤掉本地开发错误
      if (window.location.hostname === 'localhost') {
        return null;
      }

      // 可以在这里过滤敏感信息
      if (event.request) {
        delete event.request.cookies;
      }

      return event;
    },

    // 设置用户上下文
    beforeBreadcrumb(breadcrumb) {
      // 过滤敏感的面包屑
      if (breadcrumb.category === 'console' && breadcrumb.level === 'log') {
        return null;
      }
      return breadcrumb;
    },
  });
}

// 设置用户信息
export function setSentryUser(user: { id: string; username: string; email?: string }) {
  Sentry.setUser({
    id: user.id,
    username: user.username,
    email: user.email,
  });
}

// 清除用户信息（登出时调用）
export function clearSentryUser() {
  Sentry.setUser(null);
}

// 手动上报错误
export function captureError(error: Error, context?: Record<string, any>) {
  Sentry.captureException(error, {
    extra: context,
  });
}

// 手动上报消息
export function captureMessage(message: string, level: Sentry.SeverityLevel = 'info') {
  Sentry.captureMessage(message, level);
}

// 添加面包屑
export function addBreadcrumb(message: string, category: string, data?: Record<string, any>) {
  Sentry.addBreadcrumb({
    message,
    category,
    data,
    level: 'info',
  });
}
```

### 1.3 在主入口初始化

修改 `frontend/src/main.tsx`:

```typescript
import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.tsx'
import './index.css'
import { initSentry } from './utils/sentry'

// 初始化 Sentry（在所有代码之前）
initSentry()

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
```

### 1.4 在 React 组件中使用 ErrorBoundary

修改 `frontend/src/App.tsx`:

```typescript
import * as Sentry from "@sentry/react";
import { ChakraProvider } from '@chakra-ui/react'
// ... 其他导入

function App() {
  return (
    <Sentry.ErrorBoundary 
      fallback={<ErrorFallback />}
      showDialog
    >
      <ChakraProvider theme={theme}>
        {/* 你的应用内容 */}
      </ChakraProvider>
    </Sentry.ErrorBoundary>
  )
}

// 错误回退组件
function ErrorFallback() {
  return (
    <div style={{ 
      padding: '2rem', 
      textAlign: 'center',
      minHeight: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center'
    }}>
      <h1>😅 出错了</h1>
      <p>我们已经收到错误报告，正在处理中...</p>
      <button 
        onClick={() => window.location.reload()}
        style={{
          marginTop: '1rem',
          padding: '0.5rem 1rem',
          fontSize: '1rem',
          cursor: 'pointer'
        }}
      >
        刷新页面
      </button>
    </div>
  )
}

export default App
```

### 1.5 在 API 调用中使用

修改 `frontend/src/utils/api.ts`:

```typescript
import axios from 'axios';
import { captureError, addBreadcrumb } from './sentry';

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
});

// 请求拦截器
api.interceptors.request.use(
  (config) => {
    // 记录 API 请求
    addBreadcrumb(
      `API Request: ${config.method?.toUpperCase()} ${config.url}`,
      'http',
      { url: config.url, method: config.method }
    );
    return config;
  },
  (error) => {
    captureError(error, { context: 'API Request Interceptor' });
    return Promise.reject(error);
  }
);

// 响应拦截器
api.interceptors.response.use(
  (response) => response,
  (error) => {
    // 记录 API 错误
    const errorContext = {
      url: error.config?.url,
      method: error.config?.method,
      status: error.response?.status,
      statusText: error.response?.statusText,
    };

    captureError(error, errorContext);
    
    return Promise.reject(error);
  }
);

export default api;
```

### 1.6 在 AuthContext 中设置用户信息

修改 `frontend/src/contexts/AuthContext.tsx`:

```typescript
import { setSentryUser, clearSentryUser } from '../utils/sentry';

// 登录成功后
const login = async (username: string, password: string) => {
  const response = await api.post('/login', { username, password });
  const user = response.data.user;
  
  // 设置 Sentry 用户信息
  setSentryUser({
    id: user.id,
    username: user.username,
    email: user.email,
  });
  
  setUser(user);
};

// 登出时
const logout = () => {
  clearSentryUser();
  setUser(null);
};
```

### 1.7 配置环境变量

创建 `frontend/.env.production`:

```bash
VITE_SENTRY_DSN=https://your-dsn@sentry.io/project-id
VITE_SENTRY_ENVIRONMENT=production
```

然后修改 `sentry.ts` 使用环境变量:

```typescript
dsn: import.meta.env.VITE_SENTRY_DSN,
environment: import.meta.env.VITE_SENTRY_ENVIRONMENT || import.meta.env.MODE,
```

### 1.8 配置 Source Maps 上传（可选但推荐）

安装 Sentry CLI:

```bash
yarn add --dev @sentry/vite-plugin
```

修改 `frontend/vite.config.ts`:

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { sentryVitePlugin } from '@sentry/vite-plugin'

export default defineConfig({
  plugins: [
    react(),
    // 只在生产构建时上传 source maps
    process.env.NODE_ENV === 'production' && sentryVitePlugin({
      org: "your-org",
      project: "your-project",
      authToken: process.env.SENTRY_AUTH_TOKEN,
    }),
  ],
  build: {
    sourcemap: true, // 生成 source maps
  },
})
```

---

## 方案二：自建错误收集系统

如果你不想依赖第三方服务，可以自建一个简单但有效的错误收集系统。

### 2.1 前端错误收集器

创建 `frontend/src/utils/errorMonitor.ts`:

```typescript
interface ErrorInfo {
  message: string;
  stack?: string;
  level: 'error' | 'warning' | 'info';
  timestamp: number;
  url: string;
  userAgent: string;
  userId?: string;
  username?: string;
  extra?: Record<string, any>;
}

interface UnhandledError {
  message: string;
  filename?: string;
  lineno?: number;
  colno?: number;
  error?: Error;
}

class ErrorMonitor {
  private endpoint: string;
  private userId?: string;
  private username?: string;
  private batchErrors: ErrorInfo[] = [];
  private batchSize = 10;
  private batchTimeout = 5000; // 5秒
  private batchTimer?: NodeJS.Timeout;

  constructor(endpoint: string = '/api/errors') {
    this.endpoint = endpoint;
    this.init();
  }

  private init() {
    // 捕获未处理的错误
    window.addEventListener('error', (event) => {
      this.captureError({
        message: event.message,
        filename: event.filename,
        lineno: event.lineno,
        colno: event.colno,
        error: event.error,
      });
    });

    // 捕获未处理的 Promise 拒绝
    window.addEventListener('unhandledrejection', (event) => {
      this.captureError({
        message: `Unhandled Promise Rejection: ${event.reason}`,
        error: event.reason instanceof Error ? event.reason : undefined,
      });
    });

    // 页面卸载时发送剩余错误
    window.addEventListener('beforeunload', () => {
      this.flush();
    });

    // 页面隐藏时发送错误（移动端）
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this.flush();
      }
    });
  }

  setUser(userId: string, username: string) {
    this.userId = userId;
    this.username = username;
  }

  clearUser() {
    this.userId = undefined;
    this.username = undefined;
  }

  captureError(error: UnhandledError | Error, extra?: Record<string, any>) {
    const errorInfo: ErrorInfo = {
      message: error instanceof Error ? error.message : error.message,
      stack: error instanceof Error ? error.stack : error.error?.stack,
      level: 'error',
      timestamp: Date.now(),
      url: window.location.href,
      userAgent: navigator.userAgent,
      userId: this.userId,
      username: this.username,
      extra: {
        ...extra,
        ...(!(error instanceof Error) && {
          filename: error.filename,
          lineno: error.lineno,
          colno: error.colno,
        }),
      },
    };

    this.addToBatch(errorInfo);
  }

  captureMessage(message: string, level: 'error' | 'warning' | 'info' = 'info', extra?: Record<string, any>) {
    const errorInfo: ErrorInfo = {
      message,
      level,
      timestamp: Date.now(),
      url: window.location.href,
      userAgent: navigator.userAgent,
      userId: this.userId,
      username: this.username,
      extra,
    };

    this.addToBatch(errorInfo);
  }

  private addToBatch(error: ErrorInfo) {
    this.batchErrors.push(error);

    // 如果达到批量大小，立即发送
    if (this.batchErrors.length >= this.batchSize) {
      this.flush();
      return;
    }

    // 否则设置定时器
    if (!this.batchTimer) {
      this.batchTimer = setTimeout(() => {
        this.flush();
      }, this.batchTimeout);
    }
  }

  private flush() {
    if (this.batchErrors.length === 0) {
      return;
    }

    const errors = [...this.batchErrors];
    this.batchErrors = [];

    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = undefined;
    }

    // 使用 sendBeacon API（更可靠，即使页面关闭也能发送）
    if (navigator.sendBeacon) {
      const blob = new Blob([JSON.stringify({ errors })], {
        type: 'application/json',
      });
      navigator.sendBeacon(this.endpoint, blob);
    } else {
      // 降级方案
      fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ errors }),
        keepalive: true,
      }).catch(console.error);
    }
  }
}

// 导出单例
export const errorMonitor = new ErrorMonitor();

// 便捷函数
export function captureError(error: Error, context?: Record<string, any>) {
  errorMonitor.captureError(error, context);
}

export function captureMessage(message: string, level: 'error' | 'warning' | 'info' = 'info') {
  errorMonitor.captureMessage(message, level);
}

export function setUser(userId: string, username: string) {
  errorMonitor.setUser(userId, username);
}

export function clearUser() {
  errorMonitor.clearUser();
}
```

### 2.2 后端错误收集 API

创建 `internal/web/errors.go`:

```go
package web

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type FrontendError struct {
	Message   string                 `json:"message"`
	Stack     string                 `json:"stack,omitempty"`
	Level     string                 `json:"level"`
	Timestamp int64                  `json:"timestamp"`
	URL       string                 `json:"url"`
	UserAgent string                 `json:"userAgent"`
	UserID    string                 `json:"userId,omitempty"`
	Username  string                 `json:"username,omitempty"`
	Extra     map[string]interface{} `json:"extra,omitempty"`
}

type ErrorBatch struct {
	Errors []FrontendError `json:"errors"`
}

type ErrorLogger struct {
	logDir     string
	currentLog *os.File
	mu         sync.Mutex
	date       string
}

func NewErrorLogger(logDir string) (*ErrorLogger, error) {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, err
	}

	el := &ErrorLogger{
		logDir: logDir,
	}

	if err := el.rotateLog(); err != nil {
		return nil, err
	}

	// 每天轮转日志
	go el.dailyRotation()

	return el, nil
}

func (el *ErrorLogger) dailyRotation() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		currentDate := time.Now().Format("2006-01-02")
		if currentDate != el.date {
			el.rotateLog()
		}
	}
}

func (el *ErrorLogger) rotateLog() error {
	el.mu.Lock()
	defer el.mu.Unlock()

	if el.currentLog != nil {
		el.currentLog.Close()
	}

	el.date = time.Now().Format("2006-01-02")
	logPath := filepath.Join(el.logDir, "frontend-errors-"+el.date+".jsonl")

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	el.currentLog = f
	return nil
}

func (el *ErrorLogger) Log(errors []FrontendError) error {
	el.mu.Lock()
	defer el.mu.Unlock()

	for _, err := range errors {
		data, _ := json.Marshal(err)
		if _, writeErr := el.currentLog.Write(append(data, '\n')); writeErr != nil {
			return writeErr
		}
	}

	return el.currentLog.Sync()
}

func (el *ErrorLogger) Close() error {
	el.mu.Lock()
	defer el.mu.Unlock()

	if el.currentLog != nil {
		return el.currentLog.Close()
	}
	return nil
}

// HTTP Handler
func (s *Server) handleFrontendErrors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1024*1024)) // 限制 1MB
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var batch ErrorBatch
	if err := json.Unmarshal(body, &batch); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// 记录到日志
	if s.errorLogger != nil {
		if err := s.errorLogger.Log(batch.Errors); err != nil {
			log.Printf("Failed to log frontend errors: %v", err)
		}
	}

	// 打印到控制台（开发环境）
	for _, fe := range batch.Errors {
		if fe.Level == "error" {
			log.Printf("[Frontend Error] %s - %s (User: %s, URL: %s)", 
				fe.Level, fe.Message, fe.Username, fe.URL)
			if fe.Stack != "" {
				log.Printf("Stack: %s", fe.Stack)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"count":   len(batch.Errors),
	})
}
```

### 2.3 在 Server 中注册路由

修改 `internal/web/server.go`:

```go
type Server struct {
	// ... 现有字段
	errorLogger *ErrorLogger
}

func NewServer(config *config.Config) (*Server, error) {
	// ... 现有代码
	
	// 初始化错误日志器
	errorLogger, err := NewErrorLogger(filepath.Join(config.DataDir, "logs", "frontend-errors"))
	if err != nil {
		log.Printf("Warning: Failed to initialize error logger: %v", err)
	}
	
	s := &Server{
		// ... 现有字段
		errorLogger: errorLogger,
	}
	
	return s, nil
}

func (s *Server) setupRoutes() {
	// ... 现有路由
	
	// 前端错误收集 API（无需认证）
	s.mux.HandleFunc("/api/errors", s.handleFrontendErrors)
}

func (s *Server) Shutdown(ctx context.Context) error {
	// ... 现有关闭逻辑
	
	if s.errorLogger != nil {
		s.errorLogger.Close()
	}
	
	return s.httpServer.Shutdown(ctx)
}
```

### 2.4 前端集成

修改 `frontend/src/main.tsx`:

```typescript
import { errorMonitor } from './utils/errorMonitor'

// 应用启动时自动初始化，无需额外代码
```

在 `AuthContext` 中设置用户:

```typescript
import { setUser, clearUser } from '../utils/errorMonitor';

// 登录后
setUser(user.id, user.username);

// 登出时
clearUser();
```

### 2.5 查看错误日志

错误日志会保存在 `data/logs/frontend-errors/frontend-errors-YYYY-MM-DD.jsonl`

可以使用 `jq` 工具查看:

```bash
# 查看今天的错误
cat data/logs/frontend-errors/frontend-errors-$(date +%Y-%m-%d).jsonl | jq

# 统计错误类型
cat data/logs/frontend-errors/*.jsonl | jq -r '.message' | sort | uniq -c | sort -nr

# 查看特定用户的错误
cat data/logs/frontend-errors/*.jsonl | jq 'select(.username=="admin")'
```

---

## 方案三：开源替代方案

### 3.1 GlitchTip

GlitchTip 是 Sentry 的开源替代品，兼容 Sentry SDK。

**部署方式:**

```bash
# 使用 Docker Compose
docker-compose -f docker-compose.glitchtip.yml up -d
```

创建 `docker-compose.glitchtip.yml`:

```yaml
version: "3.8"

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: glitchtip
      POSTGRES_USER: glitchtip
      POSTGRES_PASSWORD: glitchtip
    volumes:
      - postgres-data:/var/lib/postgresql/data

  redis:
    image: redis:7

  web:
    image: glitchtip/glitchtip:latest
    depends_on:
      - postgres
      - redis
    ports:
      - "8000:8000"
    environment:
      DATABASE_URL: postgres://glitchtip:glitchtip@postgres:5432/glitchtip
      REDIS_URL: redis://redis:6379
      SECRET_KEY: your-secret-key-here
      PORT: 8000
      EMAIL_URL: smtp://user:password@smtp.example.com:587
    volumes:
      - uploads:/app/uploads

  worker:
    image: glitchtip/glitchtip:latest
    depends_on:
      - postgres
      - redis
    command: ./bin/run-celery-with-beat.sh
    environment:
      DATABASE_URL: postgres://glitchtip:glitchtip@postgres:5432/glitchtip
      REDIS_URL: redis://redis:6379
      SECRET_KEY: your-secret-key-here

volumes:
  postgres-data:
  uploads:
```

然后使用 Sentry SDK，只需修改 DSN 地址指向 GlitchTip 即可。

### 3.2 Rollbar

Rollbar 提供强大的 AI 辅助分析功能。

```bash
yarn add rollbar rollbar-react
```

使用方式类似 Sentry，详见官方文档。

---

## 通用最佳实践

### 4.1 错误分级

```typescript
// 严重错误：需要立即关注
captureError(error, { severity: 'critical' })

// 一般错误：正常监控
captureError(error, { severity: 'error' })

// 警告：可能的问题
captureMessage('API response time > 5s', 'warning')

// 信息：用于调试
captureMessage('User clicked button', 'info')
```

### 4.2 添加上下文信息

```typescript
// 添加用户操作上下文
captureError(error, {
  action: 'submit_form',
  formData: { /* 非敏感数据 */ },
  currentPage: '/dashboard',
})

// 添加业务上下文
captureError(error, {
  proxyId: '123',
  operation: 'update_config',
})
```

### 4.3 性能监控

```typescript
// 监控页面加载时间
window.addEventListener('load', () => {
  const perfData = window.performance.timing;
  const loadTime = perfData.loadEventEnd - perfData.navigationStart;
  
  if (loadTime > 3000) { // 超过 3 秒
    captureMessage(`Slow page load: ${loadTime}ms`, 'warning', {
      loadTime,
      url: window.location.href,
    });
  }
});

// 监控 API 响应时间
const startTime = Date.now();
try {
  const response = await api.get('/data');
  const duration = Date.now() - startTime;
  
  if (duration > 2000) { // 超过 2 秒
    captureMessage(`Slow API: ${duration}ms`, 'warning', {
      url: '/api/data',
      duration,
    });
  }
} catch (error) {
  captureError(error, { duration: Date.now() - startTime });
}
```

### 4.4 采样策略

对于高流量应用，可以设置采样率:

```typescript
// 只上报 10% 的错误
if (Math.random() < 0.1) {
  captureError(error);
}

// 或者只上报特定类型的错误
if (error.name === 'NetworkError' || error.status >= 500) {
  captureError(error);
}
```

### 4.5 错误去重

```typescript
// 使用错误指纹去重
function getErrorFingerprint(error: Error): string {
  return `${error.name}:${error.message}:${error.stack?.split('\n')[1]}`;
}

const recentErrors = new Set<string>();

function captureErrorWithDedup(error: Error) {
  const fingerprint = getErrorFingerprint(error);
  
  if (recentErrors.has(fingerprint)) {
    return; // 重复错误，不上报
  }
  
  recentErrors.add(fingerprint);
  
  // 5分钟后清除
  setTimeout(() => {
    recentErrors.delete(fingerprint);
  }, 5 * 60 * 1000);
  
  captureError(error);
}
```

### 4.6 隐私保护

```typescript
// 过滤敏感信息
function sanitizeError(error: any) {
  const sanitized = { ...error };
  
  // 移除敏感字段
  const sensitiveFields = ['password', 'token', 'secret', 'apiKey'];
  
  function removeSensitive(obj: any) {
    if (typeof obj !== 'object' || obj === null) return;
    
    for (const key in obj) {
      if (sensitiveFields.some(field => key.toLowerCase().includes(field))) {
        obj[key] = '[REDACTED]';
      } else if (typeof obj[key] === 'object') {
        removeSensitive(obj[key]);
      }
    }
  }
  
  removeSensitive(sanitized);
  return sanitized;
}
```

### 4.7 创建错误监控面板

你可以在管理后台添加一个错误监控页面:

创建 `frontend/src/pages/ErrorMonitoring.tsx`:

```typescript
import React, { useState, useEffect } from 'react';
import {
  Box,
  Heading,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  Text,
  Spinner,
  useToast,
  Button,
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalCloseButton,
  Code,
  VStack,
} from '@chakra-ui/react';
import api from '../utils/api';

interface FrontendError {
  message: string;
  stack?: string;
  level: string;
  timestamp: number;
  url: string;
  userAgent: string;
  userId?: string;
  username?: string;
  extra?: Record<string, any>;
}

const ErrorMonitoring: React.FC = () => {
  const [errors, setErrors] = useState<FrontendError[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedError, setSelectedError] = useState<FrontendError | null>(null);
  const toast = useToast();

  useEffect(() => {
    loadErrors();
  }, []);

  const loadErrors = async () => {
    try {
      const response = await api.get('/errors/recent');
      setErrors(response.data.errors);
    } catch (error) {
      toast({
        title: '加载失败',
        description: '无法加载错误日志',
        status: 'error',
        duration: 3000,
      });
    } finally {
      setLoading(false);
    }
  };

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'error':
        return 'red';
      case 'warning':
        return 'yellow';
      case 'info':
        return 'blue';
      default:
        return 'gray';
    }
  };

  if (loading) {
    return (
      <Box textAlign="center" py={10}>
        <Spinner size="xl" />
      </Box>
    );
  }

  return (
    <Box p={6}>
      <Heading mb={6}>前端错误监控</Heading>

      <Table variant="simple">
        <Thead>
          <Tr>
            <Th>时间</Th>
            <Th>级别</Th>
            <Th>消息</Th>
            <Th>用户</Th>
            <Th>URL</Th>
            <Th>操作</Th>
          </Tr>
        </Thead>
        <Tbody>
          {errors.map((error, index) => (
            <Tr key={index}>
              <Td>
                <Text fontSize="sm">
                  {new Date(error.timestamp).toLocaleString('zh-CN')}
                </Text>
              </Td>
              <Td>
                <Badge colorScheme={getLevelColor(error.level)}>
                  {error.level}
                </Badge>
              </Td>
              <Td>
                <Text noOfLines={1}>{error.message}</Text>
              </Td>
              <Td>{error.username || '-'}</Td>
              <Td>
                <Text fontSize="sm" noOfLines={1}>
                  {error.url}
                </Text>
              </Td>
              <Td>
                <Button
                  size="sm"
                  onClick={() => setSelectedError(error)}
                >
                  详情
                </Button>
              </Td>
            </Tr>
          ))}
        </Tbody>
      </Table>

      {/* 错误详情弹窗 */}
      <Modal
        isOpen={selectedError !== null}
        onClose={() => setSelectedError(null)}
        size="xl"
      >
        <ModalOverlay />
        <ModalContent maxW="800px">
          <ModalHeader>错误详情</ModalHeader>
          <ModalCloseButton />
          <ModalBody pb={6}>
            {selectedError && (
              <VStack align="stretch" spacing={4}>
                <Box>
                  <Text fontWeight="bold">消息:</Text>
                  <Text>{selectedError.message}</Text>
                </Box>

                {selectedError.stack && (
                  <Box>
                    <Text fontWeight="bold">堆栈:</Text>
                    <Code
                      display="block"
                      whiteSpace="pre"
                      p={3}
                      fontSize="xs"
                      overflowX="auto"
                    >
                      {selectedError.stack}
                    </Code>
                  </Box>
                )}

                <Box>
                  <Text fontWeight="bold">URL:</Text>
                  <Text fontSize="sm">{selectedError.url}</Text>
                </Box>

                <Box>
                  <Text fontWeight="bold">User Agent:</Text>
                  <Text fontSize="sm">{selectedError.userAgent}</Text>
                </Box>

                {selectedError.extra && (
                  <Box>
                    <Text fontWeight="bold">额外信息:</Text>
                    <Code
                      display="block"
                      whiteSpace="pre"
                      p={3}
                      fontSize="xs"
                    >
                      {JSON.stringify(selectedError.extra, null, 2)}
                    </Code>
                  </Box>
                )}
              </VStack>
            )}
          </ModalBody>
        </ModalContent>
      </Modal>
    </Box>
  );
};

export default ErrorMonitoring;
```

---

## 推荐方案

根据你的项目特点，我推荐：

1. **快速上线**: 使用 **Sentry 免费版**（方案一）
   - 5000 错误/月免费额度
   - 开箱即用，功能完善
   - 10 分钟即可完成集成

2. **数据私密性要求高**: 使用 **自建系统**（方案二）
   - 完全可控
   - 无外部依赖
   - 适合基础服务

3. **长期运营**: 考虑 **GlitchTip**（方案三）
   - 开源免费
   - 可自托管
   - 兼容 Sentry SDK

---

## 下一步

1. 选择一个方案
2. 按照指南集成
3. 在测试环境验证
4. 部署到生产环境
5. 配置告警通知（邮件/Webhook）
6. 定期查看和分析错误

如有任何问题，欢迎随时咨询！


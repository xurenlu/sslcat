import * as Sentry from "@sentry/react";

/**
 * 初始化 Sentry 错误监控
 * 
 * 环境变量配置：
 * - VITE_SENTRY_DSN: Sentry 项目的 DSN
 * - VITE_SENTRY_ENVIRONMENT: 环境标识（production/staging/development）
 * - VITE_SENTRY_TRACES_SAMPLE_RATE: 性能追踪采样率（0-1，默认 0.1）
 * - VITE_SENTRY_REPLAYS_SESSION_SAMPLE_RATE: 会话重放采样率（0-1，默认 0.1）
 * - VITE_SENTRY_ENABLED: 是否启用（默认只在生产环境启用）
 */
export function initSentry() {
  // 默认 DSN（生产环境）
  const DEFAULT_DSN = 'https://33dbec8e84b031d18045e279576a5296@o4510172014903296.ingest.us.sentry.io/4510172027486208';
  
  // 检查是否启用（生产环境默认启用）
  const isEnabled = import.meta.env.VITE_SENTRY_ENABLED === 'true' || 
                    import.meta.env.MODE === 'production';

  if (!isEnabled) {
    console.log('[Sentry] Disabled in current environment');
    return;
  }

  // 优先使用环境变量，否则使用默认 DSN
  const dsn = import.meta.env.VITE_SENTRY_DSN || DEFAULT_DSN;
  
  if (!dsn) {
    console.warn('[Sentry] DSN not configured.');
    return;
  }

  try {
    Sentry.init({
      dsn,

      // 集成配置
      integrations: [
        // 浏览器追踪（性能监控）
        Sentry.browserTracingIntegration({
          // 追踪路由变化
          enableInp: true,
        }),
        
        // 会话重放（用户操作录制）
        Sentry.replayIntegration({
          maskAllText: false,
          blockAllMedia: false,
          maskAllInputs: true, // 遮蔽所有输入框内容（隐私保护）
        }),

        // 反馈组件（用户可以主动提交反馈）
        Sentry.feedbackIntegration({
          colorScheme: 'system',
          showBranding: false,
          triggerLabel: '反馈问题',
          formTitle: '反馈问题',
          submitButtonLabel: '提交',
          cancelButtonLabel: '取消',
          confirmButtonLabel: '确认',
          addScreenshotButtonLabel: '添加截图',
          removeScreenshotButtonLabel: '移除截图',
          nameLabel: '姓名',
          namePlaceholder: '您的姓名',
          emailLabel: '邮箱',
          emailPlaceholder: '您的邮箱',
          messageLabel: '描述',
          messagePlaceholder: '请描述遇到的问题...',
          successMessageText: '感谢您的反馈！',
        }),
      ],

      // 性能监控采样率（0 = 禁用，1 = 100%）
      tracesSampleRate: parseFloat(import.meta.env.VITE_SENTRY_TRACES_SAMPLE_RATE || '0.1'),

      // Session 重放采样率
      replaysSessionSampleRate: parseFloat(import.meta.env.VITE_SENTRY_REPLAYS_SESSION_SAMPLE_RATE || '0.1'),
      
      // 出错时重放采样率（建议 100%，帮助调试）
      replaysOnErrorSampleRate: 1.0,

      // 环境标识
      environment: import.meta.env.VITE_SENTRY_ENVIRONMENT || import.meta.env.MODE || 'production',

      // 版本号（用于追踪哪个版本的问题）
      release: `sslcat-frontend@${import.meta.env.VITE_APP_VERSION || '1.0.0'}`,

      // 忽略的错误（避免噪音）
      ignoreErrors: [
        // 浏览器扩展导致的错误
        'top.GLOBALS',
        'originalCreateNotification',
        'canvas.contentDocument',
        'MyApp_RemoveAllHighlights',
        'atomicFindClose',
        
        // 已知的无害错误
        'ResizeObserver loop limit exceeded',
        'ResizeObserver loop completed with undelivered notifications',
        
        // 网络错误（通常是用户网络问题）
        'Network request failed',
        'NetworkError',
        'Failed to fetch',
        'Load failed',
        
        // 脚本加载错误（CDN 问题或浏览器插件干扰）
        'ChunkLoadError',
        'Loading chunk',
        
        // 取消的请求
        'The operation was aborted',
        'AbortError',
        
        // Safari 特有问题
        'WebKitMutationObserver',
      ],

      // 忽略的 URL（例如浏览器插件）
      denyUrls: [
        /extensions\//i,
        /^chrome:\/\//i,
        /^chrome-extension:\/\//i,
        /^moz-extension:\/\//i,
      ],

      // 请求前处理（可以修改或过滤事件）
      beforeSend(event, hint) {
        // 过滤本地开发环境（双重保险）
        if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
          return null;
        }

        // 过滤敏感信息
        if (event.request) {
          // 移除 cookies
          delete event.request.cookies;
          
          // 过滤 URL 中的敏感参数
          if (event.request.url) {
            try {
              const url = new URL(event.request.url);
              const sensitiveParams = ['token', 'password', 'secret', 'api_key', 'apikey'];
              sensitiveParams.forEach(param => {
                if (url.searchParams.has(param)) {
                  url.searchParams.set(param, '[REDACTED]');
                }
              });
              event.request.url = url.toString();
            } catch (e) {
              // URL 解析失败，保持原样
            }
          }
        }

        // 过滤额外数据中的敏感信息
        if (event.extra) {
          const sensitiveKeys = ['password', 'token', 'secret', 'apiKey', 'api_key', 'authorization'];
          Object.keys(event.extra).forEach(key => {
            if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
              event.extra![key] = '[REDACTED]';
            }
          });
        }

        return event;
      },

      // 面包屑前处理（过滤不需要的日志）
      beforeBreadcrumb(breadcrumb) {
        // 过滤 console.log（避免太多噪音）
        if (breadcrumb.category === 'console' && breadcrumb.level === 'log') {
          return null;
        }

        // 过滤点击事件的敏感信息
        if (breadcrumb.category === 'ui.click') {
          // 可以在这里过滤特定元素的点击
        }

        return breadcrumb;
      },
    });

    console.log('[Sentry] Initialized successfully', {
      environment: Sentry.getCurrentScope().getClient()?.getOptions().environment,
      release: Sentry.getCurrentScope().getClient()?.getOptions().release,
    });
  } catch (error) {
    console.error('[Sentry] Initialization failed:', error);
  }
}

/**
 * 设置用户信息（登录后调用）
 */
export function setSentryUser(user: { 
  id: string; 
  username: string; 
  email?: string;
  [key: string]: any;
}) {
  Sentry.setUser({
    id: user.id,
    username: user.username,
    email: user.email,
  });
  
  console.log('[Sentry] User set:', user.username);
}

/**
 * 清除用户信息（登出时调用）
 */
export function clearSentryUser() {
  Sentry.setUser(null);
  console.log('[Sentry] User cleared');
}

/**
 * 手动上报错误
 */
export function captureError(error: Error, context?: Record<string, any>) {
  Sentry.captureException(error, {
    extra: context,
  });
}

/**
 * 手动上报消息
 */
export function captureMessage(
  message: string, 
  level: 'fatal' | 'error' | 'warning' | 'log' | 'info' | 'debug' = 'info'
) {
  Sentry.captureMessage(message, level);
}

/**
 * 添加面包屑（用于调试上下文）
 */
export function addBreadcrumb(
  message: string, 
  category: string, 
  data?: Record<string, any>,
  level: 'fatal' | 'error' | 'warning' | 'log' | 'info' | 'debug' = 'info'
) {
  Sentry.addBreadcrumb({
    message,
    category,
    data,
    level,
  });
}

/**
 * 设置上下文标签（用于分组和过滤）
 */
export function setTag(key: string, value: string) {
  Sentry.setTag(key, value);
}

/**
 * 设置上下文信息
 */
export function setContext(name: string, context: Record<string, any>) {
  Sentry.setContext(name, context);
}

/**
 * 显示反馈对话框
 */
export function showReportDialog() {
  Sentry.showReportDialog();
}

// 导出 Sentry 实例供高级使用
export { Sentry };


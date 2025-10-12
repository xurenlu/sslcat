/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_SENTRY_DSN?: string
  readonly VITE_SENTRY_ENVIRONMENT?: string
  readonly VITE_SENTRY_ENABLED?: string
  readonly VITE_SENTRY_TRACES_SAMPLE_RATE?: string
  readonly VITE_SENTRY_REPLAYS_SESSION_SAMPLE_RATE?: string
  readonly VITE_APP_VERSION?: string
  readonly MODE: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

// 全局变量声明
declare const __APP_VERSION__: string


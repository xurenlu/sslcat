/**
 * 应用常量定义
 * Application Constants
 */

// Toast 消息持续时间（毫秒）
export const TOAST_DURATION = {
  SHORT: 3000,   // 3秒 - 成功消息、快速操作反馈
  MEDIUM: 5000,  // 5秒 - 错误/警告消息、一般操作反馈
  LONG: 8000,   // 8秒 - 重要通知、需要用户注意的消息
} as const

// API 请求超时时间（毫秒）
export const API_TIMEOUT = {
  QUICK: 5000,         // 5秒 - 快速操作（获取统计数据、简单查询）
  DEFAULT: 10000,      // 10秒 - 默认请求（大多数 API 调用）
  UPLOAD: 60000,       // 60秒 - 文件上传操作
  CERTIFICATE: 120000, // 120秒 - SSL 证书申请（可能需要较长时间）
  LONG_OPERATION: 180000, // 180秒 - 长时间操作（批量处理、复杂计算）
} as const

// 默认值常量
export const DEFAULTS = {
  TOAST_DURATION: TOAST_DURATION.MEDIUM,
  API_TIMEOUT: API_TIMEOUT.DEFAULT,
} as const


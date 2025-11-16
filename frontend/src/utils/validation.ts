/**
 * 输入验证工具函数
 */

export interface ValidationResult {
  valid: boolean
  message?: string
}

/**
 * 验证应用名称
 */
export function validateAppName(name: string): ValidationResult {
  if (!name || name.trim().length === 0) {
    return { valid: false, message: '应用名称不能为空' }
  }

  if (name.length < 2) {
    return { valid: false, message: '应用名称至少需要2个字符' }
  }

  if (name.length > 50) {
    return { valid: false, message: '应用名称不能超过50个字符' }
  }

  // 只允许字母、数字、连字符和下划线
  const validPattern = /^[a-zA-Z0-9_-]+$/
  if (!validPattern.test(name)) {
    return { valid: false, message: '应用名称只能包含字母、数字、连字符(-)和下划线(_)' }
  }

  // 不能以连字符或下划线开头或结尾
  if (/^[-_]|[-_]$/.test(name)) {
    return { valid: false, message: '应用名称不能以连字符或下划线开头或结尾' }
  }

  return { valid: true }
}

/**
 * 验证端口号
 */
export function validatePort(port: number | string): ValidationResult {
  const portNum = typeof port === 'string' ? parseInt(port, 10) : port

  if (isNaN(portNum)) {
    return { valid: false, message: '端口号必须是数字' }
  }

  if (portNum < 1 || portNum > 65535) {
    return { valid: false, message: '端口号必须在 1-65535 之间' }
  }

  return { valid: true }
}

/**
 * 验证域名
 */
export function validateDomain(domain: string): ValidationResult {
  if (!domain || domain.trim().length === 0) {
    return { valid: false, message: '域名不能为空' }
  }

  // 简单的域名验证（允许子域名）
  const domainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/
  if (!domainPattern.test(domain)) {
    return { valid: false, message: '域名格式不正确' }
  }

  if (domain.length > 253) {
    return { valid: false, message: '域名长度不能超过253个字符' }
  }

  return { valid: true }
}

/**
 * 验证SSH公钥
 */
export function validateSSHPublicKey(publicKey: string): ValidationResult {
  if (!publicKey || publicKey.trim().length === 0) {
    return { valid: false, message: 'SSH公钥不能为空' }
  }

  // 检查是否是有效的SSH公钥格式
  const sshKeyPatterns = [
    /^ssh-rsa\s+[A-Za-z0-9+/]+=*\s*.*$/, // RSA
    /^ssh-ed25519\s+[A-Za-z0-9+/]+=*\s*.*$/, // ED25519
    /^ecdsa-sha2-nistp256\s+[A-Za-z0-9+/]+=*\s*.*$/, // ECDSA
    /^ecdsa-sha2-nistp384\s+[A-Za-z0-9+/]+=*\s*.*$/, // ECDSA
    /^ecdsa-sha2-nistp521\s+[A-Za-z0-9+/]+=*\s*.*$/, // ECDSA
  ]

  const trimmedKey = publicKey.trim()
  const isValid = sshKeyPatterns.some((pattern) => pattern.test(trimmedKey))

  if (!isValid) {
    return { valid: false, message: 'SSH公钥格式不正确，支持 RSA、ED25519、ECDSA 格式' }
  }

  return { valid: true }
}

/**
 * 验证环境变量名称
 */
export function validateEnvVarName(name: string): ValidationResult {
  if (!name || name.trim().length === 0) {
    return { valid: false, message: '环境变量名称不能为空' }
  }

  // 环境变量名称通常只能包含字母、数字和下划线，且不能以数字开头
  const envVarPattern = /^[a-zA-Z_][a-zA-Z0-9_]*$/
  if (!envVarPattern.test(name)) {
    return { valid: false, message: '环境变量名称只能包含字母、数字和下划线，且不能以数字开头' }
  }

  if (name.length > 100) {
    return { valid: false, message: '环境变量名称不能超过100个字符' }
  }

  return { valid: true }
}


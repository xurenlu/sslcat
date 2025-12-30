/**
 * 代理循环检测工具
 * 用于在前端验证代理配置，防止配置循环导致系统资源耗尽
 */

/**
 * 检查主机地址是否是本地地址
 */
export function isLocalhost(host: string): boolean {
  if (!host) return false
  
  const normalizedHost = host.toLowerCase().trim()
  
  // 移除协议前缀（如果有）
  let cleanHost = normalizedHost
  if (cleanHost.startsWith('http://')) {
    cleanHost = cleanHost.substring(7)
  } else if (cleanHost.startsWith('https://')) {
    cleanHost = cleanHost.substring(8)
  }
  
  // 移除路径部分（如果有）
  const slashIndex = cleanHost.indexOf('/')
  if (slashIndex !== -1) {
    cleanHost = cleanHost.substring(0, slashIndex)
  }
  
  // 移除端口部分（如果有）
  const colonIndex = cleanHost.indexOf(':')
  if (colonIndex !== -1) {
    cleanHost = cleanHost.substring(0, colonIndex)
  }
  
  // 检查常见的本地地址
  const localAddresses = [
    'localhost',
    '127.0.0.1',
    '::1',
    '0.0.0.0',
    '::',
  ]
  
  if (localAddresses.includes(cleanHost)) {
    return true
  }
  
  // 检查 127.x.x.x 网段
  if (cleanHost.startsWith('127.')) {
    return true
  }
  
  return false
}

/**
 * 获取 sslcat 监听的端口列表
 * 注意：这里使用硬编码的默认值，实际应该从服务器配置获取
 */
export function getSSLCatListeningPorts(): number[] {
  // 标准模式下，sslcat 通常监听 80 和 443
  // TODO: 从服务器 API 获取实际的监听端口
  return [80, 443, 8080, 8443]
}

/**
 * 检测代理循环
 * @param host 后端主机地址
 * @param port 后端端口
 * @returns 如果检测到循环返回错误信息，否则返回 null
 */
export function detectProxyLoop(host: string, port: number): string | null {
  if (!host || !port) {
    return null
  }
  
  // 检查是否是本地地址
  if (!isLocalhost(host)) {
    return null
  }
  
  // 检查端口是否是 sslcat 监听的端口
  const listeningPorts = getSSLCatListeningPorts()
  if (listeningPorts.includes(port)) {
    return `⚠️ 检测到代理循环：后端地址 ${host}:${port} 指向 sslcat 自己！这会导致无限循环和资源耗尽。`
  }
  
  return null
}

/**
 * 批量检测多个后端的循环配置
 * @param backends 后端列表
 * @returns 错误信息数组
 */
export function detectProxyLoopInBackends(
  backends: Array<{ host: string; port: number; enabled?: boolean }>
): string[] {
  const errors: string[] = []
  
  backends.forEach((backend, index) => {
    // 只检查启用的后端
    if (backend.enabled === false) {
      return
    }
    
    const error = detectProxyLoop(backend.host, backend.port)
    if (error) {
      errors.push(`后端服务器 ${index + 1}: ${error}`)
    }
  })
  
  return errors
}

/**
 * 获取循环检测的帮助信息
 */
export function getProxyLoopHelpText(): string {
  return `
代理循环检测：
• 不能将后端地址设置为 localhost、127.0.0.1 等本地地址的 80/443 端口
• 这些端口是 sslcat 自己监听的端口，会导致无限循环
• 如果需要代理到本地服务，请使用其他端口（如 3000、8080 等）
• 示例：✅ 127.0.0.1:3000  ❌ 127.0.0.1:80
  `.trim()
}

/**
 * 检查端口是否安全（不是 sslcat 监听的端口）
 */
export function isSafePort(port: number): boolean {
  const listeningPorts = getSSLCatListeningPorts()
  return !listeningPorts.includes(port)
}

/**
 * 获取建议的安全端口列表
 */
export function getSuggestedSafePorts(): number[] {
  return [3000, 3001, 5000, 8000, 8081, 8082, 9000]
}


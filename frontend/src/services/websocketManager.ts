/**
 * WebSocket 管理器
 * 单例模式，管理所有 WebSocket 连接，避免资源泄漏
 */

interface WebSocketOptions {
  onMessage?: (event: MessageEvent) => void
  onOpen?: () => void
  onClose?: () => void
  onError?: (error: Event) => void
  maxReconnectAttempts?: number
  reconnectDelay?: number
}

class WebSocketManager {
  private connections: Map<string, WebSocket> = new Map()
  private reconnectAttempts: Map<string, number> = new Map()
  private reconnectTimeouts: Map<string, ReturnType<typeof setTimeout>> = new Map()
  private options: Map<string, WebSocketOptions> = new Map()
  private readonly maxReconnectAttempts = 5
  private readonly baseReconnectDelay = 1000 // 1秒

  /**
   * 连接到 WebSocket
   */
  connect(key: string, url: string, options: WebSocketOptions = {}): WebSocket {
    // 如果已存在连接，返回现有连接
    if (this.connections.has(key)) {
      const existingWs = this.connections.get(key)!
      if (existingWs.readyState === WebSocket.OPEN || existingWs.readyState === WebSocket.CONNECTING) {
        return existingWs
      }
      // 如果连接已关闭，清理并重新创建
      this.disconnect(key)
    }

    const ws = new WebSocket(url)
    this.connections.set(key, ws)
    this.options.set(key, options)
    this.reconnectAttempts.set(key, 0)

    ws.onopen = () => {
      // 重置重连次数
      this.reconnectAttempts.set(key, 0)
      options.onOpen?.()
    }

    ws.onmessage = (event) => {
      options.onMessage?.(event)
    }

    ws.onerror = (error) => {
      options.onError?.(error)
    }

    ws.onclose = () => {
      this.connections.delete(key)
      options.onClose?.()

      // 自动重连逻辑
      const attempts = this.reconnectAttempts.get(key) || 0
      const opts = this.options.get(key)
      
      if (opts && attempts < (opts.maxReconnectAttempts || this.maxReconnectAttempts)) {
        this.attemptReconnect(key, url, opts)
      }
    }

    return ws
  }

  /**
   * 尝试重连
   */
  private attemptReconnect(key: string, url: string, options: WebSocketOptions) {
    const attempts = this.reconnectAttempts.get(key) || 0
    const delay = (options.reconnectDelay || this.baseReconnectDelay) * Math.pow(2, attempts) // 指数退避

    const timeout = setTimeout(() => {
      this.reconnectAttempts.set(key, attempts + 1)
      this.connect(key, url, options)
    }, delay)

    this.reconnectTimeouts.set(key, timeout)
  }

  /**
   * 断开连接
   */
  disconnect(key: string) {
    // 清理重连定时器
    const timeout = this.reconnectTimeouts.get(key)
    if (timeout) {
      clearTimeout(timeout)
      this.reconnectTimeouts.delete(key)
    }

    // 关闭 WebSocket 连接
    const ws = this.connections.get(key)
    if (ws) {
      ws.close()
      this.connections.delete(key)
    }

    // 清理状态
    this.reconnectAttempts.delete(key)
    this.options.delete(key)
  }

  /**
   * 获取连接
   */
  getConnection(key: string): WebSocket | undefined {
    return this.connections.get(key)
  }

  /**
   * 检查连接是否存在且处于打开状态
   */
  isConnected(key: string): boolean {
    const ws = this.connections.get(key)
    return ws !== undefined && ws.readyState === WebSocket.OPEN
  }

  /**
   * 断开所有连接
   */
  disconnectAll() {
    const keys = Array.from(this.connections.keys())
    keys.forEach((key) => this.disconnect(key))
  }

  /**
   * 获取所有活跃连接数
   */
  getActiveConnectionsCount(): number {
    return Array.from(this.connections.values()).filter(
      (ws) => ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING
    ).length
  }
}

// 导出单例
export const websocketManager = new WebSocketManager()


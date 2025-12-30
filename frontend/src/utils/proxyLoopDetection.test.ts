/**
 * 代理循环检测单元测试
 */

import { 
  isLocalhost, 
  detectProxyLoop, 
  detectProxyLoopInBackends,
  isSafePort,
  getSuggestedSafePorts
} from './proxyLoopDetection'

describe('proxyLoopDetection', () => {
  describe('isLocalhost', () => {
    it('应该识别 localhost', () => {
      expect(isLocalhost('localhost')).toBe(true)
      expect(isLocalhost('LOCALHOST')).toBe(true)
      expect(isLocalhost('LocalHost')).toBe(true)
    })

    it('应该识别 127.0.0.1', () => {
      expect(isLocalhost('127.0.0.1')).toBe(true)
    })

    it('应该识别 127.x.x.x 网段', () => {
      expect(isLocalhost('127.0.0.1')).toBe(true)
      expect(isLocalhost('127.1.1.1')).toBe(true)
      expect(isLocalhost('127.255.255.255')).toBe(true)
    })

    it('应该识别 IPv6 loopback', () => {
      expect(isLocalhost('::1')).toBe(true)
    })

    it('应该识别 0.0.0.0', () => {
      expect(isLocalhost('0.0.0.0')).toBe(true)
    })

    it('应该识别 IPv6 any', () => {
      expect(isLocalhost('::')).toBe(true)
    })

    it('应该处理带协议的地址', () => {
      expect(isLocalhost('http://localhost')).toBe(true)
      expect(isLocalhost('https://127.0.0.1')).toBe(true)
      expect(isLocalhost('http://localhost:3000')).toBe(true)
    })

    it('应该处理带端口的地址', () => {
      expect(isLocalhost('localhost:80')).toBe(true)
      expect(isLocalhost('127.0.0.1:3000')).toBe(true)
    })

    it('应该处理带路径的地址', () => {
      expect(isLocalhost('localhost/api')).toBe(true)
      expect(isLocalhost('127.0.0.1/health')).toBe(true)
      expect(isLocalhost('http://localhost:3000/api/v1')).toBe(true)
    })

    it('不应该识别外部地址', () => {
      expect(isLocalhost('example.com')).toBe(false)
      expect(isLocalhost('192.168.1.1')).toBe(false)
      expect(isLocalhost('10.0.0.1')).toBe(false)
      expect(isLocalhost('8.8.8.8')).toBe(false)
    })

    it('应该处理空值', () => {
      expect(isLocalhost('')).toBe(false)
      expect(isLocalhost(null as any)).toBe(false)
      expect(isLocalhost(undefined as any)).toBe(false)
    })
  })

  describe('detectProxyLoop', () => {
    it('应该检测到 localhost:80 的循环', () => {
      const error = detectProxyLoop('localhost', 80)
      expect(error).not.toBeNull()
      expect(error).toContain('代理循环')
      expect(error).toContain('localhost:80')
    })

    it('应该检测到 127.0.0.1:80 的循环', () => {
      const error = detectProxyLoop('127.0.0.1', 80)
      expect(error).not.toBeNull()
      expect(error).toContain('代理循环')
    })

    it('应该检测到 127.0.0.1:443 的循环', () => {
      const error = detectProxyLoop('127.0.0.1', 443)
      expect(error).not.toBeNull()
      expect(error).toContain('代理循环')
    })

    it('应该检测到 ::1:80 的循环', () => {
      const error = detectProxyLoop('::1', 80)
      expect(error).not.toBeNull()
      expect(error).toContain('代理循环')
    })

    it('不应该检测到本地地址但安全端口的循环', () => {
      expect(detectProxyLoop('127.0.0.1', 3000)).toBeNull()
      expect(detectProxyLoop('localhost', 5000)).toBeNull()
      expect(detectProxyLoop('127.0.0.1', 8081)).toBeNull()
    })

    it('不应该检测到外部地址的循环', () => {
      expect(detectProxyLoop('example.com', 80)).toBeNull()
      expect(detectProxyLoop('192.168.1.1', 80)).toBeNull()
      expect(detectProxyLoop('backend.example.com', 443)).toBeNull()
    })

    it('应该处理空值', () => {
      expect(detectProxyLoop('', 80)).toBeNull()
      expect(detectProxyLoop('localhost', 0)).toBeNull()
      expect(detectProxyLoop(null as any, 80)).toBeNull()
    })
  })

  describe('detectProxyLoopInBackends', () => {
    it('应该检测单个后端的循环', () => {
      const backends = [
        { host: '127.0.0.1', port: 80, enabled: true }
      ]
      const errors = detectProxyLoopInBackends(backends)
      expect(errors).toHaveLength(1)
      expect(errors[0]).toContain('后端服务器 1')
      expect(errors[0]).toContain('代理循环')
    })

    it('应该检测多个后端的循环', () => {
      const backends = [
        { host: '127.0.0.1', port: 80, enabled: true },
        { host: 'example.com', port: 80, enabled: true },
        { host: 'localhost', port: 443, enabled: true }
      ]
      const errors = detectProxyLoopInBackends(backends)
      expect(errors).toHaveLength(2)
      expect(errors[0]).toContain('后端服务器 1')
      expect(errors[1]).toContain('后端服务器 3')
    })

    it('不应该检测禁用后端的循环', () => {
      const backends = [
        { host: '127.0.0.1', port: 80, enabled: false },
        { host: 'example.com', port: 80, enabled: true }
      ]
      const errors = detectProxyLoopInBackends(backends)
      expect(errors).toHaveLength(0)
    })

    it('应该处理没有 enabled 字段的后端', () => {
      const backends = [
        { host: '127.0.0.1', port: 80 },
        { host: 'example.com', port: 80 }
      ]
      const errors = detectProxyLoopInBackends(backends)
      expect(errors).toHaveLength(1)
    })

    it('应该处理空数组', () => {
      const errors = detectProxyLoopInBackends([])
      expect(errors).toHaveLength(0)
    })

    it('应该处理全部安全的后端', () => {
      const backends = [
        { host: '127.0.0.1', port: 3000, enabled: true },
        { host: 'example.com', port: 80, enabled: true },
        { host: 'backend.example.com', port: 443, enabled: true }
      ]
      const errors = detectProxyLoopInBackends(backends)
      expect(errors).toHaveLength(0)
    })
  })

  describe('isSafePort', () => {
    it('应该识别不安全的端口', () => {
      expect(isSafePort(80)).toBe(false)
      expect(isSafePort(443)).toBe(false)
      expect(isSafePort(8080)).toBe(false)
      expect(isSafePort(8443)).toBe(false)
    })

    it('应该识别安全的端口', () => {
      expect(isSafePort(3000)).toBe(true)
      expect(isSafePort(5000)).toBe(true)
      expect(isSafePort(8081)).toBe(true)
      expect(isSafePort(9000)).toBe(true)
    })
  })

  describe('getSuggestedSafePorts', () => {
    it('应该返回建议的安全端口列表', () => {
      const ports = getSuggestedSafePorts()
      expect(Array.isArray(ports)).toBe(true)
      expect(ports.length).toBeGreaterThan(0)
      
      // 所有建议的端口都应该是安全的
      ports.forEach(port => {
        expect(isSafePort(port)).toBe(true)
      })
    })
  })
})


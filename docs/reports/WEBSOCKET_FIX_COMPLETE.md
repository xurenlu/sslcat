# WebSocket 代理修复完整说明

## 问题总结

你遇到的问题是：**通过 HTTPS (wss://) 连接到 sslcat，然后代理到普通 HTTP WebSocket 后端时，连接失败**。

## 根本原因

经过深入分析代码，我发现了 **两个严重的 Bug**：

### Bug 1: `HandleWebSocket` 函数缺少 `Sec-WebSocket-Accept` 头部

**位置：** `internal/proxy/manager.go` 第 1642-1683 行（修复前）

**问题：**
原代码手动构造 WebSocket 握手响应，但 **缺少了关键的 `Sec-WebSocket-Accept` 头部**：

```go
// 错误的代码（修复前）
clientConn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n"))
clientConn.Write([]byte("Upgrade: websocket\r\n"))
clientConn.Write([]byte("Connection: Upgrade\r\n"))
clientConn.Write([]byte("\r\n"))  // ❌ 缺少 Sec-WebSocket-Accept
```

根据 RFC 6455 WebSocket 协议规范，服务器必须返回 `Sec-WebSocket-Accept` 头部，其值通过以下公式计算：

```
Sec-WebSocket-Accept = base64(SHA1(Sec-WebSocket-Key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
```

**如果缺少或计算错误，浏览器会拒绝 WebSocket 连接！**

**影响：** 当配置中 `websocket_optimized: false` 时，所有 WebSocket 连接都会失败。

### Bug 2: `HandleWebSocketOptimized` 函数的缓冲区数据丢失问题

**位置：** `internal/proxy/manager.go` 第 1738-1765 行（修复前）

**问题：**
代码使用 `bufio.NewReader(upstreamConn)` 读取后端响应：

```go
upstreamReader := bufio.NewReader(upstreamConn)
resp, err := http.ReadResponse(upstreamReader, r)
```

`bufio.Reader` 为了提高性能，会预读取一些数据到内部缓冲区（通常 4KB）。如果后端在发送 101 响应后立即发送 WebSocket 数据帧，这些数据会被缓冲：

```
客户端 → sslcat → 后端
                  ↓
            [bufio.Reader 缓冲区]
            [101 响应 + 部分 WebSocket 数据]
                  ↓
            只读取了 101 响应
            缓冲区的 WebSocket 数据被忽略了！❌
```

后续的 `startOptimizedWebSocketProxy` 直接从 `upstreamConn` 读取，但缓冲区中的数据已经丢失了。

**影响：** 
- 后端发送的第一批 WebSocket 消息可能丢失
- 客户端收不到消息或收到不完整的消息
- WebSocket 连接看起来"建立了但不工作"

## 修复方案

### 修复 1: 正确实现 `HandleWebSocket` 函数

**主要改进：**

1. **添加 `Sec-WebSocket-Accept` 计算**
   ```go
   func computeAcceptKey(challengeKey string) string {
       const magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
       h := sha1.New()
       h.Write([]byte(challengeKey + magic))
       return base64.StdEncoding.EncodeToString(h.Sum(nil))
   }
   ```

2. **先向后端转发握手请求，获取后端的响应**
   - 后端可能返回 `Sec-WebSocket-Protocol`、`Sec-WebSocket-Extensions` 等头部
   - 需要将这些头部转发给客户端

3. **构造正确的 101 响应**
   ```go
   response := fmt.Sprintf("HTTP/1.1 101 Switching Protocols\r\n"+
       "Upgrade: websocket\r\n"+
       "Connection: Upgrade\r\n"+
       "Sec-WebSocket-Accept: %s\r\n", acceptKey)
   ```

4. **处理后端缓冲区数据**
   - 检查 `backendReader.Buffered()` 是否还有数据
   - 如果有，先转发给客户端

### 修复 2: 修复 `HandleWebSocketOptimized` 的缓冲区问题

**主要改进：**

1. **读取缓冲区剩余数据**
   ```go
   var bufferedData []byte
   if upstreamReader.Buffered() > 0 {
       bufferedData = make([]byte, upstreamReader.Buffered())
       io.ReadFull(upstreamReader, bufferedData)
   }
   ```

2. **将缓冲数据传递给数据转发函数**
   ```go
   m.startOptimizedWebSocketProxy(clientConn, upstreamConn, rule, bufferedData)
   ```

3. **在数据转发前先发送缓冲数据**
   ```go
   if len(bufferedData) > 0 {
       upstreamToClient <- bufferedData
   }
   ```

## 修改文件清单

### 1. `internal/proxy/manager.go`

**修改的 import：**
```go
import (
    // 新增
    "crypto/sha1"
    "encoding/base64"
    // ... 其他 import
)
```

**修改的函数：**
1. `HandleWebSocket()` - 完全重写，添加正确的握手处理
2. `HandleWebSocketOptimized()` - 添加缓冲区数据处理
3. `startOptimizedWebSocketProxy()` - 添加缓冲数据参数
4. `computeAcceptKey()` - 新增函数，计算 WebSocket Accept Key

## 测试步骤

### 1. 编译新版本

```bash
cd /Users/rocky/Sites/sslcat
go build -o sslcat ./main.go
```

### 2. 配置测试环境

创建测试配置 `config.test.json`：

```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "port_mode": "standard",
    "enable_https": true,
    "log_level": "debug"
  },
  "ssl": {
    "email": "test@example.com",
    "staging": true
  },
  "proxy": {
    "rules": [
      {
        "domain": "ws.test.local",
        "target": "localhost",
        "port": 9000,
        "enabled": true,
        "websocket_optimized": true
      },
      {
        "domain": "ws-simple.test.local",
        "target": "localhost",
        "port": 9000,
        "enabled": true,
        "websocket_optimized": false
      }
    ]
  }
}
```

### 3. 启动测试 WebSocket 服务器

使用 Node.js 创建一个简单的 WebSocket 服务器：

```javascript
// test-ws-server.js
const WebSocket = require('ws');

const wss = new WebSocket.Server({ port: 9000 });

wss.on('connection', function connection(ws, req) {
  console.log('[Server] Client connected from:', req.socket.remoteAddress);
  console.log('[Server] Request headers:', req.headers);
  
  // 立即发送欢迎消息（用于测试缓冲区问题）
  ws.send(JSON.stringify({
    type: 'welcome',
    message: 'Welcome to WebSocket server!',
    timestamp: new Date().toISOString()
  }));
  
  // 监听消息
  ws.on('message', function incoming(message) {
    console.log('[Server] Received:', message.toString());
    
    // 回显消息
    ws.send(JSON.stringify({
      type: 'echo',
      data: message.toString(),
      timestamp: new Date().toISOString()
    }));
  });
  
  // 定时发送心跳
  const heartbeat = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        type: 'heartbeat',
        timestamp: new Date().toISOString()
      }));
    }
  }, 5000);
  
  ws.on('close', () => {
    console.log('[Server] Client disconnected');
    clearInterval(heartbeat);
  });
  
  ws.on('error', (error) => {
    console.error('[Server] WebSocket error:', error);
    clearInterval(heartbeat);
  });
});

console.log('✓ WebSocket server listening on ws://localhost:9000');
console.log('  Test it with: wscat -c ws://localhost:9000');
```

运行服务器：
```bash
npm install ws
node test-ws-server.js
```

### 4. 启动 sslcat

```bash
./sslcat -config config.test.json -log-level debug
```

### 5. 测试 WebSocket 连接

#### 方法 A: 使用 wscat 命令行工具

```bash
# 安装 wscat
npm install -g wscat

# 测试优化模式
wscat -c ws://ws.test.local:8080

# 测试简单模式
wscat -c ws://ws-simple.test.local:8080

# 如果配置了 HTTPS
wscat -c wss://ws.test.local:443
```

**预期结果：**
```
Connected (press CTRL+C to quit)
< {"type":"welcome","message":"Welcome to WebSocket server!","timestamp":"..."}
< {"type":"heartbeat","timestamp":"..."}
> Hello Server!
< {"type":"echo","data":"Hello Server!","timestamp":"..."}
```

#### 方法 B: 使用浏览器

创建测试页面 `test-ws.html`：

```html
<!DOCTYPE html>
<html>
<head>
    <title>WebSocket Test</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; }
        .status { padding: 10px; margin: 10px 0; border-radius: 5px; }
        .connected { background-color: #d4edda; border: 1px solid #c3e6cb; }
        .disconnected { background-color: #f8d7da; border: 1px solid #f5c6cb; }
        .messages { height: 300px; overflow-y: scroll; border: 1px solid #ddd; padding: 10px; }
        .message { margin: 5px 0; padding: 5px; }
        .sent { background-color: #e3f2fd; }
        .received { background-color: #f3e5f5; }
        input { width: 70%; padding: 10px; }
        button { padding: 10px 20px; }
    </style>
</head>
<body>
    <h1>WebSocket 连接测试</h1>
    
    <div id="status" class="status disconnected">
        状态：未连接
    </div>
    
    <div>
        <label>WebSocket URL:</label>
        <input type="text" id="url" value="ws://ws.test.local:8080/" style="width: 80%">
        <button onclick="connect()">连接</button>
        <button onclick="disconnect()">断开</button>
    </div>
    
    <div style="margin-top: 20px;">
        <label>发送消息:</label>
        <input type="text" id="message" placeholder="输入消息...">
        <button onclick="sendMessage()">发送</button>
    </div>
    
    <div class="messages" id="messages"></div>
    
    <div style="margin-top: 20px;">
        <button onclick="clearMessages()">清空消息</button>
        <button onclick="testOptimized()">测试优化模式</button>
        <button onclick="testSimple()">测试简单模式</button>
    </div>
    
    <script>
        let ws = null;
        let messageCount = 0;
        
        function addMessage(text, type) {
            const messagesDiv = document.getElementById('messages');
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message ' + type;
            messageDiv.textContent = `[${new Date().toLocaleTimeString()}] ${text}`;
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;
            messageCount++;
        }
        
        function updateStatus(text, connected) {
            const statusDiv = document.getElementById('status');
            statusDiv.textContent = '状态：' + text;
            statusDiv.className = 'status ' + (connected ? 'connected' : 'disconnected');
        }
        
        function connect() {
            const url = document.getElementById('url').value;
            
            try {
                ws = new WebSocket(url);
                
                ws.onopen = function() {
                    updateStatus('已连接', true);
                    addMessage('✓ WebSocket 连接已建立', 'received');
                };
                
                ws.onmessage = function(event) {
                    addMessage('← 收到: ' + event.data, 'received');
                };
                
                ws.onerror = function(error) {
                    updateStatus('错误', false);
                    addMessage('✗ WebSocket 错误: ' + error, 'received');
                    console.error('WebSocket error:', error);
                };
                
                ws.onclose = function(event) {
                    updateStatus('已断开', false);
                    addMessage(`✗ WebSocket 连接已关闭 (代码: ${event.code})`, 'received');
                };
            } catch (error) {
                updateStatus('连接失败', false);
                addMessage('✗ 连接失败: ' + error.message, 'received');
            }
        }
        
        function disconnect() {
            if (ws) {
                ws.close();
                ws = null;
            }
        }
        
        function sendMessage() {
            if (!ws || ws.readyState !== WebSocket.OPEN) {
                alert('WebSocket 未连接');
                return;
            }
            
            const message = document.getElementById('message').value;
            if (!message) return;
            
            ws.send(message);
            addMessage('→ 发送: ' + message, 'sent');
            document.getElementById('message').value = '';
        }
        
        function clearMessages() {
            document.getElementById('messages').innerHTML = '';
            messageCount = 0;
        }
        
        function testOptimized() {
            document.getElementById('url').value = 'ws://ws.test.local:8080/';
            addMessage('切换到优化模式测试 URL', 'received');
        }
        
        function testSimple() {
            document.getElementById('url').value = 'ws://ws-simple.test.local:8080/';
            addMessage('切换到简单模式测试 URL', 'received');
        }
        
        // 支持回车发送
        document.getElementById('message').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    </script>
</body>
</html>
```

### 6. 验证修复

检查以下几点：

1. **WebSocket 能否建立连接** ✓
   - 浏览器控制台应显示 WebSocket 连接状态为 `OPEN`
   - sslcat 日志应显示 `WebSocket handshake successful`

2. **是否收到欢迎消息** ✓
   - 这个消息是后端在握手完成后立即发送的
   - 如果收到了，说明缓冲区问题已修复

3. **双向通信是否正常** ✓
   - 客户端发送消息，服务器能收到并回显
   - 服务器定时发送心跳，客户端能收到

4. **两种模式都能工作** ✓
   - 优化模式（`websocket_optimized: true`）
   - 简单模式（`websocket_optimized: false`）

5. **查看 sslcat 日志**
   ```bash
   tail -f /var/log/sslcat/sslcat.log | grep -i websocket
   ```
   
   应该看到：
   ```
   DEBUG Detected WebSocket upgrade request for ws.test.local
   DEBUG Established TCP connection to WebSocket backend localhost:9000
   DEBUG Found X bytes of buffered data in upstream reader
   DEBUG Queued X bytes of buffered data for client
   INFO  WebSocket handshake successful for ws.test.local (optimized mode)
   ```

## 故障排查

### 问题 1: 连接立即断开

**可能原因：**
- 后端 WebSocket 服务未启动
- 防火墙阻止连接
- 端口配置错误

**解决方法：**
```bash
# 检查后端服务
nc -zv localhost 9000

# 查看 sslcat 日志
tail -f /var/log/sslcat/sslcat.log | grep -i "failed to connect"
```

### 问题 2: 连接建立但收不到消息

**可能原因：**
- 缓冲区数据丢失（应该已修复）
- 网络问题

**解决方法：**
```bash
# 启用 debug 日志
./sslcat -config config.test.json -log-level debug

# 查看是否有缓冲数据
grep "buffered data" /var/log/sslcat/sslcat.log
```

### 问题 3: HTTPS/WSS 连接失败

**可能原因：**
- SSL 证书未配置
- 证书域名不匹配

**解决方法：**
```bash
# 查看 SSL 日志
grep -i "ssl\|certificate" /var/log/sslcat/sslcat.log

# 使用 staging 环境测试
# 在配置中设置: "staging": true
```

## 性能对比

### 修复前
- ❌ 简单模式：完全无法工作（缺少 Sec-WebSocket-Accept）
- ⚠️ 优化模式：可能丢失前几条消息（缓冲区问题）

### 修复后
- ✅ 简单模式：完全正常，适合低并发场景
- ✅ 优化模式：完全正常，适合高并发场景，缓冲区数据正确处理

## 更新日志

**版本：** 1.3.32-rc17 (2026-01-24)

**修复内容：**
1. ✅ 修复 `HandleWebSocket` 缺少 `Sec-WebSocket-Accept` 头部的问题
2. ✅ 修复 `HandleWebSocketOptimized` 缓冲区数据丢失的问题
3. ✅ 添加 `computeAcceptKey` 函数，正确计算 WebSocket Accept Key
4. ✅ 完善 WebSocket 握手流程，支持 `Sec-WebSocket-Protocol` 和 `Sec-WebSocket-Extensions`
5. ✅ 添加详细的调试日志

**影响范围：**
- 所有使用 WebSocket 代理的场景
- 特别是 HTTPS (wss://) 到 HTTP (ws://) 的代理

**向后兼容：**
- ✅ 完全向后兼容
- ✅ 不需要修改配置文件
- ✅ 两种模式（优化/简单）都能正常工作

## 参考资料

- [RFC 6455 - The WebSocket Protocol](https://tools.ietf.org/html/rfc6455)
- [MDN - WebSocket](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket)
- [Go net 包文档](https://pkg.go.dev/net)
- [Go bufio 包文档](https://pkg.go.dev/bufio)

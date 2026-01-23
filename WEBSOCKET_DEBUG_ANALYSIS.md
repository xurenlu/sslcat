# WebSocket 代理问题深度分析

## 你遇到的问题

**场景：**
- 客户端通过 HTTPS/WSS → sslcat → 后端 HTTP/WS (普通未加密)
- WebSocket 连接失败

## 可能的问题点

### 1. WebSocket 握手请求头部问题

当客户端通过 HTTPS 连接到 sslcat 时，请求会包含一些特定的头部：

```http
GET /ws HTTP/1.1
Host: example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```

**问题代码位置：** `internal/proxy/manager.go` 第 1730 行

```go
// 转发WebSocket握手请求到上游服务器
err = r.Write(upstreamConn)
```

这行代码会将**整个请求对象**（包括所有头部）直接写入到后端连接。但可能存在以下问题：

#### 问题 A: Host 头部可能不正确
- 客户端发送的 `Host: example.com` 
- 但后端期望的可能是 `Host: localhost:8080` 或其他

#### 问题 B: 某些头部不应该转发
- `X-Forwarded-For`
- `X-Real-IP`
- 代理相关的头部

#### 问题 C: 连接已被 Hijack 但响应可能还在缓冲区
- Hijack 后，`http.ResponseWriter` 失效
- 需要直接操作底层连接

### 2. 简单 WebSocket 处理的问题

**问题代码位置：** `internal/proxy/manager.go` 第 1642-1683 行

`HandleWebSocket` 函数存在一个关键问题：

```go
// 发送HTTP响应
clientConn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\n"))
clientConn.Write([]byte("Upgrade: websocket\r\n"))
clientConn.Write([]byte("Connection: Upgrade\r\n"))
clientConn.Write([]byte("\r\n"))
```

**这个实现完全错误！**

WebSocket 协议要求在 `101 Switching Protocols` 响应中必须包含：

1. `Sec-WebSocket-Accept` 头部（这是关键！）
2. 可能还有 `Sec-WebSocket-Protocol`、`Sec-WebSocket-Extensions` 等

#### Sec-WebSocket-Accept 计算方式：

```
Sec-WebSocket-Accept = base64(SHA1(Sec-WebSocket-Key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
```

**如果缺少或计算错误的 `Sec-WebSocket-Accept`，客户端会拒绝连接！**

### 3. 优化的 WebSocket 处理的问题

**问题代码位置：** `internal/proxy/manager.go` 第 1692-1768 行

`HandleWebSocketOptimized` 函数的问题：

```go
// 转发WebSocket握手请求到上游服务器
err = r.Write(upstreamConn)

// 读取上游服务器的握手响应
upstreamReader := bufio.NewReader(upstreamConn)
resp, err := http.ReadResponse(upstreamReader, r)

// 转发握手响应到客户端
err = resp.Write(clientConn)
```

这个实现**几乎是正确的**，但可能存在的问题：

#### 问题 A: 请求头部未清理
- 直接转发 `r` 可能包含不必要的头部

#### 问题 B: `bufio.Reader` 可能读取了额外数据
- `http.ReadResponse` 使用 `bufio.Reader` 读取响应
- 可能会缓冲一些 WebSocket 数据帧
- 后续的数据转发会丢失这部分数据

## 诊断步骤

### 第一步：确认问题类型

运行以下命令查看日志：

```bash
# 启用 debug 日志
sslcat -config sslcat.conf -log-level debug

# 查看日志中的关键信息
tail -f /var/log/sslcat/sslcat.log | grep -i websocket
```

查找以下关键日志：

1. `Detected WebSocket upgrade request` - 是否检测到 WebSocket 升级
2. `WebSocket handshake successful` - 握手是否成功
3. `Failed to connect to upstream WebSocket server` - 连接后端失败
4. `WebSocket handshake failed with status: XXX` - 握手失败及状态码

### 第二步：使用 wscat 测试

```bash
# 安装 wscat
npm install -g wscat

# 测试 WebSocket 连接
wscat -c ws://your-domain.com/ws

# 或 HTTPS
wscat -c wss://your-domain.com/ws
```

### 第三步：使用浏览器开发者工具

打开浏览器开发者工具 → Network → WS，查看：

1. 请求头部
2. 响应头部（特别是 `Sec-WebSocket-Accept`）
3. 错误信息

### 第四步：抓包分析

```bash
# 抓取客户端到 sslcat 的流量
sudo tcpdump -i any host <client-ip> and port 443 -w client-to-sslcat.pcap

# 抓取 sslcat 到后端的流量
sudo tcpdump -i any host <backend-ip> and port 8080 -w sslcat-to-backend.pcap

# 使用 Wireshark 分析
wireshark client-to-sslcat.pcap
wireshark sslcat-to-backend.pcap
```

## 解决方案

### 方案 1：修复 HandleWebSocket (简单模式)

这个函数需要完全重写：

**问题：** 手动构造响应头部，缺少 `Sec-WebSocket-Accept`

**解决：** 使用 `gorilla/websocket` 库或正确计算 `Sec-WebSocket-Accept`

### 方案 2：修复 HandleWebSocketOptimized (优化模式)

**问题：** `bufio.Reader` 可能缓冲了 WebSocket 数据

**解决：** 
1. 读取响应后，检查缓冲区是否还有数据
2. 如果有，先将缓冲区数据转发给客户端
3. 然后再开始正常的数据转发

### 方案 3：清理请求头部

在转发请求前，清理或修改某些头部：

```go
// 创建新的请求
newReq := r.Clone(context.Background())

// 修改 Host 头部
newReq.Host = net.JoinHostPort(rule.Target, strconv.Itoa(rule.Port))

// 删除代理相关头部
newReq.Header.Del("X-Forwarded-For")
newReq.Header.Del("X-Real-IP")

// 转发请求
err = newReq.Write(upstreamConn)
```

## 推荐的修复顺序

1. **首先修复 `HandleWebSocketOptimized`** - 这个函数几乎是对的
2. **然后修复 `HandleWebSocket`** - 这个函数需要重写
3. **最后优化头部处理** - 清理不必要的头部

## 快速测试代码

创建一个简单的 WebSocket 服务器用于测试：

```javascript
// test-ws-server.js
const WebSocket = require('ws');

const wss = new WebSocket.Server({ port: 8080 });

wss.on('connection', function connection(ws, req) {
  console.log('Client connected:', req.headers.host);
  
  ws.on('message', function incoming(message) {
    console.log('Received:', message);
    ws.send('Echo: ' + message);
  });
  
  ws.send('Welcome!');
});

console.log('WebSocket server started on ws://localhost:8080');
```

运行：
```bash
node test-ws-server.js
```

然后通过 sslcat 代理测试。

## 我的初步判断

根据代码分析，我认为问题最可能出在：

1. **`HandleWebSocket` 函数完全无法工作** - 缺少 `Sec-WebSocket-Accept` 头部
2. **`HandleWebSocketOptimized` 可能有 `bufio.Reader` 缓冲区问题** - 但这个问题较小

建议你先测试确认是否启用了 `websocket_optimized`，如果是，问题可能在 `bufio.Reader` 缓冲区。

如果没有启用优化模式，那么 `HandleWebSocket` 函数肯定无法工作。

package web

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/waf"
)

// SecurityEventMessage 安全事件消息
type SecurityEventMessage struct {
	Type      string           `json:"type"`       // "attack", "scan", "block"
	Event     *waf.AttackEvent `json:"event"`
	Timestamp time.Time        `json:"timestamp"`
}

// SecurityEventHub 安全事件分发中心
type SecurityEventHub struct {
	clients map[*SecurityEventClient]bool
	register chan *SecurityEventClient
	unregister chan *SecurityEventClient
	broadcast chan *SecurityEventMessage
	log      *logrus.Entry
	mu       sync.RWMutex
}

// SecurityEventClient WebSocket客户端
type SecurityEventClient struct {
	hub  *SecurityEventHub
	conn *websocket.Conn
	send chan *SecurityEventMessage
	id   string
}

// NewSecurityEventHub 创建安全事件中心
func NewSecurityEventHub() *SecurityEventHub {
	hub := &SecurityEventHub{
		clients:    make(map[*SecurityEventClient]bool),
		register:   make(chan *SecurityEventClient),
		unregister: make(chan *SecurityEventClient),
		broadcast:  make(chan *SecurityEventMessage, 256),
		log:        logrus.WithFields(logrus.Fields{"component": "security_event_hub"}),
	}
	go hub.run()
	return hub
}

// run 运行事件中心
func (h *SecurityEventHub) run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			h.log.Infof("Client connected: %s (total: %d)", client.id, len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			h.log.Infof("Client disconnected: %s (total: %d)", client.id, len(h.clients)-1)

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					// 客户端缓冲区满，关闭连接
					delete(h.clients, client)
					close(client.send)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Broadcast 广播事件
func (h *SecurityEventHub) Broadcast(event *waf.AttackEvent, eventType string) {
	message := &SecurityEventMessage{
		Type:      eventType,
		Event:     event,
		Timestamp: time.Now(),
	}

	select {
	case h.broadcast <- message:
	default:
		// 缓冲区满，丢弃消息
		h.log.Warn("Security event broadcast buffer full, message dropped")
	}
}

// RegisterClient 注册新客户端
func (h *SecurityEventHub) RegisterClient(conn *websocket.Conn) *SecurityEventClient {
	client := &SecurityEventClient{
		hub:  h,
		conn: conn,
		send: make(chan *SecurityEventMessage, 64),
		id:   generateClientID(),
	}
	h.register <- client
	return client
}

// UnregisterClient 注销客户端
func (h *SecurityEventHub) UnregisterClient(client *SecurityEventClient) {
	h.unregister <- client
}

// writePump 写入循环
func (c *SecurityEventClient) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
		c.hub.UnregisterClient(c)
	}()

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteJSON(message); err != nil {
				return
			}

		case <-ticker.C:
			// 心跳
			c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump 读取循环
func (c *SecurityEventClient) readPump() {
	defer func() {
		c.hub.UnregisterClient(c)
	}()

	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.hub.log.Errorf("WebSocket error: %v", err)
			}
			break
		}
	}
}

// generateClientID 生成客户端ID
func generateClientID() string {
	return "client_" + time.Now().Format("20060102150405.000")
}

package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"github.com/xurenlu/sslcat/internal/waf"
)

// AttackMapData 攻击地图数据
type AttackMapData struct {
	SourceIP    string    `json:"source_ip"`
	Country     string    `json:"country"`
	CountryCode string    `json:"country_code"`
	City        string    `json:"city"`
	Latitude    float64   `json:"latitude"`
	Longitude   float64   `json:"longitude"`
	AttackType  string    `json:"attack_type"`
	Count       int       `json:"count"`
	LastSeen    time.Time `json:"last_seen"`
	Blocked     bool      `json:"blocked"`
}

// handleAttackMapWebSocket 处理攻击地图WebSocket连接
func (s *Server) handleAttackMapWebSocket(w http.ResponseWriter, r *http.Request) {
	// 升级到WebSocket
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // 允许所有来源
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Errorf("WebSocket upgrade failed: %v", err)
		return
	}

	// 创建客户端并启动
	client := s.securityEventHub.RegisterClient(conn)
	go client.writePump()
	client.readPump()

	s.log.Info("Attack map WebSocket client connected")
}

// handleGetRecentAttacks 获取最近的攻击记录
func (s *Server) handleGetRecentAttacks(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	limitStr := query.Get("limit")
	hoursStr := query.Get("hours")

	limit := 100
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}

	hours := 24
	if hoursStr != "" {
		if n, err := strconv.Atoi(hoursStr); err == nil && n > 0 && n <= 168 { // 最多7天
			hours = n
		}
	}

	// 从WAF引擎获取最近的攻击事件
	attacks := s.getRecentAttackEvents(limit, hours)

	// 转换为地图数据
	mapData := s.convertToMapData(attacks)

	s.sendJSON(w, map[string]interface{}{
		"attacks":   mapData,
		"count":     len(mapData),
		"generated": time.Now(),
	})
}

// handleGetAttackStats 获取攻击统计
func (s *Server) handleGetAttackStats(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	hoursStr := query.Get("hours")

	hours := 24
	if hoursStr != "" {
		if n, err := strconv.Atoi(hoursStr); err == nil && n > 0 && n <= 168 {
			hours = n
		}
	}

	stats := s.getAttackStatistics(hours)

	s.sendJSON(w, stats)
}

// getRecentAttackEvents 获取最近的攻击事件
func (s *Server) getRecentAttackEvents(limit, hours int) []*waf.AttackEvent {
	// 如果有WAF引擎，从引擎获取
	if s.wafEngine != nil {
		// TODO: 从WAF引擎获取最近的事件
		// 暂时返回空数组
		return make([]*waf.AttackEvent, 0)
	}

	// 从安全管理器获取
	if s.securityManager != nil {
		// TODO: 从安全管理器获取访问日志中的攻击记录
		return make([]*waf.AttackEvent, 0)
	}

	return make([]*waf.AttackEvent, 0)
}

// convertToMapData 转换为地图数据
func (s *Server) convertToMapData(attacks []*waf.AttackEvent) []*AttackMapData {
	// 按IP地址聚合
	locationMap := make(map[string]*AttackMapData)

	for _, attack := range attacks {
		key := attack.ClientIP

		data, exists := locationMap[key]
		if !exists {
			data = &AttackMapData{
				SourceIP:    attack.ClientIP,
				AttackType:  string(attack.RuleType),
				Count:       0,
				LastSeen:    attack.Timestamp,
				Blocked:     attack.Blocked,
				// TODO: 添加 GeoIP 支持
				Country:     "Unknown",
				CountryCode: "--",
				City:        "Unknown",
				Latitude:    0,
				Longitude:   0,
			}

			locationMap[key] = data
		}

		data.Count++
		if attack.Timestamp.After(data.LastSeen) {
			data.LastSeen = attack.Timestamp
		}
		if attack.Blocked {
			data.Blocked = true
		}
	}

	// 转换为数组
	result := make([]*AttackMapData, 0, len(locationMap))
	for _, data := range locationMap {
		result = append(result, data)
	}

	return result
}

// getAttackStatistics 获取攻击统计
func (s *Server) getAttackStatistics(hours int) map[string]interface{} {
	stats := map[string]interface{}{
		"total_attacks":  0,
		"blocked_attacks": 0,
		"by_type":        make(map[string]int),
		"by_country":     make(map[string]int),
		"top_ips":        make([]map[string]interface{}, 0),
		"time_range":     map[string]interface{}{
			"hours": hours,
			"start": time.Now().Add(-time.Duration(hours) * time.Hour),
			"end":   time.Now(),
		},
	}

	// TODO: 从实际数据源填充统计
	return stats
}

// handleAttackMapConfig 攻击地图配置
func (s *Server) handleAttackMapConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		enabled := s.securityEventHub != nil
		s.sendJSON(w, map[string]interface{}{
			"enabled": enabled,
			"websocket_url": "/api/attack-map/ws",
		})
	case "POST":
		var config struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if config.Enabled && s.securityEventHub == nil {
			s.securityEventHub = NewSecurityEventHub()
		}

		s.sendJSON(w, map[string]interface{}{
			"success": true,
			"enabled": config.Enabled,
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// GeoLocation 地理位置信息（简化版）
type GeoLocation struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
}

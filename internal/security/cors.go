package security

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// CORSConfig CORS配置
type CORSConfig struct {
	// 是否启用CORS
	Enabled bool `json:"enabled"`

	// 允许的源
	AllowedOrigins []string `json:"allowed_origins"`

	// 允许的HTTP方法
	AllowedMethods []string `json:"allowed_methods"`

	// 允许的请求头
	AllowedHeaders []string `json:"allowed_headers"`

	// 暴露的响应头
	ExposedHeaders []string `json:"exposed_headers"`

	// 是否允许携带凭证
	AllowCredentials bool `json:"allow_credentials"`

	// 预检请求缓存时间（秒）
	MaxAge int `json:"max_age"`

	// 是否允许私有网络请求
	AllowPrivateNetwork bool `json:"allow_private_network"`
}

// CORSMiddleware CORS中间件
type CORSMiddleware struct {
	config CORSConfig
	log    *logrus.Entry
}

// NewCORSMiddleware 创建CORS中间件
func NewCORSMiddleware(config CORSConfig) *CORSMiddleware {
	// 设置默认值
	if len(config.AllowedMethods) == 0 {
		config.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"}
	}

	if len(config.AllowedHeaders) == 0 {
		config.AllowedHeaders = []string{
			"Accept", "Accept-Language", "Content-Type", "Content-Language",
			"Authorization", "X-Requested-With", "Origin", "Referer",
			"User-Agent", "Cache-Control", "Pragma",
		}
	}

	if config.MaxAge == 0 {
		config.MaxAge = 86400 // 默认24小时
	}

	return &CORSMiddleware{
		config: config,
		log: logrus.WithFields(logrus.Fields{
			"component": "cors_middleware",
		}),
	}
}

// Handler CORS处理器
func (c *CORSMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !c.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}

		origin := r.Header.Get("Origin")

		// 检查是否是CORS请求
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}

		// 检查Origin是否被允许
		if !c.isOriginAllowed(origin) {
			c.log.Warnf("CORS request from disallowed origin: %s", origin)
			http.Error(w, "CORS: Origin not allowed", http.StatusForbidden)
			return
		}

		// 设置CORS响应头
		c.setCORSHeaders(w, r, origin)

		// 处理预检请求
		if r.Method == "OPTIONS" {
			c.handlePreflightRequest(w, r)
			return
		}

		// 继续处理实际请求
		next.ServeHTTP(w, r)
	})
}

// isOriginAllowed 检查Origin是否被允许
func (c *CORSMiddleware) isOriginAllowed(origin string) bool {
	// 如果配置了*，允许所有源
	for _, allowed := range c.config.AllowedOrigins {
		if allowed == "*" {
			return true
		}

		// 精确匹配
		if allowed == origin {
			return true
		}

		// 通配符匹配
		if c.matchWildcard(allowed, origin) {
			return true
		}
	}

	return false
}

// matchWildcard 通配符匹配
func (c *CORSMiddleware) matchWildcard(pattern, origin string) bool {
	// 简单的通配符匹配实现
	// 支持 *.example.com 格式
	if strings.HasPrefix(pattern, "*.") {
		domain := pattern[2:]
		return strings.HasSuffix(origin, "."+domain) || origin == domain
	}

	return false
}

// setCORSHeaders 设置CORS响应头
func (c *CORSMiddleware) setCORSHeaders(w http.ResponseWriter, r *http.Request, origin string) {
	// Access-Control-Allow-Origin
	if c.containsWildcard(c.config.AllowedOrigins) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	// Access-Control-Allow-Methods
	if len(c.config.AllowedMethods) > 0 {
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(c.config.AllowedMethods, ", "))
	}

	// Access-Control-Allow-Headers
	if len(c.config.AllowedHeaders) > 0 {
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(c.config.AllowedHeaders, ", "))
	}

	// Access-Control-Expose-Headers
	if len(c.config.ExposedHeaders) > 0 {
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(c.config.ExposedHeaders, ", "))
	}

	// Access-Control-Allow-Credentials
	if c.config.AllowCredentials {
		w.Header().Set("Access-Control-Allow-Credentials", "true")
	}

	// Access-Control-Allow-Private-Network
	if c.config.AllowPrivateNetwork {
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
	}

	// Vary头部
	w.Header().Add("Vary", "Origin")
	w.Header().Add("Vary", "Access-Control-Request-Method")
	w.Header().Add("Vary", "Access-Control-Request-Headers")
}

// handlePreflightRequest 处理预检请求
func (c *CORSMiddleware) handlePreflightRequest(w http.ResponseWriter, r *http.Request) {
	// 检查请求的方法是否被允许
	requestMethod := r.Header.Get("Access-Control-Request-Method")
	if requestMethod != "" && !c.isMethodAllowed(requestMethod) {
		c.log.Warnf("CORS preflight: Method not allowed: %s", requestMethod)
		http.Error(w, "CORS: Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 检查请求的头部是否被允许
	requestHeaders := r.Header.Get("Access-Control-Request-Headers")
	if requestHeaders != "" && !c.areHeadersAllowed(requestHeaders) {
		c.log.Warnf("CORS preflight: Headers not allowed: %s", requestHeaders)
		http.Error(w, "CORS: Headers not allowed", http.StatusForbidden)
		return
	}

	// 设置预检响应的缓存时间
	w.Header().Set("Access-Control-Max-Age", strconv.Itoa(c.config.MaxAge))

	// 返回成功状态
	w.WriteHeader(http.StatusNoContent)

	c.log.Debugf("CORS preflight request handled for origin: %s", r.Header.Get("Origin"))
}

// isMethodAllowed 检查HTTP方法是否被允许
func (c *CORSMiddleware) isMethodAllowed(method string) bool {
	method = strings.ToUpper(method)
	for _, allowed := range c.config.AllowedMethods {
		if strings.ToUpper(allowed) == method {
			return true
		}
	}
	return false
}

// areHeadersAllowed 检查请求头是否被允许
func (c *CORSMiddleware) areHeadersAllowed(headers string) bool {
	requestedHeaders := strings.Split(headers, ",")

	for _, header := range requestedHeaders {
		header = strings.TrimSpace(header)
		if !c.isHeaderAllowed(header) {
			return false
		}
	}

	return true
}

// isHeaderAllowed 检查单个请求头是否被允许
func (c *CORSMiddleware) isHeaderAllowed(header string) bool {
	header = strings.ToLower(strings.TrimSpace(header))

	// 简单请求头总是被允许
	simpleHeaders := []string{
		"accept", "accept-language", "content-language", "content-type",
	}

	for _, simple := range simpleHeaders {
		if header == simple {
			return true
		}
	}

	// 检查配置的允许头部
	for _, allowed := range c.config.AllowedHeaders {
		if strings.ToLower(allowed) == header {
			return true
		}
	}

	return false
}

// containsWildcard 检查是否包含通配符
func (c *CORSMiddleware) containsWildcard(origins []string) bool {
	for _, origin := range origins {
		if origin == "*" {
			return true
		}
	}
	return false
}

// GetDefaultCORSConfig 获取默认CORS配置
func GetDefaultCORSConfig() CORSConfig {
	return CORSConfig{
		Enabled:        false, // 默认禁用
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"},
		AllowedHeaders: []string{
			"Accept", "Accept-Language", "Content-Type", "Content-Language",
			"Authorization", "X-Requested-With", "Origin", "Referer",
			"User-Agent", "Cache-Control", "Pragma", "X-CSRF-Token",
		},
		ExposedHeaders: []string{
			"X-Request-ID", "X-Response-Time", "X-RateLimit-Limit",
			"X-RateLimit-Remaining", "X-RateLimit-Reset",
		},
		AllowCredentials:    false,
		MaxAge:              86400, // 24小时
		AllowPrivateNetwork: false,
	}
}

// GetSecureCORSConfig 获取安全的CORS配置
func GetSecureCORSConfig(allowedOrigins []string) CORSConfig {
	config := GetDefaultCORSConfig()
	config.Enabled = true
	config.AllowedOrigins = allowedOrigins
	config.AllowCredentials = true
	return config
}

// ValidateCORSConfig 验证CORS配置
func ValidateCORSConfig(config CORSConfig) error {
	// 检查Origin配置
	if len(config.AllowedOrigins) == 0 {
		return fmt.Errorf("allowed_origins cannot be empty when CORS is enabled")
	}

	// 检查凭证和通配符的组合
	if config.AllowCredentials {
		for _, origin := range config.AllowedOrigins {
			if origin == "*" {
				return fmt.Errorf("cannot use wildcard origin (*) with credentials")
			}
		}
	}

	// 检查MaxAge范围
	if config.MaxAge < 0 || config.MaxAge > 86400*7 { // 最大7天
		return fmt.Errorf("max_age must be between 0 and %d", 86400*7)
	}

	return nil
}

// GetStats 获取CORS统计信息
func (c *CORSMiddleware) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":               c.config.Enabled,
		"allowed_origins":       c.config.AllowedOrigins,
		"allowed_methods":       c.config.AllowedMethods,
		"allowed_headers":       len(c.config.AllowedHeaders),
		"exposed_headers":       len(c.config.ExposedHeaders),
		"allow_credentials":     c.config.AllowCredentials,
		"max_age":               c.config.MaxAge,
		"allow_private_network": c.config.AllowPrivateNetwork,
	}
}

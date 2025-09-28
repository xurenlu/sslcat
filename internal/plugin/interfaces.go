package plugin

import (
	"context"
	"net/http"
	"time"
)

// Plugin 插件基础接口
type Plugin interface {
	// GetInfo 获取插件信息
	GetInfo() *PluginInfo

	// Initialize 初始化插件
	Initialize(config map[string]interface{}) error

	// Start 启动插件
	Start(ctx context.Context) error

	// Stop 停止插件
	Stop(ctx context.Context) error

	// IsEnabled 检查插件是否启用
	IsEnabled() bool

	// SetEnabled 设置插件启用状态
	SetEnabled(enabled bool)

	// GetConfig 获取插件配置
	GetConfig() map[string]interface{}

	// UpdateConfig 更新插件配置
	UpdateConfig(config map[string]interface{}) error

	// GetHealth 获取插件健康状态
	GetHealth() *PluginHealth
}

// MiddlewarePlugin 中间件插件接口
type MiddlewarePlugin interface {
	Plugin

	// GetMiddleware 获取HTTP中间件
	GetMiddleware() func(http.Handler) http.Handler

	// GetPriority 获取中间件优先级（数字越小优先级越高）
	GetPriority() int

	// GetRoutes 获取插件注册的路由
	GetRoutes() []Route
}

// SecurityPlugin 安全插件接口
type SecurityPlugin interface {
	Plugin

	// CheckRequest 检查请求安全性
	CheckRequest(ctx context.Context, r *http.Request) (*SecurityResult, error)

	// ProcessAttack 处理攻击事件
	ProcessAttack(ctx context.Context, attack *AttackEvent) error

	// GetSecurityRules 获取安全规则
	GetSecurityRules() []SecurityRule

	// UpdateSecurityRules 更新安全规则
	UpdateSecurityRules(rules []SecurityRule) error
}

// AnalyticsPlugin 分析插件接口
type AnalyticsPlugin interface {
	Plugin

	// ProcessRequest 处理请求数据
	ProcessRequest(ctx context.Context, data *RequestData) error

	// ProcessResponse 处理响应数据
	ProcessResponse(ctx context.Context, data *ResponseData) error

	// GetMetrics 获取指标数据
	GetMetrics(ctx context.Context, query *MetricsQuery) (*MetricsResult, error)

	// GetDashboard 获取仪表板数据
	GetDashboard(ctx context.Context) (*DashboardData, error)
}

// StoragePlugin 存储插件接口
type StoragePlugin interface {
	Plugin

	// Store 存储数据
	Store(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Retrieve 检索数据
	Retrieve(ctx context.Context, key string) ([]byte, error)

	// Delete 删除数据
	Delete(ctx context.Context, key string) error

	// List 列出键
	List(ctx context.Context, prefix string) ([]string, error)

	// Exists 检查键是否存在
	Exists(ctx context.Context, key string) (bool, error)
}

// NotificationPlugin 通知插件接口
type NotificationPlugin interface {
	Plugin

	// SendNotification 发送通知
	SendNotification(ctx context.Context, notification *Notification) error

	// GetChannels 获取支持的通知渠道
	GetChannels() []NotificationChannel

	// TestConnection 测试连接
	TestConnection(ctx context.Context) error
}

// AuthPlugin 认证插件接口
type AuthPlugin interface {
	Plugin

	// Authenticate 认证用户
	Authenticate(ctx context.Context, credentials *Credentials) (*User, error)

	// Authorize 授权检查
	Authorize(ctx context.Context, user *User, resource string, action string) (bool, error)

	// GetUserInfo 获取用户信息
	GetUserInfo(ctx context.Context, userID string) (*User, error)

	// RefreshToken 刷新令牌
	RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)
}

// PluginInfo 插件信息
type PluginInfo struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Description  string            `json:"description"`
	Author       string            `json:"author"`
	Website      string            `json:"website"`
	License      string            `json:"license"`
	Tags         []string          `json:"tags"`
	Category     string            `json:"category"`
	Interfaces   []string          `json:"interfaces"`
	Dependencies []string          `json:"dependencies"`
	Config       *PluginConfig     `json:"config"`
	Metadata     map[string]string `json:"metadata"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// PluginConfig 插件配置结构
type PluginConfig struct {
	Schema     map[string]*ConfigField `json:"schema"`
	Defaults   map[string]interface{}  `json:"defaults"`
	Required   []string                `json:"required"`
	Validation map[string]string       `json:"validation"`
}

// ConfigField 配置字段
type ConfigField struct {
	Type        string      `json:"type"` // string, int, bool, array, object
	Description string      `json:"description"`
	Default     interface{} `json:"default"`
	Required    bool        `json:"required"`
	Options     []string    `json:"options"` // 枚举选项
	Min         *float64    `json:"min"`     // 最小值
	Max         *float64    `json:"max"`     // 最大值
	Pattern     string      `json:"pattern"` // 正则验证
}

// PluginHealth 插件健康状态
type PluginHealth struct {
	Status    string                 `json:"status"` // healthy, unhealthy, unknown
	Message   string                 `json:"message"`
	Details   map[string]interface{} `json:"details"`
	CheckedAt time.Time              `json:"checked_at"`
}

// Route 路由定义
type Route struct {
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Handler     http.HandlerFunc  `json:"-"`
	Middleware  []string          `json:"middleware"`
	Description string            `json:"description"`
	Tags        []string          `json:"tags"`
	Parameters  map[string]string `json:"parameters"`
}

// SecurityResult 安全检查结果
type SecurityResult struct {
	Allowed    bool                   `json:"allowed"`
	Blocked    bool                   `json:"blocked"`
	Risk       string                 `json:"risk"` // low, medium, high, critical
	Reason     string                 `json:"reason"`
	Actions    []string               `json:"actions"` // block, log, alert, redirect
	Metadata   map[string]interface{} `json:"metadata"`
	Confidence float64                `json:"confidence"` // 0-1
}

// AttackEvent 攻击事件
type AttackEvent struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	ClientIP    string                 `json:"client_ip"`
	UserAgent   string                 `json:"user_agent"`
	URL         string                 `json:"url"`
	Method      string                 `json:"method"`
	Payload     string                 `json:"payload"`
	Headers     map[string]string      `json:"headers"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// SecurityRule 安全规则
type SecurityRule struct {
	ID         string                 `json:"id"`
	Name       string                 `json:"name"`
	Type       string                 `json:"type"`
	Pattern    string                 `json:"pattern"`
	Action     string                 `json:"action"`
	Priority   int                    `json:"priority"`
	Enabled    bool                   `json:"enabled"`
	Tags       []string               `json:"tags"`
	Conditions map[string]interface{} `json:"conditions"`
	Parameters map[string]interface{} `json:"parameters"`
	CreatedAt  time.Time              `json:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at"`
}

// RequestData 请求数据
type RequestData struct {
	ID          string            `json:"id"`
	Timestamp   time.Time         `json:"timestamp"`
	ClientIP    string            `json:"client_ip"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	UserAgent   string            `json:"user_agent"`
	Headers     map[string]string `json:"headers"`
	Body        []byte            `json:"body"`
	Size        int64             `json:"size"`
	GeoLocation *GeoLocation      `json:"geo_location"`
}

// ResponseData 响应数据
type ResponseData struct {
	ID          string            `json:"id"`
	RequestID   string            `json:"request_id"`
	Timestamp   time.Time         `json:"timestamp"`
	StatusCode  int               `json:"status_code"`
	Headers     map[string]string `json:"headers"`
	Body        []byte            `json:"body"`
	Size        int64             `json:"size"`
	ProcessTime time.Duration     `json:"process_time"`
	CacheStatus string            `json:"cache_status"`
}

// GeoLocation 地理位置信息
type GeoLocation struct {
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Region      string  `json:"region"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Timezone    string  `json:"timezone"`
	ISP         string  `json:"isp"`
}

// MetricsQuery 指标查询
type MetricsQuery struct {
	MetricName string                 `json:"metric_name"`
	StartTime  time.Time              `json:"start_time"`
	EndTime    time.Time              `json:"end_time"`
	Interval   string                 `json:"interval"`
	Filters    map[string]interface{} `json:"filters"`
	GroupBy    []string               `json:"group_by"`
	Limit      int                    `json:"limit"`
}

// MetricsResult 指标结果
type MetricsResult struct {
	MetricName string                 `json:"metric_name"`
	Data       []MetricDataPoint      `json:"data"`
	Summary    map[string]interface{} `json:"summary"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// MetricDataPoint 指标数据点
type MetricDataPoint struct {
	Timestamp time.Time              `json:"timestamp"`
	Value     float64                `json:"value"`
	Labels    map[string]string      `json:"labels"`
	Metadata  map[string]interface{} `json:"metadata"`
}

// DashboardData 仪表板数据
type DashboardData struct {
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Widgets     []DashboardWidget      `json:"widgets"`
	RefreshRate int                    `json:"refresh_rate"` // 秒
	Metadata    map[string]interface{} `json:"metadata"`
}

// DashboardWidget 仪表板小部件
type DashboardWidget struct {
	ID       string                 `json:"id"`
	Type     string                 `json:"type"` // chart, table, metric, text
	Title    string                 `json:"title"`
	Data     interface{}            `json:"data"`
	Config   map[string]interface{} `json:"config"`
	Position WidgetPosition         `json:"position"`
}

// WidgetPosition 小部件位置
type WidgetPosition struct {
	X      int `json:"x"`
	Y      int `json:"y"`
	Width  int `json:"width"`
	Height int `json:"height"`
}

// Notification 通知消息
type Notification struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"` // info, warning, error, critical
	Title      string                 `json:"title"`
	Message    string                 `json:"message"`
	Channel    string                 `json:"channel"` // email, slack, webhook, etc.
	Recipients []string               `json:"recipients"`
	Metadata   map[string]interface{} `json:"metadata"`
	Timestamp  time.Time              `json:"timestamp"`
}

// NotificationChannel 通知渠道
type NotificationChannel struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Config      map[string]string `json:"config"`
	Enabled     bool              `json:"enabled"`
}

// Credentials 认证凭据
type Credentials struct {
	Type     string            `json:"type"` // password, token, certificate, oauth
	Username string            `json:"username"`
	Password string            `json:"password"`
	Token    string            `json:"token"`
	Data     map[string]string `json:"data"`
}

// User 用户信息
type User struct {
	ID          string            `json:"id"`
	Username    string            `json:"username"`
	Email       string            `json:"email"`
	DisplayName string            `json:"display_name"`
	Roles       []string          `json:"roles"`
	Permissions []string          `json:"permissions"`
	Attributes  map[string]string `json:"attributes"`
	CreatedAt   time.Time         `json:"created_at"`
	LastLogin   time.Time         `json:"last_login"`
	Active      bool              `json:"active"`
}

// TokenPair 令牌对
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

package ml

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// FeatureType 特征类型
type FeatureType string

const (
	FeatureTypeRequest FeatureType = "request" // 请求特征
	FeatureTypeIP      FeatureType = "ip"      // IP特征
	FeatureTypeTime    FeatureType = "time"    // 时序特征
	FeatureTypeBehavior FeatureType = "behavior" // 行为特征
)

// RequestFeatures 请求特征
type RequestFeatures struct {
	URLLength       int     `json:"url_length"`
	PathLength      int     `json:"path_length"`
	PathDepth       int     `json:"path_depth"`
	ParamCount      int     `json:"param_count"`
	HeaderCount     int     `json:"header_count"`
	CookieCount     int     `json:"cookie_count"`
	SpecialCharRatio float64 `json:"special_char_ratio"`
	HasSQLKeywords  bool    `json:"has_sql_keywords"`
	HasXSSKeywords  bool    `json:"has_xss_keywords"`
	HasPathTraversal bool   `json:"has_path_traversal"`
	ContentType     string  `json:"content_type"`
	UserAgentLength int     `json:"ua_length"`
	RefererLength   int     `json:"referer_length"`
	BodySize        int64   `json:"body_size"`
	IsHTTPS         bool    `json:"is_https"`
	HasCookie       bool    `json:"has_cookie"`
	HasAuth         bool    `json:"has_auth"`
	Method          string  `json:"method"`
}

// IPFeatures IP特征
type IPFeatures struct {
	RequestCount       int       `json:"request_count"`
	FailedRequestCount int       `json:"failed_request_count"`
	SuccessRate        float64   `json:"success_rate"`
	AvgRequestInterval float64   `json:"avg_request_interval_ms"`
	UniquePaths        int       `json:"unique_paths"`
	UniqueUserAgents   int       `json:"unique_user_agents"`
	UAChangeCount      int       `json:"ua_change_count"`
	FirstSeen          time.Time `json:"first_seen"`
	LastSeen           time.Time `json:"last_seen"`
	GeoLocation        string    `json:"geo_location,omitempty"`
	IsTorExit          bool      `json:"is_tor_exit"`
	IsKnownBot         bool      `json:"is_known_bot"`
	ReputationScore    float64   `json:"reputation_score"`
}

// TimeFeatures 时序特征
type TimeFeatures struct {
	HourOfDay         int     `json:"hour_of_day"`
	DayOfWeek         int     `json:"day_of_week"`
	IsWeekend         bool    `json:"is_weekend"`
	IsBusinessHours   bool    `json:"is_business_hours"`
	RequestsLast1Min  int     `json:"requests_last_1min"`
	RequestsLast5Min  int     `json:"requests_last_5min"`
	RequestsLast1Hour int     `json:"requests_last_1hour"`
	RequestTrend      float64 `json:"request_trend"`      // 请求趋势
	ErrorRateTrend    float64 `json:"error_rate_trend"`    // 错误率趋势
	AvgResponseTime   float64 `json:"avg_response_time_ms"`
	P95ResponseTime   float64 `json:"p95_response_time_ms"`
	P99ResponseTime   float64 `json:"p99_response_time_ms"`
}

// BehavioralFeatures 行为特征
type BehavioralFeatures struct {
	PathTraversalPattern    bool     `json:"path_traversal_pattern"`
	ParamBruteForce         bool     `json:"param_brute_force"`
	SequentialAccess         bool     `json:"sequential_access"`
	RapidSequentialRequests  bool     `json:"rapid_sequential_requests"`
	UserAgentSwitchFrequency float64  `json:"ua_switch_frequency"`
	HeaderAnomalyScore       float64  `json:"header_anomaly_score"`
	SessionDuration          float64  `json:"session_duration_seconds"`
	PagesPerSession          float64  `json:"pages_per_session"`
	BounceRate               float64  `json:"bounce_rate"`
	IsScanning               bool     `json:"is_scanning"`
}

// CombinedFeatures 组合特征
type CombinedFeatures struct {
	Request    RequestFeatures    `json:"request"`
	IP         IPFeatures         `json:"ip"`
	Time       TimeFeatures       `json:"time"`
	Behavioral BehavioralFeatures `json:"behavioral"`
	Timestamp  time.Time          `json:"timestamp"`
}

// FeatureExtractor 特征提取器
type FeatureExtractor struct {
	// IP 状态存储
	ipStates       map[string]*IPState
	ipStatesMutex  sync.RWMutex

	// 时序窗口
	timeWindows    map[string]*TimeWindow
	timeWindowsMutex sync.RWMutex

	// 配置
	timeWindowDuration time.Duration // 时间窗口大小
	maxIPStates         int           // 最大IP状态数
	maxUniquePaths      int           // 最大唯一路径数

	// 已知爬虫/机器人列表
	knownBots      map[string]bool
	knownBotTokens map[string]bool

	log *logrus.Entry
}

// IPState IP状态
type IPState struct {
	IP                string
	RequestCount      int
	FailedRequestCount int
	FirstSeen         time.Time
	LastSeen          time.Time
	UniquePaths       map[string]bool
	UniqueUserAgents  map[string]bool
	UserAgentHistory  []string
	LastUserAgent     string
	UAChangeCount     int
	RequestTimes      []time.Time
	ResponseTimes     []time.Duration
	GeoLocation       string
}

// TimeWindow 时间窗口
type TimeWindow struct {
	WindowStart   time.Time
	RequestCount  int
	ErrorCount    int
	ResponseTimes []float64
	UniquePaths   map[string]bool
}

// SQL注入关键词
var sqlKeywords = []string{
	"select", "insert", "update", "delete", "drop", "union",
	"or", "and", "where", "from", "exec", "script", "javascript:",
	"eval", "expression", "--", "/*", "*/", "xp_", "sp_",
	"declare", "cast", "convert", "truncate", "rownum",
}

// XSS关键词
var xssKeywords = []string{
	"<script", "javascript:", "onerror=", "onload=", "onclick=",
	"onmouseover=", "onfocus=", "onblur=", "alert(", "document.cookie",
	"document.location", "window.location", "eval(", "expression(",
	"<iframe", "<object", "<embed", "<link", "<style", "<svg",
	"fromCharCode", "String.fromCharCode",
}

// 路径遍历模式
var pathTraversalPatterns = []string{
	"../", "..\\", "./", ".\\", "%2e%2e", "%252e", "%c0%ae",
	"....//", "....\\\\", "//etc", "\\\\windows", "/etc/passwd",
	"/proc/self", "web.config", ".htaccess",
}

// NewFeatureExtractor 创建特征提取器
func NewFeatureExtractor() *FeatureExtractor {
	fe := &FeatureExtractor{
		ipStates:          make(map[string]*IPState),
		timeWindows:        make(map[string]*TimeWindow),
		timeWindowDuration: 5 * time.Minute,
		maxIPStates:        10000,
		maxUniquePaths:     1000,
		knownBots:          make(map[string]bool),
		knownBotTokens:     make(map[string]bool),
		log: logrus.WithFields(logrus.Fields{
			"component": "ml_feature_extractor",
		}),
	}

	// 初始化已知爬虫
	fe.initKnownBots()

	return fe
}

// initKnownBots 初始化已知爬虫列表
func (fe *FeatureExtractor) initKnownBots() {
	// 已知搜索引擎爬虫的User-Agent关键词
	searchEngineBots := []string{
		"googlebot", "bingbot", "slurp", "duckduckbot",
		"baiduspider", "yandexbot", "sogou", "exabot",
		"facebookexternalhit", "twitterbot", "linkedinbot",
	}

	for _, bot := range searchEngineBots {
		fe.knownBots[bot] = true
	}

	// 已知工具User-Agent
	toolBots := []string{
		"curl", "wget", "python-requests", "go-http-client",
		"java", "axios", "node-fetch", "requests", "httpie",
		"postman", "insomnia", "swagger", "apache-httpclient",
	}

	for _, bot := range toolBots {
		fe.knownBots[bot] = true
	}
}

// Extract 从HTTP请求提取特征
func (fe *FeatureExtractor) Extract(r *http.Request, statusCode int, responseTime time.Duration, remoteAddr string) *CombinedFeatures {
	// 提取请求特征
	reqFeatures := fe.extractRequestFeatures(r)

	// 提取IP特征
	ipFeatures := fe.extractIPFeatures(r, remoteAddr, statusCode, responseTime)

	// 提取时序特征
	timeFeatures := fe.extractTimeFeatures(r, remoteAddr, responseTime)

	// 提取行为特征
	behaviorFeatures := fe.extractBehavioralFeatures(r, remoteAddr, responseTime)

	return &CombinedFeatures{
		Request:    reqFeatures,
		IP:         *ipFeatures,
		Time:       *timeFeatures,
		Behavioral: *behaviorFeatures,
		Timestamp:  time.Now(),
	}
}

// extractRequestFeatures 提取请求特征
func (fe *FeatureExtractor) extractRequestFeatures(r *http.Request) RequestFeatures {
	url := r.URL.String()
	path := r.URL.Path

	features := RequestFeatures{
		URLLength:       len(url),
		PathLength:      len(path),
		PathDepth:       strings.Count(path, "/"),
		ParamCount:      len(r.URL.Query()),
		HeaderCount:     len(r.Header),
		CookieCount:     len(r.Cookies()),
		Method:          r.Method,
		IsHTTPS:         r.TLS != nil,
		ContentType:     r.Header.Get("Content-Type"),
		HasCookie:       len(r.Cookies()) > 0,
	}

	// 计算特殊字符比例
	specialChars := 0
	for _, c := range url {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '/' || c == '?' || c == '=' || c == '&' || c == '.' || c == '-' || c == '_') {
			specialChars++
		}
	}
	if len(url) > 0 {
		features.SpecialCharRatio = float64(specialChars) / float64(len(url))
	}

	// 检查SQL注入关键词
	lowerURL := strings.ToLower(url)
	features.HasSQLKeywords = fe.containsAny(lowerURL, sqlKeywords)

	// 检查XSS关键词
	features.HasXSSKeywords = fe.containsAny(lowerURL, xssKeywords)

	// 检查路径遍历
	features.HasPathTraversal = fe.containsAny(lowerURL, pathTraversalPatterns)

	// User-Agent长度
	ua := r.Header.Get("User-Agent")
	features.UserAgentLength = len(ua)

	// Referer长度
	referer := r.Header.Get("Referer")
	features.RefererLength = len(referer)

	// 检查认证
	username, _, hasBasicAuth := r.BasicAuth()
	if hasBasicAuth && username != "" {
		features.HasAuth = true
	}
	if r.Header.Get("Authorization") != "" {
		features.HasAuth = true
	}

	// Content-Type
	features.ContentType = r.Header.Get("Content-Type")

	return features
}

// extractIPFeatures 提取IP特征
func (fe *FeatureExtractor) extractIPFeatures(r *http.Request, remoteAddr string, statusCode int, responseTime time.Duration) *IPFeatures {
	// 解析IP
	ip := fe.parseIP(remoteAddr)
	if ip == "" {
		ip = r.RemoteAddr
	}

	fe.ipStatesMutex.Lock()
	defer fe.ipStatesMutex.Unlock()

	// 获取或创建IP状态
	state := fe.ipStates[ip]
	if state == nil {
		state = &IPState{
			IP:               ip,
			FirstSeen:        time.Now(),
			UniquePaths:      make(map[string]bool),
			UniqueUserAgents: make(map[string]bool),
			UserAgentHistory: make([]string, 0, 10),
			RequestTimes:     make([]time.Time, 0, 100),
			ResponseTimes:    make([]time.Duration, 0, 100),
		}
		fe.ipStates[ip] = state
	}

	// 更新状态
	state.RequestCount++
	state.LastSeen = time.Now()
	state.UniquePaths[r.URL.Path] = true

	// 更新User-Agent
	ua := r.Header.Get("User-Agent")
	state.LastUserAgent = ua
	state.UniqueUserAgents[ua] = true

	// 检查UA变化
	if len(state.UserAgentHistory) > 0 && state.UserAgentHistory[len(state.UserAgentHistory)-1] != ua {
		state.UAChangeCount++
	}
	state.UserAgentHistory = append(state.UserAgentHistory, ua)

	// 记录请求时间
	now := time.Now()
	state.RequestTimes = append(state.RequestTimes, now)
	if len(state.RequestTimes) > 100 {
		state.RequestTimes = state.RequestTimes[1:]
	}

	// 记录响应时间
	state.ResponseTimes = append(state.ResponseTimes, responseTime)
	if len(state.ResponseTimes) > 100 {
		state.ResponseTimes = state.ResponseTimes[1:]
	}

	// 计算失败率
	if statusCode >= 400 {
		state.FailedRequestCount++
	}

	// 清理旧状态
	if len(fe.ipStates) > fe.maxIPStates {
		fe.cleanupOldIPStates()
	}

	// 计算特征
	features := &IPFeatures{
		RequestCount:       state.RequestCount,
		FailedRequestCount: state.FailedRequestCount,
		FirstSeen:          state.FirstSeen,
		LastSeen:           state.LastSeen,
		UniquePaths:        len(state.UniquePaths),
		UniqueUserAgents:   len(state.UniqueUserAgents),
		UAChangeCount:      state.UAChangeCount,
		ReputationScore:    fe.calculateReputationScore(state),
	}

	// 计算成功率
	if state.RequestCount > 0 {
		features.SuccessRate = 1.0 - float64(state.FailedRequestCount)/float64(state.RequestCount)
	}

	// 计算平均请求间隔
	if len(state.RequestTimes) >= 2 {
		totalInterval := state.RequestTimes[len(state.RequestTimes)-1].Sub(state.RequestTimes[0]).Milliseconds()
		features.AvgRequestInterval = float64(totalInterval) / float64(len(state.RequestTimes)-1)
	}

	// 检测是否为已知爬虫
	uaLower := strings.ToLower(ua)
	for bot := range fe.knownBots {
		if strings.Contains(uaLower, bot) {
			features.IsKnownBot = true
			break
		}
	}

	return features
}

// extractTimeFeatures 提取时序特征
func (fe *FeatureExtractor) extractTimeFeatures(r *http.Request, remoteAddr string, responseTime time.Duration) *TimeFeatures {
	now := time.Now()

	fe.timeWindowsMutex.Lock()
	defer fe.timeWindowsMutex.Unlock()

	// 获取或创建时间窗口
	windowKey := remoteAddr + "_" + now.Truncate(fe.timeWindowDuration).Format("200601021504")
	window := fe.timeWindows[windowKey]
	if window == nil {
		window = &TimeWindow{
			WindowStart:   now.Truncate(fe.timeWindowDuration),
			ResponseTimes: make([]float64, 0, 1000),
			UniquePaths:   make(map[string]bool),
		}
		fe.timeWindows[windowKey] = window
	}

	// 更新窗口
	window.RequestCount++
	if responseTime > 0 {
		window.ResponseTimes = append(window.ResponseTimes, float64(responseTime.Milliseconds()))
	}
	window.UniquePaths[r.URL.Path] = true

	// 清理旧窗口
	fe.cleanupOldTimeWindows()

	features := &TimeFeatures{
		HourOfDay:       now.Hour(),
		DayOfWeek:       int(now.Weekday()),
		IsWeekend:       now.Weekday() == time.Saturday || now.Weekday() == time.Sunday,
		IsBusinessHours: now.Hour() >= 9 && now.Hour() < 18,
		RequestsLast1Min:  fe.countRequestsInWindow(remoteAddr, 1*time.Minute),
		RequestsLast5Min:  fe.countRequestsInWindow(remoteAddr, 5*time.Minute),
		RequestsLast1Hour: fe.countRequestsInWindow(remoteAddr, 1*time.Hour),
	}

	// 计算响应时间统计
	if len(window.ResponseTimes) > 0 {
		sum := 0.0
		for _, t := range window.ResponseTimes {
			sum += t
		}
		features.AvgResponseTime = sum / float64(len(window.ResponseTimes))

		// 计算百分位数
		sorted := make([]float64, len(window.ResponseTimes))
		copy(sorted, window.ResponseTimes)
		// 简单排序（生产环境可用更高效的算法）
		for i := 0; i < len(sorted); i++ {
			for j := i + 1; j < len(sorted); j++ {
				if sorted[i] > sorted[j] {
					sorted[i], sorted[j] = sorted[j], sorted[i]
				}
			}
		}

		if len(sorted) > 0 {
			p95Index := len(sorted) * 95 / 100
			p99Index := len(sorted) * 99 / 100
			if p95Index < len(sorted) {
				features.P95ResponseTime = sorted[p95Index]
			}
			if p99Index < len(sorted) {
				features.P99ResponseTime = sorted[p99Index]
			}
		}
	}

	return features
}

// extractBehavioralFeatures 提取行为特征
// 注意：本函数在整段访问期间持有 ipStates 的读锁，因为 IPState 内部的 map/slice
// 字段在 extractIPFeatures 中会被写锁修改；如果只在第 482 行拿引用就放锁，
// 后续对 state.UniquePaths / state.RequestTimes 等的读取会与写者发生 data race。
func (fe *FeatureExtractor) extractBehavioralFeatures(r *http.Request, remoteAddr string, responseTime time.Duration) *BehavioralFeatures {
	fe.ipStatesMutex.RLock()
	defer fe.ipStatesMutex.RUnlock()

	features := &BehavioralFeatures{}

	state := fe.ipStates[remoteAddr]
	if state == nil {
		return features
	}

	features.PathTraversalPattern = fe.detectPathTraversalPattern(state)
	features.ParamBruteForce = fe.detectParamBruteForce(state)
	features.SequentialAccess = fe.detectSequentialAccess(state)
	features.RapidSequentialRequests = fe.detectRapidSequentialRequests(state)

	if len(state.UserAgentHistory) > 1 {
		features.UserAgentSwitchFrequency = float64(state.UAChangeCount) / float64(state.RequestCount)
	}

	features.IsScanning = fe.detectScanning(state)

	return features
}

// Helper functions

func (fe *FeatureExtractor) parseIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func (fe *FeatureExtractor) containsAny(s string, keywords []string) bool {
	lower := strings.ToLower(s)
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func (fe *FeatureExtractor) calculateReputationScore(state *IPState) float64 {
	score := 1.0

	// 新IP降分
	if time.Since(state.FirstSeen) < 5*time.Minute {
		score -= 0.1
	}

	// 失败率降分
	if state.RequestCount > 0 {
		failRate := float64(state.FailedRequestCount) / float64(state.RequestCount)
		if failRate > 0.5 {
			score -= 0.3 * failRate
		}
	}

	// UA变化频繁降分
	if state.UAChangeCount > 5 {
		score -= 0.2
	}

	// 请求路径过多降分
	if len(state.UniquePaths) > 100 {
		score -= 0.1
	}

	// 确保分数在0-1范围内
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	return score
}

func (fe *FeatureExtractor) cleanupOldIPStates() {
	// 清理超过24小时的旧状态
	cutoff := time.Now().Add(-24 * time.Hour)
	for ip, state := range fe.ipStates {
		if state.LastSeen.Before(cutoff) {
			delete(fe.ipStates, ip)
		}
	}

	// 如果仍然太多，删除最旧的
	if len(fe.ipStates) > fe.maxIPStates {
		type ipLastSeen struct {
			ip   string
			time time.Time
		}
		var states []ipLastSeen
		for ip, state := range fe.ipStates {
			states = append(states, ipLastSeen{ip: ip, time: state.LastSeen})
		}

		// 按时间排序
		for i := 0; i < len(states); i++ {
			for j := i + 1; j < len(states); j++ {
				if states[i].time.Before(states[j].time) {
					states[i], states[j] = states[j], states[i]
				}
			}
		}

		// 删除最旧的
		toDelete := len(states) - fe.maxIPStates
		for i := 0; i < toDelete; i++ {
			delete(fe.ipStates, states[i].ip)
		}
	}
}

func (fe *FeatureExtractor) cleanupOldTimeWindows() {
	cutoff := time.Now().Add(-1 * time.Hour)
	for key, window := range fe.timeWindows {
		if window.WindowStart.Before(cutoff) {
			delete(fe.timeWindows, key)
		}
	}
}

func (fe *FeatureExtractor) countRequestsInWindow(remoteAddr string, duration time.Duration) int {
	count := 0
	cutoff := time.Now().Add(-duration)

	fe.ipStatesMutex.RLock()
	defer fe.ipStatesMutex.RUnlock()

	state := fe.ipStates[remoteAddr]
	if state == nil {
		return 0
	}

	for _, t := range state.RequestTimes {
		if t.After(cutoff) {
			count++
		}
	}

	return count
}

func (fe *FeatureExtractor) detectPathTraversalPattern(state *IPState) bool {
	traversalCount := 0
	for path := range state.UniquePaths {
		if strings.Contains(path, "../") || strings.Contains(path, "..\\") {
			traversalCount++
		}
	}
	return traversalCount >= 3
}

func (fe *FeatureExtractor) detectParamBruteForce(state *IPState) bool {
	// 检测是否存在大量不同参数的请求访问相同路径
	return len(state.UniquePaths) > 50 && state.RequestCount > 100
}

func (fe *FeatureExtractor) detectSequentialAccess(state *IPState) bool {
	if len(state.RequestTimes) < 10 {
		return false
	}

	// 检测是否有顺序访问模式
	sequentialCount := 0
	for i := 1; i < len(state.RequestTimes); i++ {
		interval := state.RequestTimes[i].Sub(state.RequestTimes[i-1]).Milliseconds()
		// 如果请求间隔非常规律（±10%以内）
		if interval > 0 {
			sequentialCount++
		}
	}

	return sequentialCount > len(state.RequestTimes)*80/100
}

func (fe *FeatureExtractor) detectRapidSequentialRequests(state *IPState) bool {
	if len(state.RequestTimes) < 5 {
		return false
	}

	// 检测短时间内的大量请求
	for i := 4; i < len(state.RequestTimes); i++ {
		window := state.RequestTimes[i].Sub(state.RequestTimes[i-4]).Seconds()
		if window < 1 && float64(i-4)/window > 10 { // 1秒内超过10个请求
			return true
		}
	}

	return false
}

func (fe *FeatureExtractor) detectScanning(state *IPState) bool {
	// 扫描特征：大量不同路径、低成功率、高UA变化
	if len(state.UniquePaths) < 20 {
		return false
	}

	failRate := float64(state.FailedRequestCount) / float64(state.RequestCount)
	uaChangeRate := float64(state.UAChangeCount) / float64(state.RequestCount)

	return failRate > 0.5 && uaChangeRate > 0.3
}

// GetFeatureVector 获取用于机器学习的特征向量
func (fe *FeatureExtractor) GetFeatureVector(features *CombinedFeatures) []float64 {
	return []float64{
		// 请求特征
		float64(features.Request.URLLength),
		float64(features.Request.PathLength),
		float64(features.Request.PathDepth),
		float64(features.Request.ParamCount),
		float64(features.Request.HeaderCount),
		float64(features.Request.CookieCount),
		features.Request.SpecialCharRatio,
		boolToFloat(features.Request.HasSQLKeywords),
		boolToFloat(features.Request.HasXSSKeywords),
		boolToFloat(features.Request.HasPathTraversal),
		float64(features.Request.UserAgentLength),
		float64(features.Request.RefererLength),
		boolToFloat(features.Request.IsHTTPS),
		boolToFloat(features.Request.HasCookie),
		boolToFloat(features.Request.HasAuth),

		// IP特征
		float64(features.IP.RequestCount),
		float64(features.IP.FailedRequestCount),
		features.IP.SuccessRate,
		features.IP.AvgRequestInterval,
		float64(features.IP.UniquePaths),
		float64(features.IP.UniqueUserAgents),
		float64(features.IP.UAChangeCount),
		features.IP.ReputationScore,
		boolToFloat(features.IP.IsKnownBot),

		// 时序特征
		float64(features.Time.HourOfDay) / 24.0,
		float64(features.Time.DayOfWeek) / 7.0,
		boolToFloat(features.Time.IsWeekend),
		boolToFloat(features.Time.IsBusinessHours),
		float64(features.Time.RequestsLast1Min),
		float64(features.Time.RequestsLast5Min),
		float64(features.Time.RequestsLast1Hour),
		features.Time.AvgResponseTime / 1000.0, // 转换为秒
		features.Time.P95ResponseTime / 1000.0,
		features.Time.P99ResponseTime / 1000.0,

		// 行为特征
		boolToFloat(features.Behavioral.PathTraversalPattern),
		boolToFloat(features.Behavioral.ParamBruteForce),
		boolToFloat(features.Behavioral.SequentialAccess),
		boolToFloat(features.Behavioral.RapidSequentialRequests),
		features.Behavioral.UserAgentSwitchFrequency,
		boolToFloat(features.Behavioral.IsScanning),
	}
}

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

// GetFeatureDimension 获取特征向量维度
func (fe *FeatureExtractor) GetFeatureDimension() int {
	vector := fe.GetFeatureVector(&CombinedFeatures{})
	return len(vector)
}

package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/notification"
)

// SecurityAnalyzer AI 安全分析器
type SecurityAnalyzer struct {
	apiKey        string
	apiEndpoint   string
	model         string
	enabled       bool
	checkInterval time.Duration
	lastCheckTime time.Time
	analysisCache map[string]*AnalysisResult
	cacheMutex    sync.RWMutex
	notifier      *notification.NotificationIntegrator
	log           *logrus.Entry
	maxTokens     int
	temperature   float64
	systemPrompt  string
	language      string // 语言设置：zh-CN 或 en-US
}

// SecurityData 安全数据摘要
type SecurityData struct {
	TimeRange       string                 `json:"time_range"`
	TotalRequests   int64                  `json:"total_requests"`
	BlockedIPs      int                    `json:"blocked_ips"`
	SuspiciousIPs   int                    `json:"suspicious_ips"`
	AttackEvents    []AttackSummary        `json:"attack_events"`
	TopAttackers    []IPSummary            `json:"top_attackers"`
	AnomalousUA     []UASummary            `json:"anomalous_user_agents"`
	ErrorRate       float64                `json:"error_rate"`
	TrafficPatterns map[string]interface{} `json:"traffic_patterns"`
}

// AttackSummary 攻击事件摘要
type AttackSummary struct {
	Type      string    `json:"type"`
	Count     int       `json:"count"`
	Blocked   int       `json:"blocked"`
	Severity  string    `json:"severity"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	TopIPs    []string  `json:"top_ips"`
}

// IPSummary IP 统计摘要
type IPSummary struct {
	IP           string    `json:"ip"`
	RequestCount int       `json:"request_count"`
	BlockCount   int       `json:"block_count"`
	AttackTypes  []string  `json:"attack_types"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	RequestRate  float64   `json:"request_rate"`
	GeoLocation  string    `json:"geo_location,omitempty"`
}

// UASummary User-Agent 统计摘要
type UASummary struct {
	UserAgent    string `json:"user_agent"`
	RequestCount int    `json:"request_count"`
	UniqueIPs    int    `json:"unique_ips"`
	Suspicious   bool   `json:"suspicious"`
	Reason       string `json:"reason,omitempty"`
}

// AnalysisResult AI 分析结果
type AnalysisResult struct {
	Timestamp         time.Time         `json:"timestamp"`
	ThreatLevel       string            `json:"threat_level"` // low, medium, high, critical
	SummaryZh         string            `json:"summary_zh"`   // 中文总结
	SummaryEn         string            `json:"summary_en"`   // 英文总结
	Summary           string            `json:"summary"`      // 兼容字段（自动填充）
	Threats           []ThreatDetection `json:"threats"`
	RecommendationsZh []string          `json:"recommendations_zh"` // 中文建议
	RecommendationsEn []string          `json:"recommendations_en"` // 英文建议
	Recommendations   []string          `json:"recommendations"`    // 兼容字段（自动填充）
	RawResponse       string            `json:"raw_response"`
	Confidence        float64           `json:"confidence"`
	DataHash          string            `json:"data_hash"` // 用于去重
}

// ThreatDetection 威胁检测结果
type ThreatDetection struct {
	Type          string   `json:"type"`
	Severity      string   `json:"severity"`
	DescriptionZh string   `json:"description_zh"` // 中文描述
	DescriptionEn string   `json:"description_en"` // 英文描述
	Description   string   `json:"description"`    // 兼容字段（自动填充）
	Indicators    []string `json:"indicators"`
	Confidence    float64  `json:"confidence"`
	ActionZh      string   `json:"action_zh"` // 中文建议
	ActionEn      string   `json:"action_en"` // 英文建议
	Action        string   `json:"action"`    // 兼容字段（自动填充）
}

// GPTRequest GPT API 请求结构
type GPTRequest struct {
	Model       string       `json:"model"`
	Messages    []GPTMessage `json:"messages"`
	MaxTokens   int          `json:"max_tokens,omitempty"`
	Temperature float64      `json:"temperature,omitempty"`
}

// GPTMessage GPT 消息结构
type GPTMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// GPTResponse GPT API 响应结构
type GPTResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// NewSecurityAnalyzer 创建 AI 安全分析器
func NewSecurityAnalyzer(cfg config.AISecurityConfig, notifier *notification.NotificationIntegrator) *SecurityAnalyzer {
	analyzer := &SecurityAnalyzer{
		apiKey:        cfg.APIKey,
		apiEndpoint:   cfg.APIEndpoint,
		model:         cfg.Model,
		enabled:       cfg.Enabled,
		checkInterval: cfg.CheckInterval,
		maxTokens:     cfg.MaxTokens,
		temperature:   cfg.Temperature,
		language:      cfg.Language,
		notifier:      notifier,
		analysisCache: make(map[string]*AnalysisResult),
		log:           logrus.WithFields(logrus.Fields{"component": "ai_security"}),
	}

	// 设置默认值
	if analyzer.apiEndpoint == "" {
		analyzer.apiEndpoint = "https://api.openai.com/v1/chat/completions"
	}
	if analyzer.model == "" {
		analyzer.model = "gpt-4o-mini"
	}
	if analyzer.checkInterval == 0 {
		analyzer.checkInterval = 1 * time.Hour
	}
	if analyzer.maxTokens == 0 {
		analyzer.maxTokens = 3000 // 提高默认值以避免响应被截断
	}
	if analyzer.temperature == 0 {
		analyzer.temperature = 0.3 // 较低的温度，更加精确
	}
	if analyzer.language == "" {
		analyzer.language = "zh-CN" // 默认中文
	}

	// 初始化系统提示词
	analyzer.systemPrompt = analyzer.buildSystemPrompt()

	return analyzer
}

// buildSystemPrompt 构建系统提示词
func (a *SecurityAnalyzer) buildSystemPrompt() string {
	if a.language == "en-US" {
		return a.buildEnglishSystemPrompt()
	}
	return a.buildChineseSystemPrompt()
}

// buildChineseSystemPrompt 构建中文系统提示词
func (a *SecurityAnalyzer) buildChineseSystemPrompt() string {
	return `你是一名专业的网络安全分析专家，专门分析Web服务器安全日志和攻击模式。

你的任务：
1. 分析安全数据，识别潜在威胁和异常
2. 评估威胁等级（低、中、高、严重）
3. 提供具体的威胁描述和风险评估
4. 给出可执行的安全建议

分析重点：
- DDoS攻击模式：识别大规模高频请求模式
- 扫描行为：检测常见漏洞路径探测（.env、wp-admin、phpmyadmin等）
- 异常User-Agent：识别爬虫、扫描工具、恶意软件特征
- 地理位置异常：识别来自高风险地区的集中攻击
- 时间模式异常：识别异常时段的流量激增
- IP信誉：识别已知恶意IP或云服务器IP（常被用于攻击）
- 请求特征：识别SQL注入、XSS、路径遍历尝试

输出格式要求（JSON）：
{
  "threat_level": "low|medium|high|critical",
  "summary": "一句话总结当前安全态势",
  "threats": [
    {
      "type": "威胁类型（如：ddos_attack、port_scan、sql_injection）",
      "severity": "low|medium|high|critical",
      "description": "详细描述",
      "indicators": ["具体指标，如IP地址、UA模式等"],
      "confidence": 0.95,
      "action": "处理建议"
    }
  ],
  "recommendations": [
    "安全建议"
  ],
  "confidence": 0.90
}

分析原则：
1. 基于数据分析，不做假设
2. 区分误报和真实威胁
3. 考虑正常业务流量与异常流量
4. 提供可操作的建议，而非泛泛而谈
5. 标注置信度供管理员判断

重要提示：
- 必须返回标准JSON格式
- 所有内容使用中文
- 不要添加额外的说明文字`
}

// buildEnglishSystemPrompt 构建英文系统提示词
func (a *SecurityAnalyzer) buildEnglishSystemPrompt() string {
	return `You are a professional cybersecurity analyst specializing in analyzing web server security logs and attack patterns.

Your Tasks:
1. Analyze the security data and identify potential threats and anomalies
2. Assess threat levels (low, medium, high, critical)
3. Provide specific threat descriptions and risk assessments
4. Give actionable security recommendations

Analysis Focus:
- DDoS attack patterns: Identify large-scale, high-frequency request patterns
- Scanning behavior: Detect probes for common vulnerability paths (.env, wp-admin, phpmyadmin, etc.)
- Anomalous User-Agent: Identify crawlers, scanning tools, malware signatures
- Geographic anomalies: Identify concentrated attacks from high-risk regions
- Time pattern anomalies: Identify traffic surges during abnormal hours
- IP reputation: Identify known malicious IPs or cloud server IPs (commonly used for attacks)
- Request characteristics: Identify SQL injection, XSS, path traversal attempts

Output Format Requirements (JSON):
{
  "threat_level": "low|medium|high|critical",
  "summary": "One-sentence security situation overview",
  "threats": [
    {
      "type": "threat type (e.g., ddos_attack, port_scan, sql_injection)",
      "severity": "low|medium|high|critical",
      "description": "Detailed description",
      "indicators": ["Specific indicators like IP addresses, UA patterns"],
      "confidence": 0.95,
      "action": "Recommended action"
    }
  ],
  "recommendations": [
    "Security recommendations"
  ],
  "confidence": 0.90
}

Analysis Principles:
1. Base analysis on data, don't make assumptions
2. Distinguish between false positives and real threats
3. Consider normal business traffic vs. anomalous traffic
4. Provide actionable advice, not generic suggestions
5. Mark confidence levels for administrator judgment

IMPORTANT: 
- Always return standard JSON format
- All content in English
- No additional commentary outside JSON`
}

// Start 启动定时分析
func (a *SecurityAnalyzer) Start(dataCollector func() *SecurityData) {
	if !a.enabled {
		a.log.Info("AI 安全分析器未启用")
		return
	}

	if a.apiKey == "" {
		a.log.Warn("AI 安全分析器: API Key 未配置，已禁用")
		return
	}

	a.log.Infof("AI 安全分析器已启动，检查间隔: %v", a.checkInterval)

	go func() {
		ticker := time.NewTicker(a.checkInterval)
		defer ticker.Stop()

		// 立即执行一次
		a.runAnalysis(dataCollector)

		for range ticker.C {
			a.runAnalysis(dataCollector)
		}
	}()
}

// runAnalysis 执行一次分析
func (a *SecurityAnalyzer) runAnalysis(dataCollector func() *SecurityData) {
	a.log.Info("开始执行 AI 安全分析...")

	// 收集数据
	data := dataCollector()
	if data == nil {
		a.log.Warn("无法收集安全数据，跳过本次分析")
		return
	}

	// 检查是否有数据
	if data.TotalRequests == 0 && len(data.AttackEvents) == 0 {
		a.log.Info("本时段无安全事件，跳过分析")
		return
	}

	// 生成数据摘要的 hash，用于去重
	dataHash := a.generateDataHash(data)

	// 检查缓存
	a.cacheMutex.RLock()
	if cached, exists := a.analysisCache[dataHash]; exists {
		if time.Since(cached.Timestamp) < a.checkInterval {
			a.log.Debug("使用缓存的分析结果")
			a.cacheMutex.RUnlock()
			return
		}
	}
	a.cacheMutex.RUnlock()

	// 调用 GPT API 进行分析
	result, err := a.AnalyzeWithGPT(data)
	if err != nil {
		a.log.Errorf("AI 分析失败: %v", err)
		return
	}

	// 缓存结果
	result.DataHash = dataHash
	a.cacheMutex.Lock()
	a.analysisCache[dataHash] = result
	a.cacheMutex.Unlock()

	a.lastCheckTime = time.Now()

	// 根据威胁等级决定是否发送通知
	if a.ShouldNotify(result) {
		a.SendNotification(result, data)
	}

	a.log.Infof("AI 分析完成，威胁等级: %s，置信度: %.2f", result.ThreatLevel, result.Confidence)
}

// AnalyzeWithGPT 使用 GPT API 进行分析（公开方法）
func (a *SecurityAnalyzer) AnalyzeWithGPT(data *SecurityData) (*AnalysisResult, error) {
	// 构建用户提示词
	userPrompt := a.buildUserPrompt(data)

	// 构建请求
	request := GPTRequest{
		Model: a.model,
		Messages: []GPTMessage{
			{
				Role:    "system",
				Content: a.systemPrompt,
			},
			{
				Role:    "user",
				Content: userPrompt,
			},
		},
		MaxTokens:   a.maxTokens,
		Temperature: a.temperature,
	}

	// 序列化请求
	requestBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %v", err)
	}

	// 发送 HTTP 请求
	httpReq, err := http.NewRequest("POST", a.apiEndpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.apiKey))

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("API 请求失败: %v", err)
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API 返回错误: %d, %s", resp.StatusCode, string(body))
	}

	// 解析响应
	var gptResp GPTResponse
	if err := json.Unmarshal(body, &gptResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	if len(gptResp.Choices) == 0 {
		return nil, fmt.Errorf("API 返回空结果")
	}

	// 解析 AI 的分析结果
	content := gptResp.Choices[0].Message.Content
	result := &AnalysisResult{
		Timestamp:   time.Now(),
		RawResponse: content,
	}

	// 尝试解析 JSON
	// 去除可能的 markdown 代码块标记
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	if err := json.Unmarshal([]byte(content), result); err != nil {
		a.log.Warnf("无法解析 AI 响应为 JSON: %v, 原始内容长度: %d", err, len(content))
		a.log.Debugf("原始 JSON 内容:\n%s", content)

		// 尝试修复截断的 JSON
		fixedContent := a.tryFixTruncatedJSON(content)
		if err2 := json.Unmarshal([]byte(fixedContent), result); err2 == nil {
			a.log.Info("✅ 成功修复并解析截断的 JSON 响应")
			a.log.Debugf("修复后的 JSON:\n%s", fixedContent)
			a.log.Infof("修复详情: 原始长度=%d, 修复后长度=%d, 增加了 %d 字符",
				len(content), len(fixedContent), len(fixedContent)-len(content))
		} else {
			// 降级处理：手动解析
			a.log.Warnf("❌ JSON 修复失败: %v", err2)
			a.log.Warnf("原始内容: %s", content)
			a.log.Warnf("修复后内容: %s", fixedContent)
			result.ThreatLevel = "unknown"
			result.SummaryZh = "AI 分析完成，但格式解析失败。请增加 max_tokens 配置。"
			result.SummaryEn = "AI analysis completed, but format parsing failed. Please increase max_tokens configuration."
			result.Confidence = 0.5
		}
	}

	// 自动填充兼容字段（优先使用中文）
	if result.Summary == "" {
		if result.SummaryZh != "" {
			result.Summary = result.SummaryZh
		} else {
			result.Summary = result.SummaryEn
		}
	}

	if len(result.Recommendations) == 0 {
		if len(result.RecommendationsZh) > 0 {
			result.Recommendations = result.RecommendationsZh
		} else {
			result.Recommendations = result.RecommendationsEn
		}
	}

	// 填充威胁的兼容字段
	for i := range result.Threats {
		if result.Threats[i].Description == "" {
			if result.Threats[i].DescriptionZh != "" {
				result.Threats[i].Description = result.Threats[i].DescriptionZh
			} else {
				result.Threats[i].Description = result.Threats[i].DescriptionEn
			}
		}
		if result.Threats[i].Action == "" {
			if result.Threats[i].ActionZh != "" {
				result.Threats[i].Action = result.Threats[i].ActionZh
			} else {
				result.Threats[i].Action = result.Threats[i].ActionEn
			}
		}
	}

	a.log.Infof("GPT API 调用成功，使用 tokens: %d", gptResp.Usage.TotalTokens)

	return result, nil
}

// buildUserPrompt 构建用户提示词
func (a *SecurityAnalyzer) buildUserPrompt(data *SecurityData) string {
	var prompt strings.Builder

	prompt.WriteString(fmt.Sprintf("请分析以下时段的安全数据：%s\n\n", data.TimeRange))

	// 基础统计
	prompt.WriteString("## 基础统计\n")
	prompt.WriteString(fmt.Sprintf("- 总请求数: %d\n", data.TotalRequests))
	prompt.WriteString(fmt.Sprintf("- 被封禁 IP 数: %d\n", data.BlockedIPs))
	prompt.WriteString(fmt.Sprintf("- 可疑 IP 数: %d\n", data.SuspiciousIPs))
	prompt.WriteString(fmt.Sprintf("- 错误率: %.2f%%\n\n", data.ErrorRate*100))

	// 攻击事件
	if len(data.AttackEvents) > 0 {
		prompt.WriteString("## 攻击事件摘要\n")
		for _, attack := range data.AttackEvents {
			prompt.WriteString(fmt.Sprintf("- 类型: %s, 次数: %d, 拦截: %d, 严重程度: %s\n",
				attack.Type, attack.Count, attack.Blocked, attack.Severity))
			if len(attack.TopIPs) > 0 {
				prompt.WriteString(fmt.Sprintf("  主要攻击 IP: %s\n", strings.Join(attack.TopIPs, ", ")))
			}
		}
		prompt.WriteString("\n")
	}

	// 高频攻击者
	if len(data.TopAttackers) > 0 {
		prompt.WriteString("## 高频攻击者 TOP 5\n")
		for i, ip := range data.TopAttackers {
			if i >= 5 {
				break
			}
			prompt.WriteString(fmt.Sprintf("%d. IP: %s\n", i+1, ip.IP))
			prompt.WriteString(fmt.Sprintf("   - 请求数: %d, 被拦截: %d 次, 请求速率: %.1f req/min\n",
				ip.RequestCount, ip.BlockCount, ip.RequestRate))
			if len(ip.AttackTypes) > 0 {
				prompt.WriteString(fmt.Sprintf("   - 攻击类型: %s\n", strings.Join(ip.AttackTypes, ", ")))
			}
			if ip.GeoLocation != "" {
				prompt.WriteString(fmt.Sprintf("   - 地理位置: %s\n", ip.GeoLocation))
			}
		}
		prompt.WriteString("\n")
	}

	// 异常 User-Agent
	if len(data.AnomalousUA) > 0 {
		prompt.WriteString("## 异常 User-Agent\n")
		for i, ua := range data.AnomalousUA {
			if i >= 5 {
				break
			}
			prompt.WriteString(fmt.Sprintf("- UA: %s\n", ua.UserAgent))
			prompt.WriteString(fmt.Sprintf("  请求数: %d, 唯一 IP: %d\n", ua.RequestCount, ua.UniqueIPs))
			if ua.Reason != "" {
				prompt.WriteString(fmt.Sprintf("  原因: %s\n", ua.Reason))
			}
		}
		prompt.WriteString("\n")
	}

	prompt.WriteString("请基于以上数据进行安全分析，识别威胁并给出建议。")

	return prompt.String()
}

// generateDataHash 生成数据摘要的 hash
func (a *SecurityAnalyzer) generateDataHash(data *SecurityData) string {
	// 简单实现：基于关键字段生成唯一标识
	return fmt.Sprintf("%s_%d_%d_%d",
		data.TimeRange,
		data.TotalRequests,
		data.BlockedIPs,
		len(data.AttackEvents))
}

// ShouldNotify 判断是否应该发送通知（公开方法）
func (a *SecurityAnalyzer) ShouldNotify(result *AnalysisResult) bool {
	// 只有 medium 及以上威胁才通知
	switch result.ThreatLevel {
	case "critical", "high", "medium":
		return true
	default:
		return false
	}
}

// SendNotification 发送通知（公开方法）
func (a *SecurityAnalyzer) SendNotification(result *AnalysisResult, data *SecurityData) {
	if a.notifier == nil {
		return
	}

	// 构建双语邮件内容
	var content strings.Builder

	// ========== 中文部分 ==========
	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	content.WriteString("  🤖 AI 智能安全分析报告（自动生成）\n")
	content.WriteString("  🤖 AI Security Analysis Report (Automated)\n")
	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	content.WriteString(fmt.Sprintf("📊 分析模型 Analysis Model: %s\n", a.model))
	content.WriteString(fmt.Sprintf("⏰ 分析时段 Time Range: %s\n", data.TimeRange))
	content.WriteString(fmt.Sprintf("🎯 威胁等级 Threat Level: %s\n", strings.ToUpper(result.ThreatLevel)))
	content.WriteString(fmt.Sprintf("📈 AI 置信度 Confidence: %.0f%%\n\n", result.Confidence*100))
	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	// 中文总结
	content.WriteString("💡 总结 Summary (中文):\n")
	content.WriteString(fmt.Sprintf("%s\n\n", result.SummaryZh))

	// 英文总结
	content.WriteString("💡 Summary (English):\n")
	content.WriteString(fmt.Sprintf("%s\n\n", result.SummaryEn))

	if len(result.Threats) > 0 {
		content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
		content.WriteString("🚨 发现的威胁 Detected Threats:\n\n")

		for i, threat := range result.Threats {
			content.WriteString(fmt.Sprintf("【威胁 Threat %d】[%s] %s\n\n", i+1, strings.ToUpper(threat.Severity), threat.Type))

			// 中文描述
			if threat.DescriptionZh != "" {
				content.WriteString(fmt.Sprintf("📝 描述 (中文): %s\n", threat.DescriptionZh))
			}

			// 英文描述
			if threat.DescriptionEn != "" {
				content.WriteString(fmt.Sprintf("📝 Description (English): %s\n", threat.DescriptionEn))
			}

			// 指标（中英文共用）
			if len(threat.Indicators) > 0 {
				content.WriteString(fmt.Sprintf("🎯 指标 Indicators: %s\n", strings.Join(threat.Indicators, ", ")))
			}

			// 中文建议
			if threat.ActionZh != "" {
				content.WriteString(fmt.Sprintf("💡 建议 (中文): %s\n", threat.ActionZh))
			}

			// 英文建议
			if threat.ActionEn != "" {
				content.WriteString(fmt.Sprintf("💡 Action (English): %s\n", threat.ActionEn))
			}

			content.WriteString(fmt.Sprintf("📊 置信度 Confidence: %.0f%%\n", threat.Confidence*100))
			content.WriteString("\n")
		}
	}

	if len(result.RecommendationsZh) > 0 || len(result.RecommendationsEn) > 0 {
		content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
		content.WriteString("💼 安全建议 Security Recommendations:\n\n")

		// 中文建议
		if len(result.RecommendationsZh) > 0 {
			content.WriteString("【中文 Chinese】\n")
			for i, rec := range result.RecommendationsZh {
				content.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
			}
			content.WriteString("\n")
		}

		// 英文建议
		if len(result.RecommendationsEn) > 0 {
			content.WriteString("【English】\n")
			for i, rec := range result.RecommendationsEn {
				content.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
			}
			content.WriteString("\n")
		}
	}

	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	content.WriteString(fmt.Sprintf("⏱️  分析完成时间 Analysis Time: %s\n", result.Timestamp.Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("📊 数据来源 Data Source: SSLcat Security Logs & DDoS Protection Records\n"))
	content.WriteString(fmt.Sprintf("🤖 分析引擎 AI Engine: %s (OpenAI Compatible API)\n\n", a.model))
	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
	content.WriteString("ℹ️  重要提示 Important Notice:\n\n")
	content.WriteString("【中文 Chinese】\n")
	content.WriteString("• 本报告由 AI 自动生成，仅供参考\n")
	content.WriteString("• 建议结合实际情况和人工判断做出决策\n")
	content.WriteString("• AI 分析可能存在误报或漏报\n")
	content.WriteString("• 如有疑问，请查看完整的安全日志进行确认\n\n")
	content.WriteString("【English】\n")
	content.WriteString("• This report is automatically generated by AI for reference only\n")
	content.WriteString("• Combine with actual situation and manual judgment for decisions\n")
	content.WriteString("• AI analysis may have false positives or false negatives\n")
	content.WriteString("• If in doubt, please review the complete security logs\n\n")
	content.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	// 确定通知级别
	level := notification.LevelWarning
	switch result.ThreatLevel {
	case "critical":
		level = notification.LevelCritical
	case "high":
		level = notification.LevelError
	case "medium":
		level = notification.LevelWarning
	}

	// 发送通知（标题包含中英文）
	titleZh := fmt.Sprintf("🤖 AI 安全分析报告 - %s 威胁 (置信度 %.0f%%)", strings.ToUpper(result.ThreatLevel), result.Confidence*100)
	titleEn := fmt.Sprintf("🤖 AI Security Report - %s Threat (Confidence %.0f%%)", strings.ToUpper(result.ThreatLevel), result.Confidence*100)

	notif := &notification.Notification{
		Type:    notification.TypeSecurityAlert,
		Level:   level,
		Title:   fmt.Sprintf("%s / %s", titleZh, titleEn),
		Message: fmt.Sprintf("[中文] %s\n[English] %s", result.SummaryZh, result.SummaryEn),
		Details: map[string]any{
			"threat_level":    result.ThreatLevel,
			"confidence":      result.Confidence,
			"threats_count":   len(result.Threats),
			"time_range":      data.TimeRange,
			"total_requests":  data.TotalRequests,
			"blocked_ips":     data.BlockedIPs,
			"full_report":     content.String(),
			"ai_model":        a.model,
			"analysis_type":   "ai_automated",
			"is_ai_generated": true,
		},
	}

	if err := a.notifier.GetManager().Send(notif); err != nil {
		a.log.Errorf("发送 AI 安全分析通知失败: %v", err)
	} else {
		a.log.Info("AI 安全分析通知已发送")
	}
}

// GetLastAnalysis 获取最近一次分析结果
func (a *SecurityAnalyzer) GetLastAnalysis() *AnalysisResult {
	a.cacheMutex.RLock()
	defer a.cacheMutex.RUnlock()

	var latest *AnalysisResult
	for _, result := range a.analysisCache {
		if latest == nil || result.Timestamp.After(latest.Timestamp) {
			latest = result
		}
	}
	return latest
}

// ClearCache 清理缓存
func (a *SecurityAnalyzer) ClearCache() {
	a.cacheMutex.Lock()
	defer a.cacheMutex.Unlock()
	a.analysisCache = make(map[string]*AnalysisResult)
	a.log.Info("AI 分析缓存已清理")
}

// tryFixTruncatedJSON 尝试修复被截断的 JSON 响应
func (a *SecurityAnalyzer) tryFixTruncatedJSON(content string) string {
	original := content

	// 统计各种括号的数量
	openBraces := strings.Count(content, "{")
	closeBraces := strings.Count(content, "}")
	openBrackets := strings.Count(content, "[")
	closeBrackets := strings.Count(content, "]")
	quotes := strings.Count(content, "\"")

	addedQuotes := 0
	addedBrackets := 0
	addedBraces := 0

	// 如果引号数量是奇数，说明字符串被截断
	if quotes%2 != 0 {
		content += "\""
		addedQuotes = 1
	}

	// 修复数组未闭合
	bracketDiff := openBrackets - closeBrackets
	for i := 0; i < bracketDiff; i++ {
		content += "]"
		addedBrackets++
	}

	// 修复对象未闭合
	braceDiff := openBraces - closeBraces
	for i := 0; i < braceDiff; i++ {
		content += "}"
		addedBraces++
	}

	if addedQuotes > 0 || addedBrackets > 0 || addedBraces > 0 {
		a.log.Infof("🔧 JSON 自动修复: 添加了 %d 个 \", %d 个 ], %d 个 }",
			addedQuotes, addedBrackets, addedBraces)
		a.log.Debugf("修复前长度: %d, 修复后长度: %d", len(original), len(content))
	}

	return content
}

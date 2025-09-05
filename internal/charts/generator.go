package charts

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"time"

	"withssl/internal/monitor"

	"github.com/sirupsen/logrus"
)

// ChartType 图表类型
type ChartType string

const (
	ChartTypeLine     ChartType = "line"
	ChartTypeBar      ChartType = "bar"
	ChartTypePie      ChartType = "pie"
	ChartTypeDoughnut ChartType = "doughnut"
	ChartTypeArea     ChartType = "area"
	ChartTypeScatter  ChartType = "scatter"
	ChartTypeHeatmap  ChartType = "heatmap"
)

// ChartData 图表数据
type ChartData struct {
	Type        ChartType              `json:"type"`
	Title       string                 `json:"title"`
	Labels      []string               `json:"labels"`
	Datasets    []Dataset              `json:"datasets"`
	Options     map[string]interface{} `json:"options"`
	UpdateTime  time.Time              `json:"update_time"`
	Period      string                 `json:"period"`
	Description string                 `json:"description"`
}

// Dataset 数据集
type Dataset struct {
	Label           string      `json:"label"`
	Data            []float64   `json:"data"`
	BackgroundColor interface{} `json:"backgroundColor,omitempty"`
	BorderColor     string      `json:"borderColor,omitempty"`
	BorderWidth     int         `json:"borderWidth,omitempty"`
	Fill            bool        `json:"fill,omitempty"`
	Tension         float64     `json:"tension,omitempty"`
	PointRadius     int         `json:"pointRadius,omitempty"`
	Hidden          bool        `json:"hidden,omitempty"`
}

// TimeSeriesPoint 时间序列数据点
type TimeSeriesPoint struct {
	Time  time.Time `json:"time"`
	Value float64   `json:"value"`
	Label string    `json:"label,omitempty"`
}

// ChartGenerator 图表生成器
type ChartGenerator struct {
	monitor      *monitor.Monitor
	colorPalette []string
	log          *logrus.Entry
}

// NewChartGenerator 创建图表生成器
func NewChartGenerator(monitor *monitor.Monitor) *ChartGenerator {
	return &ChartGenerator{
		monitor: monitor,
		colorPalette: []string{
			"#007bff", "#28a745", "#ffc107", "#dc3545", "#17a2b8",
			"#6f42c1", "#e83e8c", "#fd7e14", "#20c997", "#6c757d",
			"#495057", "#343a40", "#f8f9fa", "#e9ecef", "#dee2e6",
		},
		log: logrus.WithFields(logrus.Fields{
			"component": "chart_generator",
		}),
	}
}

// GenerateTrafficChart 生成流量图表
func (g *ChartGenerator) GenerateTrafficChart(period string, interval string) (*ChartData, error) {
	data := g.monitor.GetTimeSeriesData(g.parsePeriod(period))

	chart := &ChartData{
		Type:        ChartTypeLine,
		Title:       "流量监控",
		Labels:      data["labels"].([]string),
		UpdateTime:  time.Now(),
		Period:      period,
		Description: fmt.Sprintf("过去%s的流量统计", period),
		Options: map[string]interface{}{
			"responsive":          true,
			"maintainAspectRatio": false,
			"scales": map[string]interface{}{
				"y": map[string]interface{}{
					"beginAtZero": true,
					"title": map[string]interface{}{
						"display": true,
						"text":    "请求数/分钟",
					},
				},
				"x": map[string]interface{}{
					"title": map[string]interface{}{
						"display": true,
						"text":    "时间",
					},
				},
			},
			"plugins": map[string]interface{}{
				"legend": map[string]interface{}{
					"display":  true,
					"position": "top",
				},
				"tooltip": map[string]interface{}{
					"mode":      "index",
					"intersect": false,
				},
			},
			"interaction": map[string]interface{}{
				"mode":      "nearest",
				"axis":      "x",
				"intersect": false,
			},
		},
	}

	// 添加请求数据集
	if requests, ok := data["requests"].([]int); ok {
		requestData := make([]float64, len(requests))
		for i, v := range requests {
			requestData[i] = float64(v)
		}

		chart.Datasets = append(chart.Datasets, Dataset{
			Label:           "请求数",
			Data:            requestData,
			BorderColor:     g.colorPalette[0],
			BackgroundColor: g.addAlpha(g.colorPalette[0], 0.1),
			BorderWidth:     2,
			Fill:            true,
			Tension:         0.4,
			PointRadius:     3,
		})
	}

	// 添加错误数据集
	if errors, ok := data["errors"].([]int); ok {
		errorData := make([]float64, len(errors))
		for i, v := range errors {
			errorData[i] = float64(v)
		}

		chart.Datasets = append(chart.Datasets, Dataset{
			Label:           "错误数",
			Data:            errorData,
			BorderColor:     g.colorPalette[3],
			BackgroundColor: g.addAlpha(g.colorPalette[3], 0.1),
			BorderWidth:     2,
			Fill:            false,
			Tension:         0.4,
			PointRadius:     3,
		})
	}

	return chart, nil
}

// GenerateStatusCodeChart 生成状态码分布图表
func (g *ChartGenerator) GenerateStatusCodeChart() (*ChartData, error) {
	globalStats := g.monitor.GetGlobalStats()
	domainStats := g.monitor.GetAllDomainStats()

	// 收集所有状态码统计
	statusCodes := make(map[int]int64)
	for _, domain := range domainStats {
		for code, count := range domain.StatusCodes {
			statusCodes[code] += count
		}
	}

	// 转换为图表数据
	var labels []string
	var data []float64
	var colors []string

	// 按状态码排序
	var codes []int
	for code := range statusCodes {
		codes = append(codes, code)
	}
	sort.Ints(codes)

	for i, code := range codes {
		labels = append(labels, fmt.Sprintf("%d", code))
		data = append(data, float64(statusCodes[code]))
		colors = append(colors, g.getStatusCodeColor(code, i))
	}

	chart := &ChartData{
		Type:        ChartTypeDoughnut,
		Title:       "状态码分布",
		Labels:      labels,
		UpdateTime:  time.Now(),
		Period:      "current",
		Description: "HTTP状态码分布统计",
		Datasets: []Dataset{
			{
				Label:           "请求数",
				Data:            data,
				BackgroundColor: colors,
				BorderWidth:     2,
			},
		},
		Options: map[string]interface{}{
			"responsive":          true,
			"maintainAspectRatio": false,
			"plugins": map[string]interface{}{
				"legend": map[string]interface{}{
					"display":  true,
					"position": "right",
				},
				"tooltip": map[string]interface{}{
					"callbacks": map[string]interface{}{
						"label": "function(context) { return context.label + ': ' + context.parsed + ' (' + ((context.parsed / context.dataset.data.reduce((a, b) => a + b, 0)) * 100).toFixed(1) + '%)'; }",
					},
				},
			},
		},
	}

	return chart, nil
}

// GenerateResponseTimeChart 生成响应时间图表
func (g *ChartGenerator) GenerateResponseTimeChart(period string) (*ChartData, error) {
	// 这里应该从监控系统获取响应时间历史数据
	// 现在使用模拟数据

	labels := g.generateTimeLabels(period, "1h")
	responseTimeData := g.generateResponseTimeData(len(labels))

	chart := &ChartData{
		Type:        ChartTypeArea,
		Title:       "响应时间趋势",
		Labels:      labels,
		UpdateTime:  time.Now(),
		Period:      period,
		Description: fmt.Sprintf("过去%s的响应时间趋势", period),
		Datasets: []Dataset{
			{
				Label:           "平均响应时间 (ms)",
				Data:            responseTimeData,
				BorderColor:     g.colorPalette[1],
				BackgroundColor: g.addAlpha(g.colorPalette[1], 0.2),
				BorderWidth:     2,
				Fill:            true,
				Tension:         0.4,
				PointRadius:     2,
			},
		},
		Options: map[string]interface{}{
			"responsive":          true,
			"maintainAspectRatio": false,
			"scales": map[string]interface{}{
				"y": map[string]interface{}{
					"beginAtZero": true,
					"title": map[string]interface{}{
						"display": true,
						"text":    "响应时间 (ms)",
					},
				},
			},
			"plugins": map[string]interface{}{
				"legend": map[string]interface{}{
					"display": false,
				},
			},
		},
	}

	return chart, nil
}

// GenerateTopDomainsChart 生成热门域名图表
func (g *ChartGenerator) GenerateTopDomainsChart(limit int) (*ChartData, error) {
	topDomains := g.monitor.GetTopDomains(limit)

	var labels []string
	var data []float64
	var colors []string

	for i, domain := range topDomains {
		labels = append(labels, domain.Domain)
		data = append(data, float64(domain.RequestStats.TotalRequests))
		colors = append(colors, g.colorPalette[i%len(g.colorPalette)])
	}

	chart := &ChartData{
		Type:        ChartTypeBar,
		Title:       fmt.Sprintf("Top %d 域名", limit),
		Labels:      labels,
		UpdateTime:  time.Now(),
		Period:      "current",
		Description: "访问量最高的域名统计",
		Datasets: []Dataset{
			{
				Label:           "请求数",
				Data:            data,
				BackgroundColor: colors,
				BorderWidth:     1,
			},
		},
		Options: map[string]interface{}{
			"responsive":          true,
			"maintainAspectRatio": false,
			"scales": map[string]interface{}{
				"y": map[string]interface{}{
					"beginAtZero": true,
					"title": map[string]interface{}{
						"display": true,
						"text":    "请求数",
					},
				},
			},
			"plugins": map[string]interface{}{
				"legend": map[string]interface{}{
					"display": false,
				},
			},
		},
	}

	return chart, nil
}

// GenerateErrorRateChart 生成错误率图表
func (g *ChartGenerator) GenerateErrorRateChart(period string) (*ChartData, error) {
	labels := g.generateTimeLabels(period, "1h")
	errorRateData := g.generateErrorRateData(len(labels))

	chart := &ChartData{
		Type:        ChartTypeLine,
		Title:       "错误率趋势",
		Labels:      labels,
		UpdateTime:  time.Now(),
		Period:      period,
		Description: fmt.Sprintf("过去%s的错误率趋势", period),
		Datasets: []Dataset{
			{
				Label:           "错误率 (%)",
				Data:            errorRateData,
				BorderColor:     g.colorPalette[3],
				BackgroundColor: g.addAlpha(g.colorPalette[3], 0.1),
				BorderWidth:     2,
				Fill:            true,
				Tension:         0.4,
				PointRadius:     3,
			},
		},
		Options: map[string]interface{}{
			"responsive":          true,
			"maintainAspectRatio": false,
			"scales": map[string]interface{}{
				"y": map[string]interface{}{
					"beginAtZero": true,
					"max":         10,
					"title": map[string]interface{}{
						"display": true,
						"text":    "错误率 (%)",
					},
				},
			},
			"plugins": map[string]interface{}{
				"legend": map[string]interface{}{
					"display": false,
				},
			},
		},
	}

	return chart, nil
}

// GenerateHeatmapChart 生成热力图
func (g *ChartGenerator) GenerateHeatmapChart(period string) (*ChartData, error) {
	// 生成24小时x7天的热力图数据
	data := g.generateHeatmapData()

	chart := &ChartData{
		Type:        ChartTypeHeatmap,
		Title:       "访问热力图",
		UpdateTime:  time.Now(),
		Period:      period,
		Description: "一周内不同时间段的访问热力图",
		Datasets: []Dataset{
			{
				Label: "访问量",
				Data:  data,
			},
		},
		Options: map[string]interface{}{
			"responsive":          true,
			"maintainAspectRatio": false,
			"plugins": map[string]interface{}{
				"legend": map[string]interface{}{
					"display": false,
				},
			},
		},
	}

	return chart, nil
}

// 辅助函数

// parsePeriod 解析时间周期
func (g *ChartGenerator) parsePeriod(period string) int {
	switch period {
	case "1h":
		return 60
	case "6h":
		return 360
	case "24h":
		return 1440
	case "7d":
		return 10080
	case "30d":
		return 43200
	default:
		return 60
	}
}

// generateTimeLabels 生成时间标签
func (g *ChartGenerator) generateTimeLabels(period string, interval string) []string {
	var labels []string
	now := time.Now()

	switch period {
	case "1h":
		for i := 60; i >= 0; i -= 5 {
			t := now.Add(-time.Duration(i) * time.Minute)
			labels = append(labels, t.Format("15:04"))
		}
	case "24h":
		for i := 24; i >= 0; i-- {
			t := now.Add(-time.Duration(i) * time.Hour)
			labels = append(labels, t.Format("15:04"))
		}
	case "7d":
		for i := 7; i >= 0; i-- {
			t := now.Add(-time.Duration(i) * 24 * time.Hour)
			labels = append(labels, t.Format("01-02"))
		}
	}

	return labels
}

// generateResponseTimeData 生成响应时间数据
func (g *ChartGenerator) generateResponseTimeData(count int) []float64 {
	data := make([]float64, count)
	base := 150.0

	for i := 0; i < count; i++ {
		// 模拟波动的响应时间数据
		variation := math.Sin(float64(i)*0.1) * 50
		data[i] = base + variation + float64(i%10)*5
	}

	return data
}

// generateErrorRateData 生成错误率数据
func (g *ChartGenerator) generateErrorRateData(count int) []float64 {
	data := make([]float64, count)

	for i := 0; i < count; i++ {
		// 模拟错误率数据
		data[i] = math.Max(0, 2+math.Sin(float64(i)*0.05)*1.5)
	}

	return data
}

// generateHeatmapData 生成热力图数据
func (g *ChartGenerator) generateHeatmapData() []float64 {
	data := make([]float64, 24*7) // 24小时 x 7天

	for day := 0; day < 7; day++ {
		for hour := 0; hour < 24; hour++ {
			index := day*24 + hour
			// 模拟访问模式：工作时间访问量较高
			if hour >= 9 && hour <= 18 && day < 5 {
				data[index] = 50 + float64(hour%12)*10
			} else if hour >= 20 && hour <= 23 {
				data[index] = 30 + float64(hour%4)*5
			} else {
				data[index] = 10 + float64(hour%6)*2
			}
		}
	}

	return data
}

// getStatusCodeColor 获取状态码颜色
func (g *ChartGenerator) getStatusCodeColor(code int, index int) string {
	switch {
	case code >= 200 && code < 300:
		return g.colorPalette[1] // 绿色系
	case code >= 300 && code < 400:
		return g.colorPalette[2] // 黄色系
	case code >= 400 && code < 500:
		return g.colorPalette[3] // 红色系
	case code >= 500:
		return g.colorPalette[4] // 深红色系
	default:
		return g.colorPalette[index%len(g.colorPalette)]
	}
}

// addAlpha 添加透明度
func (g *ChartGenerator) addAlpha(color string, alpha float64) string {
	if len(color) == 7 && color[0] == '#' {
		r, _ := parseHex(color[1:3])
		g, _ := parseHex(color[3:5])
		b, _ := parseHex(color[5:7])
		return fmt.Sprintf("rgba(%d,%d,%d,%.2f)", r, g, b, alpha)
	}
	return color
}

// parseHex 解析十六进制
func parseHex(s string) (int, error) {
	var result int
	for _, c := range s {
		result *= 16
		if c >= '0' && c <= '9' {
			result += int(c - '0')
		} else if c >= 'a' && c <= 'f' {
			result += int(c - 'a' + 10)
		} else if c >= 'A' && c <= 'F' {
			result += int(c - 'A' + 10)
		}
	}
	return result, nil
}

// GetAvailableCharts 获取可用的图表类型
func (g *ChartGenerator) GetAvailableCharts() map[string]interface{} {
	return map[string]interface{}{
		"traffic": map[string]interface{}{
			"name":        "流量监控",
			"description": "实时流量和请求统计",
			"type":        ChartTypeLine,
			"periods":     []string{"1h", "6h", "24h", "7d"},
		},
		"status_codes": map[string]interface{}{
			"name":        "状态码分布",
			"description": "HTTP状态码分布统计",
			"type":        ChartTypeDoughnut,
			"periods":     []string{"current"},
		},
		"response_time": map[string]interface{}{
			"name":        "响应时间",
			"description": "平均响应时间趋势",
			"type":        ChartTypeArea,
			"periods":     []string{"1h", "6h", "24h", "7d"},
		},
		"top_domains": map[string]interface{}{
			"name":        "热门域名",
			"description": "访问量最高的域名",
			"type":        ChartTypeBar,
			"periods":     []string{"current"},
		},
		"error_rate": map[string]interface{}{
			"name":        "错误率",
			"description": "错误率趋势分析",
			"type":        ChartTypeLine,
			"periods":     []string{"1h", "6h", "24h", "7d"},
		},
		"heatmap": map[string]interface{}{
			"name":        "访问热力图",
			"description": "时间段访问分布热力图",
			"type":        ChartTypeHeatmap,
			"periods":     []string{"7d", "30d"},
		},
	}
}

// ExportChartData 导出图表数据
func (g *ChartGenerator) ExportChartData(chartType string, format string) ([]byte, error) {
	var chart *ChartData
	var err error

	switch chartType {
	case "traffic":
		chart, err = g.GenerateTrafficChart("24h", "1h")
	case "status_codes":
		chart, err = g.GenerateStatusCodeChart()
	case "response_time":
		chart, err = g.GenerateResponseTimeChart("24h")
	case "top_domains":
		chart, err = g.GenerateTopDomainsChart(10)
	case "error_rate":
		chart, err = g.GenerateErrorRateChart("24h")
	case "heatmap":
		chart, err = g.GenerateHeatmapChart("7d")
	default:
		return nil, fmt.Errorf("不支持的图表类型: %s", chartType)
	}

	if err != nil {
		return nil, err
	}

	switch format {
	case "json":
		return json.MarshalIndent(chart, "", "  ")
	default:
		return nil, fmt.Errorf("不支持的导出格式: %s", format)
	}
}

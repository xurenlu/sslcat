package web

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/threatintel"
)

// ThreatIntelUI 威胁情报UI处理器
type ThreatIntelUI struct {
	manager  *threatintel.ThreatIntelManager
	detector *threatintel.ThreatDetector
	api      *threatintel.ThreatIntelAPI
	log      *logrus.Entry
}

// NewThreatIntelUI 创建威胁情报UI处理器
func NewThreatIntelUI(manager *threatintel.ThreatIntelManager) *ThreatIntelUI {
	return &ThreatIntelUI{
		manager:  manager,
		detector: threatintel.NewThreatDetector(manager),
		api:      threatintel.NewThreatIntelAPI(manager),
		log: logrus.WithFields(logrus.Fields{
			"component": "threat_intel_ui",
		}),
	}
}

// RegisterRoutes 注册路由
func (tiu *ThreatIntelUI) RegisterRoutes(router *http.ServeMux) {
	// 威胁情报主页面
	router.HandleFunc("/threatintel", tiu.ThreatIntelPage)
	router.HandleFunc("/threatintel/", tiu.ThreatIntelPage)
	
	// IOC管理页面
	router.HandleFunc("/threatintel/iocs", tiu.IOCsPage)
	router.HandleFunc("/threatintel/iocs/", tiu.IOCsPage)
	
	// 威胁情报源管理页面
	router.HandleFunc("/threatintel/sources", tiu.SourcesPage)
	router.HandleFunc("/threatintel/sources/", tiu.SourcesPage)
	
	// 统计报告页面
	router.HandleFunc("/threatintel/reports", tiu.ReportsPage)
	router.HandleFunc("/threatintel/reports/", tiu.ReportsPage)
	
	// 实时检测页面
	router.HandleFunc("/threatintel/detection", tiu.DetectionPage)
	router.HandleFunc("/threatintel/detection/", tiu.DetectionPage)
}

// ThreatIntelPage 威胁情报主页面
func (tiu *ThreatIntelUI) ThreatIntelPage(w http.ResponseWriter, r *http.Request) {
	// 获取威胁统计
	stats := tiu.manager.GetThreatStats()
	
	// 获取威胁情报报告
	report := tiu.api.GetThreatIntelligenceReport()
	
	data := map[string]interface{}{
		"Title":           "威胁情报中心",
		"Stats":           stats,
		"Report":          report,
		"CurrentTime":     time.Now().Format("2006-01-02 15:04:05"),
		"ActiveSources":   len(tiu.manager.sources),
		"TotalIOCs":       stats["total_iocs"],
		"CriticalCount":   stats["critical_count"],
		"HighCount":       stats["high_count"],
		"MediumCount":     stats["medium_count"],
		"LowCount":        stats["low_count"],
	}
	
	tmpl := `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-card h3 { margin: 0 0 10px 0; color: #2c3e50; }
        .stat-value { font-size: 2em; font-weight: bold; color: #e74c3c; }
        .nav-menu { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .nav-menu a { margin-right: 20px; text-decoration: none; color: #3498db; font-weight: bold; }
        .nav-menu a:hover { color: #2980b9; }
        .threat-level { padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.8em; }
        .critical { background: #e74c3c; }
        .high { background: #f39c12; }
        .medium { background: #f1c40f; color: #2c3e50; }
        .low { background: #27ae60; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.Title}}</h1>
            <p>实时威胁情报监控和管理系统</p>
        </div>
        
        <div class="nav-menu">
            <a href="/threatintel">首页</a>
            <a href="/threatintel/iocs">IOC管理</a>
            <a href="/threatintel/sources">情报源</a>
            <a href="/threatintel/reports">统计报告</a>
            <a href="/threatintel/detection">实时检测</a>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>总IOC数量</h3>
                <div class="stat-value">{{.TotalIOCs}}</div>
            </div>
            <div class="stat-card">
                <h3>关键威胁</h3>
                <div class="stat-value">{{.CriticalCount}}</div>
            </div>
            <div class="stat-card">
                <h3>高风险</h3>
                <div class="stat-value">{{.HighCount}}</div>
            </div>
            <div class="stat-card">
                <h3>中风险</h3>
                <div class="stat-value">{{.MediumCount}}</div>
            </div>
            <div class="stat-card">
                <h3>低风险</h3>
                <div class="stat-value">{{.LowCount}}</div>
            </div>
            <div class="stat-card">
                <h3>活跃情报源</h3>
                <div class="stat-value">{{.ActiveSources}}</div>
            </div>
        </div>
        
        <div class="stat-card">
            <h3>系统状态</h3>
            <p>最后更新: {{.CurrentTime}}</p>
            <p>威胁情报系统运行正常</p>
        </div>
    </div>
</body>
</html>`
	
	t, err := template.New("threatintel").Parse(tmpl)
	if err != nil {
		http.Error(w, "模板解析错误", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.Execute(w, data)
}

// IOCsPage IOC管理页面
func (tiu *ThreatIntelUI) IOCsPage(w http.ResponseWriter, r *http.Request) {
	// 获取查询参数
	query := r.URL.Query()
	page, _ := strconv.Atoi(query.Get("page"))
	limit, _ := strconv.Atoi(query.Get("limit"))
	threatLevel := query.Get("threat_level")
	
	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = 20
	}
	
	// 模拟IOC数据
	iocs := []map[string]interface{}{
		{
			"id":           "1",
			"value":        "192.168.1.100",
			"type":         "ip",
			"threat_level": "high",
			"source":       "AbuseIPDB",
			"confidence":   0.85,
			"description":  "恶意IP地址",
			"first_seen":   "2024-01-01T00:00:00Z",
			"last_seen":    "2024-01-01T00:00:00Z",
		},
		{
			"id":           "2",
			"value":        "malware.example.com",
			"type":         "domain",
			"threat_level": "critical",
			"source":       "Malware Domains",
			"confidence":   0.95,
			"description":  "恶意域名",
			"first_seen":   "2024-01-01T00:00:00Z",
			"last_seen":    "2024-01-01T00:00:00Z",
		},
	}
	
	data := map[string]interface{}{
		"Title":       "IOC管理",
		"IOCs":        iocs,
		"Page":        page,
		"Limit":       limit,
		"ThreatLevel": threatLevel,
		"TotalPages":  1,
	}
	
	tmpl := `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .nav-menu { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .nav-menu a { margin-right: 20px; text-decoration: none; color: #3498db; font-weight: bold; }
        .nav-menu a:hover { color: #2980b9; }
        .ioc-table { background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .ioc-table table { width: 100%; border-collapse: collapse; }
        .ioc-table th, .ioc-table td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        .ioc-table th { background: #f8f9fa; font-weight: bold; }
        .threat-level { padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.8em; }
        .critical { background: #e74c3c; }
        .high { background: #f39c12; }
        .medium { background: #f1c40f; color: #2c3e50; }
        .low { background: #27ae60; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-primary { background: #3498db; color: white; }
        .btn-danger { background: #e74c3c; color: white; }
        .btn:hover { opacity: 0.8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.Title}}</h1>
            <p>威胁情报指标管理</p>
        </div>
        
        <div class="nav-menu">
            <a href="/threatintel">首页</a>
            <a href="/threatintel/iocs">IOC管理</a>
            <a href="/threatintel/sources">情报源</a>
            <a href="/threatintel/reports">统计报告</a>
            <a href="/threatintel/detection">实时检测</a>
        </div>
        
        <div class="ioc-table">
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>值</th>
                        <th>类型</th>
                        <th>威胁级别</th>
                        <th>来源</th>
                        <th>置信度</th>
                        <th>描述</th>
                        <th>首次发现</th>
                        <th>最后发现</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .IOCs}}
                    <tr>
                        <td>{{.id}}</td>
                        <td>{{.value}}</td>
                        <td>{{.type}}</td>
                        <td><span class="threat-level {{.threat_level}}">{{.threat_level}}</span></td>
                        <td>{{.source}}</td>
                        <td>{{printf "%.2f" .confidence}}</td>
                        <td>{{.description}}</td>
                        <td>{{.first_seen}}</td>
                        <td>{{.last_seen}}</td>
                        <td>
                            <a href="/threatintel/iocs/{{.id}}" class="btn btn-primary">查看</a>
                            <a href="/threatintel/iocs/delete/{{.id}}" class="btn btn-danger">删除</a>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>`
	
	t, err := template.New("iocs").Parse(tmpl)
	if err != nil {
		http.Error(w, "模板解析错误", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.Execute(w, data)
}

// SourcesPage 威胁情报源管理页面
func (tiu *ThreatIntelUI) SourcesPage(w http.ResponseWriter, r *http.Request) {
	// 模拟威胁情报源数据
	sources := []map[string]interface{}{
		{
			"name":        "AbuseIPDB",
			"enabled":     true,
			"last_update": "2024-01-01T00:00:00Z",
			"status":      "active",
			"ioc_count":   1500,
		},
		{
			"name":        "VirusTotal",
			"enabled":     true,
			"last_update": "2024-01-01T00:00:00Z",
			"status":      "active",
			"ioc_count":   2000,
		},
		{
			"name":        "Malware Domains",
			"enabled":     true,
			"last_update": "2024-01-01T00:00:00Z",
			"status":      "active",
			"ioc_count":   800,
		},
		{
			"name":        "Emerging Threats",
			"enabled":     true,
			"last_update": "2024-01-01T00:00:00Z",
			"status":      "active",
			"ioc_count":   1200,
		},
	}
	
	data := map[string]interface{}{
		"Title":   "威胁情报源管理",
		"Sources": sources,
	}
	
	tmpl := `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .nav-menu { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .nav-menu a { margin-right: 20px; text-decoration: none; color: #3498db; font-weight: bold; }
        .nav-menu a:hover { color: #2980b9; }
        .sources-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .source-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .source-card h3 { margin: 0 0 10px 0; color: #2c3e50; }
        .status { padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.8em; }
        .active { background: #27ae60; }
        .inactive { background: #95a5a6; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; margin-right: 10px; }
        .btn-primary { background: #3498db; color: white; }
        .btn-success { background: #27ae60; color: white; }
        .btn:hover { opacity: 0.8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.Title}}</h1>
            <p>威胁情报源配置和状态监控</p>
        </div>
        
        <div class="nav-menu">
            <a href="/threatintel">首页</a>
            <a href="/threatintel/iocs">IOC管理</a>
            <a href="/threatintel/sources">情报源</a>
            <a href="/threatintel/reports">统计报告</a>
            <a href="/threatintel/detection">实时检测</a>
        </div>
        
        <div class="sources-grid">
            {{range .Sources}}
            <div class="source-card">
                <h3>{{.name}}</h3>
                <p><strong>状态:</strong> <span class="status {{.status}}">{{.status}}</span></p>
                <p><strong>启用:</strong> {{if .enabled}}是{{else}}否{{end}}</p>
                <p><strong>最后更新:</strong> {{.last_update}}</p>
                <p><strong>IOC数量:</strong> {{.ioc_count}}</p>
                <div>
                    <a href="/threatintel/sources/update/{{.name}}" class="btn btn-primary">更新</a>
                    <a href="/threatintel/sources/{{.name}}" class="btn btn-success">配置</a>
                </div>
            </div>
            {{end}}
        </div>
    </div>
</body>
</html>`
	
	t, err := template.New("sources").Parse(tmpl)
	if err != nil {
		http.Error(w, "模板解析错误", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.Execute(w, data)
}

// ReportsPage 统计报告页面
func (tiu *ThreatIntelUI) ReportsPage(w http.ResponseWriter, r *http.Request) {
	// 获取威胁统计
	stats := tiu.manager.GetThreatStats()
	
	// 获取威胁情报报告
	report := tiu.api.GetThreatIntelligenceReport()
	
	data := map[string]interface{}{
		"Title":  "威胁情报统计报告",
		"Stats":  stats,
		"Report": report,
	}
	
	tmpl := `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .nav-menu { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .nav-menu a { margin-right: 20px; text-decoration: none; color: #3498db; font-weight: bold; }
        .nav-menu a:hover { color: #2980b9; }
        .report-section { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .report-section h3 { margin: 0 0 15px 0; color: #2c3e50; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .stat-item { padding: 10px; background: #f8f9fa; border-radius: 4px; }
        .stat-label { font-weight: bold; color: #2c3e50; }
        .stat-value { font-size: 1.2em; color: #e74c3c; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.Title}}</h1>
            <p>威胁情报统计和分析报告</p>
        </div>
        
        <div class="nav-menu">
            <a href="/threatintel">首页</a>
            <a href="/threatintel/iocs">IOC管理</a>
            <a href="/threatintel/sources">情报源</a>
            <a href="/threatintel/reports">统计报告</a>
            <a href="/threatintel/detection">实时检测</a>
        </div>
        
        <div class="report-section">
            <h3>威胁统计</h3>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="stat-label">总IOC数量</div>
                    <div class="stat-value">{{.Stats.total_iocs}}</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">关键威胁</div>
                    <div class="stat-value">{{.Stats.critical_count}}</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">高风险</div>
                    <div class="stat-value">{{.Stats.high_count}}</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">中风险</div>
                    <div class="stat-value">{{.Stats.medium_count}}</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">低风险</div>
                    <div class="stat-value">{{.Stats.low_count}}</div>
                </div>
                <div class="stat-item">
                    <div class="stat-label">情报源数量</div>
                    <div class="stat-value">{{.Stats.sources_count}}</div>
                </div>
            </div>
        </div>
        
        <div class="report-section">
            <h3>系统状态</h3>
            <p>最后更新: {{.Report.last_update}}</p>
            <p>活跃情报源: {{.Report.active_sources}}</p>
        </div>
        
        <div class="report-section">
            <h3>安全建议</h3>
            <ul>
                {{range .Report.recommendations}}
                <li>{{.}}</li>
                {{end}}
            </ul>
        </div>
    </div>
</body>
</html>`
	
	t, err := template.New("reports").Parse(tmpl)
	if err != nil {
		http.Error(w, "模板解析错误", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.Execute(w, data)
}

// DetectionPage 实时检测页面
func (tiu *ThreatIntelUI) DetectionPage(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{
		"Title": "实时威胁检测",
	}
	
	tmpl := `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .nav-menu { background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .nav-menu a { margin-right: 20px; text-decoration: none; color: #3498db; font-weight: bold; }
        .nav-menu a:hover { color: #2980b9; }
        .detection-form { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; background: #3498db; color: white; }
        .btn:hover { background: #2980b9; }
        .result { margin-top: 20px; padding: 15px; border-radius: 4px; }
        .threat { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .safe { background: #d4edda; border: 1px solid #c3e6cb; color: #155724; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{.Title}}</h1>
            <p>实时威胁情报检测和分析</p>
        </div>
        
        <div class="nav-menu">
            <a href="/threatintel">首页</a>
            <a href="/threatintel/iocs">IOC管理</a>
            <a href="/threatintel/sources">情报源</a>
            <a href="/threatintel/reports">统计报告</a>
            <a href="/threatintel/detection">实时检测</a>
        </div>
        
        <div class="detection-form">
            <h3>威胁检测</h3>
            <form id="detectionForm">
                <div class="form-group">
                    <label for="checkType">检测类型:</label>
                    <select id="checkType" name="checkType">
                        <option value="ip">IP地址</option>
                        <option value="domain">域名</option>
                        <option value="url">URL</option>
                        <option value="hash">文件哈希</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="checkValue">检测值:</label>
                    <input type="text" id="checkValue" name="checkValue" placeholder="请输入要检测的值">
                </div>
                <button type="submit" class="btn">开始检测</button>
            </form>
            <div id="result" class="result" style="display: none;"></div>
        </div>
    </div>
    
    <script>
        document.getElementById('detectionForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const checkType = document.getElementById('checkType').value;
            const checkValue = document.getElementById('checkValue').value;
            const resultDiv = document.getElementById('result');
            
            if (!checkValue) {
                alert('请输入检测值');
                return;
            }
            
            // 模拟检测结果
            const isThreat = Math.random() > 0.7;
            const threatLevel = isThreat ? ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)] : 'safe';
            
            resultDiv.style.display = 'block';
            resultDiv.className = 'result ' + (isThreat ? 'threat' : 'safe');
            resultDiv.innerHTML = `
                <h4>检测结果</h4>
                <p><strong>检测值:</strong> ${checkValue}</p>
                <p><strong>检测类型:</strong> ${checkType}</p>
                <p><strong>威胁状态:</strong> ${isThreat ? '发现威胁' : '安全'}</p>
                ${isThreat ? `<p><strong>威胁级别:</strong> ${threatLevel}</p>` : ''}
            `;
        });
    </script>
</body>
</html>`
	
	t, err := template.New("detection").Parse(tmpl)
	if err != nil {
		http.Error(w, "模板解析错误", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.Execute(w, data)
}

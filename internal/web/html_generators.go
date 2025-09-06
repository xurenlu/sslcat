package web

import (
	"fmt"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/ssl"
)

// HTML 生成函数

func (s *Server) generateSidebar(adminPrefix, activePage string) string {
	title := s.translator.T("app.description")
	navDashboard := s.translator.T("nav.dashboard")
	navProxy := s.translator.T("nav.proxy")
	navSSL := s.translator.T("nav.ssl")
	navSecurity := s.translator.T("nav.security")
	navSettings := s.translator.T("nav.settings")
	logout := s.translator.T("menu.logout")
	official := s.translator.T("menu.官方站点")
	if official == "menu.官方站点" {
		// fallback: 若未翻译，使用已有键
		official = s.translator.T("menu.official_site")
	}
	navTokens := "Token 管理"
	return fmt.Sprintf(`
                <nav class="d-md-block sidebar collapse">
                    <div class="position-sticky pt-3">
                        <div class="text-center mb-4">
                            <h4 class="navbar-brand text-primary">SSLcat</h4>
                            <small class="text-muted">%s</small>
                            <div class="mt-2">
                                <a class="btn btn-sm btn-outline-primary" href="https://sslcat.com" target="_blank" rel="noopener">%s</a>
                            </div>
                        </div>
                        
                        <div class="dropdown mb-3 px-3">
                            <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                                语言 Language
                            </button>
                            <ul class="dropdown-menu">
                                <li><a class="dropdown-item" href="?lang=zh-CN">简体中文</a></li>
                                <li><a class="dropdown-item" href="?lang=en-US">English</a></li>
                                <li><a class="dropdown-item" href="?lang=ja-JP">日本語</a></li>
                                <li><a class="dropdown-item" href="?lang=es-ES">Español</a></li>
                                <li><a class="dropdown-item" href="?lang=fr-FR">Français</a></li>
                                <li><a class="dropdown-item" href="?lang=ru-RU">Русский</a></li>
                            </ul>
                        </div>
                        
                        <ul class="nav flex-column">
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/">
                                    <i class="bi bi-speedometer2"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/proxy">
                                    <i class="bi bi-arrow-left-right"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/ssl">
                                    <i class="bi bi-shield-lock"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/security">
                                    <i class="bi bi-shield-check"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/tokens">
                                    <i class="bi bi-key"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/settings">
                                    <i class="bi bi-gear"></i> %s
                                </a>
                            </li>
                        </ul>
                        
                        <hr>
                        <div class="dropdown">
                            <a href="%s/logout" class="btn btn-outline-danger btn-sm">
                                <i class="bi bi-box-arrow-right"></i> %s
                            </a>
                        </div>
                    </div>
                </nav>`,
		title,
		official,
		func() string {
			if activePage == "dashboard" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navDashboard,
		func() string {
			if activePage == "proxy" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navProxy,
		func() string {
			if activePage == "ssl" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navSSL,
		func() string {
			if activePage == "security" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navSecurity,
		func() string {
			if activePage == "tokens" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navTokens,
		func() string {
			if activePage == "settings" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navSettings,
		adminPrefix,
		logout)
}

func (s *Server) generateProxyManagementHTML(data map[string]interface{}) string {
	title := s.translator.T("proxy.title")
	addRule := s.translator.T("proxy.add_rule")
	thDomain := s.translator.T("proxy.domain")
	thTarget := s.translator.T("proxy.target")
	thStatus := s.translator.T("proxy.status")
	thActions := s.translator.T("proxy.actions")
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">%s</h1>
                    <a href="%s/proxy/add" class="btn btn-primary">
                        <i class="bi bi-plus-circle"></i> %s
                    </a>
                </div>
                
                <div class="card">
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>%s</th>
                                        <th>%s</th>
                                        <th>%s</th>
                                        <th>%s</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    %s
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>
    <script src="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>`,
		title,
		s.generateSidebar(data["AdminPrefix"].(string), "proxy"),
		title,
		data["AdminPrefix"].(string),
		addRule,
		thDomain,
		thTarget,
		thStatus,
		thActions,
		s.generateProxyRulesTable(data))
}

func (s *Server) generateProxyRulesTable(data map[string]interface{}) string {
	rules, ok := data["Rules"].([]config.ProxyRule)
	if !ok || len(rules) == 0 {
		return `<tr><td colspan="4" class="text-center">` + s.translator.T("proxy.no_rules") + `</td></tr>`
	}

	var rows strings.Builder
	for i, rule := range rules {
		statusBadge := `<span class="badge bg-secondary">` + s.translator.T("common.disabled") + `</span>`
		if rule.Enabled {
			statusBadge = `<span class="badge bg-success">` + s.translator.T("common.enabled") + `</span>`
		}
		rows.WriteString(fmt.Sprintf(`
                    <tr>
                        <td>%s</td>
                        <td>%s</td>
                        <td>%s</td>
                        <td>
                            <a href="%s/proxy/edit?index=%d" class="btn btn-sm btn-outline-primary">`+s.translator.T("proxy.edit")+`</a>
                            <a href="%s/proxy/delete?index=%d" class="btn btn-sm btn-outline-danger" onclick="return confirm('`+s.translator.T("proxy.delete_confirm")+`')">`+s.translator.T("proxy.delete")+`</a>
                        </td>
                    </tr>`,
			rule.Domain, rule.Target, statusBadge, data["AdminPrefix"].(string), i, data["AdminPrefix"].(string), i))
	}
	return rows.String()
}

func (s *Server) generateSSLCertsTable(data map[string]interface{}) string {
	certs, _ := data["Certificates"].([]ssl.CertificateInfo)
	if len(certs) == 0 {
		return `<tr><td colspan="6" class="text-center">` + s.translator.T("ssl.none") + `</td></tr>`
	}
	var b strings.Builder
	for _, c := range certs {
		ctype := s.translator.T("ssl.type.ca")
		if c.SelfSigned {
			ctype = s.translator.T("ssl.type.self_signed")
		}
		b.WriteString(fmt.Sprintf(`
			<tr>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td>%s</td>
				<td>
					<a class="btn btn-sm btn-outline-primary" href="%s/ssl/download?domain=%s&type=cert">`+s.translator.T("ssl.download_cert")+`</a>
					<a class="btn btn-sm btn-outline-secondary" href="%s/ssl/download?domain=%s&type=key">`+s.translator.T("ssl.download_key")+`</a>
					<a class="btn btn-sm btn-outline-danger" href="%s/ssl/delete?domain=%s" onclick="return confirm('`+s.translator.T("ssl.delete_confirm")+`')">`+s.translator.T("proxy.delete")+`</a>
				</td>
			</tr>`,
			c.Domain,
			c.IssuedAt.Format("2006-01-02"),
			c.ExpiresAt.Format("2006-01-02"),
			c.Status,
			ctype,
			data["AdminPrefix"].(string), c.Domain,
			data["AdminPrefix"].(string), c.Domain,
			data["AdminPrefix"].(string), c.Domain,
		))
	}
	return b.String()
}

func (s *Server) generateBlockedIPsTable(data map[string]interface{}) string {
	// 暂时返回示例，实际应该从SecurityManager获取
	return `<tr><td colspan="3" class="text-center">` + s.translator.T("security.no_blocked") + `</td></tr>`
}

// 辅助函数来安全地获取配置值
func (s *Server) getConfigAdminUsername(data map[string]interface{}) string {
	if cfg, ok := data["Config"].(*config.Config); ok {
		return cfg.Admin.Username
	}
	return s.config.Admin.Username
}

func (s *Server) getConfigSSLEmail(data map[string]interface{}) string {
	if cfg, ok := data["Config"].(*config.Config); ok {
		return cfg.SSL.Email
	}
	return s.config.SSL.Email
}

func (s *Server) getConfigSSLDisableSelfSigned(data map[string]interface{}) string {
	if cfg, ok := data["Config"].(*config.Config); ok {
		if cfg.SSL.DisableSelfSigned {
			return "checked"
		}
	} else if s.config.SSL.DisableSelfSigned {
		return "checked"
	}
	return ""
}

func (s *Server) generateProxyAddHTML(data map[string]interface{}) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>添加代理规则 - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">添加代理规则</h1>
                    <a href="%s/proxy" class="btn btn-secondary">返回</a>
                </div>
                
                <div class="card">
                    <div class="card-body">
                        <form method="POST">
                            <div class="mb-3">
                                <label for="domain" class="form-label">域名</label>
                                <input type="text" class="form-control" id="domain" name="domain" required 
                                       placeholder="example.com">
                                <div class="form-text">输入要代理的域名，支持通配符 *.example.com</div>
                            </div>
                            <div class="mb-3">
                                <label for="target" class="form-label">目标地址</label>
                                <input type="text" class="form-control" id="target" name="target" required 
                                       placeholder="http://192.168.1.100:8080">
                                <div class="form-text">输入后端服务地址，包括协议和端口</div>
                            </div>
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="enabled" name="enabled">
                                <label class="form-check-label" for="enabled">启用该规则</label>
                            </div>
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="ssl_only" name="ssl_only">
                                <label class="form-check-label" for="ssl_only">仅限HTTPS（HTTP访问将自动301到HTTPS）</label>
                            </div>
                            <button type="submit" class="btn btn-primary">添加规则</button>
                            <a href="%s/proxy" class="btn btn-secondary">取消</a>
                        </form>
                    </div>
                </div>
            </main>
        </div>
    </div>
</body>
</html>`,
		s.generateSidebar(data["AdminPrefix"].(string), "proxy"),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string))
}

func (s *Server) generateProxyEditHTML(data map[string]interface{}) string {
	rule := data["Rule"].(config.ProxyRule)
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>编辑代理规则 - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">编辑代理规则</h1>
                    <a href="%s/proxy" class="btn btn-secondary">返回</a>
                </div>
                
                <div class="card">
                    <div class="card-body">
                        <form method="POST">
                            <div class="mb-3">
                                <label for="domain" class="form-label">域名</label>
                                <input type="text" class="form-control" id="domain" name="domain" required 
                                       value="%s">
                            </div>
                            <div class="mb-3">
                                <label for="target" class="form-label">目标地址</label>
                                <input type="text" class="form-control" id="target" name="target" required 
                                       value="%s">
                            </div>
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="enabled" name="enabled" %s>
                                <label class="form-check-label" for="enabled">启用该规则</label>
                            </div>
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="ssl_only" name="ssl_only" %s>
                                <label class="form-check-label" for="ssl_only">仅限HTTPS（HTTP访问将自动301到HTTPS）</label>
                            </div>
                            <button type="submit" class="btn btn-primary">保存更改</button>
                            <a href="%s/proxy" class="btn btn-secondary">取消</a>
                        </form>
                    </div>
                </div>
            </main>
        </div>
    </div>
</body>
</html>`,
		s.generateSidebar(data["AdminPrefix"].(string), "proxy"),
		data["AdminPrefix"].(string),
		rule.Domain,
		rule.Target,
		map[bool]string{true: "checked"}[rule.Enabled],
		map[bool]string{true: "checked"}[rule.SSLOnly],
		data["AdminPrefix"].(string))
}

func (s *Server) generateSSLManagementHTML(data map[string]interface{}) string {
	title := s.translator.T("ssl.title")
	genBtn := s.translator.T("ssl.request_cert")
	thDomain := s.translator.T("ssl.columns.domain")
	thIssued := s.translator.T("ssl.columns.issued")
	thExpires := s.translator.T("ssl.columns.expires")
	thStatus := s.translator.T("ssl.columns.status")
	thActions := s.translator.T("ssl.columns.actions")
	thType := s.translator.T("ssl.columns.type")
	uploadTitle := s.translator.T("ssl.upload_title")
	uploadNote := s.translator.T("ssl.upload_note")
	uploadBtn := s.translator.T("ssl.upload_button")
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">%s</h1>
                    <div class="btn-group">
                        <a href="%s/ssl/generate" class="btn btn-primary">
                            <i class="bi bi-plus-circle"></i> %s
                        </a>
                        <a href="%s/ssl/download-all" class="btn btn-outline-secondary">
                            <i class="bi bi-download"></i> 下载全部
                        </a>
                        <a href="%s/ssl/upload-all" class="btn btn-outline-secondary">
                            <i class="bi bi-upload"></i> 导入全部
                        </a>
                        <form method="POST" action="%s/ssl/sync-acme" class="d-inline ms-2">
                            <button type="submit" class="btn btn-outline-success">
                                <i class="bi bi-arrow-repeat"></i> 同步ACME证书到本地
                            </button>
                        </form>
                    </div>
                </div>
                
                <div class="card mb-3">
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>%s</th>
                                        <th>%s</th>
                                        <th>%s</th>
                                        <th>%s</th>
                                        <th>%s</th>
                                        <th>%s</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    %s
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">%s</h5>
                        <p class="text-muted">%s</p>
                        <a class="btn btn-outline-primary" href="%s/ssl/upload">%s</a>
                    </div>
                </div>
            </main>
        </div>
    </div>
    <script src="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>`,
		title,
		s.generateSidebar(data["AdminPrefix"].(string), "ssl"),
		title,
		data["AdminPrefix"].(string),
		genBtn,
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		thDomain, thIssued, thExpires, thStatus, thActions, thType,
		s.generateSSLCertsTable(data),
		uploadTitle, uploadNote,
		data["AdminPrefix"].(string), uploadBtn)
}

func (s *Server) generateSSLGenerateHTML(data map[string]interface{}) string {
	pageTitle := s.translator.T("ssl.request_cert")
	back := s.translator.T("common.back")
	labelDomains := s.translator.T("ssl.domain")
	help := s.translator.T("ssl.generate_help")
	btnGenerate := s.translator.T("ssl.request_cert")
	btnCancel := s.translator.T("proxy.cancel")
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">%s</h1>
                    <a href="%s/ssl" class="btn btn-secondary">%s</a>
                </div>
                
                <div class="card">
                    <div class="card-body">
                        <form method="POST">
                            <div class="mb-3">
                                <label for="domains" class="form-label">%s</label>
                                <textarea class="form-control" id="domains" name="domains" rows="4" required 
                                         placeholder="example.com, www.example.com, *.example.com"></textarea>
                                <div class="form-text">%s</div>
                            </div>
                            <button type="submit" class="btn btn-primary">%s</button>
                            <a href="%s/ssl" class="btn btn-secondary">%s</a>
                        </form>
                    </div>
                </div>
            </main>
        </div>
    </div>
</body>
</html>`,
		pageTitle,
		s.generateSidebar(data["AdminPrefix"].(string), "ssl"),
		pageTitle,
		data["AdminPrefix"].(string), back,
		labelDomains,
		help,
		btnGenerate,
		data["AdminPrefix"].(string), btnCancel)
}

func (s *Server) generateSecurityManagementHTML(data map[string]interface{}) string {
	title := s.translator.T("security.title")
	blockedIPs := s.translator.T("security.blocked_ips")
	thIP := s.translator.T("security.ip")
	thBlockTime := s.translator.T("security.block_time")
	thActions := s.translator.T("security.actions")
	securityConfig := s.translator.T("security.config")
	maxAttempts := s.translator.T("security.max_attempts")
	maxAttempts5 := s.translator.T("security.max_attempts_5min")
	blockDuration := s.translator.T("security.block_duration")
	uaCheck := s.translator.T("security.ua_check")
	auditLog := s.translator.T("security.audit_log")
	exportJSON := s.translator.T("security.export_json")
	auditTime := s.translator.T("audit.time")
	auditUser := s.translator.T("audit.user_ip")
	auditAction := s.translator.T("audit.action")
	auditDetail := s.translator.T("audit.detail")
	loading := s.translator.T("security.loading")
	noRecords := s.translator.T("security.no_records")
	loadFailed := s.translator.T("security.load_failed")
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">%s</h1>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">%s</h5>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-sm">
                                        <thead>
                                            <tr>
                                                <th>%s</th>
                                                <th>%s</th>
                                                <th>%s</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            %s
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">%s</h5>
                            </div>
                            <div class="card-body">
                                <p><strong>%s:</strong> %d/1min</p>
                                <p><strong>%s:</strong> %d/5min</p>
                                <p><strong>%s:</strong> %s</p>
                                <p><strong>%s:</strong> ON</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="row mt-3">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="mb-0">%s</h5>
                                <a class="btn btn-sm btn-outline-secondary" href="%s/api/tls-fingerprints">JSON</a>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-sm table-striped">
                                        <thead>
                                            <tr>
                                                <th>指纹</th>
                                                <th>次数</th>
                                                <th>最后访问</th>
                                            </tr>
                                        </thead>
                                        <tbody id="tls-fingerprint-body">
                                            <tr><td colspan="3" class="text-center text-muted">%s</td></tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="mb-0">%s</h5>
                                <a class="btn btn-sm btn-outline-secondary" href="%s/api/audit?download=1">%s</a>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-sm table-striped">
                                        <thead>
                                            <tr>
                                                <th style="width: 22%%">%s</th>
                                                <th style="width: 18%%">%s</th>
                                                <th style="width: 20%%">%s</th>
                                                <th>%s</th>
                                            </tr>
                                        </thead>
                                        <tbody id="audit-body">
                                            <tr><td colspan="4" class="text-center text-muted">%s</td></tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>
    <script src="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    // 加载 TLS 指纹统计
    (function(){
      fetch('%s/api/tls-fingerprints').then(r=>r.json()).then(data=>{
        const body = document.getElementById('tls-fingerprint-body');
        body.innerHTML = '';
        const fingerprints = (data && data.fingerprints) || [];
        if (fingerprints.length === 0) {
          body.innerHTML = '<tr><td colspan="3" class="text-center text-muted">暂无数据</td></tr>';
          return;
        }
        fingerprints.slice(0, 10).forEach(fp=>{
          const tr = document.createElement('tr');
          tr.innerHTML = '<td><code>'+(fp.fp||'').substring(0,16)+'...</code></td>'+
                         '<td>'+(fp.count||0)+'</td>'+
                         '<td>'+(fp.last_seen||'')+'</td>';
          body.appendChild(tr);
        });
      }).catch(()=>{
        const body = document.getElementById('tls-fingerprint-body');
        body.innerHTML = '<tr><td colspan="3" class="text-center text-muted">加载失败</td></tr>';
      });
    })();
    
    // 加载审计日志
    (function(){
      fetch('%s/api/audit').then(r=>r.json()).then(data=>{
        const body = document.getElementById('audit-body');
        body.innerHTML = '';
        const logs = (data && data.logs) || [];
        if (logs.length === 0) {
          body.innerHTML = '<tr><td colspan="4" class="text-center text-muted">%s</td></tr>';
          return;
        }
        logs.slice(-50).forEach(it=>{
          const tr = document.createElement('tr');
          tr.innerHTML = '<td>'+(it.time||'')+'</td>'+
                         '<td>'+(it.user||'')+'</td>'+
                         '<td>'+(it.action||'')+'</td>'+
                         '<td><code>'+(it.detail||'')+'</code></td>';
          body.appendChild(tr);
        });
      }).catch(()=>{
        const body = document.getElementById('audit-body');
        body.innerHTML = '<tr><td colspan="4" class="text-center text-muted">%s</td></tr>';
      });
    })();
    </script>
</body>
</html>`,
		title,
		s.generateSidebar(data["AdminPrefix"].(string), "security"),
		title,
		blockedIPs,
		thIP, thBlockTime, thActions,
		s.generateBlockedIPsTable(data),
		securityConfig,
		maxAttempts, s.config.Security.MaxAttempts, maxAttempts5, s.config.Security.MaxAttempts5Min, blockDuration, s.config.Security.BlockDuration.String(), uaCheck,
		s.translator.T("security.tls_fp_stats"),
		data["AdminPrefix"].(string), loading,
		auditLog, data["AdminPrefix"].(string), exportJSON,
		auditTime, auditUser, auditAction, auditDetail, loading,
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string), noRecords, loadFailed)
}

func (s *Server) generateSettingsHTML(data map[string]interface{}) string {
	title := s.translator.T("settings.title")
	adminPrefixLabel := s.translator.T("settings.admin_prefix")
	adminUserLabel := s.translator.T("settings.admin_username")
	adminPassLabel := s.translator.T("settings.admin_password")
	saveBtn := s.translator.T("settings.save")
	exportBtn := s.translator.T("settings.export")
	importPreview := s.translator.T("settings.import_preview")
	viewLastDiff := s.translator.T("settings.view_last_diff")
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">%s</h1>
                </div>
                
                <div class="card">
                    <div class="card-body">
                        <form method="POST" action="%s/settings/save">
                            <h5 class="mb-3">系统设置</h5>
                            <div class="mb-3">
                                <label for="admin_prefix" class="form-label">%s</label>
                                <input type="text" class="form-control" id="admin_prefix" name="admin_prefix" 
                                       value="%s">
                            </div>
                            <div class="mb-3">
                                <label for="admin_username" class="form-label">%s</label>
                                <input type="text" class="form-control" id="admin_username" name="admin_username" 
                                       value="%s">
                            </div>
                            <div class="mb-3">
                                <label for="admin_password" class="form-label">%s</label>
                                <input type="password" class="form-control" id="admin_password" name="admin_password" 
                                       placeholder="留空表示不修改">
                            </div>
                            <hr>
                            <h5 class="mb-3">SSL 设置</h5>
                            <div class="mb-3">
                                <label for="ssl_email" class="form-label">ACME 邮箱（Let's Encrypt）</label>
                                <input type="email" class="form-control" id="ssl_email" name="ssl_email" value="%s" placeholder="admin@example.com">
                                <div class="form-text">填写有效邮箱以启用 ACME 自动签发与到期提醒</div>
                            </div>
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="ssl_disable_self_signed" name="ssl_disable_self_signed" %s>
                                <label class="form-check-label" for="ssl_disable_self_signed">禁用自签名证书回退</label>
                            </div>
                            <hr>
                            <h5 class="mb-3">代理设置</h5>
                            <div class="mb-3">
                                <label for="proxy_unmatched_behavior" class="form-label">未命中代理时的行为</label>
                                <select class="form-select" id="proxy_unmatched_behavior" name="proxy_unmatched_behavior">
                                    <option value="502" %s>502 Bad Gateway</option>
                                    <option value="404" %s>404 Not Found</option>
                                    <option value="302" %s>302 Redirect</option>
                                    <option value="blank" %s>空白响应</option>
                                </select>
                                <div class="form-text">当选择 302 时，必须填写下方重定向URL</div>
                            </div>
                            <div class="mb-3">
                                <label for="proxy_unmatched_redirect_url" class="form-label">未命中时重定向URL</label>
                                <input type="text" class="form-control" id="proxy_unmatched_redirect_url" name="proxy_unmatched_redirect_url" value="%s" placeholder="https://example.com/"> 
                            </div>
                            <button type="submit" class="btn btn-primary">%s</button>
                            <a href="%s/config/export" class="btn btn-outline-secondary ms-2">%s</a>
                            <a href="%s/config/import" class="btn btn-outline-primary ms-2">%s</a>
                            <a href="%s/config/preview" class="btn btn-warning ms-2">%s</a>
                        </form>
                    </div>
                </div>
            </main>
        </div>
    </div>
</body>
</html>`,
		title,
		s.generateSidebar(data["AdminPrefix"].(string), "settings"),
		title,
		data["AdminPrefix"].(string),
		adminPrefixLabel,
		data["AdminPrefix"].(string),
		adminUserLabel,
		s.getConfigAdminUsername(data),
		adminPassLabel,
		s.getConfigSSLEmail(data),
		s.getConfigSSLDisableSelfSigned(data),
		map[bool]string{true: "selected"}[s.config.Proxy.UnmatchedBehavior == "502"],
		map[bool]string{true: "selected"}[s.config.Proxy.UnmatchedBehavior == "404"],
		map[bool]string{true: "selected"}[s.config.Proxy.UnmatchedBehavior == "302"],
		map[bool]string{true: "selected"}[s.config.Proxy.UnmatchedBehavior == "blank"],
		s.config.Proxy.UnmatchedRedirectURL,
		saveBtn,
		data["AdminPrefix"].(string), exportBtn,
		data["AdminPrefix"].(string), importPreview,
		data["AdminPrefix"].(string), viewLastDiff)
}

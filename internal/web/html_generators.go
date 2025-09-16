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
	navStatic := s.translator.T("nav.static_sites")
	navPHP := s.translator.T("nav.php_sites")
	navSSL := s.translator.T("nav.ssl")
	navDNS := "DNS配置"
	navSecurity := s.translator.T("nav.security")
	navSettings := s.translator.T("nav.settings")
	navCDN := "类CDN缓存"
	logout := s.translator.T("menu.logout")
	official := s.translator.T("menu.官方站点")
	if official == "menu.官方站点" {
		// fallback: 若未翻译，使用已有键
		official = s.translator.T("menu.official_site")
	}
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
                                <a class="nav-link %s" href="%s/static-sites">
                                    <i class="bi bi-file-earmark-text"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/php-sites">
                                    <i class="bi bi-code-square"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/ssl">
                                    <i class="bi bi-shield-lock"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/dns">
                                    <i class="bi bi-globe"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/security">
                                    <i class="bi bi-shield-check"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/settings">
                                    <i class="bi bi-gear"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/cdn-cache">
                                    <i class="bi bi-hdd"></i> %s
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
			if activePage == "static-sites" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navStatic,
		func() string {
			if activePage == "php-sites" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navPHP,
		func() string {
			if activePage == "ssl" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navSSL,
		func() string {
			if activePage == "dns" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navDNS,
		func() string {
			if activePage == "security" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navSecurity,
		func() string {
			if activePage == "settings" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navSettings,
		func() string {
			if activePage == "cdn-cache" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navCDN,
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
                                        <th>认证</th>
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
		return `<tr><td colspan="5" class="text-center">` + s.translator.T("proxy.no_rules") + `</td></tr>`
	}

	var rows strings.Builder
	for i, rule := range rules {
		statusBadge := `<span class="badge bg-secondary">` + s.translator.T("common.disabled") + `</span>`
		if rule.Enabled {
			statusBadge = `<span class="badge bg-success">` + s.translator.T("common.enabled") + `</span>`
		}

		// 认证状态
		authBadge := `<span class="badge bg-secondary">未开启</span>`
		if rule.AuthEnabled {
			userCount := len(rule.AuthUsers)
			authBadge = fmt.Sprintf(`<span class="badge bg-warning">已开启 (%d用户)</span>`, userCount)
		}

		rows.WriteString(fmt.Sprintf(`
                    <tr>
                        <td>%s</td>
                        <td>%s</td>
                        <td>%s</td>
                        <td>%s</td>
                        <td>
                            <a href="%s/proxy/edit?index=%d" class="btn btn-sm btn-outline-primary">`+s.translator.T("proxy.edit")+`</a>
                            <a href="%s/proxy/delete?index=%d" class="btn btn-sm btn-outline-danger" onclick="return confirm('`+s.translator.T("proxy.delete_confirm")+`')">`+s.translator.T("proxy.delete")+`</a>
                        </td>
                    </tr>`,
			rule.Domain, rule.Target, statusBadge, authBadge, data["AdminPrefix"].(string), i, data["AdminPrefix"].(string), i))
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
	blockedIPs, ok := data["BlockedIPs"].([]interface{})
	if !ok || len(blockedIPs) == 0 {
		return `<tr><td colspan="3" class="text-center text-muted">暂无封禁IP</td></tr>`
	}
	var rows strings.Builder
	for _, item := range blockedIPs {
		if blocked, ok := item.(map[string]interface{}); ok {
			ip := blocked["ip"].(string)
			blockTime := blocked["block_time"].(string)
			rows.WriteString(fmt.Sprintf(`
				<tr>
					<td>%s</td>
					<td>%s</td>
					<td>
						<form method="POST" action="%s/security/unblock" class="d-inline">
							<input type="hidden" name="ip" value="%s">
							<button class="btn btn-sm btn-outline-danger" type="submit">解除封禁</button>
						</form>
					</td>
				</tr>`,
				ip, blockTime, data["AdminPrefix"].(string), ip))
		}
	}
	return rows.String()
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
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
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
                            <hr>
                            <h6>类CDN缓存（针对该域名）</h6>
                            <div class="form-check form-switch mb-2">
                                <input class="form-check-input" type="checkbox" id="cdn_enabled" name="cdn_enabled">
                                <label class="form-check-label" for="cdn_enabled">启用域名级CDN缓存</label>
                            </div>
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">预设</label>
                                    <select class="form-select" name="cdn_preset">
                                        <option value="none">自定义/无预设</option>
                                        <option value="static">静态资源（.js,.css,.png,.jpg,.ico,.woff2）</option>
                                        <option value="images">图片（image/*）</option>
                                    </select>
                                </div>
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">默认TTL（秒，留空使用全局）</label>
                                    <input class="form-control" name="cdn_ttl_seconds" placeholder="例如 86400">
                                </div>
                            </div>
                            
                            <hr>
                            <h6>访问控制</h6>
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="auth_enabled" name="auth_enabled" 
                                       onchange="toggleAuthSettings()">
                                <label class="form-check-label" for="auth_enabled">启用登录验证</label>
                            </div>
                            
                            <div id="auth_settings" style="display: none;">
                                <div class="card border-primary mb-3">
                                    <div class="card-header">
                                        <strong>认证配置</strong>
                                    </div>
                                    <div class="card-body">
                                        <div class="row mb-3">
                                            <div class="col-md-6">
                                                <label class="form-label">登录有效期（秒）</label>
                                                <input type="number" class="form-control" name="auth_session_timeout" 
                                                       value="3600" min="300" max="86400" placeholder="3600">
                                                <div class="form-text">建议1小时(3600秒)到24小时(86400秒)</div>
                                            </div>
                                            <div class="col-md-6">
                                                <label class="form-label">Cookie域名（留空自动设置）</label>
                                                <input type="text" class="form-control" name="auth_cookie_domain" 
                                                       placeholder="自动使用代理域名">
                                            </div>
                                        </div>
                                        
                                        <div class="mb-3">
                                            <label class="form-label">
                                                <strong>用户账号</strong>
                                                <button type="button" class="btn btn-sm btn-outline-primary ms-2" 
                                                        onclick="addAuthUser()">
                                                    <i class="bi bi-plus"></i> 添加用户
                                                </button>
                                            </label>
                                            <div id="auth_users_container">
                                                <div class="text-muted">点击"添加用户"按钮添加用户账号</div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <script>
                            function toggleAuthSettings() {
                                const enabled = document.getElementById('auth_enabled').checked;
                                const settings = document.getElementById('auth_settings');
                                settings.style.display = enabled ? 'block' : 'none';
                            }
                            
                            function addAuthUser() {
                                const container = document.getElementById('auth_users_container');
                                
                                // 如果是首次添加，清空提示文本
                                if (container.children.length === 1 && container.firstElementChild.classList.contains('text-muted')) {
                                    container.innerHTML = '';
                                }
                                
                                const userIndex = container.children.length;
                                const userHtml = 
                                    '<div class="row mb-2 auth-user-row">' +
                                        '<div class="col-md-5">' +
                                            '<input type="text" class="form-control" name="auth_users[' + userIndex + '][username]" placeholder="用户名" required>' +
                                        '</div>' +
                                        '<div class="col-md-5">' +
                                            '<input type="password" class="form-control" name="auth_users[' + userIndex + '][password]" placeholder="密码" required>' +
                                        '</div>' +
                                        '<div class="col-md-2">' +
                                            '<button type="button" class="btn btn-outline-danger" onclick="removeAuthUser(this)">' +
                                                '<i class="bi bi-trash"></i>' +
                                            '</button>' +
                                        '</div>' +
                                    '</div>';
                                container.insertAdjacentHTML('beforeend', userHtml);
                            }
                            
                            function removeAuthUser(button) {
                                const container = document.getElementById('auth_users_container');
                                button.closest('.auth-user-row').remove();
                                
                                // 如果删除后没有用户了，显示提示文本
                                if (container.children.length === 0) {
                                    container.innerHTML = '<div class="text-muted">点击"添加用户"按钮添加用户账号</div>';
                                }
                            }
                            </script>
                            
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
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
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
                            <hr>
                            <h6>类CDN缓存（针对该域名）</h6>
                            <div class="form-check form-switch mb-2">
                                <input class="form-check-input" type="checkbox" id="cdn_enabled" name="cdn_enabled" %s>
                                <label class="form-check-label" for="cdn_enabled">启用域名级CDN缓存</label>
                            </div>
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">预设</label>
                                    <select class="form-select" name="cdn_preset">
                                        <option value="none" %s>自定义/无预设</option>
                                        <option value="static" %s>静态资源（.js,.css,.png,.jpg,.ico,.woff2）</option>
                                        <option value="images" %s>图片（image/*）</option>
                                    </select>
                                </div>
                                <div class="col-md-6 mb-3">
                                    <label class="form-label">默认TTL（秒，留空使用全局）</label>
                                    <input class="form-control" name="cdn_ttl_seconds" value="%s" placeholder="例如 86400">
                                </div>
                            </div>
                            
                            <hr>
                            <h6>访问控制</h6>
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="auth_enabled" name="auth_enabled" %s 
                                       onchange="toggleAuthSettings()">
                                <label class="form-check-label" for="auth_enabled">启用登录验证</label>
                            </div>
                            
                            <div id="auth_settings" style="display: %s;">
                                <div class="card border-primary mb-3">
                                    <div class="card-header">
                                        <strong>认证配置</strong>
                                    </div>
                                    <div class="card-body">
                                        <div class="row mb-3">
                                            <div class="col-md-6">
                                                <label class="form-label">登录有效期（秒）</label>
                                                <input type="number" class="form-control" name="auth_session_timeout" 
                                                       value="%s" min="300" max="86400" placeholder="3600">
                                                <div class="form-text">建议1小时(3600秒)到24小时(86400秒)</div>
                                            </div>
                                            <div class="col-md-6">
                                                <label class="form-label">Cookie域名（留空自动设置）</label>
                                                <input type="text" class="form-control" name="auth_cookie_domain" 
                                                       value="%s" placeholder="自动使用代理域名">
                                            </div>
                                        </div>
                                        
                                        <div class="mb-3">
                                            <label class="form-label">
                                                <strong>用户账号</strong>
                                                <button type="button" class="btn btn-sm btn-outline-primary ms-2" 
                                                        onclick="addAuthUser()">
                                                    <i class="bi bi-plus"></i> 添加用户
                                                </button>
                                            </label>
                                            <div id="auth_users_container">%s</div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <script>
                            function toggleAuthSettings() {
                                const enabled = document.getElementById('auth_enabled').checked;
                                const settings = document.getElementById('auth_settings');
                                settings.style.display = enabled ? 'block' : 'none';
                            }
                            
                            function addAuthUser() {
                                const container = document.getElementById('auth_users_container');
                                const userIndex = container.children.length;
                                const userHtml = 
                                    '<div class="row mb-2 auth-user-row">' +
                                        '<div class="col-md-5">' +
                                            '<input type="text" class="form-control" name="auth_users[' + userIndex + '][username]" placeholder="用户名" required>' +
                                        '</div>' +
                                        '<div class="col-md-5">' +
                                            '<input type="password" class="form-control" name="auth_users[' + userIndex + '][password]" placeholder="密码" required>' +
                                        '</div>' +
                                        '<div class="col-md-2">' +
                                            '<button type="button" class="btn btn-outline-danger" onclick="removeAuthUser(this)">' +
                                                '<i class="bi bi-trash"></i>' +
                                            '</button>' +
                                        '</div>' +
                                    '</div>';
                                container.insertAdjacentHTML('beforeend', userHtml);
                            }
                            
                            function removeAuthUser(button) {
                                button.closest('.auth-user-row').remove();
                            }
                            
                            // 初始化显示状态
                            document.addEventListener('DOMContentLoaded', function() {
                                toggleAuthSettings();
                            });
                            </script>
                            
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
		map[bool]string{true: "checked"}[rule.CDNEnabled],
		map[bool]string{true: "selected"}[rule.CDNPreset == "none"],
		map[bool]string{true: "selected"}[rule.CDNPreset == "static"],
		map[bool]string{true: "selected"}[rule.CDNPreset == "images"],
		func() string {
			if rule.CDNDefaultTTLSeconds > 0 {
				return fmt.Sprintf("%d", rule.CDNDefaultTTLSeconds)
			}
			return ""
		}(),
		// 访问控制相关字段
		map[bool]string{true: "checked"}[rule.AuthEnabled],
		map[bool]string{true: "block", false: "none"}[rule.AuthEnabled],
		func() string {
			if rule.AuthSessionTimeout > 0 {
				return fmt.Sprintf("%d", rule.AuthSessionTimeout)
			}
			return "3600"
		}(),
		rule.AuthCookieDomain,
		s.generateAuthUsersHTML(rule.AuthUsers),
		data["AdminPrefix"].(string))
}

// generateAuthUsersHTML 生成认证用户的HTML
func (s *Server) generateAuthUsersHTML(users []config.ProxyAuthUser) string {
	if len(users) == 0 {
		return `<div class="text-muted">暂无用户，点击"添加用户"按钮添加</div>`
	}

	var html strings.Builder
	for i, user := range users {
		html.WriteString(fmt.Sprintf(`
		<div class="row mb-2 auth-user-row">
			<div class="col-md-5">
				<input type="text" class="form-control" name="auth_users[%d][username]" 
					   value="%s" placeholder="用户名" required>
			</div>
			<div class="col-md-5">
				<input type="password" class="form-control" name="auth_users[%d][password]" 
					   value="%s" placeholder="密码" required>
			</div>
			<div class="col-md-2">
				<button type="button" class="btn btn-outline-danger" onclick="removeAuthUser(this)">
					<i class="bi bi-trash"></i>
				</button>
			</div>
		</div>`, i, user.Username, i, user.Password))
	}
	return html.String()
}

// generateDNSManagementHTML 生成DNS管理页面HTML
func (s *Server) generateDNSManagementHTML(data map[string]interface{}) string {
	title := "DNS配置管理"
	providers, _ := data["Providers"].([]config.DNSProvider)
	defaultProvider, _ := data["DefaultProvider"].(string)
	challengeMethods, _ := data["ChallengeMethods"].([]string)

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
                    <div>
                        <a href="%s/dns/add" class="btn btn-primary me-2">
                            <i class="bi bi-plus-circle"></i> 添加DNS服务商
                        </a>
                        <a href="%s/dns/config" class="btn btn-outline-secondary">
                            <i class="bi bi-gear"></i> 全局配置
                        </a>
                    </div>
                </div>
                
                <div class="row mb-4">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">当前配置</h5>
                            </div>
                            <div class="card-body">
                                <p><strong>默认DNS服务商:</strong> %s</p>
                                <p><strong>支持的验证方式:</strong> %s</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">使用说明</h5>
                            </div>
                            <div class="card-body">
                                <p class="mb-1">• DNS验证支持通配符证书申请</p>
                                <p class="mb-1">• 无需开放80端口即可申请证书</p>
                                <p class="mb-0">• 支持多个DNS服务商配置</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">DNS服务商列表</h5>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>名称</th>
                                        <th>类型</th>
                                        <th>状态</th>
                                        <th>优先级</th>
                                        <th>配置状态</th>
                                        <th>操作</th>
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
		s.generateSidebar(data["AdminPrefix"].(string), "dns"),
		title,
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		func() string {
			if defaultProvider == "" {
				return "未设置"
			}
			return defaultProvider
		}(),
		func() string {
			if len(challengeMethods) == 0 {
				return "未设置"
			}
			return strings.Join(challengeMethods, ", ")
		}(),
		s.generateDNSProvidersTable(providers, data["AdminPrefix"].(string)))
}

// generateDNSProvidersTable 生成DNS服务商表格
func (s *Server) generateDNSProvidersTable(providers []config.DNSProvider, adminPrefix string) string {
	if len(providers) == 0 {
		return `<tr><td colspan="6" class="text-center">暂无DNS服务商配置</td></tr>`
	}

	var rows strings.Builder
	for i, provider := range providers {
		statusBadge := `<span class="badge bg-secondary">未启用</span>`
		if provider.Enabled {
			statusBadge = `<span class="badge bg-success">已启用</span>`
		}

		// 配置状态
		configStatus := `<span class="badge bg-warning">配置不完整</span>`
		if provider.APIKey != "" {
			if provider.Type == "cloudflare" && provider.ZoneID != "" {
				configStatus = `<span class="badge bg-success">配置完整</span>`
			} else if provider.Type != "cloudflare" {
				configStatus = `<span class="badge bg-success">配置完整</span>`
			}
		}

		rows.WriteString(fmt.Sprintf(`
                    <tr>
                        <td>%s</td>
                        <td><span class="badge bg-info">%s</span></td>
                        <td>%s</td>
                        <td>%d</td>
                        <td>%s</td>
                        <td>
                            <a href="%s/dns/edit?index=%d" class="btn btn-sm btn-outline-primary">编辑</a>
                            <a href="%s/dns/delete?index=%d" class="btn btn-sm btn-outline-danger" onclick="return confirm('确定要删除这个DNS服务商吗？')">删除</a>
                        </td>
                    </tr>`,
			provider.Name, provider.Type, statusBadge, provider.Priority, configStatus, adminPrefix, i, adminPrefix, i))
	}
	return rows.String()
}

// generateDNSAddHTML 生成添加DNS服务商页面HTML
func (s *Server) generateDNSAddHTML(data map[string]interface{}) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>添加DNS服务商 - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">添加DNS服务商</h1>
                    <a href="%s/dns" class="btn btn-secondary">返回</a>
                </div>
                
                <div class="card">
                    <div class="card-body">
                        <form method="POST">
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="name" class="form-label">服务商名称</label>
                                    <input type="text" class="form-control" id="name" name="name" required 
                                           placeholder="例如: my-cloudflare">
                                    <div class="form-text">用于标识这个DNS服务商配置</div>
                                </div>
                                <div class="col-md-6 mb-3">
                                    <label for="type" class="form-label">服务商类型</label>
                                    <select class="form-select" id="type" name="type" required onchange="toggleProviderFields()">
                                        <option value="">请选择服务商类型</option>
                                        <option value="cloudflare">Cloudflare</option>
                                        <option value="aliyun">阿里云DNS</option>
                                        <option value="tencent">腾讯云DNS</option>
                                        <option value="aws">AWS Route53</option>
                                        <option value="godaddy">GoDaddy</option>
                                        <option value="custom">自定义API</option>
                                    </select>
                                </div>
                            </div>
                            
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="enabled" name="enabled" checked>
                                <label class="form-check-label" for="enabled">启用此服务商</label>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="priority" class="form-label">优先级</label>
                                    <input type="number" class="form-control" id="priority" name="priority" 
                                           value="1" min="1" max="100">
                                    <div class="form-text">数字越小优先级越高</div>
                                </div>
                            </div>
                            
                            <hr>
                            <h6>API配置</h6>
                            
                            <div id="cloudflare-fields" style="display: none;">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="api_key" class="form-label">API Token</label>
                                        <input type="password" class="form-control" id="api_key" name="api_key" 
                                               placeholder="Cloudflare API Token">
                                        <div class="form-text">需要 Zone:Read, DNS:Edit 权限</div>
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label for="zone_id" class="form-label">Zone ID</label>
                                        <input type="text" class="form-control" id="zone_id" name="zone_id" 
                                               placeholder="域名对应的Zone ID">
                                    </div>
                                </div>
                            </div>
                            
                            <div id="aliyun-fields" style="display: none;">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="api_key" class="form-label">Access Key ID</label>
                                        <input type="text" class="form-control" id="api_key" name="api_key" 
                                               placeholder="阿里云Access Key ID">
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label for="api_secret" class="form-label">Access Key Secret</label>
                                        <input type="password" class="form-control" id="api_secret" name="api_secret" 
                                               placeholder="阿里云Access Key Secret">
                                    </div>
                                </div>
                            </div>
                            
                            <div id="tencent-fields" style="display: none;">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="api_key" class="form-label">Secret ID</label>
                                        <input type="text" class="form-control" id="api_key" name="api_key" 
                                               placeholder="腾讯云Secret ID">
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label for="api_secret" class="form-label">Secret Key</label>
                                        <input type="password" class="form-control" id="api_secret" name="api_secret" 
                                               placeholder="腾讯云Secret Key">
                                    </div>
                                </div>
                            </div>
                            
                            <div id="custom-fields" style="display: none;">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="api_key" class="form-label">API Key</label>
                                        <input type="password" class="form-control" id="api_key" name="api_key" 
                                               placeholder="自定义API密钥">
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label for="endpoint" class="form-label">API端点</label>
                                        <input type="url" class="form-control" id="endpoint" name="endpoint" 
                                               placeholder="https://api.example.com">
                                    </div>
                                </div>
                            </div>
                            
                            <button type="submit" class="btn btn-primary">添加服务商</button>
                            <a href="%s/dns" class="btn btn-secondary">取消</a>
                        </form>
                    </div>
                </div>
            </main>
        </div>
    </div>
    
    <script>
    function toggleProviderFields() {
        const type = document.getElementById('type').value;
        
        // 隐藏所有字段组
        document.getElementById('cloudflare-fields').style.display = 'none';
        document.getElementById('aliyun-fields').style.display = 'none';
        document.getElementById('tencent-fields').style.display = 'none';
        document.getElementById('custom-fields').style.display = 'none';
        
        // 显示对应的字段组
        if (type === 'cloudflare') {
            document.getElementById('cloudflare-fields').style.display = 'block';
        } else if (type === 'aliyun') {
            document.getElementById('aliyun-fields').style.display = 'block';
        } else if (type === 'tencent') {
            document.getElementById('tencent-fields').style.display = 'block';
        } else if (type === 'custom') {
            document.getElementById('custom-fields').style.display = 'block';
        }
    }
    </script>
    
    <script src="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>`,
		s.generateSidebar(data["AdminPrefix"].(string), "dns"),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string))
}

// generateDNSEditHTML 生成编辑DNS服务商页面HTML
func (s *Server) generateDNSEditHTML(data map[string]interface{}) string {
	provider := data["Provider"].(config.DNSProvider)

	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>编辑DNS服务商 - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">编辑DNS服务商</h1>
                    <a href="%s/dns" class="btn btn-secondary">返回</a>
                </div>
                
                <div class="card">
                    <div class="card-body">
                        <form method="POST">
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="name" class="form-label">服务商名称</label>
                                    <input type="text" class="form-control" id="name" name="name" required 
                                           value="%s">
                                </div>
                                <div class="col-md-6 mb-3">
                                    <label for="type" class="form-label">服务商类型</label>
                                    <select class="form-select" id="type" name="type" required onchange="toggleProviderFields()">
                                        <option value="cloudflare" %s>Cloudflare</option>
                                        <option value="aliyun" %s>阿里云DNS</option>
                                        <option value="tencent" %s>腾讯云DNS</option>
                                        <option value="aws" %s>AWS Route53</option>
                                        <option value="godaddy" %s>GoDaddy</option>
                                        <option value="custom" %s>自定义API</option>
                                    </select>
                                </div>
                            </div>
                            
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="enabled" name="enabled" %s>
                                <label class="form-check-label" for="enabled">启用此服务商</label>
                            </div>
                            
                            <div class="row">
                                <div class="col-md-6 mb-3">
                                    <label for="priority" class="form-label">优先级</label>
                                    <input type="number" class="form-control" id="priority" name="priority" 
                                           value="%d" min="1" max="100">
                                </div>
                            </div>
                            
                            <hr>
                            <h6>API配置</h6>
                            
                            <div id="cloudflare-fields" style="display: %s;">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="api_key" class="form-label">API Token</label>
                                        <input type="password" class="form-control" id="api_key" name="api_key" 
                                               value="%s" placeholder="Cloudflare API Token">
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label for="zone_id" class="form-label">Zone ID</label>
                                        <input type="text" class="form-control" id="zone_id" name="zone_id" 
                                               value="%s" placeholder="域名对应的Zone ID">
                                    </div>
                                </div>
                            </div>
                            
                            <div id="aliyun-fields" style="display: %s;">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="api_key" class="form-label">Access Key ID</label>
                                        <input type="text" class="form-control" id="api_key" name="api_key" 
                                               value="%s" placeholder="阿里云Access Key ID">
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label for="api_secret" class="form-label">Access Key Secret</label>
                                        <input type="password" class="form-control" id="api_secret" name="api_secret" 
                                               value="%s" placeholder="阿里云Access Key Secret">
                                    </div>
                                </div>
                            </div>
                            
                            <div id="tencent-fields" style="display: %s;">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="api_key" class="form-label">Secret ID</label>
                                        <input type="text" class="form-control" id="api_key" name="api_key" 
                                               value="%s" placeholder="腾讯云Secret ID">
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label for="api_secret" class="form-label">Secret Key</label>
                                        <input type="password" class="form-control" id="api_secret" name="api_secret" 
                                               value="%s" placeholder="腾讯云Secret Key">
                                    </div>
                                </div>
                            </div>
                            
                            <div id="custom-fields" style="display: %s;">
                                <div class="row">
                                    <div class="col-md-6 mb-3">
                                        <label for="api_key" class="form-label">API Key</label>
                                        <input type="password" class="form-control" id="api_key" name="api_key" 
                                               value="%s" placeholder="自定义API密钥">
                                    </div>
                                    <div class="col-md-6 mb-3">
                                        <label for="endpoint" class="form-label">API端点</label>
                                        <input type="url" class="form-control" id="endpoint" name="endpoint" 
                                               value="%s" placeholder="https://api.example.com">
                                    </div>
                                </div>
                            </div>
                            
                            <button type="submit" class="btn btn-primary">保存更改</button>
                            <a href="%s/dns" class="btn btn-secondary">取消</a>
                        </form>
                    </div>
                </div>
            </main>
        </div>
    </div>
    
    <script>
    function toggleProviderFields() {
        const type = document.getElementById('type').value;
        
        // 隐藏所有字段组
        document.getElementById('cloudflare-fields').style.display = 'none';
        document.getElementById('aliyun-fields').style.display = 'none';
        document.getElementById('tencent-fields').style.display = 'none';
        document.getElementById('custom-fields').style.display = 'none';
        
        // 显示对应的字段组
        if (type === 'cloudflare') {
            document.getElementById('cloudflare-fields').style.display = 'block';
        } else if (type === 'aliyun') {
            document.getElementById('aliyun-fields').style.display = 'block';
        } else if (type === 'tencent') {
            document.getElementById('tencent-fields').style.display = 'block';
        } else if (type === 'custom') {
            document.getElementById('custom-fields').style.display = 'block';
        }
    }
    
    // 初始化显示状态
    document.addEventListener('DOMContentLoaded', function() {
        toggleProviderFields();
    });
    </script>
    
    <script src="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>`,
		s.generateSidebar(data["AdminPrefix"].(string), "dns"),
		data["AdminPrefix"].(string),
		provider.Name,
		map[bool]string{true: "selected"}[provider.Type == "cloudflare"],
		map[bool]string{true: "selected"}[provider.Type == "aliyun"],
		map[bool]string{true: "selected"}[provider.Type == "tencent"],
		map[bool]string{true: "selected"}[provider.Type == "aws"],
		map[bool]string{true: "selected"}[provider.Type == "godaddy"],
		map[bool]string{true: "selected"}[provider.Type == "custom"],
		map[bool]string{true: "checked"}[provider.Enabled],
		provider.Priority,
		map[bool]string{true: "block", false: "none"}[provider.Type == "cloudflare"],
		provider.APIKey,
		provider.ZoneID,
		map[bool]string{true: "block", false: "none"}[provider.Type == "aliyun"],
		provider.APIKey,
		provider.APISecret,
		map[bool]string{true: "block", false: "none"}[provider.Type == "tencent"],
		provider.APIKey,
		provider.APISecret,
		map[bool]string{true: "block", false: "none"}[provider.Type == "custom"],
		provider.APIKey,
		provider.Endpoint,
		data["AdminPrefix"].(string))
}

// generateDNSConfigHTML 生成DNS全局配置页面HTML
func (s *Server) generateDNSConfigHTML(data map[string]interface{}) string {
	defaultProvider, _ := data["DefaultProvider"].(string)
	challengeMethods, _ := data["ChallengeMethods"].([]string)
	providers, _ := data["Providers"].([]config.DNSProvider)

	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS全局配置 - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">DNS全局配置</h1>
                    <a href="%s/dns" class="btn btn-secondary">返回</a>
                </div>
                
                <div class="card">
                    <div class="card-body">
                        <form method="POST">
                            <div class="mb-3">
                                <label for="default_provider" class="form-label">默认DNS服务商</label>
                                <select class="form-select" id="default_provider" name="default_provider">
                                    <option value="">请选择默认服务商</option>
                                    %s
                                </select>
                                <div class="form-text">用于自动申请证书时的默认DNS服务商</div>
                            </div>
                            
                            <div class="mb-3">
                                <label class="form-label">支持的验证方式</label>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="http-01" name="challenge_methods" value="http-01" %s>
                                    <label class="form-check-label" for="http-01">
                                        HTTP-01 验证
                                    </label>
                                    <div class="form-text">需要80端口可访问，适用于单域名证书</div>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="dns-01" name="challenge_methods" value="dns-01" %s>
                                    <label class="form-check-label" for="dns-01">
                                        DNS-01 验证
                                    </label>
                                    <div class="form-text">通过DNS记录验证，支持通配符证书</div>
                                </div>
                            </div>
                            
                            <button type="submit" class="btn btn-primary">保存配置</button>
                            <a href="%s/dns" class="btn btn-secondary">取消</a>
                        </form>
                    </div>
                </div>
            </main>
        </div>
    </div>
    <script src="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>`,
		s.generateSidebar(data["AdminPrefix"].(string), "dns"),
		data["AdminPrefix"].(string),
		func() string {
			var options strings.Builder
			for _, provider := range providers {
				selected := ""
				if provider.Name == defaultProvider {
					selected = "selected"
				}
				options.WriteString(fmt.Sprintf(`<option value="%s" %s>%s (%s)</option>`, provider.Name, selected, provider.Name, provider.Type))
			}
			return options.String()
		}(),
		func() string {
			for _, method := range challengeMethods {
				if method == "http-01" {
					return "checked"
				}
			}
			return ""
		}(),
		func() string {
			for _, method := range challengeMethods {
				if method == "dns-01" {
					return "checked"
				}
			}
			return ""
		}(),
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
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
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
	// DDoS 统计
	ddosStats := data["DDOSStats"].(map[string]interface{})
	ddosStatus := "关闭"
	blockedClients := 0
	totalAttacks := 0
	if enabled, ok := ddosStats["enabled"].(bool); ok && enabled {
		ddosStatus = "启用"
	}
	if v, ok := ddosStats["blocked_clients"].(int); ok {
		blockedClients = v
	}
	if v, ok := ddosStats["total_attacks"].(int); ok {
		totalAttacks = v
	}
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全设置 - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">安全设置</h1>
                </div>
                
                <!-- 安全配置表单 -->
                <div class="card mb-3">
                    <div class="card-header"><h5>人机验证与防护设置</h5></div>
                    <div class="card-body">
                        <form method="POST" action="%s/security/save">
                            <div class="row">
                                <div class="col-md-6">
                                    <h6>人机验证</h6>
                                    <div class="form-check form-switch mb-2">
                                        <input class="form-check-input" type="checkbox" name="enable_captcha" %s>
                                        <label class="form-check-label">启用图形验证码</label>
                                    </div>
                                    <div class="mb-3">
                                        <label class="form-label">最小填写时长（毫秒）</label>
                                        <input class="form-control" name="min_form_ms" value="%d" placeholder="800">
                                        <div class="form-text">小于此时长的提交将被拒绝</div>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <h6>DDoS 防护</h6>
                                    <div class="form-check form-switch mb-3">
                                        <input class="form-check-input" type="checkbox" name="enable_ddos" %s>
                                        <label class="form-check-label">启用 DDoS 防护</label>
                                    </div>
                                    <div class="alert alert-info">
                                        <small>
                                            当前状态：%s<br>
                                            封禁客户端：%d<br>
                                            总攻击数：%d
                                        </small>
                                    </div>
                                </div>
                            </div>
                            <button class="btn btn-primary" type="submit">保存设置</button>
                        </form>
                    </div>
                </div>

                <!-- 被封禁IP与最近攻击 -->
                <div class="row">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header"><h5>被封禁IP</h5></div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-sm">
                                        <thead>
                                            <tr>
                                                <th>IP地址</th>
                                                <th>封禁时间</th>
                                                <th>操作</th>
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
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="mb-0">最近攻击</h5>
                                <a class="btn btn-sm btn-outline-secondary" href="%s/api/security/attacks">JSON</a>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-sm table-striped">
                                        <thead>
                                            <tr>
                                                <th>时间</th>
                                                <th>IP</th>
                                                <th>类型</th>
                                                <th>状态</th>
                                            </tr>
                                        </thead>
                                        <tbody id="attacks-body">
                                            <tr><td colspan="4" class="text-center text-muted">加载中...</td></tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- TLS指纹与审计日志 -->
                <div class="row mt-3">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="mb-0">TLS 指纹统计</h5>
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
                                            <tr><td colspan="3" class="text-center text-muted">加载中...</td></tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <h5 class="mb-0">审计日志</h5>
                                <a class="btn btn-sm btn-outline-secondary" href="%s/api/audit?download=1">导出JSON</a>
                            </div>
                            <div class="card-body">
                                <div class="table-responsive">
                                    <table class="table table-sm table-striped">
                                        <thead>
                                            <tr>
                                                <th style="width: 22%%">时间</th>
                                                <th style="width: 18%%">用户/IP</th>
                                                <th style="width: 20%%">操作</th>
                                                <th>详情</th>
                                            </tr>
                                        </thead>
                                        <tbody id="audit-body">
                                            <tr><td colspan="4" class="text-center text-muted">加载中...</td></tr>
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
    fetch('%s/api/tls-fingerprints?limit=10').then(r=>r.json()).then(data=>{
        const body = document.getElementById('tls-fingerprint-body');
        body.innerHTML = '';
        const fingerprints = (data && data.fingerprints) || [];
        if (fingerprints.length === 0) {
            body.innerHTML = '<tr><td colspan="3" class="text-center text-muted">暂无数据</td></tr>';
            return;
        }
        fingerprints.forEach(fp=>{
            const tr = document.createElement('tr');
            tr.innerHTML = '<td><code>'+(fp.fp||'').substring(0,16)+'...</code></td>'+
                           '<td>'+(fp.count||0)+'</td>'+
                           '<td>'+(fp.last_seen||'').substring(11,19)+'</td>';
            body.appendChild(tr);
        });
    }).catch(()=>{
        document.getElementById('tls-fingerprint-body').innerHTML = '<tr><td colspan="3" class="text-center text-muted">加载失败</td></tr>';
    });
    
    // 加载最近攻击
    fetch('%s/api/security/attacks?limit=20').then(r=>r.json()).then(data=>{
        const body = document.getElementById('attacks-body');
        body.innerHTML = '';
        const attacks = (data && data.attacks) || [];
        if (attacks.length === 0) {
            body.innerHTML = '<tr><td colspan="4" class="text-center text-muted">暂无攻击</td></tr>';
            return;
        }
        attacks.slice(-10).forEach(att=>{
            const tr = document.createElement('tr');
            const badge = att.blocked ? '<span class="badge bg-danger">已阻止</span>' : '<span class="badge bg-warning">检测</span>';
            tr.innerHTML = '<td>'+(att.time||'').substring(11,19)+'</td>'+
                           '<td>'+(att.ip||'')+'</td>'+
                           '<td>'+(att.type||'')+'</td>'+
                           '<td>'+badge+'</td>';
            body.appendChild(tr);
        });
    }).catch(()=>{
        document.getElementById('attacks-body').innerHTML = '<tr><td colspan="4" class="text-center text-muted">加载失败</td></tr>';
    });
    
    // 加载审计日志
    fetch(document.location.pathname.split('/')[1]+'/api/audit').then(r=>r.json()).then(data=>{
        const body = document.getElementById('audit-body');
        body.innerHTML = '';
        const logs = (data && data.logs) || [];
        if (logs.length === 0) {
            body.innerHTML = '<tr><td colspan="4" class="text-center text-muted">暂无记录</td></tr>';
            return;
        }
        logs.slice(-20).forEach(it=>{
            const tr = document.createElement('tr');
            tr.innerHTML = '<td>'+(it.time||'').substring(11,19)+'</td>'+
                           '<td>'+(it.user||'')+'</td>'+
                           '<td>'+(it.action||'')+'</td>'+
                           '<td><code>'+(it.detail||'').substring(0,40)+'</code></td>';
            body.appendChild(tr);
        });
    }).catch(()=>{
        document.getElementById('audit-body').innerHTML = '<tr><td colspan="4" class="text-center text-muted">加载失败</td></tr>';
    });
    </script>
</body>
</html>`,
		s.generateSidebar(data["AdminPrefix"].(string), "security"),
		data["AdminPrefix"].(string),
		map[bool]string{true: "checked"}[s.config.Security.EnableCaptcha],
		s.config.Security.MinFormMs,
		map[bool]string{true: "checked"}[s.config.Security.EnableDDOS],
		ddosStatus,
		blockedClients,
		totalAttacks,
		s.generateBlockedIPsTable(data),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string))
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
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify_content_between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
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
                            <h5 class="mb-3">安全认证</h5>
                            <div class="mb-3">
                                <label class="form-label">TOTP 二次验证</label>
                                <div class="d-flex align-items-center">
                                    <span class="badge %s me-2">%s</span>
                                    <a href="%s/settings/totp" class="btn btn-sm btn-outline-info">%s</a>
                                </div>
                                <div class="form-text">为管理员账户启用基于时间的一次性密码验证</div>
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
                            <a href="%s/settings/totp" class="btn btn-outline-info ms-2">TOTP设置</a>
                            <a href="%s/config/export" class="btn btn-outline_secondary ms-2">%s</a>
                            <a href="%s/config/import" class="btn btn-outline_primary ms-2">%s</a>
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
		map[bool]string{true: "bg-success", false: "bg-secondary"}[s.config.Admin.EnableTOTP],
		map[bool]string{true: "已启用", false: "未启用"}[s.config.Admin.EnableTOTP],
		data["AdminPrefix"].(string),
		map[bool]string{true: "管理TOTP", false: "设置TOTP"}[s.config.Admin.EnableTOTP],
		s.getConfigSSLEmail(data),
		s.getConfigSSLDisableSelfSigned(data),
		map[bool]string{true: "selected"}[s.config.Proxy.UnmatchedBehavior == "502"],
		map[bool]string{true: "selected"}[s.config.Proxy.UnmatchedBehavior == "404"],
		map[bool]string{true: "selected"}[s.config.Proxy.UnmatchedBehavior == "302"],
		map[bool]string{true: "selected"}[s.config.Proxy.UnmatchedBehavior == "blank"],
		s.config.Proxy.UnmatchedRedirectURL,
		saveBtn,
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string), exportBtn,
		data["AdminPrefix"].(string), importPreview,
		data["AdminPrefix"].(string), viewLastDiff)
}

func (s *Server) generateCDNCacheHTML(data map[string]interface{}) string {
	cdn := data["CDN"].(config.CDNCacheConfig)

	// 获取实时统计
	cdnStats := map[string]interface{}{"enabled": false}
	if pm, ok := interface{}(s.proxyManager).(interface {
		GetCDNCache() interface{ Stats() map[string]interface{} }
	}); ok {
		if cache := pm.GetCDNCache(); cache != nil {
			cdnStats = cache.Stats()
		}
	}
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>类CDN缓存 - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">类CDN缓存</h1>
                    <div class="btn-group">
                        <a class="btn btn-outline-secondary" href="%s/api/cdn-cache/stats">统计JSON</a>
                    </div>
                </div>

                <!-- 缓存统计 -->
                <div class="row mb-3">
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title">%.1f%%</h5>
                                <p class="card-text">命中率</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title">%d</h5>
                                <p class="card-text">缓存对象</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title">%.1f%%</h5>
                                <p class="card-text">容量利用率</p>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title">%d/%d</h5>
                                <p class="card-text">命中/未命中</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="card mb-3">
                    <div class="card-body">
                        <form method="POST" action="%s/cdn-cache/save">
                            <div class="form-check form-switch mb-3">
                                <input class="form-check-input" type="checkbox" id="enabled" name="enabled" %s>
                                <label class="form-check-label" for="enabled">启用类CDN缓存</label>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">缓存目录</label>
                                <input class="form-control" name="cache_dir" value="%s" placeholder="./data/cache/static">
                            </div>
                            <div class="row">
                              <div class="col-md-4 mb-3">
                                <label class="form-label">最大缓存体积（字节）</label>
                                <input class="form-control" name="max_size_bytes" value="%d">
                              </div>
                              <div class="col-md-4 mb-3">
                                <label class="form-label">默认TTL（秒）</label>
                                <input class="form-control" name="default_ttl_seconds" value="%d">
                              </div>
                              <div class="col-md-4 mb-3">
                                <label class="form-label">清理间隔（秒）</label>
                                <input class="form-control" name="clean_interval_seconds" value="%d">
                              </div>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">单对象最大体积（字节）</label>
                                <input class="form-control" name="max_object_bytes" value="%d">
                            </div>
                            <div class="mb-3">
                                <label class="form-label">规则（每行：matchType|patternOrMediaCSV|ttlSeconds）</label>
                                <textarea class="form-control" name="rules" rows="8" placeholder="prefix|/assets/|86400&#10;suffix|.js|86400&#10;media|image/,text/css|86400">%s</textarea>
                                <div class="form-text">matchType: prefix/suffix/media。media 时第二列以逗号分隔多个类型前缀</div>
                            </div>
                            <button class="btn btn-primary" type="submit">保存设置</button>
                        </form>
                    </div>
                </div>

                <div class="card">
                    <div class="card-body">
                        <h5>一键清理</h5>
                        <form class="row g-2" method="POST" action="%s/cdn-cache/clear">
                            <div class="col-md-3">
                                <select class="form-select" name="type">
                                    <option value="all">全部</option>
                                    <option value="prefix">按前缀</option>
                                    <option value="suffix">按后缀</option>
                                    <option value="media">按媒体类型</option>
                                </select>
                            </div>
                            <div class="col-md-4">
                                <input class="form-control" name="pattern" placeholder="当选择前缀/后缀时填写">
                            </div>
                            <div class="col-md-4">
                                <input class="form-control" name="media_types" placeholder="media模式：image/,text/css">
                            </div>
                            <div class="col-md-1">
                                <button class="btn btn-danger w-100" type="submit">清理</button>
                            </div>
                        </form>
                    </div>
                </div>

            </main>
        </div>
    </div>
</body>
</html>`,
		s.generateSidebar(data["AdminPrefix"].(string), "cdn-cache"),
		data["AdminPrefix"].(string),
		func() float64 {
			if v, ok := cdnStats["hit_rate"].(float64); ok {
				return v
			}
			return 0
		}(),
		func() int64 {
			if v, ok := cdnStats["objects"].(int64); ok {
				return v
			}
			return 0
		}(),
		func() float64 {
			if v, ok := cdnStats["utilization"].(float64); ok {
				return v
			}
			return 0
		}(),
		func() int64 {
			if v, ok := cdnStats["hits"].(int64); ok {
				return v
			}
			return 0
		}(),
		func() int64 {
			if v, ok := cdnStats["misses"].(int64); ok {
				return v
			}
			return 0
		}(),
		data["AdminPrefix"].(string),
		map[bool]string{true: "checked"}[cdn.Enabled],
		cdn.CacheDir,
		cdn.MaxSizeBytes,
		cdn.DefaultTTLSeconds,
		cdn.CleanIntervalSec,
		cdn.MaxObjectBytes,
		s.formatCDNRules(cdn.Rules),
		data["AdminPrefix"].(string))
}

func (s *Server) formatCDNRules(rules []config.CDNCacheRule) string {
	if len(rules) == 0 {
		return ""
	}
	var b strings.Builder
	for _, r := range rules {
		if strings.EqualFold(r.MatchType, "media") {
			b.WriteString("media|")
			b.WriteString(strings.Join(r.MediaTypes, ","))
			b.WriteString("|")
			b.WriteString(fmt.Sprintf("%d\n", r.TTLSeconds))
		} else {
			b.WriteString(r.MatchType)
			b.WriteString("|")
			b.WriteString(r.Pattern)
			b.WriteString("|")
			b.WriteString(fmt.Sprintf("%d\n", r.TTLSeconds))
		}
	}
	return b.String()
}

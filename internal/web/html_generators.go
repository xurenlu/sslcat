package web

import (
	"fmt"
	"net/http"
	"strings"
)

// HTML 生成函数

func (s *Server) generateSidebar(adminPrefix, activePage string) string {
	title := s.translator.T("app.description")
	navDashboard := s.translator.T("nav.dashboard")
	navProxy := s.translator.T("nav.proxy")
	navStatic := s.translator.T("nav.static_sites")
	navPHP := s.translator.T("nav.php_sites")
	navSSL := s.translator.T("nav.ssl")
	navDNS := s.translator.T("nav.dns")
	navSecurity := s.translator.T("nav.security")
	navSettings := s.translator.T("nav.settings")
	navRunners := s.translator.T("nav.runners")
	navGitDeployServer := s.translator.T("nav.git_deploy_server")
	navNotifications := s.translator.T("nav.notifications")
	navCluster := s.translator.T("nav.cluster")
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
                                <a class="nav-link %s" href="%s/cluster">
                                    <i class="bi bi-diagram-3"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/runners">
                                    <i class="bi bi-terminal"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/git-server">
                                    <i class="bi bi-git"></i> %s
                                </a>
                            </li>
                            <li class="nav-item">
                                <a class="nav-link %s" href="%s/notifications">
                                    <i class="bi bi-bell"></i> %s
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
			if activePage == "cluster" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navCluster,
		func() string {
			if activePage == "runners" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navRunners,
		func() string {
			if activePage == "git-server" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navGitDeployServer,
		func() string {
			if activePage == "notifications" {
				return "active"
			}
			return ""
		}(),
		adminPrefix,
		navNotifications,
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
    <link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
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
    <script src="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/axios@0.27.2/dist/axios.min.js"></script>
    <script>
    // SSL重试功能
    function retrySSL(domain) {
        if (!confirm('确定要重试申请证书 ' + domain + ' 吗？')) {
            return;
        }
        
        const button = event.target;
        const originalText = button.innerHTML;
        
        // 显示加载状态
        button.disabled = true;
        button.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span> 重试中...';
        
        // 调用重试API
        axios.post('%s/api/ssl/retry', {
            domain: domain
        })
        .then(function (response) {
            if (response.data.success) {
                showAlert('success', '重试成功', '证书申请成功：' + domain);
                // 刷新页面以显示最新状态
                setTimeout(() => {
                    window.location.reload();
                }, 2000);
            } else {
                showAlert('danger', '重试失败', response.data.error || '未知错误');
            }
        })
        .catch(function (error) {
            console.error('重试失败:', error);
            showAlert('danger', '重试失败', '网络错误或服务器错误');
        })
        .finally(function () {
            // 恢复按钮状态
            button.disabled = false;
            button.innerHTML = originalText;
        });
    }
    
    // 显示提示信息
    function showAlert(type, title, message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-' + type + ' alert-dismissible fade show';
        alertDiv.innerHTML = 
            '<strong>' + title + '</strong> ' + message +
            '<button type="button" class="btn-close" data-bs-dismiss="alert"></button>';
        
        // 在页面顶部显示提示
        const container = document.querySelector('.container-fluid');
        container.insertBefore(alertDiv, container.firstChild);
        
        // 5秒后自动隐藏
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 5000);
    }
    </script>
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
		data["AdminPrefix"].(string), uploadBtn,
		data["AdminPrefix"].(string))
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
    <link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
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
    <link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
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
    
    <script src="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
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
    fetch('%s/api/audit').then(r=>r.json()).then(data=>{
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
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string))
}

// generateRunnersManagementHTML 生成Runners管理页面HTML
func (s *Server) generateRunnersManagementHTML(data map[string]interface{}) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Runners管理 - SSLcat</title>
    <link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">Runners管理</h1>
                </div>
                
                <!-- Local Runner -->
                <div class="card mb-4">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <i class="bi bi-terminal"></i> Local Runner
                            <span class="badge %s ms-2">%s</span>
                        </h5>
                        <div>
                            <button class="btn btn-sm btn-outline-primary" onclick="addLocalTask()">
                                <i class="bi bi-plus-circle"></i> 添加任务
                            </button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>任务名称</th>
                                        <th>类型</th>
                                        <th>端口</th>
                                        <th>状态</th>
                                        <th>操作</th>
                                    </tr>
                                </thead>
                                <tbody id="local-tasks-body">
                                    <tr><td colspan="5" class="text-center text-muted">加载中...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Docker Runner -->
                <div class="card mb-4">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">
                            <i class="bi bi-docker"></i> Docker Runner
                            <span class="badge %s ms-2">%s</span>
                        </h5>
                        <div>
                            <button class="btn btn-sm btn-outline-primary" onclick="addDockerTask()">
                                <i class="bi bi-plus-circle"></i> 添加任务
                            </button>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>任务名称</th>
                                        <th>Git URL</th>
                                        <th>端口</th>
                                        <th>状态</th>
                                        <th>操作</th>
                                    </tr>
                                </thead>
                                <tbody id="docker-tasks-body">
                                    <tr><td colspan="5" class="text-center text-muted">加载中...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

            </main>
        </div>
    </div>
    
    <script src="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    // 加载Local Runner任务
    fetch('%s/api/local-runner/tasks').then(r=>r.json()).then(data=>{
        const body = document.getElementById('local-tasks-body');
        body.innerHTML = '';
        const tasks = (data && data.data) || [];
        if (tasks.length === 0) {
            body.innerHTML = '<tr><td colspan="5" class="text-center text-muted">暂无任务</td></tr>';
            return;
        }
        tasks.forEach(task=>{
            const tr = document.createElement('tr');
            const statusBadge = task.status === 'running' ? 
                '<span class="badge bg-success">运行中</span>' : 
                '<span class="badge bg-secondary">已停止</span>';
            tr.innerHTML = '<td>'+task.name+'</td>'+
                           '<td>'+task.type+'</td>'+
                           '<td>'+task.port+'</td>'+
                           '<td>'+statusBadge+'</td>'+
                           '<td><button class="btn btn-sm btn-outline-danger" onclick="removeLocalTask(\''+task.id+'\')">删除</button></td>';
            body.appendChild(tr);
        });
    }).catch(()=>{
        document.getElementById('local-tasks-body').innerHTML = '<tr><td colspan="5" class="text-center text-muted">加载失败</td></tr>';
    });

    // 加载Docker Runner任务
    fetch('%s/api/docker-runner/tasks').then(r=>r.json()).then(data=>{
        const body = document.getElementById('docker-tasks-body');
        body.innerHTML = '';
        const tasks = (data && data.data) || [];
        if (tasks.length === 0) {
            body.innerHTML = '<tr><td colspan="5" class="text-center text-muted">暂无任务</td></tr>';
            return;
        }
        tasks.forEach(task=>{
            const tr = document.createElement('tr');
            const statusBadge = task.status === 'running' ? 
                '<span class="badge bg-success">运行中</span>' : 
                '<span class="badge bg-secondary">已停止</span>';
            tr.innerHTML = '<td>'+task.name+'</td>'+
                           '<td>'+task.git_url+'</td>'+
                           '<td>'+task.port+'</td>'+
                           '<td>'+statusBadge+'</td>'+
                           '<td><button class="btn btn-sm btn-outline-danger" onclick="removeDockerTask(\''+task.id+'\')">删除</button></td>';
            body.appendChild(tr);
        });
    }).catch(()=>{
        document.getElementById('docker-tasks-body').innerHTML = '<tr><td colspan="5" class="text-center text-muted">加载失败</td></tr>';
    });


    function addLocalTask() {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = '<div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title">添加Local Runner任务</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="addLocalTaskForm"><div class="mb-3"><label for="taskName" class="form-label">任务名称</label><input type="text" class="form-control" id="taskName" name="name" required></div><div class="mb-3"><label for="taskType" class="form-label">任务类型</label><select class="form-select" id="taskType" name="type" required><option value="web">Web应用</option><option value="api">API服务</option><option value="worker">后台任务</option><option value="custom">自定义</option></select></div><div class="mb-3"><label for="binaryPath" class="form-label">二进制文件路径</label><input type="text" class="form-control" id="binaryPath" name="binary_path" required placeholder="/path/to/your/binary"></div><div class="mb-3"><label for="taskPort" class="form-label">端口号</label><input type="number" class="form-control" id="taskPort" name="port" required min="1" max="65535" placeholder="8080"></div><div class="mb-3"><label for="taskArgs" class="form-label">启动参数（每行一个）</label><textarea class="form-control" id="taskArgs" name="args" rows="3" placeholder="--port=8080&#10;--debug"></textarea></div><div class="mb-3"><label for="taskEnv" class="form-label">环境变量（每行一个，格式：KEY=VALUE）</label><textarea class="form-control" id="taskEnv" name="env" rows="3" placeholder="NODE_ENV=production&#10;PORT=8080"></textarea></div></form></div><div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button><button type="button" class="btn btn-primary" onclick="submitLocalTask()">添加任务</button></div></div></div>';
        document.body.appendChild(modal);
        new bootstrap.Modal(modal).show();
        modal.addEventListener('hidden.bs.modal', () => modal.remove());
    }

    function addDockerTask() {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = '<div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title">添加Docker Runner任务</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="addDockerTaskForm"><div class="mb-3"><label for="dockerTaskName" class="form-label">任务名称</label><input type="text" class="form-control" id="dockerTaskName" name="name" required></div><div class="mb-3"><label for="gitUrl" class="form-label">Git仓库URL</label><input type="url" class="form-control" id="gitUrl" name="git_url" required placeholder="https://github.com/user/repo.git"></div><div class="mb-3"><label for="gitBranch" class="form-label">分支</label><input type="text" class="form-control" id="gitBranch" name="git_branch" value="main" placeholder="main"></div><div class="mb-3"><label for="dockerPort" class="form-label">端口号</label><input type="number" class="form-control" id="dockerPort" name="port" required min="1" max="65535" placeholder="8080"></div><div class="mb-3"><label for="dockerEnv" class="form-label">环境变量（每行一个，格式：KEY=VALUE）</label><textarea class="form-control" id="dockerEnv" name="env" rows="3" placeholder="NODE_ENV=production&#10;PORT=8080"></textarea></div></form></div><div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button><button type="button" class="btn btn-primary" onclick="submitDockerTask()">添加任务</button></div></div></div>';
        document.body.appendChild(modal);
        new bootstrap.Modal(modal).show();
        modal.addEventListener('hidden.bs.modal', () => modal.remove());
    }

    function removeLocalTask(id) {
        if (confirm('确定要删除这个任务吗？')) {
            fetch('%s/api/local-runner/task/remove?id='+id, {method: 'POST'})
                .then(() => location.reload())
                .catch(() => alert('删除失败'));
        }
    }

    function removeDockerTask(id) {
        if (confirm('确定要删除这个任务吗？')) {
            fetch('%s/api/docker-runner/task/remove?id='+id, {method: 'POST'})
                .then(() => location.reload())
                .catch(() => alert('删除失败'));
        }
    }


    function submitLocalTask() {
        const form = document.getElementById('addLocalTaskForm');
        const formData = new FormData(form);
        
        // 处理参数和环境变量
        const args = formData.get('args').split('\n').filter(arg => arg.trim());
        const env = {};
        formData.get('env').split('\n').forEach(line => {
            const [key, value] = line.split('=');
            if (key && value) {
                env[key.trim()] = value.trim();
            }
        });
        
        const taskData = {
            name: formData.get('name'),
            type: formData.get('type'),
            binary_path: formData.get('binary_path'),
            port: parseInt(formData.get('port')),
            args: args,
            env: env
        };
        
        fetch('%s/api/local-runner/task/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(taskData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('添加失败: ' + (data.error || '未知错误'));
            }
        })
        .catch(() => alert('添加失败'));
    }

    function submitDockerTask() {
        const form = document.getElementById('addDockerTaskForm');
        const formData = new FormData(form);
        
        // 处理环境变量
        const env = {};
        formData.get('env').split('\n').forEach(line => {
            const [key, value] = line.split('=');
            if (key && value) {
                env[key.trim()] = value.trim();
            }
        });
        
        const taskData = {
            name: formData.get('name'),
            git_url: formData.get('git_url'),
            git_branch: formData.get('git_branch') || 'main',
            port: parseInt(formData.get('port')),
            env: env
        };
        
        fetch('%s/api/docker-runner/task/add', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(taskData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                location.reload();
            } else {
                alert('添加失败: ' + (data.error || '未知错误'));
            }
        })
        .catch(() => alert('添加失败'));
    }
    </script>
</body>
</html>`,
		s.generateSidebar(data["AdminPrefix"].(string), "runners"),
		map[bool]string{true: "bg-success", false: "bg-secondary"}[data["LocalEnabled"].(bool)],
		map[bool]string{true: "已启用", false: "已禁用"}[data["LocalEnabled"].(bool)],
		map[bool]string{true: "bg-success", false: "bg-secondary"}[data["DockerEnabled"].(bool)],
		map[bool]string{true: "已启用", false: "已禁用"}[data["DockerEnabled"].(bool)],
		data["AdminPrefix"].(string),
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
    <link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
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

// generateGitServerManagementHTML 生成Git Deploy Server管理页面HTML (已移动到git_server_html.go)

// generateSSLCertsTable 生成SSL证书表格HTML
func (s *Server) generateSSLCertsTable(data map[string]interface{}) string {
	var b strings.Builder
	b.WriteString(`<div class="table-responsive"><table class="table table-sm">
		<thead>
			<tr>
				<th>域名</th>
				<th>状态</th>
				<th>到期时间</th>
				<th>操作</th>
			</tr>
		</thead>
		<tbody>`)

	// TODO: 实现SSL证书表格生成
	b.WriteString(`
			<tr>
				<td colspan="4" class="text-center text-muted">暂无SSL证书</td>
			</tr>`)

	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

// generateBlockedIPsTable 生成被阻止IP表格HTML
func (s *Server) generateBlockedIPsTable(data map[string]interface{}) string {
	var rows strings.Builder
	rows.WriteString(`<div class="table-responsive"><table class="table table-sm">
		<thead>
			<tr>
				<th>IP地址</th>
				<th>阻止时间</th>
				<th>原因</th>
				<th>操作</th>
			</tr>
		</thead>
		<tbody>`)

	// TODO: 实现被阻止IP表格生成
	rows.WriteString(`
			<tr>
				<td colspan="4" class="text-center text-muted">暂无被阻止的IP</td>
			</tr>`)

	rows.WriteString(`</tbody></table></div>`)
	return rows.String()
}

// 辅助函数来安全地获取配置值
func (s *Server) getConfigAdminUsername(data map[string]interface{}) string {
	if username, ok := data["AdminUsername"].(string); ok {
		return username
	}
	return s.config.Admin.Username
}

func (s *Server) getConfigSSLEmail(data map[string]interface{}) string {
	if email, ok := data["SSLEmail"].(string); ok {
		return email
	}
	return s.config.SSL.Email
}

func (s *Server) getConfigSSLDisableSelfSigned(data map[string]interface{}) string {
	if disable, ok := data["SSLDisableSelfSigned"].(string); ok {
		return disable
	}
	return ""
}

// ==================== Git Deploy Server 页面处理 ====================

// handleCreateApp 处理创建应用页面
func (s *Server) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	data := map[string]interface{}{
		"AdminPrefix":    s.config.AdminPrefix,
		"GitEnabled":     s.config.Runners.Git.Enabled,
		"CreateAppTitle": s.translator.T("git_deploy_server.create_app_title"),
		"ReturnText":     s.translator.T("git_deploy_server.return"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateCreateAppHTML(data)
	w.Write([]byte(html))
}

// handleServerConfig 处理服务器配置页面
func (s *Server) handleServerConfig(w http.ResponseWriter, r *http.Request) {
	if !s.checkAuth(w, r) {
		return
	}

	// 获取服务器配置
	serverConfig := s.gitServer.GetServerConfig()

	data := map[string]interface{}{
		"AdminPrefix":       s.config.AdminPrefix,
		"GitEnabled":        s.config.Runners.Git.Enabled,
		"ServerConfig":      serverConfig,
		"DomainSuffix":      serverConfig.DomainSuffix,
		"ServerConfigTitle": s.translator.T("git_deploy_server.server_config_title"),
		"ReturnText":        s.translator.T("git_deploy_server.return"),
		"PortRange":         serverConfig.PortRange,
		"WelcomeMessage":    serverConfig.WelcomeMessage,
		"AutoSSL":           serverConfig.AutoSSL,
		"SSLEmail":          s.config.SSL.Email, // 使用系统配置中的SSL邮箱
		"AutoDomain":        serverConfig.AutoDomain,
		"DefaultStrategy":   serverConfig.DefaultStrategy,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := s.generateServerConfigHTML(data)
	w.Write([]byte(html))
}

// generateCreateAppHTML 生成创建应用页面 HTML
func (s *Server) generateCreateAppHTML(data map[string]interface{}) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s</title>
    <link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        .form-section {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .form-section h5 {
            color: #495057;
            margin-bottom: 1rem;
        }
        .help-text {
            font-size: 0.875rem;
            color: #6c757d;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">创建新应用</h1>
                    <div>
                        <a href="%s/git-server" class="btn btn-outline-secondary">
                            <i class="bi bi-arrow-left"></i> %s
                        </a>
                    </div>
                </div>
                
                <form id="createAppForm" class="needs-validation" novalidate>
                    <!-- 基本配置 -->
                    <div class="form-section">
                        <h5><i class="bi bi-info-circle"></i> 基本配置</h5>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="appName" class="form-label">应用名称 <span class="text-danger">*</span></label>
                                    <input type="text" class="form-control" id="appName" placeholder="my-app" required>
                                    <div class="help-text">应用名称将用于生成域名和 Git 仓库路径，只能包含字母、数字和连字符</div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="appDisplayName" class="form-label">显示名称</label>
                                    <input type="text" class="form-control" id="appDisplayName" placeholder="我的应用">
                                    <div class="help-text">可选，用于显示的应用名称</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- 部署配置 -->
                    <div class="form-section">
                        <h5><i class="bi bi-gear"></i> 部署配置</h5>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="deployStrategy" class="form-label">部署策略</label>
                                    <select class="form-select" id="deployStrategy">
                                        <option value="auto">自动检测</option>
                                        <option value="docker">Docker</option>
                                        <option value="static">静态文件</option>
                                        <option value="php">PHP</option>
                                    </select>
                                    <div class="help-text">选择应用的部署方式</div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="buildTimeout" class="form-label">构建超时（秒）</label>
                                    <input type="number" class="form-control" id="buildTimeout" value="300" min="60" max="3600">
                                    <div class="help-text">构建过程的最大等待时间</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- SSL 配置 -->
                    <div class="form-section">
                        <h5><i class="bi bi-shield-check"></i> SSL 配置</h5>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-check mb-3">
                                    <input class="form-check-input" type="checkbox" id="autoSSL" checked>
                                    <label class="form-check-label" for="autoSSL">
                                        自动申请 SSL 证书
                                    </label>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-check mb-3">
                                    <input class="form-check-input" type="checkbox" id="autoDomain" checked>
                                    <label class="form-check-label" for="autoDomain">
                                        自动分配域名
                                    </label>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- 环境变量 -->
                    <div class="form-section">
                        <h5><i class="bi bi-list-ul"></i> 环境变量</h5>
                        <div id="envVarsContainer">
                            <div class="row mb-2">
                                <div class="col-md-5">
                                    <input type="text" class="form-control" placeholder="变量名" name="envKey">
                                </div>
                                <div class="col-md-5">
                                    <input type="text" class="form-control" placeholder="变量值" name="envValue">
                                </div>
                                <div class="col-md-2">
                                    <button type="button" class="btn btn-outline-danger btn-sm" onclick="removeEnvVar(this)">
                                        <i class="bi bi-trash"></i>
                                    </button>
                                </div>
                            </div>
                        </div>
                        <button type="button" class="btn btn-outline-primary btn-sm" onclick="addEnvVar()">
                            <i class="bi bi-plus"></i> 添加环境变量
                        </button>
                    </div>

                    <!-- 提交按钮 -->
                    <div class="d-flex justify-content-end gap-2">
                        <a href="%s/git-server" class="btn btn-secondary">取消</a>
                        <button type="submit" class="btn btn-primary">
                            <i class="bi bi-plus-circle"></i> 创建应用
                        </button>
                    </div>
                </form>
            </main>
        </div>
    </div>

    <script src="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 表单验证
        (function() {
            'use strict';
            window.addEventListener('load', function() {
                var forms = document.getElementsByClassName('needs-validation');
                var validation = Array.prototype.filter.call(forms, function(form) {
                    form.addEventListener('submit', function(event) {
                        if (form.checkValidity() === false) {
                            event.preventDefault();
                            event.stopPropagation();
                        }
                        form.classList.add('was-validated');
                    }, false);
                });
            }, false);
        })();

        // 添加环境变量
        function addEnvVar() {
            const container = document.getElementById('envVarsContainer');
            const newRow = document.createElement('div');
            newRow.className = 'row mb-2';
            newRow.innerHTML = 
                '<div class="col-md-5">' +
                    '<input type="text" class="form-control" placeholder="变量名" name="envKey">' +
                '</div>' +
                '<div class="col-md-5">' +
                    '<input type="text" class="form-control" placeholder="变量值" name="envValue">' +
                '</div>' +
                '<div class="col-md-2">' +
                    '<button type="button" class="btn btn-outline-danger btn-sm" onclick="removeEnvVar(this)">' +
                        '<i class="bi bi-trash"></i>' +
                    '</button>' +
                '</div>';
            container.appendChild(newRow);
        }

        // 删除环境变量
        function removeEnvVar(button) {
            button.closest('.row').remove();
        }

        // 表单提交
        document.getElementById('createAppForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const appData = {
                name: document.getElementById('appName').value,
                display_name: document.getElementById('appDisplayName').value || document.getElementById('appName').value,
                deploy_strategy: document.getElementById('deployStrategy').value,
                build_timeout: parseInt(document.getElementById('buildTimeout').value),
                auto_ssl: document.getElementById('autoSSL').checked,
                auto_domain: document.getElementById('autoDomain').checked,
                env_vars: {}
            };

            // 收集环境变量
            const envRows = document.querySelectorAll('#envVarsContainer .row');
            envRows.forEach(row => {
                const key = row.querySelector('input[name="envKey"]').value;
                const value = row.querySelector('input[name="envValue"]').value;
                if (key && value) {
                    appData.env_vars[key] = value;
                }
            });

            // 提交数据
            fetch('%s/api/git-server/app/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(appData)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('应用创建成功！');
                    window.location.href = '%s/git-server';
                } else {
                    alert('创建失败: ' + (data.message || '未知错误'));
                }
            })
            .catch(error => {
                alert('创建失败: ' + error.message);
            });
        });
    </script>
</body>
</html>`,
		data["CreateAppTitle"].(string),
		s.generateSidebar(data["AdminPrefix"].(string), "git-server"),
		data["AdminPrefix"].(string),
		data["ReturnText"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string))
}

// generateServerConfigHTML 生成服务器配置页面 HTML
func (s *Server) generateServerConfigHTML(data map[string]interface{}) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s</title>
    <link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        .form-section {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .form-section h5 {
            color: #495057;
            margin-bottom: 1rem;
        }
        .help-text {
            font-size: 0.875rem;
            color: #6c757d;
        }
        .config-preview {
            background: #e9ecef;
            border-radius: 4px;
            padding: 1rem;
            font-family: monospace;
            font-size: 0.875rem;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">服务器配置</h1>
                    <div>
                        <a href="%s/git-server" class="btn btn-outline-secondary">
                            <i class="bi bi-arrow-left"></i> %s
                        </a>
                    </div>
                </div>
                
                <form id="serverConfigForm" class="needs-validation" novalidate>
                    <!-- 基本配置 -->
                    <div class="form-section">
                        <h5><i class="bi bi-globe"></i> 基本配置</h5>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="domainSuffix" class="form-label">主域名后缀</label>
                                    <input type="text" class="form-control" id="domainSuffix" value="%s" placeholder="your-domain.com">
                                    <div class="help-text">应用将分配到此域名的子域名，如 app.your-domain.com</div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="welcomeMessage" class="form-label">Git 推送欢迎语</label>
                                    <textarea class="form-control" id="welcomeMessage" rows="3" placeholder="欢迎使用 SSLcat Git 部署平台！">%s</textarea>
                                    <div class="help-text">用户推送代码时显示的消息</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- 端口配置 -->
                    <div class="form-section">
                        <h5><i class="bi bi-hdd-network"></i> 端口配置</h5>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="portRangeStart" class="form-label">端口范围起始</label>
                                    <input type="number" class="form-control" id="portRangeStart" value="%s" min="8000" max="65535">
                                    <div class="help-text">应用端口分配的起始端口</div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="portRangeEnd" class="form-label">端口范围结束</label>
                                    <input type="number" class="form-control" id="portRangeEnd" value="%s" min="8000" max="65535">
                                    <div class="help-text">应用端口分配的结束端口</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- SSL 配置 -->
                    <div class="form-section">
                        <h5><i class="bi bi-shield-check"></i> SSL 配置</h5>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-check mb-3">
                                    <input class="form-check-input" type="checkbox" id="autoSSL" %s>
                                    <label class="form-check-label" for="autoSSL">
                                        自动申请 SSL 证书
                                    </label>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-check mb-3">
                                    <input class="form-check-input" type="checkbox" id="autoDomain" %s>
                                    <label class="form-check-label" for="autoDomain">
                                        自动分配域名
                                    </label>
                                </div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-12">
                                <div class="mb-3">
                                    <label for="sslEmail" class="form-label">SSL 证书邮箱</label>
                                    <input type="email" class="form-control" id="sslEmail" value="%s" placeholder="admin@your-domain.com">
                                    <div class="help-text">用于 Let's Encrypt 证书申请的邮箱地址</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- 部署配置 -->
                    <div class="form-section">
                        <h5><i class="bi bi-gear"></i> 部署配置</h5>
                        <div class="row">
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="defaultStrategy" class="form-label">默认部署策略</label>
                                    <select class="form-select" id="defaultStrategy">
                                        <option value="auto" %s>自动检测</option>
                                        <option value="docker" %s>Docker</option>
                                        <option value="static" %s>静态文件</option>
                                        <option value="php" %s>PHP</option>
                                    </select>
                                    <div class="help-text">新应用的默认部署方式</div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="mb-3">
                                    <label for="buildTimeout" class="form-label">构建超时（秒）</label>
                                    <input type="number" class="form-control" id="buildTimeout" value="300" min="60" max="3600">
                                    <div class="help-text">构建过程的最大等待时间</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- 配置预览 -->
                    <div class="form-section">
                        <h5><i class="bi bi-eye"></i> 配置预览</h5>
                        <div class="config-preview" id="configPreview">
                            配置预览将在这里显示...
                        </div>
                    </div>

                    <!-- 提交按钮 -->
                    <div class="d-flex justify-content-end gap-2">
                        <a href="%s/git-server" class="btn btn-secondary">取消</a>
                        <button type="submit" class="btn btn-primary">
                            <i class="bi bi-check-circle"></i> 保存配置
                        </button>
                    </div>
                </form>
            </main>
        </div>
    </div>

    <script src="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // 更新配置预览
        function updateConfigPreview() {
            const config = {
                domain_suffix: document.getElementById('domainSuffix').value,
                port_range: [
                    parseInt(document.getElementById('portRangeStart').value),
                    parseInt(document.getElementById('portRangeEnd').value)
                ],
                welcome_message: document.getElementById('welcomeMessage').value,
                auto_ssl: document.getElementById('autoSSL').checked,
                ssl_email: document.getElementById('sslEmail').value,
                auto_domain: document.getElementById('autoDomain').checked,
                default_strategy: document.getElementById('defaultStrategy').value,
                build_timeout: parseInt(document.getElementById('buildTimeout').value)
            };
            
            document.getElementById('configPreview').innerHTML = JSON.stringify(config, null, 2);
        }

        // 监听表单变化
        document.querySelectorAll('#serverConfigForm input, #serverConfigForm select, #serverConfigForm textarea').forEach(element => {
            element.addEventListener('change', updateConfigPreview);
            element.addEventListener('input', updateConfigPreview);
        });

        // 初始化预览
        updateConfigPreview();

        // 表单提交
        document.getElementById('serverConfigForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const config = {
                domain_suffix: document.getElementById('domainSuffix').value,
                port_range: [
                    parseInt(document.getElementById('portRangeStart').value),
                    parseInt(document.getElementById('portRangeEnd').value)
                ],
                welcome_message: document.getElementById('welcomeMessage').value,
                auto_ssl: document.getElementById('autoSSL').checked,
                ssl_email: document.getElementById('sslEmail').value,
                auto_domain: document.getElementById('autoDomain').checked,
                default_strategy: document.getElementById('defaultStrategy').value,
                build_timeout: parseInt(document.getElementById('buildTimeout').value)
            };

            fetch('%s/api/git-server/config/update', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(config)
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('服务器配置已保存！');
                    window.location.href = '%s/git-server';
                } else {
                    alert('保存失败: ' + (data.message || '未知错误'));
                }
            })
            .catch(error => {
                alert('保存失败: ' + error.message);
            });
        });
    </script>
</body>
</html>`,
		s.generateSidebar(data["AdminPrefix"].(string), "git-server"),
		data["AdminPrefix"].(string),
		data["DomainSuffix"].(string),
		data["WelcomeMessage"].(string),
		fmt.Sprintf("%d", data["PortRange"].([2]int)[0]),
		fmt.Sprintf("%d", data["PortRange"].([2]int)[1]),
		map[bool]string{true: "checked", false: ""}[data["AutoSSL"].(bool)],
		map[bool]string{true: "checked", false: ""}[data["AutoDomain"].(bool)],
		data["SSLEmail"].(string),
		map[string]string{"auto": "selected", "docker": "", "static": "", "php": ""}[data["DefaultStrategy"].(string)],
		map[string]string{"auto": "", "docker": "selected", "static": "", "php": ""}[data["DefaultStrategy"].(string)],
		map[string]string{"auto": "", "docker": "", "static": "selected", "php": ""}[data["DefaultStrategy"].(string)],
		map[string]string{"auto": "", "docker": "", "static": "", "php": "selected"}[data["DefaultStrategy"].(string)],
		data["ServerConfigTitle"].(string),
		s.generateSidebar(data["AdminPrefix"].(string), "git-server"),
		data["AdminPrefix"].(string),
		data["ReturnText"].(string),
		data["AdminPrefix"].(string))
}

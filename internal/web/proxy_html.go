package web

import (
	"fmt"
	"strings"

	"github.com/xurenlu/sslcat/internal/config"
)

// generateProxyManagementHTML 生成代理管理页面HTML
func (s *Server) generateProxyManagementHTML(data map[string]interface{}) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>代理管理 - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        .proxy-rule-card {
            transition: all 0.3s ease;
        }
        .proxy-rule-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%%;
            display: inline-block;
            margin-right: 8px;
        }
        .status-enabled { background-color: #28a745; }
        .status-disabled { background-color: #dc3545; }
        .status-ssl { background-color: #17a2b8; }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">代理管理</h1>
                    <div>
                        <a href="%s/proxy/add" class="btn btn-primary">
                            <i class="bi bi-plus-circle"></i> 添加代理规则
                        </a>
                    </div>
                </div>
                
                <!-- 说明卡片 -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0">代理规则说明</h5>
                    </div>
                    <div class="card-body">
                        <p>代理规则用于将特定域名的请求转发到后端服务器。支持以下功能：</p>
                        <ul>
                            <li>HTTP/HTTPS 代理转发</li>
                            <li>SSL终止和重新加密</li>
                            <li>负载均衡（多目标支持）</li>
                            <li>访问控制和认证</li>
                            <li>CDN缓存优化</li>
                        </ul>
                    </div>
                </div>

                <!-- 代理规则列表 -->
                <div class="row" id="proxy-rules-container">
                    <!-- 动态加载的代理规则卡片 -->
                </div>
            </main>
        </div>
    </div>


    <!-- 编辑代理规则模态框 -->
    <div class="modal fade" id="editProxyModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">编辑代理规则</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    %s
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-primary" onclick="updateProxyRule()">保存</button>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    let currentEditingRule = null;

    // 页面加载完成后初始化
    document.addEventListener('DOMContentLoaded', function() {
        loadProxyRules();
    });

    // 加载代理规则
    function loadProxyRules() {
        fetch('%s/api/proxy/rules')
            .then(response => response.json())
            .then(data => {
                const container = document.getElementById('proxy-rules-container');
                container.innerHTML = '';
                
                if (!data.success || !data.data || data.data.length === 0) {
                    container.innerHTML = '<div class="col-12"><div class="alert alert-info">暂无代理规则</div></div>';
                    return;
                }

                data.data.forEach(rule => {
                    const card = createProxyRuleCard(rule);
                    container.appendChild(card);
                });
            })
            .catch(error => {
                console.error('加载代理规则失败:', error);
                document.getElementById('proxy-rules-container').innerHTML = 
                    '<div class="col-12"><div class="alert alert-danger">加载失败</div></div>';
            });
    }

    // 创建代理规则卡片
    function createProxyRuleCard(rule) {
        const div = document.createElement('div');
        div.className = 'col-md-6 col-lg-4 mb-3';
        
        const statusClass = rule.enabled ? 'status-enabled' : 'status-disabled';
        const sslClass = rule.ssl_only ? 'status-ssl' : '';
        const statusText = rule.enabled ? '启用' : '禁用';
        const sslText = rule.ssl_only ? ' (SSL)' : '';
        
        div.innerHTML = '<div class="card proxy-rule-card h-100">' +
            '<div class="card-header d-flex justify-content-between align-items-center">' +
                '<h6 class="mb-0">' +
                    '<span class="status-indicator ' + statusClass + '"></span>' +
                    rule.domain +
                '</h6>' +
                '<div class="btn-group btn-group-sm">' +
                    '<button class="btn btn-outline-primary" onclick="editProxyRule(\'' + rule.domain + '\')" title="编辑">' +
                        '<i class="bi bi-pencil"></i>' +
                    '</button>' +
                    '<button class="btn btn-outline-danger" onclick="deleteProxyRule(\'' + rule.domain + '\')" title="删除">' +
                        '<i class="bi bi-trash"></i>' +
                    '</button>' +
                '</div>' +
            '</div>' +
            '<div class="card-body">' +
                '<p class="card-text">' +
                    '<strong>目标:</strong> ' + rule.target + ':' + rule.port + '<br>' +
                    '<strong>状态:</strong> ' + statusText + sslText + '<br>' +
                    '<strong>CDN:</strong> ' + (rule.cdn_enabled ? '启用' : '禁用') +
                '</p>' +
            '</div>' +
        '</div>';
        
        return div;
    }


    function editProxyRule(domain) {
        currentEditingRule = domain;
        const modal = new bootstrap.Modal(document.getElementById('editProxyModal'));
        modal.show();
        
        // 加载规则数据到编辑表单
        loadProxyRuleData(domain);
    }

    function loadProxyRuleData(domain) {
        fetch('%s/api/proxy/rule?domain=' + encodeURIComponent(domain))
            .then(response => response.json())
            .then(data => {
                if (data.success && data.data) {
                    const rule = data.data;
                    document.getElementById('editDomain').value = rule.domain;
                    document.getElementById('editTarget').value = rule.target;
                    document.getElementById('editPort').value = rule.port;
                    document.getElementById('editSSLOnly').checked = rule.ssl_only;
                    document.getElementById('editCDNEnabled').checked = rule.cdn_enabled;
                    document.getElementById('editEnabled').checked = rule.enabled;
                }
            });
    }


    function updateProxyRule() {
        if (!currentEditingRule) return;

        const formData = {
            domain: document.getElementById('editDomain').value,
            target: document.getElementById('editTarget').value,
            port: parseInt(document.getElementById('editPort').value),
            ssl_only: document.getElementById('editSSLOnly').checked,
            cdn_enabled: document.getElementById('editCDNEnabled').checked,
            enabled: document.getElementById('editEnabled').checked
        };

        fetch('%s/api/proxy/rule', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                bootstrap.Modal.getInstance(document.getElementById('editProxyModal')).hide();
                loadProxyRules();
                showAlert('success', '代理规则更新成功');
            } else {
                showAlert('danger', '更新失败: ' + (data.message || '未知错误'));
            }
        })
        .catch(error => {
            showAlert('danger', '更新失败: ' + error.message);
        });
    }

    function deleteProxyRule(domain) {
        if (confirm('确定要删除代理规则 "' + domain + '" 吗？')) {
            fetch('%s/api/proxy/rule?domain=' + encodeURIComponent(domain), {
                method: 'DELETE'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadProxyRules();
                    showAlert('success', '代理规则删除成功');
                } else {
                    showAlert('danger', '删除失败: ' + (data.message || '未知错误'));
                }
            })
            .catch(error => {
                showAlert('danger', '删除失败: ' + error.message);
            });
        }
    }

    function showAlert(type, message) {
        const alertDiv = document.createElement('div');
        alertDiv.className = 'alert alert-' + type + ' alert-dismissible fade show';
        alertDiv.innerHTML = message +
            '<button type="button" class="btn-close" data-bs-dismiss="alert"></button>';
        
        const container = document.querySelector('.container-fluid');
        container.insertBefore(alertDiv, container.firstChild);
        
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 3000);
    }
    </script>
</body>
</html>`,
		s.generateSidebar(data["AdminPrefix"].(string), "proxy"),
		data["AdminPrefix"].(string),
		s.generateProxyEditHTML(data),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string))
}

// generateProxyAddHTML 生成添加代理规则表单HTML
func (s *Server) generateProxyAddHTML(data map[string]interface{}) string {
	return `
<form id="addProxyForm">
    <div class="row">
        <div class="col-md-6">
            <div class="mb-3">
                <label for="domain" class="form-label">域名 <span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="domain" required placeholder="example.com">
                <div class="form-text">支持通配符，如 *.example.com</div>
            </div>
            <div class="mb-3">
                <label for="target" class="form-label">目标地址 <span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="target" required placeholder="127.0.0.1">
            </div>
            <div class="mb-3">
                <label for="port" class="form-label">端口 <span class="text-danger">*</span></label>
                <input type="number" class="form-control" id="port" required placeholder="8080" min="1" max="65535">
            </div>
        </div>
        <div class="col-md-6">
            <div class="mb-3">
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="sslOnly">
                    <label class="form-check-label" for="sslOnly">
                        仅HTTPS
                    </label>
                </div>
            </div>
            <div class="mb-3">
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="cdnEnabled">
                    <label class="form-check-label" for="cdnEnabled">
                        启用CDN缓存
                    </label>
                </div>
            </div>
            <div class="mb-3">
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="enabled" checked>
                    <label class="form-check-label" for="enabled">
                        启用规则
                    </label>
                </div>
            </div>
        </div>
    </div>
</form>
`
}

// generateProxyEditHTML 生成编辑代理规则表单HTML
func (s *Server) generateProxyEditHTML(data map[string]interface{}) string {
	return `
<form id="editProxyForm">
    <div class="row">
        <div class="col-md-6">
            <div class="mb-3">
                <label for="editDomain" class="form-label">域名 <span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="editDomain" required>
            </div>
            <div class="mb-3">
                <label for="editTarget" class="form-label">目标地址 <span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="editTarget" required>
            </div>
            <div class="mb-3">
                <label for="editPort" class="form-label">端口 <span class="text-danger">*</span></label>
                <input type="number" class="form-control" id="editPort" required min="1" max="65535">
            </div>
        </div>
        <div class="col-md-6">
            <div class="mb-3">
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="editSSLOnly">
                    <label class="form-check-label" for="editSSLOnly">
                        仅HTTPS
                    </label>
                </div>
            </div>
            <div class="mb-3">
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="editCDNEnabled">
                    <label class="form-check-label" for="editCDNEnabled">
                        启用CDN缓存
                    </label>
                </div>
            </div>
            <div class="mb-3">
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="editEnabled">
                    <label class="form-check-label" for="editEnabled">
                        启用规则
                    </label>
                </div>
            </div>
        </div>
    </div>
</form>
`
}

// generateAuthUsersHTML 生成认证用户列表HTML
func (s *Server) generateAuthUsersHTML(users []config.ProxyAuthUser) string {
	if len(users) == 0 {
		return `<div class="alert alert-info">暂无认证用户</div>`
	}

	var b strings.Builder
	b.WriteString(`<div class="table-responsive"><table class="table table-sm">
		<thead>
			<tr>
				<th>用户名</th>
				<th>状态</th>
				<th>操作</th>
			</tr>
		</thead>
		<tbody>`)

	for _, user := range users {
		b.WriteString(fmt.Sprintf(`
			<tr>
				<td>%s</td>
				<td><span class="badge bg-success">活跃</span></td>
				<td>
					<button class="btn btn-sm btn-outline-danger" onclick="removeAuthUser('%s')">
						<i class="bi bi-trash"></i> 删除
					</button>
				</td>
			</tr>`, user.Username, user.Username))
	}

	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

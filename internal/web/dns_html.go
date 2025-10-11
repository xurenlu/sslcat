package web

import (
	"fmt"
)

// generateDNSManagementHTML 生成DNS管理页面HTML
func (s *Server) generateDNSManagementHTML(data map[string]interface{}) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS管理 - SSLcat</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link href="/static/css/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">DNS管理</h1>
                    <div>
                        <button class="btn btn-primary" onclick="showAddDNSModal()">
                            <i class="bi bi-plus-circle"></i> 添加DNS提供商
                        </button>
                    </div>
                </div>
                
                <!-- 说明卡片 -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0">DNS提供商说明</h5>
                    </div>
                    <div class="card-body">
                        <p>配置DNS提供商以支持DNS-01验证方式申请SSL证书：</p>
                        <ul>
                            <li>Cloudflare - 全球CDN服务商</li>
                            <li>阿里云DNS - 阿里云域名解析服务</li>
                            <li>腾讯云DNS - 腾讯云域名解析服务</li>
                            <li>AWS Route53 - Amazon云服务</li>
                            <li>GoDaddy - 域名注册商</li>
                            <li>自定义API - 支持自定义DNS API</li>
                        </ul>
                    </div>
                </div>

                <!-- DNS提供商列表 -->
                <div class="row" id="dns-providers-container">
                    <!-- 动态加载的DNS提供商卡片 -->
                </div>
            </main>
        </div>
    </div>

    <!-- 添加DNS提供商模态框 -->
    <div class="modal fade" id="addDNSModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">添加DNS提供商</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    %s
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-primary" onclick="addDNSProvider()">添加</button>
                </div>
            </div>
        </div>
    </div>

    <!-- 编辑DNS提供商模态框 -->
    <div class="modal fade" id="editDNSModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">编辑DNS提供商</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    %s
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-primary" onclick="updateDNSProvider()">保存</button>
                </div>
            </div>
        </div>
    </div>
    
    <script src="/static/js/bootstrap.bundle.min.js"></script>
    <script>
    let currentEditingProvider = null;

    // 页面加载完成后初始化
    document.addEventListener('DOMContentLoaded', function() {
        loadDNSProviders();
    });

    // 加载DNS提供商
    function loadDNSProviders() {
        fetch('%s/api/dns/providers')
            .then(response => response.json())
            .then(data => {
                const container = document.getElementById('dns-providers-container');
                container.innerHTML = '';
                
                if (!data.success || !data.data || data.data.length === 0) {
                    container.innerHTML = '<div class="col-12"><div class="alert alert-info">暂无DNS提供商</div></div>';
                    return;
                }

                data.data.forEach(provider => {
                    const card = createDNSProviderCard(provider);
                    container.appendChild(card);
                });
            })
            .catch(error => {
                console.error('加载DNS提供商失败:', error);
                document.getElementById('dns-providers-container').innerHTML = 
                    '<div class="col-12"><div class="alert alert-danger">加载失败</div></div>';
            });
    }

    // 创建DNS提供商卡片
    function createDNSProviderCard(provider) {
        const div = document.createElement('div');
        div.className = 'col-md-6 col-lg-4 mb-3';
        
        const statusClass = provider.enabled ? 'bg-success' : 'bg-secondary';
        const statusText = provider.enabled ? '启用' : '禁用';
        
        div.innerHTML = '<div class="card h-100">' +
            '<div class="card-header d-flex justify-content-between align-items-center">' +
                '<h6 class="mb-0">' + provider.name + '</h6>' +
                '<div class="btn-group btn-group-sm">' +
                    '<button class="btn btn-outline-primary" onclick="editDNSProvider(\'' + provider.name + '\')" title="编辑">' +
                        '<i class="bi bi-pencil"></i>' +
                    '</button>' +
                    '<button class="btn btn-outline-danger" onclick="deleteDNSProvider(\'' + provider.name + '\')" title="删除">' +
                        '<i class="bi bi-trash"></i>' +
                    '</button>' +
                '</div>' +
            '</div>' +
            '<div class="card-body">' +
                '<p class="card-text">' +
                    '<strong>类型:</strong> ' + provider.type + '<br>' +
                    '<strong>状态:</strong> <span class="badge ' + statusClass + '">' + statusText + '</span><br>' +
                    '<strong>优先级:</strong> ' + provider.priority +
                '</p>' +
            '</div>' +
        '</div>';
        
        return div;
    }

    function showAddDNSModal() {
        const modal = new bootstrap.Modal(document.getElementById('addDNSModal'));
        modal.show();
    }

    function editDNSProvider(name) {
        currentEditingProvider = name;
        const modal = new bootstrap.Modal(document.getElementById('editDNSModal'));
        modal.show();
        
        // 加载提供商数据到编辑表单
        loadDNSProviderData(name);
    }

    function loadDNSProviderData(name) {
        fetch('%s/api/dns/provider?name=' + encodeURIComponent(name))
            .then(response => response.json())
            .then(data => {
                if (data.success && data.data) {
                    const provider = data.data;
                    document.getElementById('editProviderName').value = provider.name;
                    document.getElementById('editProviderType').value = provider.type;
                    document.getElementById('editProviderAPIKey').value = provider.api_key || '';
                    document.getElementById('editProviderAPISecret').value = provider.api_secret || '';
                    document.getElementById('editProviderZoneID').value = provider.zone_id || '';
                    document.getElementById('editProviderEndpoint').value = provider.endpoint || '';
                    document.getElementById('editProviderPriority').value = provider.priority;
                    document.getElementById('editProviderEnabled').checked = provider.enabled;
                }
            });
    }

    function addDNSProvider() {
        const formData = {
            name: document.getElementById('providerName').value,
            type: document.getElementById('providerType').value,
            api_key: document.getElementById('providerAPIKey').value,
            api_secret: document.getElementById('providerAPISecret').value,
            zone_id: document.getElementById('providerZoneID').value,
            endpoint: document.getElementById('providerEndpoint').value,
            priority: parseInt(document.getElementById('providerPriority').value),
            enabled: document.getElementById('providerEnabled').checked
        };

        fetch('%s/api/dns/provider', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                bootstrap.Modal.getInstance(document.getElementById('addDNSModal')).hide();
                document.getElementById('addDNSForm').reset();
                loadDNSProviders();
                showAlert('success', 'DNS提供商添加成功');
            } else {
                showAlert('danger', '添加失败: ' + (data.message || '未知错误'));
            }
        })
        .catch(error => {
            showAlert('danger', '添加失败: ' + error.message);
        });
    }

    function updateDNSProvider() {
        if (!currentEditingProvider) return;

        const formData = {
            name: document.getElementById('editProviderName').value,
            type: document.getElementById('editProviderType').value,
            api_key: document.getElementById('editProviderAPIKey').value,
            api_secret: document.getElementById('editProviderAPISecret').value,
            zone_id: document.getElementById('editProviderZoneID').value,
            endpoint: document.getElementById('editProviderEndpoint').value,
            priority: parseInt(document.getElementById('editProviderPriority').value),
            enabled: document.getElementById('editProviderEnabled').checked
        };

        fetch('%s/api/dns/provider', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                bootstrap.Modal.getInstance(document.getElementById('editDNSModal')).hide();
                loadDNSProviders();
                showAlert('success', 'DNS提供商更新成功');
            } else {
                showAlert('danger', '更新失败: ' + (data.message || '未知错误'));
            }
        })
        .catch(error => {
            showAlert('danger', '更新失败: ' + error.message);
        });
    }

    function deleteDNSProvider(name) {
        if (confirm('确定要删除DNS提供商 "' + name + '" 吗？')) {
            fetch('%s/api/dns/provider?name=' + encodeURIComponent(name), {
                method: 'DELETE'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadDNSProviders();
                    showAlert('success', 'DNS提供商删除成功');
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
		s.generateSidebar(data["AdminPrefix"].(string), "dns"),
		s.generateDNSAddHTML(data),
		s.generateDNSEditHTML(data),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string))
}

// generateDNSAddHTML 生成添加DNS提供商表单HTML
func (s *Server) generateDNSAddHTML(data map[string]interface{}) string {
	return `
<form id="addDNSForm">
    <div class="row">
        <div class="col-md-6">
            <div class="mb-3">
                <label for="providerName" class="form-label">提供商名称 <span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="providerName" required placeholder="My Cloudflare">
            </div>
            <div class="mb-3">
                <label for="providerType" class="form-label">提供商类型 <span class="text-danger">*</span></label>
                <select class="form-select" id="providerType" required>
                    <option value="">请选择</option>
                    <option value="cloudflare">Cloudflare</option>
                    <option value="aliyun">阿里云DNS</option>
                    <option value="tencent">腾讯云DNS</option>
                    <option value="aws">AWS Route53</option>
                    <option value="godaddy">GoDaddy</option>
                    <option value="custom">自定义API</option>
                </select>
            </div>
            <div class="mb-3">
                <label for="providerAPIKey" class="form-label">API Key <span class="text-danger">*</span></label>
                <input type="password" class="form-control" id="providerAPIKey" required>
            </div>
            <div class="mb-3">
                <label for="providerAPISecret" class="form-label">API Secret</label>
                <input type="password" class="form-control" id="providerAPISecret">
                <div class="form-text">部分提供商需要</div>
            </div>
        </div>
        <div class="col-md-6">
            <div class="mb-3">
                <label for="providerZoneID" class="form-label">Zone ID</label>
                <input type="text" class="form-control" id="providerZoneID">
                <div class="form-text">Cloudflare等需要</div>
            </div>
            <div class="mb-3">
                <label for="providerEndpoint" class="form-label">API端点</label>
                <input type="url" class="form-control" id="providerEndpoint">
                <div class="form-text">自定义API需要</div>
            </div>
            <div class="mb-3">
                <label for="providerPriority" class="form-label">优先级</label>
                <input type="number" class="form-control" id="providerPriority" value="1" min="1" max="100">
                <div class="form-text">数字越小优先级越高</div>
            </div>
            <div class="mb-3">
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="providerEnabled" checked>
                    <label class="form-check-label" for="providerEnabled">
                        启用提供商
                    </label>
                </div>
            </div>
        </div>
    </div>
</form>
`
}

// generateDNSEditHTML 生成编辑DNS提供商表单HTML
func (s *Server) generateDNSEditHTML(data map[string]interface{}) string {
	return `
<form id="editDNSForm">
    <div class="row">
        <div class="col-md-6">
            <div class="mb-3">
                <label for="editProviderName" class="form-label">提供商名称 <span class="text-danger">*</span></label>
                <input type="text" class="form-control" id="editProviderName" required>
            </div>
            <div class="mb-3">
                <label for="editProviderType" class="form-label">提供商类型 <span class="text-danger">*</span></label>
                <select class="form-select" id="editProviderType" required>
                    <option value="cloudflare">Cloudflare</option>
                    <option value="aliyun">阿里云DNS</option>
                    <option value="tencent">腾讯云DNS</option>
                    <option value="aws">AWS Route53</option>
                    <option value="godaddy">GoDaddy</option>
                    <option value="custom">自定义API</option>
                </select>
            </div>
            <div class="mb-3">
                <label for="editProviderAPIKey" class="form-label">API Key <span class="text-danger">*</span></label>
                <input type="password" class="form-control" id="editProviderAPIKey" required>
            </div>
            <div class="mb-3">
                <label for="editProviderAPISecret" class="form-label">API Secret</label>
                <input type="password" class="form-control" id="editProviderAPISecret">
            </div>
        </div>
        <div class="col-md-6">
            <div class="mb-3">
                <label for="editProviderZoneID" class="form-label">Zone ID</label>
                <input type="text" class="form-control" id="editProviderZoneID">
            </div>
            <div class="mb-3">
                <label for="editProviderEndpoint" class="form-label">API端点</label>
                <input type="url" class="form-control" id="editProviderEndpoint">
            </div>
            <div class="mb-3">
                <label for="editProviderPriority" class="form-label">优先级</label>
                <input type="number" class="form-control" id="editProviderPriority" min="1" max="100">
            </div>
            <div class="mb-3">
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="editProviderEnabled">
                    <label class="form-check-label" for="editProviderEnabled">
                        启用提供商
                    </label>
                </div>
            </div>
        </div>
    </div>
</form>
`
}

// generateDNSConfigHTML 生成DNS配置页面HTML
func (s *Server) generateDNSConfigHTML(data map[string]interface{}) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS配置 - SSLcat</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link href="/static/css/bootstrap-icons.css" rel="stylesheet">
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">DNS配置</h1>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h5 class="mb-0">DNS验证配置</h5>
                    </div>
                    <div class="card-body">
                        <form id="dnsConfigForm">
                            <div class="mb-3">
                                <label for="defaultDNSProvider" class="form-label">默认DNS提供商</label>
                                <select class="form-select" id="defaultDNSProvider">
                                    <option value="">请选择</option>
                                </select>
                            </div>
                            <div class="mb-3">
                                <label for="challengeMethods" class="form-label">支持的验证方式</label>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="http01" value="http-01" checked>
                                    <label class="form-check-label" for="http01">
                                        HTTP-01 (推荐)
                                    </label>
                                </div>
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="dns01" value="dns-01">
                                    <label class="form-check-label" for="dns01">
                                        DNS-01 (需要DNS提供商支持)
                                    </label>
                                </div>
                            </div>
                            <button type="button" class="btn btn-primary" onclick="saveDNSConfig()">保存配置</button>
                        </form>
                    </div>
                </div>
            </main>
        </div>
    </div>
    
    <script src="/static/js/bootstrap.bundle.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function() {
        loadDNSProviders();
        loadDNSConfig();
    });

    function loadDNSProviders() {
        fetch('%s/api/dns/providers')
            .then(response => response.json())
            .then(data => {
                const select = document.getElementById('defaultDNSProvider');
                select.innerHTML = '<option value="">请选择</option>';
                
                if (data.success && data.data) {
                    data.data.forEach(provider => {
                        if (provider.enabled) {
                            const option = document.createElement('option');
                            option.value = provider.name;
                            option.textContent = provider.name + ' (' + provider.type + ')';
                            select.appendChild(option);
                        }
                    });
                }
            });
    }

    function loadDNSConfig() {
        fetch('%s/api/dns/config')
            .then(response => response.json())
            .then(data => {
                if (data.success && data.data) {
                    const config = data.data;
                    document.getElementById('defaultDNSProvider').value = config.default_dns_provider || '';
                    
                    // 设置验证方式
                    const methods = config.challenge_methods || ['http-01'];
                    document.getElementById('http01').checked = methods.includes('http-01');
                    document.getElementById('dns01').checked = methods.includes('dns-01');
                }
            });
    }

    function saveDNSConfig() {
        const challengeMethods = [];
        if (document.getElementById('http01').checked) {
            challengeMethods.push('http-01');
        }
        if (document.getElementById('dns01').checked) {
            challengeMethods.push('dns-01');
        }

        const config = {
            default_dns_provider: document.getElementById('defaultDNSProvider').value,
            challenge_methods: challengeMethods
        };

        fetch('%s/api/dns/config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(config)
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showAlert('success', 'DNS配置保存成功');
            } else {
                showAlert('danger', '保存失败: ' + (data.message || '未知错误'));
            }
        })
        .catch(error => {
            showAlert('danger', '保存失败: ' + error.message);
        });
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
		s.generateSidebar(data["AdminPrefix"].(string), "dns"),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string))
}

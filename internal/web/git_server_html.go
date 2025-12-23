package web

import (
	"fmt"
)

// generateGitServerManagementHTML 生成Git Deploy Server管理页面HTML
func (s *Server) generateGitServerManagementHTML(data map[string]interface{}) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s - SSLcat</title>
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        .deploy-progress {
            height: 8px;
        }
        .deploy-logs {
            max-height: 300px;
            overflow-y: auto;
            font-family: monospace;
            font-size: 0.875rem;
        }
        .status-badge {
            font-size: 0.75rem;
        }
        .app-card {
            transition: transform 0.2s;
        }
        .app-card:hover {
            transform: translateY(-2px);
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-md-2">%s</div>
            <main class="col-md-10">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">%s</h1>
                    <div>
                        <span class="badge %s me-2">%s</span>
                        <a href="%s/git-server/create-app" class="btn btn-primary">
                            <i class="bi bi-plus-circle"></i> 创建应用
                        </a>
                        <a href="%s/git-server/server-config" class="btn btn-outline-secondary">
                            <i class="bi bi-gear"></i> 服务器配置
                        </a>
                    </div>
                </div>
                
                <!-- 说明卡片 -->
                <div class="card mb-4">
                    <div class="card-header">
                        <h5 class="mb-0">%s</h5>
                    </div>
                    <div class="card-body">
                        <p>%s</p>
                        <div class="row">
                            <div class="col-md-6">
                                <ul>
                                    <li>Git 推送自动部署</li>
                                    <li>多语言项目支持（Node.js、Python、Go、PHP、Docker等）</li>
                                    <li>自动构建和部署</li>
                                    <li>环境变量管理</li>
                                </ul>
                            </div>
                            <div class="col-md-6">
                                <ul>
                                    <li>自动域名分配</li>
                                    <li>SSL证书自动申请</li>
                                    <li>端口自动分配</li>
                                    <li>部署历史和日志</li>
                                </ul>
                            </div>
                        </div>
                        <div class="alert alert-info mt-3">
                            <h6><i class="bi bi-info-circle"></i> 使用方法</h6>
                            <p class="mb-0">1. 创建应用 → 2. 添加 Git 远程仓库 → 3. 推送代码 → 4. 自动部署</p>
                            <code>git remote add sslcat git@your-server.com:app-name.git</code><br>
                            <code>git push sslcat main</code>
                        </div>
                    </div>
                </div>

                <!-- 应用列表 -->
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h5 class="mb-0">应用列表</h5>
                        <button class="btn btn-sm btn-outline-secondary" onclick="refreshApps()">
                            <i class="bi bi-arrow-clockwise"></i> 刷新
                        </button>
                    </div>
                    <div class="card-body">
                        <div id="apps-container">
                            <div class="text-center text-muted">加载中...</div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>

    <!-- 创建应用模态框 -->
    <div class="modal fade" id="createAppModal" tabindex="-1">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">创建新应用</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="createAppForm">
                        <div class="mb-3">
                            <label for="appName" class="form-label">应用名称</label>
                            <input type="text" class="form-control" id="appName" placeholder="my-app" required>
                            <div class="form-text">应用名称将用于生成域名和 Git 仓库路径</div>
                        </div>
                        <div class="mb-3">
                            <label for="appDisplayName" class="form-label">显示名称</label>
                            <input type="text" class="form-control" id="appDisplayName" placeholder="我的应用">
                            <div class="form-text">可选，用于显示的应用名称</div>
                        </div>
                        <div class="mb-3">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" id="autoSSL" checked>
                                <label class="form-check-label" for="autoSSL">
                                    自动申请 SSL 证书
                                </label>
                            </div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-primary" onclick="createApp()">创建应用</button>
                </div>
            </div>
        </div>
    </div>

    <!-- 服务器配置模态框 -->
    <div class="modal fade" id="serverConfigModal" tabindex="-1">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">服务器配置</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="serverConfigForm">
                        <div class="row">
                            <div class="col-md-6">
                                <h6>基本配置</h6>
                                <div class="mb-3">
                                    <label for="domainSuffix" class="form-label">主域名后缀</label>
                                    <input type="text" class="form-control" id="domainSuffix" placeholder="your-domain.com">
                                    <div class="form-text">应用将分配到此域名的子域名</div>
                                </div>
                                <div class="mb-3">
                                    <label for="portRange" class="form-label">端口范围</label>
                                    <div class="row">
                                        <div class="col-6">
                                            <input type="number" class="form-control" id="portRangeStart" placeholder="8000">
                                        </div>
                                        <div class="col-6">
                                            <input type="number" class="form-control" id="portRangeEnd" placeholder="9000">
                                        </div>
                                    </div>
                                </div>
                                <div class="mb-3">
                                    <label for="welcomeMessage" class="form-label">Git 推送欢迎语</label>
                                    <textarea class="form-control" id="welcomeMessage" rows="3" placeholder="欢迎使用 SSLcat Git 部署平台！"></textarea>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <h6>SSL 配置</h6>
                                <div class="mb-3">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="autoSSLConfig">
                                        <label class="form-check-label" for="autoSSLConfig">
                                            自动申请 SSL 证书
                                        </label>
                                    </div>
                                </div>
                                <div class="mb-3">
                                    <label for="sslEmail" class="form-label">SSL 证书邮箱</label>
                                    <input type="email" class="form-control" id="sslEmail" placeholder="admin@example.com">
                                </div>
                                <div class="mb-3">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="autoDomain">
                                        <label class="form-check-label" for="autoDomain">
                                            自动分配域名
                                        </label>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-primary" onclick="saveServerConfig()">保存配置</button>
                </div>
            </div>
        </div>
    </div>

    <!-- 配置部署模态框 -->
    <div class="modal fade" id="configDeployModal" tabindex="-1">
        <div class="modal-dialog modal-xl">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">配置部署</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <form id="configDeployForm">
                        <input type="hidden" id="configRepoId">
                        
                        <div class="row">
                            <div class="col-md-6">
                                <h6>基本配置</h6>
                                <div class="mb-3">
                                    <label for="deployStrategy" class="form-label">部署策略</label>
                                    <select class="form-select" id="deployStrategy" onchange="updateDeployConfig()">
                                        <option value="local">本地部署</option>
                                        <option value="docker">Docker部署</option>
                                        <option value="static">静态文件部署</option>
                                        <option value="php">PHP部署</option>
                                    </select>
                                </div>
                                <div class="mb-3">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="autoDeployConfig">
                                        <label class="form-check-label" for="autoDeployConfig">
                                            启用自动部署
                                        </label>
                                    </div>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <h6>目标配置</h6>
                                <div class="mb-3" id="targetPathGroup">
                                    <label for="targetPath" class="form-label">部署路径</label>
                                    <input type="text" class="form-control" id="targetPath" placeholder="/var/www/html">
                                </div>
                                <div class="mb-3" id="targetPortGroup" style="display:none;">
                                    <label for="targetPort" class="form-label">端口</label>
                                    <input type="number" class="form-control" id="targetPort" value="8080">
                                </div>
                                <div class="mb-3" id="dockerConfigGroup" style="display:none;">
                                    <label for="imageName" class="form-label">镜像名称</label>
                                    <input type="text" class="form-control" id="imageName" placeholder="my-app">
                                    <label for="containerName" class="form-label mt-2">容器名称</label>
                                    <input type="text" class="form-control" id="containerName" placeholder="my-app-container">
                                </div>
                            </div>
                        </div>

                        <div class="row">
                            <div class="col-md-6">
                                <h6>构建配置</h6>
                                <div class="mb-3">
                                    <label for="buildCommands" class="form-label">构建命令（每行一个）</label>
                                    <textarea class="form-control" id="buildCommands" rows="3" placeholder="npm install&#10;npm run build"></textarea>
                                </div>
                                <div class="mb-3">
                                    <label for="buildWorkDir" class="form-label">构建工作目录</label>
                                    <input type="text" class="form-control" id="buildWorkDir" placeholder="./">
                                </div>
                            </div>
                            <div class="col-md-6">
                                <h6>域名和SSL</h6>
                                <div class="mb-3">
                                    <label for="deployDomains" class="form-label">域名（每行一个）</label>
                                    <textarea class="form-control" id="deployDomains" rows="2" placeholder="app.example.com"></textarea>
                                </div>
                                <div class="mb-3">
                                    <div class="form-check">
                                        <input class="form-check-input" type="checkbox" id="autoSSL">
                                        <label class="form-check-label" for="autoSSL">
                                            自动申请SSL证书
                                        </label>
                                    </div>
                                </div>
                                <div class="mb-3">
                                    <label for="sslEmail" class="form-label">SSL证书邮箱</label>
                                    <input type="email" class="form-control" id="sslEmail">
                                </div>
                            </div>
                        </div>
                    </form>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                    <button type="button" class="btn btn-primary" onclick="saveDeployConfig()">保存配置</button>
                </div>
            </div>
        </div>
    </div>

    <!-- 部署状态模态框 -->
    <div class="modal fade" id="deployStatusModal" tabindex="-1">
        <div class="modal-dialog modal-lg">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">部署状态</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                    <div id="deployStatusContent">
                        <div class="text-center">
                            <div class="spinner-border" role="status">
                                <span class="visually-hidden">加载中...</span>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                    <button type="button" class="btn btn-primary" onclick="refreshDeployStatus()">刷新</button>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdnproxy.some.im/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    let currentAppName = null;
    let deployStatusInterval = null;

    // 页面加载完成后初始化
    document.addEventListener('DOMContentLoaded', function() {
        loadApps();
        loadServerConfig();
    });

    // 加载应用列表
    function loadApps() {
        fetch('%s/api/git-server/apps')
            .then(r => r.json())
            .then(data => {
                const container = document.getElementById('apps-container');
                const apps = (data && data.data) || [];
                
                if (apps.length === 0) {
                    container.innerHTML = '<div class="text-center text-muted py-4">暂无应用</div>';
                    return;
                }
                
                container.innerHTML = '';
                apps.forEach(app => {
                    const appCard = createAppCard(app);
                    container.appendChild(appCard);
                });
            })
            .catch(() => {
                document.getElementById('apps-container').innerHTML = '<div class="text-center text-muted py-4">加载失败</div>';
            });
    }

    // 创建应用卡片
    function createAppCard(app) {
        const card = document.createElement('div');
        card.className = 'col-md-6 col-lg-4 mb-3';
        
        const statusBadge = getAppStatusBadge(app.status);
        const appTypeBadge = getAppTypeBadge(app.app_type);
        
        card.innerHTML = '<div class="card app-card h-100">' +
            '<div class="card-header d-flex justify-content-between align-items-center">' +
                '<h6 class="mb-0">' + (app.display_name || app.name) + '</h6>' +
                statusBadge +
            '</div>' +
            '<div class="card-body">' +
                '<div class="mb-2">' +
                    '<small class="text-muted">应用类型:</small> ' + appTypeBadge +
                '</div>' +
                '<div class="mb-2">' +
                    '<small class="text-muted">域名:</small> ' +
                    '<code>' + (app.domain || '未分配') + '</code>' +
                '</div>' +
                '<div class="mb-2">' +
                    '<small class="text-muted">端口:</small> ' +
                    '<span class="badge bg-secondary">' + (app.port || '未分配') + '</span>' +
                '</div>' +
                '<div class="mb-2">' +
                    '<small class="text-muted">Git 仓库:</small><br>' +
                    '<code>git@your-server.com:' + app.name + '.git</code>' +
                '</div>' +
                '<div class="mb-2">' +
                    '<small class="text-muted">最后部署:</small><br>' +
                    '<small>' + formatDate(app.last_deploy) + '</small>' +
                '</div>' +
            '</div>' +
            '<div class="card-footer">' +
                '<div class="btn-group btn-group-sm w-100">' +
                    '<button class="btn btn-outline-primary" onclick="viewApp(\'' + app.name + '\')" title="查看详情">' +
                        '<i class="bi bi-eye"></i>' +
                    '</button>' +
                    '<button class="btn btn-outline-success" onclick="showDeployStatus(\'' + app.name + '\')" title="部署状态">' +
                        '<i class="bi bi-graph-up"></i>' +
                    '</button>' +
                    '<button class="btn btn-outline-info" onclick="showAppLogs(\'' + app.name + '\')" title="查看日志">' +
                        '<i class="bi bi-file-text"></i>' +
                    '</button>' +
                    '<button class="btn btn-outline-danger" onclick="deleteApp(\'' + app.name + '\')" title="删除应用">' +
                        '<i class="bi bi-trash"></i>' +
                    '</button>' +
                '</div>' +
            '</div>' +
        '</div>';
        
        return card;
    }

    function refreshApps() {
        loadApps();
    }

    function getAppStatusBadge(status) {
        const badges = {
            'idle': '<span class="badge bg-secondary status-badge">空闲</span>',
            'building': '<span class="badge bg-warning status-badge">构建中</span>',
            'deploying': '<span class="badge bg-info status-badge">部署中</span>',
            'running': '<span class="badge bg-success status-badge">运行中</span>',
            'failed': '<span class="badge bg-danger status-badge">失败</span>'
        };
        return badges[status] || '<span class="badge bg-secondary status-badge">未知</span>';
    }

    function getAppTypeBadge(appType) {
        const badges = {
            'nodejs': '<span class="badge bg-success">Node.js</span>',
            'python': '<span class="badge bg-primary">Python</span>',
            'go': '<span class="badge bg-info">Go</span>',
            'php': '<span class="badge bg-warning">PHP</span>',
            'docker': '<span class="badge bg-dark">Docker</span>',
            'static': '<span class="badge bg-secondary">静态</span>'
        };
        return badges[appType] || '<span class="badge bg-secondary">未知</span>';
    }

    function formatDate(dateStr) {
        if (!dateStr) return '未知';
        try {
            return new Date(dateStr).toLocaleString();
        } catch (e) {
            return dateStr;
        }
    }

    function showCreateAppModal() {
        const modal = new bootstrap.Modal(document.getElementById('createAppModal'));
        modal.show();
    }

    function createApp() {
        const appData = {
            name: document.getElementById('appName').value,
            display_name: document.getElementById('appDisplayName').value || document.getElementById('appName').value,
            auto_ssl: document.getElementById('autoSSL').checked
        };

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
                bootstrap.Modal.getInstance(document.getElementById('createAppModal')).hide();
                document.getElementById('createAppForm').reset();
                loadApps();
                showAlert('success', '应用创建成功');
            } else {
                showAlert('danger', '创建失败: ' + (data.message || '未知错误'));
            }
        })
        .catch(error => {
            showAlert('danger', '创建失败: ' + error.message);
        });
    }

    function showServerConfigModal() {
        const modal = new bootstrap.Modal(document.getElementById('serverConfigModal'));
        modal.show();
    }

    function loadServerConfig() {
        fetch('%s/api/git-server/config')
            .then(r => r.json())
            .then(data => {
                if (data.success && data.data) {
                    const config = data.data;
                    document.getElementById('domainSuffix').value = config.domain_suffix || '';
                    document.getElementById('portRangeStart').value = config.port_range[0] || '';
                    document.getElementById('portRangeEnd').value = config.port_range[1] || '';
                    document.getElementById('welcomeMessage').value = config.welcome_message || '';
                    document.getElementById('autoSSLConfig').checked = config.auto_ssl || false;
                    document.getElementById('sslEmail').value = config.ssl_email || '';
                    document.getElementById('autoDomain').checked = config.auto_domain || false;
                }
            });
    }

    function saveServerConfig() {
        const config = {
            domain_suffix: document.getElementById('domainSuffix').value,
            port_range: [
                parseInt(document.getElementById('portRangeStart').value) || 8000,
                parseInt(document.getElementById('portRangeEnd').value) || 9000
            ],
            welcome_message: document.getElementById('welcomeMessage').value,
            auto_ssl: document.getElementById('autoSSLConfig').checked,
            ssl_email: document.getElementById('sslEmail').value,
            auto_domain: document.getElementById('autoDomain').checked
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
                bootstrap.Modal.getInstance(document.getElementById('serverConfigModal')).hide();
                showAlert('success', '服务器配置已保存');
            } else {
                showAlert('danger', '保存失败: ' + (data.message || '未知错误'));
            }
        })
        .catch(error => {
            showAlert('danger', '保存失败: ' + error.message);
        });
    }

    function viewApp(appName) {
        // TODO: 实现应用详情查看
        showAlert('info', '应用详情功能正在开发中');
    }

    function showDeployStatus(appName) {
        currentAppName = appName;
        // TODO: 实现部署状态查看
        showAlert('info', '部署状态功能正在开发中');
    }

    function showAppLogs(appName) {
        // TODO: 实现应用日志查看
        showAlert('info', '应用日志功能正在开发中');
    }

    function deleteApp(appName) {
        if (confirm('确定要删除应用 "' + appName + '" 吗？此操作不可恢复！')) {
            fetch('%s/api/git-server/app/delete?name=' + appName, {method: 'POST'})
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showAlert('success', '应用已删除');
                        loadApps();
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
        
        // 插入到页面顶部
        const container = document.querySelector('.container-fluid');
        container.insertBefore(alertDiv, container.firstChild);
        
        // 3秒后自动消失
        setTimeout(() => {
            if (alertDiv.parentNode) {
                alertDiv.remove();
            }
        }, 3000);
    }
    </script>
</body>
</html>`,
		data["Title"].(string),
		s.generateSidebar(data["AdminPrefix"].(string), "git-server"),
		map[bool]string{true: "bg-success", false: "bg-secondary"}[data["GitEnabled"].(bool)],
		map[bool]string{true: "已启用", false: "已禁用"}[data["GitEnabled"].(bool)],
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		data["FunctionDescription"].(string),
		data["Description"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string),
		data["AdminPrefix"].(string))
}

package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/mcp"
	mcptools "github.com/xurenlu/sslcat/internal/mcp/tools"
)

// setupMCPRoutes 当配置启用 MCP 时，挂载 Streamable HTTP transport 到 admin mux。
// 路径形如：/sslcat-panel/mcp/stream
//
// 关闭或未配置时是 no-op。挂上的 handler 自己处理 Bearer 鉴权与会话。
func (s *Server) setupMCPRoutes() {
	if s.config == nil || !s.config.IsMCPEnabled() {
		s.log.Info("MCP service disabled (config.mcp.enabled=false)")
		return
	}

	// 1. 构造审计器
	var auditor *mcp.Auditor
	if s.config.MCP.Audit.Enabled {
		a, err := mcp.NewAuditor(s.config.GetMCPAuditFile())
		if err != nil {
			s.log.WithError(err).Warn("init MCP auditor failed; auditing disabled")
		} else {
			auditor = a
		}
	}

	// 2. 注册中心 + tool
	registry := mcp.NewRegistry()
	taskReg := mcp.NewTaskRegistry()
	deps := &mcptools.Deps{
		Version:    s.version,
		Config:     s.config,
		ConfigFile: s.config.ConfigFile,
		SSL:        s.sslManager,
		Proxy:      s.proxyManager,
		Tasks:      taskReg,
		// 写类 tool 需通过这里持久化（行为与 api_proxy.go 一致）
		SaveConfig: func() error {
			return s.config.Save(s.config.ConfigFile)
		},
		// 新增/启用站点时异步预取证书（与 api_proxy.go 行为一致）
		EnsureCert: func(domain string) {
			if s.sslManager == nil {
				return
			}
			go func(d string) {
				if err := s.sslManager.EnsureDomainCert(d); err != nil {
					s.log.Warnf("MCP: failed to prefetch certificate for %s: %v", d, err)
				}
			}(domain)
		},
	}
	if err := mcptools.RegisterReadOnly(registry, deps); err != nil {
		s.log.WithError(err).Error("register MCP read-only tools failed; MCP service NOT mounted")
		return
	}
	if err := mcptools.RegisterSiteWriters(registry, deps); err != nil {
		s.log.WithError(err).Error("register MCP site writer tools failed; MCP service NOT mounted")
		return
	}
	if err := mcptools.RegisterCertWriters(registry, deps); err != nil {
		s.log.WithError(err).Error("register MCP cert writer tools failed; MCP service NOT mounted")
		return
	}
	if err := mcptools.RegisterTaskReaders(registry, deps); err != nil {
		s.log.WithError(err).Error("register MCP task reader tools failed; MCP service NOT mounted")
		return
	}

	// 3. 协议核心 + 二次确认 + Prometheus 指标
	srv := mcp.NewServer(mcp.ServerInfo{
		Name:    "sslcat",
		Version: strings.TrimPrefix(s.version, "v"),
	}, registry, auditor)
	srv.Confirm = mcp.NewConfirmGate(60 * time.Second)
	srv.Metrics = mcp.NewPromMetrics()

	// 4. 鉴权
	auth := mcp.NewAuthenticator(&s.config.MCP)
	if len(s.config.MCP.Tokens) == 0 {
		s.log.Warn("MCP enabled but no tokens configured; all requests will be rejected. " +
			"Run: sslcat mcp token create --name <name> --scopes read,site:write,...")
	}

	// 5. 挂载 handler
	prefix := s.config.AdminPrefix + s.config.GetMCPPathPrefix()
	// Streamable HTTP 单端点；同时挂带 / 与不带 / 两个路径，避免 mux 行为差异
	handler := mcp.NewStreamableHTTPHandler(srv, auth, mcp.HTTPHandlerOptions{})
	streamPath := prefix + "/stream"

	// http.ServeMux 区分尾斜杠；这里挂精确路径，AI 客户端按 docs 写死即可
	s.mux.Handle(streamPath, withMCPRequestLog(s, "stream", handler))

	// 健康检查（便于 ops 排查）：GET /sslcat-panel/mcp/health
	s.mux.HandleFunc(prefix+"/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-MCP-Protocol-Version", mcp.ProtocolVersion)
		_, _ = w.Write([]byte(`{"status":"ok","protocol":"` + mcp.ProtocolVersion + `"}`))
	})

	s.log.Infof("MCP service mounted at %s (stream=%s)", prefix, streamPath)
}

// withMCPRequestLog 简单访问日志：只记录路径、方法、状态、远端地址。
// 业务级审计走 mcp.Auditor，这里仅用于运维侧排查 transport 问题。
func withMCPRequestLog(s *Server, label string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.log.Debugf("mcp[%s] %s %s from %s", label, r.Method, r.URL.Path, r.RemoteAddr)
		h.ServeHTTP(w, r)
	})
}

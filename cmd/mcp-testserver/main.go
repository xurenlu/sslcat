// mcp-testserver 是 sslcat MCP 服务的最小化集成测试 stub。
// 仅供 tests/mcp_e2e.rb 调用，不应在生产中启动。
//
// 它把 MCP 协议核心（internal/mcp） + 站点 / 证书（无 ACME） / 转发 / Resources
// 全部挂到一个 bare http.Server 上，省掉 sslcat 主进程的登录、TLS、首次设置等流程。
//
// 用法：
//
//	go run ./cmd/mcp-testserver -addr=:18000 -data=./reports/mcp-e2e-data
//
// 端点：
//
//	GET  /health                          → ok
//	POST /admin/token                     → 一次性创建 token，返回明文（仅测试用）
//	POST /mcp/stream  (MCP Streamable HTTP)
//	GET  /mcp/stream/health
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/mcp"
	mcpresources "github.com/xurenlu/sslcat/internal/mcp/resources"
	mcptools "github.com/xurenlu/sslcat/internal/mcp/tools"
)

func main() {
	addr := flag.String("addr", ":18000", "listen addr")
	dataDir := flag.String("data", "./reports/mcp-e2e-data", "data dir for cert/key/access.log")
	flag.Parse()

	if err := os.MkdirAll(*dataDir, 0755); err != nil {
		log.Fatalf("mkdir data: %v", err)
	}
	certDir := *dataDir + "/certs"
	keyDir := *dataDir + "/keys"
	accessLog := *dataDir + "/access.log"
	errorLog := *dataDir + "/error.log"
	_ = os.MkdirAll(certDir, 0755)
	_ = os.MkdirAll(keyDir, 0700)
	if _, err := os.Stat(accessLog); err != nil {
		_ = os.WriteFile(accessLog, []byte{}, 0644)
	}
	if _, err := os.Stat(errorLog); err != nil {
		line := time.Now().Add(-5*time.Minute).Format(time.RFC3339) + " ERROR internal startup check failed component=mcp-testserver domain=ruby.example.com\n"
		_ = os.WriteFile(errorLog, []byte(line), 0644)
	}

	cfg := &config.Config{
		AdminPrefix: "/sslcat-panel",
		Server: config.ServerConfig{
			Host:            "127.0.0.1",
			Port:            8443, // 必须 1..65535，否则 cfg.Save 内 validate 会拒绝
			PortMode:        "standard",
			CustomPort:      8080,
			EnableHTTPS:     true,
			LogLevel:        "info",
			DataDir:         *dataDir,
			AccessLogPath:   accessLog,
			ErrorLogEnabled: true,
			ErrorLogPath:    errorLog,
		},
		SSL: config.SSLConfig{
			Email:            "test@example.com",
			CertDir:          certDir,
			KeyDir:           keyDir,
			ChallengeMethods: []string{"http-01"},
		},
		Admin: config.AdminConfig{
			Username: "admin",
			Password: "test-only-not-used",
		},
		Proxy:   config.ProxyConfig{Rules: []config.ProxyRule{}, UnmatchedBehavior: "503"},
		Cluster: config.ClusterConfig{Mode: "standalone", NodeID: "test-node", NodeName: "test"},
		MCP: config.MCPConfig{
			Enabled:    true,
			PathPrefix: "/mcp",
			Audit:      config.MCPAuditConfig{Enabled: true, File: *dataDir + "/mcp_audit.log"},
		},
	}
	cfg.ConfigFile = *dataDir + "/sslcat.conf"

	auditor, err := mcp.NewAuditor(cfg.GetMCPAuditFile())
	if err != nil {
		log.Fatalf("auditor: %v", err)
	}

	registry := mcp.NewRegistry()
	taskReg := mcp.NewTaskRegistry()
	deps := &mcptools.Deps{
		Version:    "test",
		Config:     cfg,
		ConfigFile: cfg.ConfigFile,
		SSL:        nil, // 不挂真实 ssl manager；cert_issue/renew 会被显式 short-circuit
		Proxy:      nil,
		Tasks:      taskReg,
		SaveConfig: func() error { return cfg.Save(cfg.ConfigFile) },
	}
	if err := mcptools.RegisterReadOnly(registry, deps); err != nil {
		log.Fatalf("register read-only: %v", err)
	}
	if err := mcptools.RegisterSiteWriters(registry, deps); err != nil {
		log.Fatalf("register site: %v", err)
	}
	if err := mcptools.RegisterCertWriters(registry, deps); err != nil {
		log.Fatalf("register cert: %v", err)
	}
	if err := mcptools.RegisterTaskReaders(registry, deps); err != nil {
		log.Fatalf("register task: %v", err)
	}
	if err := mcptools.RegisterProxyTools(registry, deps); err != nil {
		log.Fatalf("register proxy: %v", err)
	}

	resReg := mcp.NewResourceRegistry()
	if err := mcpresources.Register(resReg, &mcpresources.Deps{
		Version:    "test",
		Config:     cfg,
		ConfigFile: cfg.ConfigFile,
		Tasks:      taskReg,
	}); err != nil {
		log.Fatalf("register resources: %v", err)
	}

	srv := mcp.NewServer(mcp.ServerInfo{Name: "sslcat-test", Version: "0.0.0-test"}, registry, auditor)
	srv.Confirm = mcp.NewConfirmGate(60 * time.Second)
	srv.Resources = resReg

	authPool := &tokenPool{cfg: &cfg.MCP}
	streamHandler := mcp.NewStreamableHTTPHandler(srv, authPool.authenticator(), mcp.HTTPHandlerOptions{})

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/mcp/stream/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-MCP-Protocol-Version", mcp.ProtocolVersion)
		_, _ = w.Write([]byte(`{"status":"ok","protocol":"` + mcp.ProtocolVersion + `"}`))
	})
	mux.Handle("/mcp/stream", streamHandler)
	// 一次性创建 token 用于测试。生产中绝不要暴露此端点。
	mux.HandleFunc("/admin/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Name   string   `json:"name"`
			Scopes []string `json:"scopes"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Name == "" {
			req.Name = "ut-" + randHex(4)
		}
		if len(req.Scopes) == 0 {
			req.Scopes = []string{"admin"}
		}
		plain, err := mcp.GenerateToken()
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		hash, err := mcp.HashToken(plain)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		cfg.MCP.Tokens = append(cfg.MCP.Tokens, config.MCPToken{
			Name:      req.Name,
			TokenHash: hash,
			Scopes:    req.Scopes,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		})
		// 不写配置文件，全在内存（保持 testserver 短暂）
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"name":   req.Name,
			"token":  plain,
			"scopes": req.Scopes,
		})
	})

	fmt.Fprintf(os.Stderr, "mcp-testserver listening on %s (data=%s)\n", *addr, *dataDir)
	log.Fatal(http.ListenAndServe(*addr, withCORS(mux)))
}

type tokenPool struct{ cfg *config.MCPConfig }

func (p *tokenPool) authenticator() *mcp.Authenticator {
	return mcp.NewAuthenticator(p.cfg)
}

func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Session-Id")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return strings.ToLower(hex.EncodeToString(b))
}

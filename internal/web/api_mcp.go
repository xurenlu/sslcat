package web

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/mcp"
)

// 这一组 API 走现有 admin session 鉴权（authorizeAPI），不是 MCP Bearer。
// 前端 React 页面通过 fetch + credentials:'include' 调用。
//
// 路由（在 setupRoutes 末尾注册）：
//   GET    ${admin_prefix}/api/mcp/status
//   GET    ${admin_prefix}/api/mcp/tokens
//   POST   ${admin_prefix}/api/mcp/tokens
//   DELETE ${admin_prefix}/api/mcp/tokens?name=<name>
//   GET    ${admin_prefix}/api/mcp/audit?tail=N&date=YYYYMMDD
//   POST   ${admin_prefix}/api/mcp/enable
//   POST   ${admin_prefix}/api/mcp/disable

// setupMCPManagementRoutes 注册以上 admin API（由 setupRoutes 调用）。
func (s *Server) setupMCPManagementRoutes() {
	prefix := s.config.AdminPrefix + "/api/mcp"
	s.mux.HandleFunc(prefix+"/status", s.handleMCPMgmtStatus)
	s.mux.HandleFunc(prefix+"/tokens", s.handleMCPMgmtTokens)
	s.mux.HandleFunc(prefix+"/audit", s.handleMCPMgmtAudit)
	s.mux.HandleFunc(prefix+"/enable", s.handleMCPMgmtToggle(true))
	s.mux.HandleFunc(prefix+"/disable", s.handleMCPMgmtToggle(false))
}

// mcpTokenPublic 给前端的安全形态：不含 token_hash。
type mcpTokenPublic struct {
	Name        string   `json:"name"`
	Scopes      []string `json:"scopes"`
	IPAllowlist []string `json:"ip_allowlist,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	RateLimit   string   `json:"rate_limit,omitempty"`
	CreatedAt   string   `json:"created_at,omitempty"`
	Description string   `json:"description,omitempty"`
}

func publicToken(t *config.MCPToken) mcpTokenPublic {
	return mcpTokenPublic{
		Name:        t.Name,
		Scopes:      t.Scopes,
		IPAllowlist: t.IPAllowlist,
		ExpiresAt:   t.ExpiresAt,
		RateLimit:   t.RateLimit,
		CreatedAt:   t.CreatedAt,
		Description: t.Description,
	}
}

// ---------- GET /status ----------

func (s *Server) handleMCPMgmtStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	out := map[string]any{
		"enabled":           s.config.MCP.Enabled,
		"path_prefix":       s.config.GetMCPPathPrefix(),
		"stream_url_path":   s.config.AdminPrefix + s.config.GetMCPPathPrefix() + "/stream",
		"health_url_path":   s.config.AdminPrefix + s.config.GetMCPPathPrefix() + "/health",
		"token_count":       len(s.config.MCP.Tokens),
		"audit_enabled":     s.config.MCP.Audit.Enabled,
		"audit_file":        s.config.GetMCPAuditFile(),
		"protocol_version":  mcp.ProtocolVersion,
	}
	writeJSONStatus(w,http.StatusOK, out)
}

// ---------- /tokens : GET 列出, POST 创建, DELETE 删除 ----------

func (s *Server) handleMCPMgmtTokens(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !s.authorizeAPI(w, r, true) {
			return
		}
		out := make([]mcpTokenPublic, 0, len(s.config.MCP.Tokens))
		for i := range s.config.MCP.Tokens {
			out = append(out, publicToken(&s.config.MCP.Tokens[i]))
		}
		writeJSONStatus(w,http.StatusOK, map[string]any{
			"tokens": out,
			"total":  len(out),
		})
	case http.MethodPost:
		if !s.authorizeAPI(w, r, false) {
			return
		}
		s.handleMCPMgmtTokensCreate(w, r)
	case http.MethodDelete:
		if !s.authorizeAPI(w, r, false) {
			return
		}
		s.handleMCPMgmtTokensDelete(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type mcpTokenCreateReq struct {
	Name        string   `json:"name"`
	Scopes      []string `json:"scopes"`
	IPAllowlist []string `json:"ip_allowlist,omitempty"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	RateLimit   string   `json:"rate_limit,omitempty"`
	Description string   `json:"description,omitempty"`
}

func (s *Server) handleMCPMgmtTokensCreate(w http.ResponseWriter, r *http.Request) {
	var req mcpTokenCreateReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONStatus(w,http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeJSONStatus(w,http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	// 重名检查
	for _, t := range s.config.MCP.Tokens {
		if t.Name == req.Name {
			writeJSONStatus(w,http.StatusConflict, map[string]string{"error": "token name already exists"})
			return
		}
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{"read"}
	}
	if err := validateMCPScopes(req.Scopes); err != nil {
		writeJSONStatus(w,http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.ExpiresAt != "" {
		if _, err := time.Parse(time.RFC3339, req.ExpiresAt); err != nil {
			writeJSONStatus(w,http.StatusBadRequest, map[string]string{"error": "expires_at must be RFC3339"})
			return
		}
	}

	plain, err := mcp.GenerateToken()
	if err != nil {
		writeJSONStatus(w,http.StatusInternalServerError, map[string]string{"error": "generate token: " + err.Error()})
		return
	}
	hash, err := mcp.HashToken(plain)
	if err != nil {
		writeJSONStatus(w,http.StatusInternalServerError, map[string]string{"error": "hash token: " + err.Error()})
		return
	}
	entry := config.MCPToken{
		Name:        req.Name,
		TokenHash:   hash,
		Scopes:      req.Scopes,
		IPAllowlist: req.IPAllowlist,
		ExpiresAt:   req.ExpiresAt,
		RateLimit:   req.RateLimit,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		Description: req.Description,
	}
	s.config.MCP.Tokens = append(s.config.MCP.Tokens, entry)
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		s.config.MCP.Tokens = s.config.MCP.Tokens[:len(s.config.MCP.Tokens)-1]
		writeJSONStatus(w,http.StatusInternalServerError, map[string]string{"error": "save config: " + err.Error()})
		return
	}
	writeJSONStatus(w,http.StatusCreated, map[string]any{
		"ok":     true,
		"token":  plain, // 明文，仅本次返回
		"public": publicToken(&entry),
		"hint":   "请立刻保存 token；它不会再被显示。",
	})
}

func (s *Server) handleMCPMgmtTokensDelete(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeJSONStatus(w,http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	idx := -1
	for i, t := range s.config.MCP.Tokens {
		if t.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		writeJSONStatus(w,http.StatusNotFound, map[string]string{"error": "token not found"})
		return
	}
	deleted := s.config.MCP.Tokens[idx]
	s.config.MCP.Tokens = append(s.config.MCP.Tokens[:idx], s.config.MCP.Tokens[idx+1:]...)
	if err := s.config.Save(s.config.ConfigFile); err != nil {
		// 回滚
		newList := make([]config.MCPToken, 0, len(s.config.MCP.Tokens)+1)
		newList = append(newList, s.config.MCP.Tokens[:idx]...)
		newList = append(newList, deleted)
		newList = append(newList, s.config.MCP.Tokens[idx:]...)
		s.config.MCP.Tokens = newList
		writeJSONStatus(w,http.StatusInternalServerError, map[string]string{"error": "save config: " + err.Error()})
		return
	}
	writeJSONStatus(w,http.StatusOK, map[string]any{
		"ok":             true,
		"deleted_public": publicToken(&deleted),
	})
}

// ---------- GET /audit?date=YYYYMMDD&tail=N ----------

func (s *Server) handleMCPMgmtAudit(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	date := strings.TrimSpace(r.URL.Query().Get("date"))
	if date == "" {
		date = time.Now().Format("20060102")
	}
	if len(date) != 8 {
		writeJSONStatus(w,http.StatusBadRequest, map[string]string{"error": "date must be YYYYMMDD"})
		return
	}
	tail := 200
	if v := r.URL.Query().Get("tail"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			tail = n
		}
	}
	if tail > 2000 {
		tail = 2000
	}

	base := s.config.GetMCPAuditFile()
	dir := filepath.Dir(base)
	bn := filepath.Base(base)
	ext := filepath.Ext(bn)
	name := bn[:len(bn)-len(ext)]
	if ext == "" {
		ext = ".log"
	}
	path := filepath.Join(dir, fmt.Sprintf("%s.%s%s", name, date, ext))

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSONStatus(w,http.StatusOK, map[string]any{
				"date":    date,
				"path":    path,
				"exists":  false,
				"entries": []any{},
			})
			return
		}
		writeJSONStatus(w,http.StatusInternalServerError, map[string]string{"error": "open audit: " + err.Error()})
		return
	}
	defer f.Close()

	// 环形读：每行解析为 JSON 对象（audit 行就是 JSON）。
	buf := make([]map[string]any, 0, tail+8)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			obj = map[string]any{"raw": line, "parse_error": err.Error()}
		}
		buf = append(buf, obj)
		if len(buf) > tail {
			buf = buf[len(buf)-tail:]
		}
	}
	writeJSONStatus(w,http.StatusOK, map[string]any{
		"date":    date,
		"path":    path,
		"exists":  true,
		"total":   len(buf),
		"entries": buf,
	})
}

// ---------- POST /enable, /disable ----------

func (s *Server) handleMCPMgmtToggle(enable bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorizeAPI(w, r, false) {
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if s.config.MCP.Enabled == enable {
			writeJSONStatus(w,http.StatusOK, map[string]any{
				"ok":     true,
				"no_op":  true,
				"state":  enable,
			})
			return
		}
		s.config.MCP.Enabled = enable
		if err := s.config.Save(s.config.ConfigFile); err != nil {
			s.config.MCP.Enabled = !enable
			writeJSONStatus(w,http.StatusInternalServerError, map[string]string{"error": "save config: " + err.Error()})
			return
		}
		writeJSONStatus(w,http.StatusOK, map[string]any{
			"ok":             true,
			"state":          enable,
			"requires_restart": true,
			"hint":           "MCP 服务挂载在 admin server 启动时；需要重启 sslcat 主进程才生效。",
		})
	}
}

// ---------- helpers ----------

func validateMCPScopes(scopes []string) error {
	allowed := map[string]bool{
		"read":           true,
		"site:write":     true,
		"cert:write":     true,
		"proxy:write":    true,
		"security:write": true,
		"ops:write":      true,
		"admin":          true,
	}
	for _, s := range scopes {
		if !allowed[s] {
			return fmt.Errorf("invalid scope %q", s)
		}
	}
	return nil
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

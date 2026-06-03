package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// HTTPHandlerOptions 创建 HTTP transport 时的可选参数。
type HTTPHandlerOptions struct {
	MaxRequestBytes int64 // 单次请求体上限，0 = 默认 1 MiB
}

// NewStreamableHTTPHandler 把 mcp.Server 包成符合 MCP Streamable HTTP 规范的 http.Handler。
//
// 路径前缀由调用方挂载（如 /sslcat-panel/mcp/stream）。该 handler 自身不关心前缀。
// 实现要点：
//   - POST 接收 JSON-RPC 请求，返回 application/json 响应；
//   - GET 当前不支持（无服务端推送），返回 405；
//   - DELETE 用于客户端主动结束 session（按规范 200 No Content）；
//   - Authorization: Bearer <token> 必填；
//   - Mcp-Session-Id 头：initialize 后由服务端下发，后续请求带上；服务端校验存在性；
//   - 鉴权结果按 sessionId 缓存，避免每请求都走 argon2。
func NewStreamableHTTPHandler(srv *Server, auth *Authenticator, opts HTTPHandlerOptions) http.Handler {
	if opts.MaxRequestBytes <= 0 {
		opts.MaxRequestBytes = 1 << 20
	}
	h := &streamableHTTP{
		srv:      srv,
		auth:     auth,
		opts:     opts,
		sessions: make(map[string]*session),
		log:      logrus.WithField("component", "mcp-http"),
	}
	go h.gcLoop()
	return h
}

type streamableHTTP struct {
	srv  *Server
	auth *Authenticator
	opts HTTPHandlerOptions
	log  *logrus.Entry

	mu       sync.RWMutex
	sessions map[string]*session
}

type session struct {
	id        string
	tokenName string
	scopes    []Scope
	createdAt time.Time
	lastUsed  time.Time
}

func (h *streamableHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.handlePOST(w, r)
	case http.MethodGet:
		// 当前不实现服务端 push 流；用 405 明确告知客户端。
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "server-initiated stream not supported", http.StatusMethodNotAllowed)
	case http.MethodDelete:
		h.handleDELETE(w, r)
	case http.MethodOptions:
		h.writeCORS(w, r)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *streamableHTTP) handlePOST(w http.ResponseWriter, r *http.Request) {
	h.writeCORS(w, r)

	// 鉴权
	caller, sessID, err := h.authenticate(r)
	if err != nil {
		writeRPCError(w, http.StatusUnauthorized, nil, mapAuthErr(err))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, h.opts.MaxRequestBytes))
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, nil, NewError(CodeParseError, "read body: "+err.Error()))
		return
	}
	defer r.Body.Close()

	req, err := ParseRequest(body)
	if err != nil {
		writeRPCError(w, http.StatusBadRequest, nil, NewError(CodeParseError, err.Error()))
		return
	}

	// initialize 时若客户端没带 session id 则下发一个新的；
	// 其它方法则必须带有效 session id。
	if req.Method == "initialize" {
		if sessID == "" {
			sessID = uuid.NewString()
		}
		h.upsertSession(sessID, caller)
		w.Header().Set("Mcp-Session-Id", sessID)
	} else {
		if sessID == "" || !h.touchSession(sessID) {
			writeRPCError(w, http.StatusBadRequest, req.ID,
				NewError(CodeInvalidRequest, "missing or unknown Mcp-Session-Id; call initialize first"))
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	resp := h.srv.Handle(ctx, req, caller)
	if resp == nil {
		// notification, no body
		w.WriteHeader(http.StatusAccepted)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-MCP-Protocol-Version", ProtocolVersion)
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *streamableHTTP) handleDELETE(w http.ResponseWriter, r *http.Request) {
	h.writeCORS(w, r)
	sessID := r.Header.Get("Mcp-Session-Id")
	if sessID != "" {
		h.mu.Lock()
		delete(h.sessions, sessID)
		h.mu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *streamableHTTP) writeCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Session-Id")
	w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id, X-MCP-Protocol-Version")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS")
}

// authenticate 校验 Authorization 头与 Session 缓存。
// 返回 (caller, sessionId, err)。sessionId 为客户端传入的（可能为空）。
func (h *streamableHTTP) authenticate(r *http.Request) (*CallContext, string, error) {
	token := ExtractBearer(r.Header.Get("Authorization"))
	if token == "" {
		return nil, "", ErrUnauthorized
	}
	sessID := r.Header.Get("Mcp-Session-Id")
	clientIP := clientIP(r)

	// 已有会话：可直接复用缓存的 scope
	if sessID != "" {
		if s := h.getSession(sessID); s != nil {
			return &CallContext{TokenName: s.tokenName, Scopes: s.scopes, IP: clientIP}, sessID, nil
		}
	}
	res, err := h.auth.Authenticate(token, clientIP)
	if err != nil {
		return nil, sessID, err
	}
	return &CallContext{TokenName: res.TokenName, Scopes: res.Scopes, IP: clientIP}, sessID, nil
}

func (h *streamableHTTP) upsertSession(id string, caller *CallContext) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	h.sessions[id] = &session{
		id:        id,
		tokenName: caller.TokenName,
		scopes:    caller.Scopes,
		createdAt: now,
		lastUsed:  now,
	}
}

func (h *streamableHTTP) getSession(id string) *session {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.sessions[id]
}

func (h *streamableHTTP) touchSession(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sessions[id]
	if !ok {
		return false
	}
	s.lastUsed = time.Now()
	return true
}

// gcLoop 定期清理空闲超过 30 分钟的 session。
func (h *streamableHTTP) gcLoop() {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-30 * time.Minute)
		h.mu.Lock()
		for id, s := range h.sessions {
			if s.lastUsed.Before(cutoff) {
				delete(h.sessions, id)
			}
		}
		h.mu.Unlock()
	}
}

func writeRPCError(w http.ResponseWriter, httpStatus int, id json.RawMessage, e *RPCError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_ = json.NewEncoder(w).Encode(NewErrorResponse(id, e))
}

func mapAuthErr(err error) *RPCError {
	switch {
	case errors.Is(err, ErrUnauthorized):
		return NewError(CodeUnauthorized, "unauthorized: missing or invalid bearer token")
	case errors.Is(err, ErrForbidden):
		return NewError(CodeForbidden, "forbidden: ip not in allowlist")
	case errors.Is(err, ErrRateLimited):
		return NewError(CodeRateLimited, "rate limited")
	case errors.Is(err, ErrExpired):
		return NewError(CodeUnauthorized, "token expired")
	default:
		return NewError(CodeUnauthorized, "unauthorized: "+err.Error())
	}
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		// 取第一个
		if i := strings.IndexByte(v, ','); i > 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

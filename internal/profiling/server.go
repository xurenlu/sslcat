package profiling

import (
	"context"
	"fmt"
	"net"
	"net/http"
	httppprof "net/http/pprof"
	"strings"
	"time"
)

const DefaultAddr = "127.0.0.1:6060"

// Server 在独立的 loopback 监听器上提供 pprof，避免调试端点进入业务路由。
type Server struct {
	httpServer *http.Server
	listener   net.Listener
}

// ValidateAddr 确保 pprof 只能绑定到 loopback，禁止私网地址和通配地址。
func ValidateAddr(addr string) error {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return fmt.Errorf("invalid pprof address %q: %w", addr, err)
	}

	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return nil
	}

	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("pprof address %q must use a loopback host", addr)
	}
	return nil
}

// Start 启动独立 pprof 服务。监听动作同步完成，调用方可立即获知端口占用等错误。
func Start(addr string) (*Server, error) {
	if strings.TrimSpace(addr) == "" {
		addr = DefaultAddr
	}
	if err := ValidateAddr(addr); err != nil {
		return nil, err
	}
	host, port, _ := net.SplitHostPort(strings.TrimSpace(addr))
	if strings.EqualFold(strings.Trim(host, "[]"), "localhost") {
		addr = net.JoinHostPort("127.0.0.1", port)
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen for pprof on %s: %w", addr, err)
	}

	httpServer := &http.Server{
		Addr:              listener.Addr().String(),
		Handler:           newHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    64 * 1024,
	}
	server := &Server{httpServer: httpServer, listener: listener}
	go func() {
		_ = httpServer.Serve(listener)
	}()
	return server, nil
}

func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", httppprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", httppprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", httppprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", httppprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", httppprof.Trace)
	return mux
}

func (s *Server) Addr() string {
	if s == nil || s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

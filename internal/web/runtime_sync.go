package web

// syncSSLManagerConfig 保持证书申请逻辑与已保存的 SSL/DNS 配置一致。
func (s *Server) syncSSLManagerConfig() {
	if s.sslManager == nil {
		return
	}
	if err := s.sslManager.Reload(s.config); err != nil {
		s.log.Warnf("Failed to reload SSL manager after config update: %v", err)
	}
}

// syncProxyManagerConfig 保持代理运行时与已保存配置一致。
func (s *Server) syncProxyManagerConfig() {
	if s.proxyManager == nil {
		return
	}
	if err := s.proxyManager.Reload(s.config); err != nil {
		s.log.Warnf("Failed to reload proxy manager after config update: %v", err)
	}
}

// syncSecurityManagerConfig 保持安全运行时与已保存配置一致。
func (s *Server) syncSecurityManagerConfig() {
	if s.securityManager != nil {
		if err := s.securityManager.Reload(s.config); err != nil {
			s.log.Warnf("Failed to reload security manager after config update: %v", err)
		}
	}

	if s.wafEngine != nil && s.wafEngine.Engine != nil {
		s.wafEngine.Engine.SetEnabled(s.config.Security.EnableWAF)
	}
	if s.ddosProtector != nil && s.config.Security.MaxAttempts5Min > 0 {
		s.ddosProtector.SetCustomRequestsPer5Minutes(s.config.Security.MaxAttempts5Min)
	}
}

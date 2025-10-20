package web

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// handleAPIClusterSettings 提供获取/更新集群配置的 API
func (s *Server) handleAPIClusterSettings(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, r.Method != http.MethodGet) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		resp := map[string]any{
			"mode":      s.config.Cluster.Mode,
			"node_id":   s.config.Cluster.NodeID,
			"node_name": s.config.Cluster.NodeName,
			"master": map[string]any{
				"host":           s.config.Cluster.Master.Host,
				"port":           s.config.Cluster.Master.Port,
				"timeout":        s.config.Cluster.Master.Timeout,
				"retry_interval": s.config.Cluster.Master.RetryInterval,
			},
			"sync": map[string]any{
				"config_enabled":  s.config.Cluster.Sync.ConfigEnabled,
				"cert_enabled":    s.config.Cluster.Sync.CertEnabled,
				"interval":        s.config.Cluster.Sync.Interval,
				"timeout":         s.config.Cluster.Sync.Timeout,
				"exclude_configs": s.config.Cluster.Sync.ExcludeConfigs,
			},
			"port":     s.config.Cluster.Port,
			"auth_key": maskSecret(s.config.Cluster.AuthKey),
		}
		s.writeSuccessResponse(w, resp, "Cluster settings retrieved")
		return
	case http.MethodPost, http.MethodPut:
		var req struct {
			Mode     string `json:"mode"`
			NodeName string `json:"node_name"`
			Master   struct {
				Host          string `json:"host"`
				Port          int    `json:"port"`
				AuthKey       string `json:"auth_key"`
				Timeout       int    `json:"timeout"`
				RetryInterval int    `json:"retry_interval"`
			} `json:"master"`
			Sync struct {
				ConfigEnabled  *bool    `json:"config_enabled"`
				CertEnabled    *bool    `json:"cert_enabled"`
				Interval       *int     `json:"interval"`
				Timeout        *int     `json:"timeout"`
				ExcludeConfigs []string `json:"exclude_configs"`
			} `json:"sync"`
			Port    *int   `json:"port"`
			AuthKey string `json:"auth_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON")
			return
		}

		if req.Mode != "" {
			s.config.Cluster.Mode = strings.ToLower(req.Mode)
		}
		if req.NodeName != "" {
			s.config.Cluster.NodeName = req.NodeName
		}
		// Master
		if req.Master.Host != "" {
			s.config.Cluster.Master.Host = req.Master.Host
		}
		if req.Master.Port != 0 {
			s.config.Cluster.Master.Port = req.Master.Port
		}
		if req.Master.AuthKey != "" {
			s.config.Cluster.Master.AuthKey = req.Master.AuthKey
		}
		if req.Master.Timeout != 0 {
			s.config.Cluster.Master.Timeout = req.Master.Timeout
		}
		if req.Master.RetryInterval != 0 {
			s.config.Cluster.Master.RetryInterval = req.Master.RetryInterval
		}
		// Sync
		if req.Sync.ConfigEnabled != nil {
			s.config.Cluster.Sync.ConfigEnabled = *req.Sync.ConfigEnabled
		}
		if req.Sync.CertEnabled != nil {
			s.config.Cluster.Sync.CertEnabled = *req.Sync.CertEnabled
		}
		if req.Sync.Interval != nil {
			s.config.Cluster.Sync.Interval = *req.Sync.Interval
		}
		if req.Sync.Timeout != nil {
			s.config.Cluster.Sync.Timeout = *req.Sync.Timeout
		}
		if req.Sync.ExcludeConfigs != nil {
			s.config.Cluster.Sync.ExcludeConfigs = req.Sync.ExcludeConfigs
		}
		// Cluster port/key
		if req.Port != nil {
			s.config.Cluster.Port = *req.Port
		}
		if req.AuthKey != "" {
			s.config.Cluster.AuthKey = req.AuthKey
		}

		if err := s.config.Save(s.config.ConfigFile); err != nil {
			s.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to save config: %v", err))
			return
		}
		s.writeSuccessResponse(w, map[string]any{"updated_at": time.Now().Format("2006-01-02 15:04:05")}, "Cluster settings updated")
		return
	default:
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
}

// handleAPIClusterExportCerts Master 端导出证书供 Slave 拉取
func (s *Server) handleAPIClusterExportCerts(w http.ResponseWriter, r *http.Request) {
	// 校验共享密钥
	key := r.Header.Get("X-Cluster-Key")
	if key == "" || key != s.config.Cluster.AuthKey {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=certs.tar.gz")
	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	// 将证书和私钥目录打包
	paths := []string{}
	if s.config.SSL.CertDir != "" {
		paths = append(paths, s.config.SSL.CertDir)
	}
	if s.config.SSL.KeyDir != "" {
		paths = append(paths, s.config.SSL.KeyDir)
	}
	for _, base := range paths {
		base = filepath.Clean(base)
		_ = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			rel, err := filepath.Rel(filepath.Dir(base), path)
			if err != nil {
				return nil
			}
			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return nil
			}
			header.Name = rel
			if err := tw.WriteHeader(header); err != nil {
				return nil
			}
			if info.Mode().IsRegular() {
				f, err := os.Open(path)
				if err != nil {
					return nil
				}
				defer f.Close()
				_, _ = io.Copy(tw, f)
			}
			return nil
		})
	}
}

// handleAPIClusterSyncCerts Slave 端从 Master 拉取证书并解包到本地
func (s *Server) handleAPIClusterSyncCerts(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, false) {
		return
	}
	if r.Method != http.MethodPost {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.config.Cluster.Master.Host == "" || s.config.Cluster.Master.Port == 0 {
		s.writeErrorResponse(w, http.StatusBadRequest, "Master not configured")
		return
	}
	masterURL := fmt.Sprintf("http://%s:%d%s/api/cluster/export-certs", s.config.Cluster.Master.Host, s.config.Cluster.Master.Port, s.config.AdminPrefix)
	req, err := http.NewRequest(http.MethodGet, masterURL, nil)
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("X-Cluster-Key", s.config.Cluster.Master.AuthKey)
	client := &http.Client{Timeout: time.Duration(maxInt(s.config.Cluster.Master.Timeout, 10)) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadGateway, fmt.Sprintf("Failed to contact master: %v", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.writeErrorResponse(w, resp.StatusCode, fmt.Sprintf("Master responded with %s", resp.Status))
		return
	}
	// 解包 tar.gz 到本地 cert/key 目录
	if err := s.extractCertBundle(resp.Body, s.config.SSL.CertDir, s.config.SSL.KeyDir); err != nil {
		s.clusterLastSyncError = err.Error()
		s.writeErrorResponse(w, http.StatusInternalServerError, fmt.Sprintf("Failed to extract bundle: %v", err))
		return
	}
	s.clusterLastCertSyncAt = time.Now()
	s.clusterLastSyncError = ""
	s.writeSuccessResponse(w, map[string]any{"synced_at": s.clusterLastCertSyncAt.Format("2006-01-02 15:04:05")}, "Certificates synced from master")
}

func (s *Server) extractCertBundle(r io.Reader, certDir, keyDir string) error {
	gr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name := filepath.Clean(hdr.Name)
		var targetBase string
		// 简单规则：路径包含 "/cert" 放入 certDir，包含 "/key" 放入 keyDir，否则放入 certDir
		if strings.Contains(name, "cert") {
			targetBase = certDir
		} else if strings.Contains(name, "key") {
			targetBase = keyDir
		} else {
			targetBase = certDir
		}
		targetPath := filepath.Join(targetBase, filepath.Base(name))
		switch hdr.Typeflag {
		case tar.TypeDir:
			_ = os.MkdirAll(targetPath, 0o755)
		case tar.TypeReg:
			_ = os.MkdirAll(filepath.Dir(targetPath), 0o755)
			f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return err
			}
			_ = f.Close()
		}
	}
	return nil
}

func maskSecret(v string) string {
	if v == "" {
		return ""
	}
	if len(v) <= 4 {
		return "****"
	}
	return v[:2] + strings.Repeat("*", len(v)-4) + v[len(v)-2:]
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// handleAPIClusterStatus 返回集群运行状态（简版）
func (s *Server) handleAPIClusterStatus(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}
	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	// count certs on disk (simple .crt/.pem files in certDir)
	certCount := 0
	if dir := strings.TrimSpace(s.config.SSL.CertDir); dir != "" {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			name := strings.ToLower(info.Name())
			if strings.HasSuffix(name, ".crt") || strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".cer") {
				certCount++
			}
			return nil
		})
	}
	status := map[string]any{
		"mode":                     s.config.Cluster.Mode,
		"node_id":                  s.config.Cluster.NodeID,
		"node_name":                s.config.Cluster.NodeName,
		"master":                   s.config.Cluster.Master.Host,
		"port":                     s.config.Cluster.Port,
		"sync":                     s.config.Cluster.Sync,
		"server_port":              s.config.Server.Port,
		"cert_count":               certCount,
		"last_cert_sync_at":        timeOrEmpty(s.clusterLastCertSyncAt),
		"last_config_sync_at":      timeOrEmpty(s.clusterLastConfigSyncAt),
		"master_last_reachable_at": timeOrEmpty(s.clusterMasterLastReachableAt),
		"last_sync_error":          s.clusterLastSyncError,
	}
	s.writeSuccessResponse(w, status, "Cluster status")
}

// handleAPIClusterTestMaster 测试与 Master 的连通性
func (s *Server) handleAPIClusterTestMaster(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeAPI(w, r, true) {
		return
	}
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.config.Cluster.Master.Host == "" || s.config.Cluster.Master.Port == 0 {
		s.writeErrorResponse(w, http.StatusBadRequest, "Master not configured")
		return
	}
	url := fmt.Sprintf("http://%s:%d%s/api/cluster/settings", s.config.Cluster.Master.Host, s.config.Cluster.Master.Port, s.config.AdminPrefix)
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("X-Cluster-Key", s.config.Cluster.Master.AuthKey)
	client := &http.Client{Timeout: time.Duration(maxInt(s.config.Cluster.Master.Timeout, 10)) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadGateway, fmt.Sprintf("connect failed: %v", err))
		return
	}
	defer resp.Body.Close()
	ok := resp.StatusCode == http.StatusOK
	if ok {
		s.clusterMasterLastReachableAt = time.Now()
	}
	s.writeSuccessResponse(w, map[string]any{"reachable": ok, "status": resp.Status}, "Master connectivity tested")
}

func timeOrEmpty(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02 15:04:05")
}

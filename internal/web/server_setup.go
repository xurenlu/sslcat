package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/compression"
	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/ml"
	"github.com/xurenlu/sslcat/internal/security"
	"github.com/xurenlu/sslcat/internal/ssl"
	"github.com/xurenlu/sslcat/internal/threatintel"
)

// SetupConfigReload 设置配置热重载功能
func (s *Server) SetupConfigReload(configWatcher *config.ConfigWatcher, reloadManager *config.ReloadManager) {
	s.configWatcher = configWatcher
	s.reloadManager = reloadManager
	s.configReloadAPI = NewConfigReloadAPI(s, configWatcher, reloadManager)

	s.configVersionManager = config.NewVersionManager(s.config.ConfigFile)
	if err := s.configVersionManager.LoadVersions(); err != nil {
		s.log.Warnf("Failed to load config versions: %v", err)
	} else {
		s.log.Infof("Loaded %d config versions", len(s.configVersionManager.GetVersions()))
	}

	s.setupMLSystem()
	s.configReloadAPI.SetupRoutes()
	s.setupConfigVersionRoutes()
	s.setupHTTP2ControlRoutes()

	s.log.Info("Config hot reload functionality enabled")
}

// setupMLSystem 初始化 ML/AI 异常检测系统
func (s *Server) setupMLSystem() {
	s.log.Info("Initializing ML/AI anomaly detection system")

	s.mlAPIHandler = NewMLAPIHandler()
	s.mlFeatureExtractor = ml.NewFeatureExtractor()
	s.mlThreatScorer = ml.NewThreatScorer()

	s.mlSampler = ml.NewRequestSampler(s.mlFeatureExtractor, 5000)

	dataDir := s.config.Server.DataDir
	if dataDir == "" {
		dataDir = "./data"
	}
	mlDir := filepath.Join(dataDir, "ml")
	s.mlModelPath = filepath.Join(mlDir, "isolation_forest.json")
	s.mlHistoryStore = ml.NewTrainingHistoryStore(filepath.Join(mlDir, "training_history.json"), 50)

	if loaded, err := ml.LoadModelJSON(s.mlModelPath); err == nil && loaded != nil {
		s.mlForest = loaded
		s.log.WithFields(logrus.Fields{
			"path":          s.mlModelPath,
			"n_trees":       loaded.NTrees,
			"feature_dim":   loaded.FeatureDim,
			"total_samples": loaded.TotalSamples,
		}).Info("Loaded persisted ML model")
		if last := s.mlHistoryStore.Last(); last != nil {
			s.mlLastTrainingMu.Lock()
			s.mlLastTrainingAt = last.Timestamp
			s.mlLastTrainingMu.Unlock()
		}
	} else if err != nil && !os.IsNotExist(err) {
		s.log.WithError(err).Warn("Failed to load persisted ML model")
	}

	mlConfig := s.config.AISecurity.MLInference

	workerSize := mlConfig.WorkerPoolSize
	if workerSize <= 0 {
		workerSize = 50
	}
	maxQueueSize := mlConfig.MaxQueueSize
	if maxQueueSize <= 0 {
		maxQueueSize = 5000
	}
	batchTimeout := mlConfig.BatchTimeout
	if batchTimeout == 0 {
		batchTimeout = 100 * time.Millisecond
	}
	queueStrategy := mlConfig.QueueFullStrategy
	if queueStrategy == "" {
		queueStrategy = "drop"
	}

	s.mlInferenceEngine = ml.NewInferenceEngineWithConfig(
		workerSize, maxQueueSize, batchTimeout, queueStrategy,
	)
	s.mlInferenceEngine.Start()

	if s.mlForest != nil {
		s.mlInferenceEngine.SetModel(s.mlForest, s.mlFeatureExtractor)
	}

	s.mlAPIHandler.SetEngine(s.mlInferenceEngine, s.mlForest, s.mlFeatureExtractor, s.mlThreatScorer)
	s.mlAPIHandler.SetPersistence(s.mlSampler, s.mlHistoryStore, s.mlModelPath, func(f *ml.IsolationForest) {
		s.mlForest = f
		s.mlLastTrainingMu.Lock()
		s.mlLastTrainingAt = time.Now()
		s.mlLastTrainingMu.Unlock()
	})

	prefix := s.config.AdminPrefix + "/api/ml"
	s.mux.HandleFunc(prefix+"/train", s.handleMLTrain)
	s.mux.HandleFunc(prefix+"/stats", s.handleMLStats)
	s.mux.HandleFunc(prefix+"/predict", s.handleMLPredict)
	s.mux.HandleFunc(prefix+"/feedback", s.handleMLFeedback)
	s.mux.HandleFunc(prefix+"/threat/score", s.handleMLThreatScore)
	s.mux.HandleFunc(prefix+"/features/extract", s.handleMLExtractFeatures)
	s.mux.HandleFunc(prefix+"/predictions/recent", s.handleMLRecentPredictions)
	s.mux.HandleFunc(prefix+"/training/history", s.handleMLTrainingHistory)

	s.log.WithFields(logrus.Fields{
		"worker_pool_size":    workerSize,
		"max_queue_size":      maxQueueSize,
		"batch_timeout":       batchTimeout.String(),
		"queue_full_strategy": queueStrategy,
	}).Info("ML/AI anomaly detection system initialized")
}

// setupHTTP2ControlRoutes 设置 HTTP/2 控制 API 路由
func (s *Server) setupHTTP2ControlRoutes() {
	prefix := s.config.AdminPrefix + "/api/http2"
	s.mux.HandleFunc(prefix+"/status", s.handleHTTP2Status)
	s.mux.HandleFunc(prefix+"/enable", s.handleHTTP2Enable)
	s.mux.HandleFunc(prefix+"/disable", s.handleHTTP2Disable)
	s.log.Info("HTTP/2 control API routes registered")
}

// StopMLSystem 停止 ML 系统
func (s *Server) StopMLSystem() {
	if s.mlInferenceEngine != nil {
		s.mlInferenceEngine.Stop()
		s.log.Info("ML inference engine stopped")
	}
}

// setupConfigVersionRoutes 设置配置版本管理API路由
func (s *Server) setupConfigVersionRoutes() {
	prefix := s.config.AdminPrefix + "/api/config/versions"
	s.mux.HandleFunc(prefix, s.handleAPIConfigVersionList)
	s.mux.HandleFunc(prefix+"/get", s.handleAPIConfigVersionGet)
	s.mux.HandleFunc(prefix+"/create", s.handleAPIConfigVersionCreate)
	s.mux.HandleFunc(prefix+"/rollback", s.handleAPIConfigVersionRollback)
	s.mux.HandleFunc(prefix+"/delete", s.handleAPIConfigVersionDelete)
	s.mux.HandleFunc(prefix+"/update", s.handleAPIConfigVersionUpdateDescription)
	s.mux.HandleFunc(prefix+"/diff", s.handleAPIConfigVersionDiff)
	s.mux.HandleFunc(prefix+"/compare-current", s.handleAPIConfigVersionCompareCurrent)
	s.mux.HandleFunc(prefix+"/stats", s.handleAPIConfigVersionStats)
	s.mux.HandleFunc(prefix+"/export", s.handleAPIConfigVersionExport)
	s.mux.HandleFunc(prefix+"/import", s.handleAPIConfigVersionImport)
	s.mux.HandleFunc(prefix+"/reload", s.handleAPIConfigVersionReloadVersions)
	s.log.Info("Config version management API routes registered")
}

// UpdateConfig 更新服务器配置（热重载时调用）
func (s *Server) UpdateConfig(newConfig *config.Config) {
	s.log.Info("Updating server configuration")

	oldConfig := s.config
	s.cleanupOldConfigResources(oldConfig, newConfig)
	s.config = newConfig

	if s.compressor != nil {
		s.compressor = compression.NewCompressor(compression.FromConfig(newConfig))
		s.log.Info("Updated compressor configuration")
	}

	if s.notificationIntegrator != nil {
		s.log.Info("Reloading notification manager configuration")
		s.notificationIntegrator.ReloadFromConfig(newConfig.Notification)
	}

	if s.ddosProtector != nil {
		s.ddosProtector.SetOutdatedBrowserEnabled(newConfig.Security.OutdatedBrowser.Enabled)
		if newConfig.Security.MaxAttempts5Min > 0 {
			s.ddosProtector.SetCustomRequestsPer5Minutes(newConfig.Security.MaxAttempts5Min)
		}
	}

	if oldConfig.AdminPrefix != newConfig.AdminPrefix {
		s.log.Infof("Admin prefix changed: %s -> %s", oldConfig.AdminPrefix, newConfig.AdminPrefix)
	}

	s.log.Info("Server configuration updated successfully")
}

// SetThreatIntelManager 设置威胁情报管理器
func (s *Server) SetThreatIntelManager(tim *threatintel.ThreatIntelManager) {
	s.threatIntelManager = tim
	s.threatIntelAPI = NewThreatIntelAPI(tim)
	s.threatIntelAPI.RegisterRoutes(s.mux, s.config.AdminPrefix)
	s.log.Info("Threat intelligence manager linked to web server")
}

// cleanupOldConfigResources 清理旧配置相关的资源
func (s *Server) cleanupOldConfigResources(oldConfig, newConfig *config.Config) {
	if s.dnsCache != nil {
		oldProviders := make(map[string]bool)
		for _, p := range oldConfig.SSL.DNSProviders {
			if p.Enabled {
				oldProviders[p.Name] = true
			}
		}
		newProviders := make(map[string]bool)
		for _, p := range newConfig.SSL.DNSProviders {
			if p.Enabled {
				newProviders[p.Name] = true
			}
		}
		hasChanges := false
		for name := range oldProviders {
			if !newProviders[name] {
				hasChanges = true
				break
			}
		}
		for name := range newProviders {
			if !oldProviders[name] {
				hasChanges = true
				break
			}
		}
		if hasChanges {
			s.log.Info("DNS providers changed, stopping old periodic update")
			s.dnsCache.StopPeriodicUpdate()
			var enabledProviders []string
			for _, provider := range newConfig.SSL.DNSProviders {
				if provider.Enabled {
					enabledProviders = append(enabledProviders, provider.Name)
				}
			}
			s.dnsCache.UpdateAllProvidersCache(enabledProviders)
			s.dnsCache.StartPeriodicUpdate(enabledProviders, 5*time.Minute)
			s.log.Infof("DNS cache reinitialized for %d providers", len(enabledProviders))
		}
	}

	if s.securityManager != nil {
		oldGeoPath := oldConfig.Security.GeoBlocking.DatabasePath
		newGeoPath := newConfig.Security.GeoBlocking.DatabasePath
		if oldGeoPath != newGeoPath {
			s.log.Info("GeoIP database path changed, will reload on next access")
		}
	}

	if s.compressionCache != nil {
		if oldConfig.Compression.Enabled != newConfig.Compression.Enabled ||
			oldConfig.Compression.Level != newConfig.Compression.Level {
			s.log.Info("Compression config changed significantly, clearing cache asynchronously")
			go func() {
				s.compressionCache.Clear()
				s.log.Info("Compression cache cleared")
			}()
		}
	}

	if s.imageOptimizer != nil {
		if oldConfig.ImageOptimization.Enabled != newConfig.ImageOptimization.Enabled ||
			oldConfig.ImageOptimization.WebPQuality != newConfig.ImageOptimization.WebPQuality ||
			oldConfig.ImageOptimization.JPEGQuality != newConfig.ImageOptimization.JPEGQuality {
			s.log.Info("Image optimization config changed, clearing cache asynchronously")
			go func() {
				s.imageOptimizer.ClearCache()
				s.log.Info("Image optimization cache cleared")
			}()
		}
	}

	s.log.Debug("Old config resources cleanup completed")
}

// initDNSCache 初始化DNS缓存并启动定期更新
func (s *Server) initDNSCache() {
	var enabledProviders []string
	for _, provider := range s.config.SSL.DNSProviders {
		if provider.Enabled {
			enabledProviders = append(enabledProviders, provider.Name)
		}
	}
	s.dnsCache.UpdateAllProvidersCache(enabledProviders)
	s.dnsCache.StartPeriodicUpdate(enabledProviders, 5*time.Minute)
	s.log.Infof("DNS cache initialized for %d providers: %v", len(enabledProviders), enabledProviders)
}

// initConfigWatch 计算初始哈希并启动后台监听
func (s *Server) initConfigWatch() {
	path := s.config.ConfigFile
	if path == "" {
		path = "/etc/sslcat/sslcat.conf"
	}
	if b, err := os.ReadFile(path); err == nil {
		sum := sha256.Sum256(b)
		s.lastConfigHash = hex.EncodeToString(sum[:])
	}
	go s.watchConfigFileLoop()
	go s.watchConfigFileFS()
}

// initZeroTrustComponents 初始化 Zero Trust 组件 (Phase 5)
func (s *Server) initZeroTrustComponents() {
	s.rbacManager = security.NewRBACManager()
	s.log.Info("RBAC manager initialized")

	mtlsConfig := &ssl.MTLSConfig{
		Enabled:            false,
		Mode:               "optional",
		CADir:              "./data/mtls/ca",
		ClientCADir:        "./data/mtls/client-ca",
		CertFile:           "./data/mtls/server.crt",
		KeyFile:            "./data/mtls/server.key",
		ClientCertRequired: false,
		CRLCheckEnabled:    false,
		CRLUpdateInterval:  24 * time.Hour,
		CertPinningEnabled: false,
		AllowedCerts:       []string{},
	}

	mtlsMgr, err := ssl.NewMTLSManager(mtlsConfig)
	if err != nil {
		s.log.Warnf("Failed to initialize mTLS manager: %v", err)
	} else if mtlsMgr != nil {
		s.mtlsManager = mtlsMgr
		s.log.Info("mTLS manager initialized")
	}
}

// watchConfigFileLoop 定时检查配置文件变化并热加载（仅在 Slave 模式生效）
func (s *Server) watchConfigFileLoop() {
	interval := 5 * time.Second
	if !s.config.IsSlaveMode() {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if !s.config.IsSlaveMode() {
			continue
		}
		path := s.config.ConfigFile
		if path == "" {
			path = "/etc/sslcat/sslcat.conf"
		}
		b, err := os.ReadFile(path)
		if err != nil || len(b) == 0 {
			continue
		}
		sum := sha256.Sum256(b)
		hash := hex.EncodeToString(sum[:])
		if hash == s.lastConfigHash || hash == "" {
			continue
		}
		var newCfg config.Config
		if err := json.Unmarshal(b, &newCfg); err != nil {
			s.log.Warnf("Failed to parse synced config: %v", err)
			continue
		}
		newCfg.ConfigFile = s.config.ConfigFile
		oldPrefix := s.config.AdminPrefix
		s.applyConfigInPlace(&newCfg)
		s.lastConfigHash = hash
		if oldPrefix != s.config.AdminPrefix {
			s.mux = http.NewServeMux()
			s.setupRoutes()
		}
		s.log.Infof("Config reloaded from %s (cluster sync)", path)
	}
}

// watchConfigFileFS 使用 fsnotify 监听文件变化，触发热加载
func (s *Server) watchConfigFileFS() {
	if !s.config.IsSlaveMode() {
		return
	}
	path := s.config.ConfigFile
	if path == "" {
		path = "/etc/sslcat/sslcat.conf"
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		s.log.Warnf("fsnotify init failed: %v", err)
		return
	}
	defer watcher.Close()

	dir := filepath.Dir(path)
	if err := watcher.Add(dir); err != nil {
		s.log.Warnf("fsnotify add failed: %v", err)
		return
	}
	for {
		select {
		case ev, ok := <-watcher.Events:
			if !ok {
				return
			}
			if ev.Name == path && (ev.Op&fsnotify.Write == fsnotify.Write || ev.Op&fsnotify.Create == fsnotify.Create || ev.Op&fsnotify.Rename == fsnotify.Rename) {
				time.Sleep(150 * time.Millisecond)
				if b, err := os.ReadFile(path); err == nil && len(b) > 0 {
					var newCfg config.Config
					if err := json.Unmarshal(b, &newCfg); err == nil {
						newCfg.ConfigFile = s.config.ConfigFile
						oldPrefix := s.config.AdminPrefix
						s.applyConfigInPlace(&newCfg)
						sum := sha256.Sum256(b)
						s.lastConfigHash = hex.EncodeToString(sum[:])
						if oldPrefix != s.config.AdminPrefix {
							s.mux = http.NewServeMux()
							s.setupRoutes()
						}
						s.log.Infof("Config reloaded by fsnotify from %s", path)
					}
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			s.log.Debugf("fsnotify error: %v", err)
		}
	}
}

// applyConfigInPlace 将 newCfg 内容拷贝到现有 s.config，保持指针不变
func (s *Server) applyConfigInPlace(newCfg *config.Config) {
	if newCfg == nil {
		return
	}
	s.config.Server = newCfg.Server
	s.config.SSL = newCfg.SSL
	s.config.Admin = newCfg.Admin
	s.config.Proxy = newCfg.Proxy
	s.config.Security = newCfg.Security
	s.config.AdminPrefix = newCfg.AdminPrefix
	s.config.Cluster = newCfg.Cluster
	s.config.StaticSites = newCfg.StaticSites
	s.config.PHPSites = newCfg.PHPSites
	s.config.CDNCache = newCfg.CDNCache
}

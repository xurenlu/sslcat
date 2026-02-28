package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
	"github.com/xurenlu/sslcat/internal/notification"
)

// handleAPIConfigVersionList 获取配置版本列表
func (s *Server) handleAPIConfigVersionList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// 获取版本列表
	versions := s.configVersionManager.GetVersions()

	// 获取当前配置的哈希
	currentHash, _ := s.configVersionManager.GetCurrentHash()

	response := map[string]interface{}{
		"success":      true,
		"current_hash": currentHash,
		"versions":     versions,
		"stats":        s.configVersionManager.GetStats(),
		"total":        len(versions),
	}

	json.NewEncoder(w).Encode(response)
}

// handleAPIConfigVersionGet 获取指定版本的详细信息
func (s *Server) handleAPIConfigVersionGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// 获取版本ID
	versionID := r.URL.Query().Get("id")
	if versionID == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Version ID is required"})
		return
	}

	// 获取版本信息
	version := s.configVersionManager.GetVersion(versionID)
	if version == nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Version not found"})
		return
	}

	// 获取版本内容
	content, err := s.configVersionManager.GetVersionContent(versionID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to get version content: %v", err)})
		return
	}

	response := map[string]interface{}{
		"success": true,
		"version": version,
		"content": content,
	}

	json.NewEncoder(w).Encode(response)
}

// handleAPIConfigVersionCreate 创建新版本（手动备份）
func (s *Server) handleAPIConfigVersionCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// 解析请求
	var req struct {
		Author      string `json:"author"`
		Description string `json:"description"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Invalid request body: %v", err)})
		return
	}

	// 设置默认值
	if req.Author == "" {
		req.Author = "admin" // TODO: 从session获取实际用户名
	}
	if req.Description == "" {
		req.Description = "Manual backup"
	}

	// 创建版本
	version, err := s.configVersionManager.CreateVersion(req.Author, req.Description)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to create version: %v", err)})
		return
	}

	// 发送通知
	if s.notificationIntegrator != nil {
		s.notificationIntegrator.GetManager().Send(&notification.Notification{
			Type:    notification.TypeConfigReloaded,
			Level:   notification.LevelInfo,
			Title:   "配置备份已创建",
			Message: fmt.Sprintf("版本 v%d 已创建", version.Version),
			Details: map[string]any{
				"version":     version.Version,
				"author":      req.Author,
				"description": req.Description,
			},
		})
	}

	response := map[string]interface{}{
		"success": true,
		"message": "Version created successfully",
		"version": version,
	}

	json.NewEncoder(w).Encode(response)
}

// handleAPIConfigVersionRollback 回滚到指定版本
func (s *Server) handleAPIConfigVersionRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// 解析请求
	var req struct {
		VersionID string `json:"version_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Invalid request body: %v", err)})
		return
	}

	if req.VersionID == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Version ID is required"})
		return
	}

	// 获取版本信息
	version := s.configVersionManager.GetVersion(req.VersionID)
	if version == nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Version not found"})
		return
	}

	// 回滚
	if err := s.configVersionManager.RollbackToVersion(req.VersionID); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to rollback: %v", err)})
		return
	}

	// 触发配置重载
	if s.configWatcher != nil {
		if err := s.configWatcher.ForceReload(); err != nil {
			s.log.Errorf("Failed to reload config after rollback: %v", err)
		}
	}

	// 发送通知
	if s.notificationIntegrator != nil {
		s.notificationIntegrator.GetManager().Send(&notification.Notification{
			Type:    notification.TypeConfigReloaded,
			Level:   notification.LevelWarning,
			Title:   "配置已回滚",
			Message: fmt.Sprintf("配置已回滚到版本 v%d", version.Version),
			Details: map[string]any{
				"rolled_back_to": version.Version,
				"timestamp":      version.Timestamp.Format(time.RFC3339),
			},
		})
	}

	response := map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Successfully rolled back to version %d", version.Version),
		"version": version,
	}

	json.NewEncoder(w).Encode(response)
}

// handleAPIConfigVersionDiff 比较两个版本的差异
func (s *Server) handleAPIConfigVersionDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// 获取参数
	id1 := r.URL.Query().Get("v1")
	id2 := r.URL.Query().Get("v2")

	if id1 == "" || id2 == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Both v1 and v2 parameters are required"})
		return
	}

	// 比较版本
	changes, err := s.configVersionManager.CompareVersions(id1, id2)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to compare versions: %v", err)})
		return
	}

	response := map[string]interface{}{
		"success": true,
		"changes": changes,
		"summary": fmt.Sprintf("%d changes between %s and %s", len(changes), id1, id2),
	}

	json.NewEncoder(w).Encode(response)
}

// handleAPIConfigVersionDelete 删除指定版本
func (s *Server) handleAPIConfigVersionDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// 获取版本ID
	versionID := r.URL.Query().Get("id")
	if versionID == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Version ID is required"})
		return
	}

	// 删除版本
	if err := s.configVersionManager.DeleteVersion(versionID); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to delete version: %v", err)})
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "Version deleted successfully",
	}

	json.NewEncoder(w).Encode(response)
}

// handleAPIConfigVersionUpdateDescription 更新版本描述
func (s *Server) handleAPIConfigVersionUpdateDescription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// 解析请求
	var req struct {
		VersionID   string `json:"version_id"`
		Description string `json:"description"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Invalid request body: %v", err)})
		return
	}

	if req.VersionID == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Version ID is required"})
		return
	}

	// 更新描述
	if err := s.configVersionManager.UpdateVersionDescription(req.VersionID, req.Description); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to update description: %v", err)})
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "Description updated successfully",
	}

	json.NewEncoder(w).Encode(response)
}

// handleAPIConfigVersionStats 获取版本统计信息
func (s *Server) handleAPIConfigVersionStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")

	response := map[string]interface{}{
		"success": true,
		"stats":   s.configVersionManager.GetStats(),
	}

	json.NewEncoder(w).Encode(response)
}

// handleAPIConfigVersionExport 导出版本
func (s *Server) handleAPIConfigVersionExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.checkAuth(w, r) {
		return
	}

	// 获取版本ID
	versionID := r.URL.Query().Get("id")
	if versionID == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Version ID is required"})
		return
	}

	// 获取版本
	version := s.configVersionManager.GetVersion(versionID)
	if version == nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "Version not found"})
		return
	}

	// 设置下载文件名
	filename := fmt.Sprintf("sslcat.config.v%d.json", version.Version)
	if version.IsDaily {
		filename = fmt.Sprintf("sslcat.config.%s.json", version.Date)
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Type", "application/json")

	// 读取并写入文件
	http.ServeFile(w, r, version.FilePath)
}

// handleAPIConfigVersionImport 导入版本
func (s *Server) handleAPIConfigVersionImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// 解析表单（支持文件上传）
	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB max
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to parse form: %v", err)})
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": "File is required"})
		return
	}
	defer file.Close()

	author := r.FormValue("author")
	if author == "" {
		author = "admin"
	}

	description := r.FormValue("description")
	if description == "" {
		description = "Imported from file"
	}

	// TODO: 实现完整的文件导入逻辑
	response := map[string]interface{}{
		"success": true,
		"message": "Version import not fully implemented yet",
	}

	json.NewEncoder(w).Encode(response)
}

// handleAPIConfigVersionCompareCurrent 比较指定版本与当前配置的差异
func (s *Server) handleAPIConfigVersionCompareCurrent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// 获取版本ID
	versionID := r.URL.Query().Get("id")
	if versionID == "" {
		json.NewEncoder(w).Encode(map[string]string{"error": "Version ID is required"})
		return
	}

	// 读取当前配置文件
	currentConfig, err := config.Load(s.config.ConfigFile)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to load current config: %v", err)})
		return
	}

	// 获取指定版本的内容
	versionContent, err := s.configVersionManager.GetVersionContent(versionID)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to get version content: %v", err)})
		return
	}

	// 转换当前配置为map
	currentData, _ := json.Marshal(currentConfig)
	var currentMap map[string]interface{}
	json.Unmarshal(currentData, &currentMap)

	// 计算差异
	changes := make(map[string]config.DiffChange)
	compareMaps(currentMap, versionContent, "", changes)

	response := map[string]interface{}{
		"success": true,
		"changes": changes,
		"summary": fmt.Sprintf("%d changes between version and current", len(changes)),
	}

	json.NewEncoder(w).Encode(response)
}

// compareMaps 比较两个map的辅助函数
func compareMaps(m1, m2 map[string]interface{}, prefix string, changes map[string]config.DiffChange) {
	allKeys := make(map[string]bool)
	for k := range m1 {
		allKeys[k] = true
	}
	for k := range m2 {
		allKeys[k] = true
	}

	for key := range allKeys {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}

		v1, ok1 := m1[key]
		v2, ok2 := m2[key]

		if !ok1 {
			changes[path] = config.DiffChange{
				Path:       path,
				NewValue:   v2,
				ChangeType: "added",
			}
		} else if !ok2 {
			changes[path] = config.DiffChange{
				Path:       path,
				OldValue:   v1,
				ChangeType: "removed",
			}
		} else {
			j1, _ := json.Marshal(v1)
			j2, _ := json.Marshal(v2)
			if string(j1) == string(j2) {
				continue
			}

			map1, ok1Map := v1.(map[string]interface{})
			map2, ok2Map := v2.(map[string]interface{})

			if ok1Map && ok2Map {
				compareMaps(map1, map2, path, changes)
			} else {
				changes[path] = config.DiffChange{
					Path:       path,
					OldValue:   v1,
					NewValue:   v2,
					ChangeType: "modified",
				}
			}
		}
	}
}

// handleAPIConfigVersionReloadVersions 重新加载版本列表
func (s *Server) handleAPIConfigVersionReloadVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.checkAuth(w, r) {
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// 重新加载版本列表
	if err := s.configVersionManager.LoadVersions(); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Failed to reload versions: %v", err)})
		return
	}

	response := map[string]interface{}{
		"success": true,
		"message": "Versions reloaded successfully",
		"stats":   s.configVersionManager.GetStats(),
	}

	json.NewEncoder(w).Encode(response)
}

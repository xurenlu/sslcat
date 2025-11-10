package web

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/runner"
)

// testedTemplates 测试通过的模板ID集合
// 根据 docs/zh/testing/template-test-status.md 文档统计，共137个已通过测试的模板
var testedTemplates = map[string]bool{
	"anythingllm":                  true,
	"chatbot-ui":                   true,
	"chroma":                       true,
	"continue":                     true,
	"elasticsearch":                true,
	"gitlab":                       true,
	"grafana":                      true,
	"harbor":                       true,
	"jenkins":                      true,
	"langchain":                    true,
	"librechat":                   true,
	"llamaindex":                   true,
	"mattermost":                   true,
	"metabase":                     true,
	"minio":                        true,
	"mongo-express":                true,
	"mongodb":                      true,
	"mysql":                        true,
	"nexus":                        true,
	"nginx":                        true,
	"ollama":                       true,
	"open-webui":                   true,
	"phpmyadmin":                   true,
	"pinecone-alternative":         true,
	"portainer":                    true,
	"portainer-ce":                 true,
	"postgresql":                   true,
	"prometheus":                   true,
	"qdrant":                       true,
	"redash":                       true,
	"redis":                        true,
	"slack-bot":                    true,
	"superset":                     true,
	"weaviate":                     true,
	"wordpress":                    true,
	"erpnext":                      true,
	"espocrm":                      true,
	"dolibarr":                     true,
	"akaunting":                    true,
	"invoice-ninja":                true,
	"sonarqube":                    true,
	"prefect":                      true,
	"github-actions-runner":        true,
	"clickhouse":                   true,
	"cassandra":                    true,
	"timescaledb":                  true,
	"influxdb":                     true,
	"couchdb":                      true,
	"meilisearch":                  true,
	"ghost":                        true,
	"drupal":                       true,
	"bookstack":                    true,
	"wiki-js":                      true,
	"hedgedoc":                     true,
	"netdata":                      true,
	"uptime-kuma":                  true,
	"loki":                         true,
	"seq":                          true,
	"fathom":                       true,
	"chatwoot":                     true,
	"element":                      true,
	"vaultwarden":                  true,
	"keycloak":                     true,
	"suitecrm":                     true,
	"invoiceplane":                 true,
	"woodpecker":                   true,
	"typesense":                    true,
	"directus":                     true,
	"outline":                      true,
	"graylog":                      true,
	"plausible":                    true,
	"discourse":                    true,
	"authelia":                     true,
	"peertube":                     true,
	"owncast":                      true,
	"pi-hole":                      true,
	"homeassistant":                true,
	"umami":                        true,
	"jellyfin":                     true,
	"calibre-web":                  true,
	"domoticz":                     true,
	"dozzle":                       true,
	"duplicati":                    true,
	"freshrss":                     true,
	"glances":                      true,
	"grafana-dashboard":            true,
	"heimdall":                     true,
	"jaeger":                       true,
	"kafka":                        true,
	"lidarr":                       true,
	"node-red":                     true,
	"n8n":                          true,
	"obsidian":                     true,
	"odoo":                         true,
	"ombi":                         true,
	"airflow":                      true,
	"strapi":                       true,
	"photoprism":                   true,
	"piwigo":                       true,
	"baichuan":                     true,
	"chatglm":                      true,
	"localai":                      true,
	"qwen":                         true,
	"replicate-stable-diffusion":   true,
	"text-generation-webui":        true,
	"yi":                           true,
	"torchserve":                   true,
	"stable-diffusion-webui":       true,
	"stable-diffusion-inpainting":  true,
}

// TemplateAPI 模板相关 API
type TemplateAPI struct {
	manager  *runner.TemplateManager
	logger   *logrus.Entry
	basePath string
}

// NewTemplateAPI 创建模板 API 处理器
func NewTemplateAPI(manager *runner.TemplateManager, basePath string) *TemplateAPI {
	if manager == nil {
		return nil
	}
	return &TemplateAPI{
		manager:  manager,
		logger:   logrus.WithField("component", "template_api"),
		basePath: strings.TrimSuffix(basePath, "/"),
	}
}

// HandleTemplates 路由入口
func (api *TemplateAPI) HandleTemplates(w http.ResponseWriter, r *http.Request) {
	if api == nil {
		writeErrorJSON(w, "模板服务未启用", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		api.listTemplates(w, r)
	case http.MethodPost:
		api.writeError(w, "暂未支持的操作", http.StatusNotImplemented)
	default:
		api.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleTemplateDetail 处理模板详情请求
func (api *TemplateAPI) HandleTemplateDetail(w http.ResponseWriter, r *http.Request) {
	if api == nil {
		writeErrorJSON(w, "模板服务未启用", http.StatusServiceUnavailable)
		return
	}

	if r.Method != http.MethodGet {
		api.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, api.basePath)
	path = strings.Trim(path, "/")
	if path == "" {
		api.writeError(w, "模板 ID 不能为空", http.StatusBadRequest)
		return
	}
	parts := strings.Split(path, "/")
	id := parts[len(parts)-1]
	if id == "" {
		api.writeError(w, "模板 ID 不能为空", http.StatusBadRequest)
		return
	}
	if strings.EqualFold(id, "reload") {
		api.writeError(w, "模板 ID 不能为空", http.StatusBadRequest)
		return
	}

	tpl, ok := api.manager.Get(id)
	if !ok {
		api.writeError(w, "模板不存在", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"meta":   api.buildTemplateMeta(tpl),
		"readme": tpl.Readme,
		"assets": tpl.Assets,
	}

	api.writeJSON(w, response)
}

// HandleTemplateReload 手动重新加载模板
func (api *TemplateAPI) HandleTemplateReload(w http.ResponseWriter, r *http.Request) {
	if api == nil {
		writeErrorJSON(w, "模板服务未启用", http.StatusServiceUnavailable)
		return
	}

	if r.Method != http.MethodPost {
		api.writeError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := api.manager.LoadAll(); err != nil {
		api.logger.WithError(err).Error("重新加载模板失败")
		api.writeError(w, "重新加载模板失败: "+err.Error(), http.StatusInternalServerError)
		return
	}

	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "模板已重新加载",
		"count":   api.manager.Count(),
	})
}

func (api *TemplateAPI) listTemplates(w http.ResponseWriter, r *http.Request) {
	templates := api.manager.List()
	
	// 添加调试日志
	api.logger.WithFields(logrus.Fields{
		"total_templates": len(templates),
		"manager_count":   api.manager.Count(),
		"show_all":        r.URL.Query().Get("showAll"),
	}).Info("模板列表请求")
	
	if len(templates) == 0 {
		api.logger.Warn("模板列表为空，可能模板未正确加载")
		api.writeJSON(w, map[string]interface{}{
			"success": true,
			"data":    []interface{}{},
			"count":   0,
		})
		return
	}

	categoryFilter := strings.TrimSpace(r.URL.Query().Get("category"))
	tagFilter := strings.TrimSpace(r.URL.Query().Get("tag"))
	keyword := strings.TrimSpace(r.URL.Query().Get("keyword"))
	sourceFilter := strings.TrimSpace(r.URL.Query().Get("source"))
	// 默认只显示测试通过的模板，可以通过 ?showAll=true 显示所有模板
	showAll := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("showAll"))) == "true"

	resp := make([]map[string]interface{}, 0, len(templates))
	filteredCount := 0

	for _, tpl := range templates {
		// 如果未设置 showAll=true，则只显示测试通过的模板
		if !showAll && !testedTemplates[tpl.Meta.ID] {
			filteredCount++
			continue
		}
		if categoryFilter != "" && !strings.EqualFold(tpl.Meta.Category, categoryFilter) {
			continue
		}
		if sourceFilter != "" && !strings.EqualFold(string(tpl.Source), sourceFilter) {
			continue
		}
		if tagFilter != "" && !containsFold(tpl.Meta.Tags, tagFilter) {
			continue
		}
		if keyword != "" && !api.matchKeyword(tpl, keyword) {
			continue
		}

		resp = append(resp, api.buildTemplateMeta(tpl))
	}

	sort.SliceStable(resp, func(i, j int) bool {
		catI, _ := resp[i]["category"].(string)
		catJ, _ := resp[j]["category"].(string)
		if strings.EqualFold(catI, catJ) {
			nameI, _ := resp[i]["name"].(string)
			nameJ, _ := resp[j]["name"].(string)
			return strings.ToLower(nameI) < strings.ToLower(nameJ)
		}
		return strings.ToLower(catI) < strings.ToLower(catJ)
	})

	api.logger.WithFields(logrus.Fields{
		"total":         len(templates),
		"filtered":     filteredCount,
		"returned":      len(resp),
		"show_all":      showAll,
		"category":      categoryFilter,
		"tag":           tagFilter,
		"keyword":       keyword,
	}).Info("模板列表返回")
	
	api.writeJSON(w, map[string]interface{}{
		"success": true,
		"data":    resp,
		"count":   len(resp),
	})
}

func (api *TemplateAPI) buildTemplateMeta(tpl *runner.AppTemplate) map[string]interface{} {
	meta := tpl.Meta
	response := map[string]interface{}{
		"id":          meta.ID,
		"name":        meta.Name,
		"category":    meta.Category,
		"subcategory": meta.Subcategory,
		"tags":        meta.Tags,
		"description": meta.Description,
		"icon":        meta.Icon,
		"version":     meta.Version,
		"author":      meta.Author,
		"website":     meta.Website,
		"source":      string(tpl.Source),
		"compose":     meta.ComposeFile,
		"variables":   meta.Variables,
		"services":    meta.Services,
	}

	if !tpl.LastModified.IsZero() {
		response["last_modified"] = tpl.LastModified.Format(time.RFC3339)
	}

	// 检测是否需要 GPU
	if meta.Metadata != nil {
		if gpuRequired, ok := meta.Metadata["gpu_required"]; ok && strings.ToLower(gpuRequired) == "true" {
			response["gpu_required"] = true
		} else {
			// 检查 services 中是否有 gpu: required
			for _, svc := range meta.Services {
				if svc.Resources.GPU == "required" {
					response["gpu_required"] = true
					break
				}
			}
		}
	} else {
		// 检查 services 中是否有 gpu: required
		for _, svc := range meta.Services {
			if svc.Resources.GPU == "required" {
				response["gpu_required"] = true
				break
			}
		}
	}

	// 检测是否使用 ghcr.io 镜像
	response["requires_ghcr_token"] = api.checkRequiresGHCRToken(tpl)

	return response
}

// checkRequiresGHCRToken 检查模板是否使用 ghcr.io 镜像
func (api *TemplateAPI) checkRequiresGHCRToken(tpl *runner.AppTemplate) bool {
	composePath := tpl.ComposePath
	if composePath == "" {
		composePath = "docker-compose.yml"
	}

	// 尝试读取 compose 文件
	composeBytes, err := fs.ReadFile(tpl.RootFS, composePath)
	if err != nil {
		// 如果无法读取，返回 false（保守策略）
		return false
	}

	composeContent := string(composeBytes)
	// 检查是否包含 ghcr.io
	return strings.Contains(composeContent, "ghcr.io/")
}

func (api *TemplateAPI) matchKeyword(tpl *runner.AppTemplate, keyword string) bool {
	kw := strings.ToLower(keyword)
	meta := tpl.Meta
	if strings.Contains(strings.ToLower(meta.Name), kw) {
		return true
	}
	if strings.Contains(strings.ToLower(meta.Description), kw) {
		return true
	}
	if strings.Contains(strings.ToLower(meta.Category), kw) {
		return true
	}
	for _, tag := range meta.Tags {
		if strings.Contains(strings.ToLower(tag), kw) {
			return true
		}
	}
	return false
}

func containsFold(values []string, target string) bool {
	for _, v := range values {
		if strings.EqualFold(v, target) {
			return true
		}
	}
	return false
}

func (api *TemplateAPI) writeJSON(w http.ResponseWriter, data interface{}) {
	writeJSON(w, data)
}

func (api *TemplateAPI) writeError(w http.ResponseWriter, message string, status int) {
	writeErrorJSON(w, message, status)
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(data); err != nil {
		logrus.WithError(err).Error("写入 JSON 响应失败")
	}
}

func writeErrorJSON(w http.ResponseWriter, message string, status int) {
	w.WriteHeader(status)
	writeJSON(w, map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

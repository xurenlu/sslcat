package main

import (
	"sort"
	"strings"
)

// TemplatePriority 模板优先级
type TemplatePriority int

const (
	PriorityHigh   TemplatePriority = 1 // 高优先级：AI相关、企业常用工具
	PriorityMedium TemplatePriority = 2 // 中优先级：开发工具、数据库、CMS等
	PriorityLow    TemplatePriority = 3 // 低优先级：小众工具、实验性模板
)

// GetTemplatePriority 获取模板优先级
func GetTemplatePriority(template *TemplateInfo) TemplatePriority {
	id := strings.ToLower(template.ID)
	category := strings.ToLower(template.Category)
	name := strings.ToLower(template.Name)

	// 高优先级：AI相关、企业常用工具
	highPriorityKeywords := []string{
		// AI相关
		"ollama", "localai", "stable-diffusion", "comfyui", "anythingllm", "chatbot",
		"llm", "llama", "gpt", "openai", "chatglm", "baichuan", "qwen", "yi",
		"text-generation", "koboldcpp", "librechat", "open-webui", "continue",
		"langchain", "llamaindex", "chroma", "qdrant", "milvus", "weaviate",
		"pinecone", "vector", "embedding", "rag",
		// 企业常用工具
		"gitlab", "jenkins", "grafana", "prometheus", "portainer", "nginx",
		"mysql", "postgresql", "redis", "mongodb", "elasticsearch",
		"jira", "confluence", "mattermost", "slack", "discord",
		"wordpress", "nextcloud", "gitea", "drone", "woodpecker",
		"metabase", "superset", "redash", "grafana",
		"minio", "s3", "harbor", "nexus",
	}

	// 中优先级：开发工具、数据库、CMS
	mediumPriorityKeywords := []string{
		"cms", "blog", "wiki", "documentation", "crm", "erp",
		"database", "db", "cache", "queue", "message",
		"monitoring", "logging", "analytics", "tracking",
		"api", "gateway", "proxy", "loadbalancer",
		"devops", "ci", "cd", "deploy", "build",
		"forum", "qa", "chat", "support",
		"ecommerce", "shop", "store", "payment",
	}

	for _, keyword := range highPriorityKeywords {
		if strings.Contains(id, keyword) || strings.Contains(category, keyword) || strings.Contains(name, keyword) {
			return PriorityHigh
		}
	}

	for _, keyword := range mediumPriorityKeywords {
		if strings.Contains(id, keyword) || strings.Contains(category, keyword) || strings.Contains(name, keyword) {
			return PriorityMedium
		}
	}

	// 默认低优先级
	return PriorityLow
}

// SortTemplatesByPriority 按优先级排序模板
func SortTemplatesByPriority(templates []TemplateInfo) []TemplateInfo {
	// 创建带优先级的模板列表
	type templateWithPriority struct {
		template TemplateInfo
		priority TemplatePriority
	}

	templatesWithPriority := make([]templateWithPriority, len(templates))
	for i, tpl := range templates {
		templatesWithPriority[i] = templateWithPriority{
			template: tpl,
			priority: GetTemplatePriority(&tpl),
		}
	}

	// 排序：优先级高的在前，同优先级按名称排序
	sort.Slice(templatesWithPriority, func(i, j int) bool {
		if templatesWithPriority[i].priority != templatesWithPriority[j].priority {
			return templatesWithPriority[i].priority < templatesWithPriority[j].priority
		}
		return strings.ToLower(templatesWithPriority[i].template.Name) < strings.ToLower(templatesWithPriority[j].template.Name)
	})

	// 提取排序后的模板
	result := make([]TemplateInfo, len(templates))
	for i, twp := range templatesWithPriority {
		result[i] = twp.template
	}

	return result
}

// GroupTemplatesByPriority 按优先级分组模板
func GroupTemplatesByPriority(templates []TemplateInfo) map[TemplatePriority][]TemplateInfo {
	groups := make(map[TemplatePriority][]TemplateInfo)

	for _, tpl := range templates {
		priority := GetTemplatePriority(&tpl)
		groups[priority] = append(groups[priority], tpl)
	}

	return groups
}


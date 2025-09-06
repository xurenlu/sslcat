package web

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"

	"github.com/xurenlu/sslcat/internal/assets"
	"github.com/xurenlu/sslcat/internal/i18n"

	"github.com/sirupsen/logrus"
)

// TemplateRenderer 模板渲染器
type TemplateRenderer struct {
	templates  map[string]*template.Template
	translator *i18n.Translator
	mutex      sync.RWMutex
	log        *logrus.Entry
}

// NewTemplateRenderer 创建新的模板渲染器
func NewTemplateRenderer(translator *i18n.Translator) *TemplateRenderer {
	return &TemplateRenderer{
		templates:  make(map[string]*template.Template),
		translator: translator,
		log: logrus.WithFields(logrus.Fields{
			"component": "template_renderer",
		}),
	}
}

// DetectLanguageAndRender 检测语言并渲染模板
func (tr *TemplateRenderer) DetectLanguageAndRender(w http.ResponseWriter, r *http.Request, templateName string, data map[string]interface{}) {
	// 检测语言偏好
	lang := tr.detectLanguage(r)
	tr.translator.SetLanguage(lang)

	// 渲染模板
	tr.Render(w, templateName, data)
}

// detectLanguage 检测用户语言偏好
func (tr *TemplateRenderer) detectLanguage(r *http.Request) i18n.SupportedLanguage {
	// 1. 检查 URL 参数
	if langParam := r.URL.Query().Get("lang"); langParam != "" {
		if lang := i18n.SupportedLanguage(langParam); tr.isValidLanguage(lang) {
			return lang
		}
	}

	// 2. 检查 Cookie
	if cookie, err := r.Cookie("language"); err == nil {
		if lang := i18n.SupportedLanguage(cookie.Value); tr.isValidLanguage(lang) {
			return lang
		}
	}

	// 3. 检查 Accept-Language 头
	acceptLang := r.Header.Get("Accept-Language")
	if acceptLang != "" {
		// 简单解析，取第一个语言
		langs := parseAcceptLanguage(acceptLang)
		for _, lang := range langs {
			if supportedLang := tr.mapToSupportedLanguage(lang); tr.isValidLanguage(supportedLang) {
				return supportedLang
			}
		}
	}

	// 4. 默认语言
	return i18n.LangZhCN
}

// parseAcceptLanguage 解析 Accept-Language 头
func parseAcceptLanguage(acceptLang string) []string {
	// 简化实现，实际应该考虑权重
	var langs []string
	parts := strings.Split(acceptLang, ",")
	for _, part := range parts {
		lang := strings.TrimSpace(strings.Split(part, ";")[0])
		if lang != "" {
			langs = append(langs, lang)
		}
	}
	return langs
}

// mapToSupportedLanguage 将语言代码映射到支持的语言
func (tr *TemplateRenderer) mapToSupportedLanguage(lang string) i18n.SupportedLanguage {
	switch strings.ToLower(lang) {
	case "zh", "zh-cn", "zh-hans":
		return i18n.LangZhCN
	case "en", "en-us":
		return i18n.LangEnUS
	case "ja", "ja-jp":
		return i18n.LangJaJP
	case "es", "es-es":
		return i18n.LangEsES
	case "fr", "fr-fr":
		return i18n.LangFrFR
	case "ru", "ru-ru":
		return i18n.LangRuRU
	default:
		return i18n.LangZhCN
	}
}

// isValidLanguage 检查是否为有效的支持语言
func (tr *TemplateRenderer) isValidLanguage(lang i18n.SupportedLanguage) bool {
	supportedLangs := tr.translator.GetSupportedLanguages()
	_, exists := supportedLangs[lang]
	return exists
}

// Render 渲染模板
func (tr *TemplateRenderer) Render(w http.ResponseWriter, templateName string, data map[string]interface{}) {
	tr.mutex.RLock()
	tmpl, exists := tr.templates[templateName]
	tr.mutex.RUnlock()

	if !exists {
		// 尝试从嵌入资源加载模板
		if err := tr.loadTemplate(templateName); err != nil {
			tr.log.Errorf("加载模板失败 %s: %v", templateName, err)
			http.Error(w, "模板加载失败", http.StatusInternalServerError)
			return
		}

		tr.mutex.RLock()
		tmpl = tr.templates[templateName]
		tr.mutex.RUnlock()
	}

	if tmpl == nil {
		tr.log.Errorf("模板不存在: %s", templateName)
		http.Error(w, "模板不存在", http.StatusNotFound)
		return
	}

	// 添加翻译函数到模板数据
	if data == nil {
		data = make(map[string]interface{})
	}
	data["T"] = tr.translator.T

	// 渲染模板
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		tr.log.Errorf("渲染模板失败 %s: %v", templateName, err)
		http.Error(w, "模板渲染失败", http.StatusInternalServerError)
		return
	}
}

// loadTemplate 从嵌入资源加载模板
func (tr *TemplateRenderer) loadTemplate(templateName string) error {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()

	// 从嵌入资源读取模板内容
	templateContent, err := assets.ReadTemplate(templateName)
	if err != nil {
		return fmt.Errorf("读取模板文件失败: %w", err)
	}

	// 创建带翻译函数的模板
	funcMap := template.FuncMap{
		"t": tr.translator.T,
		"T": tr.translator.T,
	}

	// 解析模板
	tmpl, err := template.New(templateName).Funcs(funcMap).Parse(string(templateContent))
	if err != nil {
		return fmt.Errorf("解析模板失败: %w", err)
	}

	tr.templates[templateName] = tmpl
	tr.log.Infof("成功加载模板: %s", templateName)
	return nil
}

// PreloadTemplates 预加载所有模板
func (tr *TemplateRenderer) PreloadTemplates() error {
	templateNames, err := assets.ListTemplates()
	if err != nil {
		return fmt.Errorf("获取模板列表失败: %w", err)
	}

	for _, name := range templateNames {
		if err := tr.loadTemplate(name); err != nil {
			tr.log.Warnf("预加载模板失败 %s: %v", name, err)
		}
	}

	return nil
}

// GetLoadedTemplates 获取已加载的模板列表
func (tr *TemplateRenderer) GetLoadedTemplates() []string {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()

	var templates []string
	for name := range tr.templates {
		templates = append(templates, name)
	}
	return templates
}

// TemplateExists 检查模板是否存在
func (tr *TemplateRenderer) TemplateExists(templateName string) bool {
	tr.mutex.RLock()
	defer tr.mutex.RUnlock()

	_, exists := tr.templates[templateName]
	return exists
}

// ClearCache 清理模板缓存
func (tr *TemplateRenderer) ClearCache() {
	tr.mutex.Lock()
	defer tr.mutex.Unlock()

	tr.templates = make(map[string]*template.Template)
	tr.log.Info("模板缓存已清理")
}

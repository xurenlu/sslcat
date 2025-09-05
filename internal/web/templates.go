package web

import (
	"fmt"
	"html/template"
	"net/http"
	"sync"

	"withssl/internal/assets"
	"withssl/internal/i18n"

	"github.com/sirupsen/logrus"
)

// TemplateRenderer 模板渲染器
type TemplateRenderer struct {
	templates  map[string]*template.Template
	translator *i18n.Translator
	mutex      sync.RWMutex
	log        *logrus.Entry
}

// NewTemplateRenderer 创建模板渲染器
func NewTemplateRenderer(translator *i18n.Translator) *TemplateRenderer {
	renderer := &TemplateRenderer{
		templates:  make(map[string]*template.Template),
		translator: translator,
		log: logrus.WithFields(logrus.Fields{
			"component": "template_renderer",
		}),
	}

	// 加载所有模板
	if err := renderer.loadTemplates(); err != nil {
		renderer.log.Errorf("加载模板失败: %v", err)
	}

	return renderer
}

// loadTemplates 加载所有模板
func (tr *TemplateRenderer) loadTemplates() error {
	templateFiles, err := assets.ListTemplates()
	if err != nil {
		return err
	}

	// 创建模板函数
	funcMap := template.FuncMap{
		// 国际化函数
		"t": func(key string, args ...interface{}) string {
			return tr.translator.T(key, args...)
		},
		"tLang": func(lang i18n.SupportedLanguage, key string, args ...interface{}) string {
			return tr.translator.TLang(lang, key, args...)
		},
		"currentLang": func() i18n.SupportedLanguage {
			return tr.translator.GetCurrentLanguage()
		},
		"supportedLangs": func() map[i18n.SupportedLanguage]*i18n.LanguageInfo {
			return tr.translator.GetSupportedLanguages()
		},
		
		
		// 通用工具函数
		"formatNumber": func(n interface{}) string {
			switch v := n.(type) {
			case int:
				if v >= 1000000 {
					return fmt.Sprintf("%.1fM", float64(v)/1000000)
				} else if v >= 1000 {
					return fmt.Sprintf("%.1fK", float64(v)/1000)
				}
				return fmt.Sprintf("%d", v)
			case int64:
				if v >= 1000000 {
					return fmt.Sprintf("%.1fM", float64(v)/1000000)
				} else if v >= 1000 {
					return fmt.Sprintf("%.1fK", float64(v)/1000)
				}
				return fmt.Sprintf("%d", v)
			case float64:
				if v >= 1000000 {
					return fmt.Sprintf("%.1fM", v/1000000)
				} else if v >= 1000 {
					return fmt.Sprintf("%.1fK", v/1000)
				}
				return fmt.Sprintf("%.0f", v)
			default:
				return fmt.Sprintf("%v", v)
			}
		},
		"formatBytes": func(bytes interface{}) string {
			var b int64
			switch v := bytes.(type) {
			case int:
				b = int64(v)
			case int64:
				b = v
			case float64:
				b = int64(v)
			default:
				return fmt.Sprintf("%v", bytes)
			}
			
			const unit = 1024
			if b < unit {
				return fmt.Sprintf("%d B", b)
			}
			div, exp := int64(unit), 0
			for n := b / unit; n >= unit; n /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
		},
		"formatDuration": func(seconds interface{}) string {
			var s int64
			switch v := seconds.(type) {
			case int:
				s = int64(v)
			case int64:
				s = v
			case float64:
				s = int64(v)
			default:
				return fmt.Sprintf("%v", seconds)
			}
			
			if s < 60 {
				return fmt.Sprintf("%ds", s)
			} else if s < 3600 {
				return fmt.Sprintf("%dm%ds", s/60, s%60)
			} else {
				return fmt.Sprintf("%dh%dm", s/3600, (s%3600)/60)
			}
		},
	}

	tr.mutex.Lock()
	defer tr.mutex.Unlock()

	for _, fileName := range templateFiles {
		// 读取模板内容
		content, err := assets.ReadTemplate(fileName)
		if err != nil {
			tr.log.Errorf("读取模板文件失败 %s: %v", fileName, err)
			continue
		}

		// 解析模板
		tmpl, err := template.New(fileName).Funcs(funcMap).Parse(string(content))
		if err != nil {
			tr.log.Errorf("解析模板失败 %s: %v", fileName, err)
			continue
		}

		// 存储模板
		tr.templates[fileName] = tmpl
		tr.log.Debugf("加载模板: %s", fileName)
	}

	tr.log.Infof("成功加载 %d 个模板", len(tr.templates))
	return nil
}

// Render 渲染模板
func (tr *TemplateRenderer) Render(w http.ResponseWriter, templateName string, data interface{}) error {
	tr.mutex.RLock()
	tmpl, exists := tr.templates[templateName]
	tr.mutex.RUnlock()

	if !exists {
		tr.log.Errorf("模板不存在: %s", templateName)
		http.Error(w, "模板不存在", http.StatusInternalServerError)
		return nil
	}

	// 设置响应头
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// 渲染模板
	if err := tmpl.Execute(w, data); err != nil {
		tr.log.Errorf("渲染模板失败 %s: %v", templateName, err)
		http.Error(w, "渲染失败", http.StatusInternalServerError)
		return err
	}

	return nil
}

// RenderWithLang 使用指定语言渲染模板
func (tr *TemplateRenderer) RenderWithLang(w http.ResponseWriter, templateName string, lang i18n.SupportedLanguage, data interface{}) error {
	// 临时切换语言
	originalLang := tr.translator.GetCurrentLanguage()
	if err := tr.translator.SetLanguage(lang); err != nil {
		tr.log.Warnf("切换语言失败 %s: %v", lang, err)
	}

	// 渲染模板
	err := tr.Render(w, templateName, data)

	// 恢复原始语言
	if originalLang != lang {
		tr.translator.SetLanguage(originalLang)
	}

	return err
}

// DetectLanguageAndRender 检测语言并渲染模板
func (tr *TemplateRenderer) DetectLanguageAndRender(w http.ResponseWriter, r *http.Request, templateName string, data interface{}) error {
	// 从请求中检测语言
	acceptLanguage := r.Header.Get("Accept-Language")
	detectedLang := tr.translator.DetectLanguageFromRequest(acceptLanguage)

	// 检查是否有语言参数
	if langParam := r.URL.Query().Get("lang"); langParam != "" {
		if supportedLang := i18n.SupportedLanguage(langParam); tr.isSupportedLanguage(supportedLang) {
			detectedLang = supportedLang
		}
	}

	// 检查Cookie中的语言设置
	if cookie, err := r.Cookie("language"); err == nil {
		if supportedLang := i18n.SupportedLanguage(cookie.Value); tr.isSupportedLanguage(supportedLang) {
			detectedLang = supportedLang
		}
	}

	return tr.RenderWithLang(w, templateName, detectedLang, data)
}

// isSupportedLanguage 检查是否为支持的语言
func (tr *TemplateRenderer) isSupportedLanguage(lang i18n.SupportedLanguage) bool {
	supportedLangs := tr.translator.GetSupportedLanguages()
	_, exists := supportedLangs[lang]
	return exists
}

// ReloadTemplates 重新加载模板
func (tr *TemplateRenderer) ReloadTemplates() error {
	tr.log.Info("重新加载模板...")
	return tr.loadTemplates()
}

// GetTemplateList 获取模板列表
func (tr *TemplateRenderer) GetTemplateList() []string {
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

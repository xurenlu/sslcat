package i18n

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// SupportedLanguage 支持的语言
type SupportedLanguage string

const (
	LangZhCN SupportedLanguage = "zh-CN" // 中文简体
	LangZhTW SupportedLanguage = "zh-TW" // 中文繁体
	LangEnUS SupportedLanguage = "en-US" // 英语
	LangJaJP SupportedLanguage = "ja-JP" // 日语
	LangEsES SupportedLanguage = "es-ES" // 西班牙语
	LangFrFR SupportedLanguage = "fr-FR" // 法语
	LangRuRU SupportedLanguage = "ru-RU" // 俄语
	LangKoKR SupportedLanguage = "ko-KR" // 韩语
	LangDeDE SupportedLanguage = "de-DE" // 德语
)

// LanguageInfo 语言信息
type LanguageInfo struct {
	Code         SupportedLanguage `json:"code"`
	Name         string            `json:"name"`
	NativeName   string            `json:"native_name"`
	Flag         string            `json:"flag"`
	RTL          bool              `json:"rtl"`          // 是否从右到左
	Enabled      bool              `json:"enabled"`      // 是否启用
	Progress     float64           `json:"progress"`     // 翻译完成度
	LastUpdated  string            `json:"last_updated"` // 最后更新时间
}

// Translator 翻译器
type Translator struct {
	defaultLang   SupportedLanguage
	currentLang   SupportedLanguage
	translations  map[SupportedLanguage]map[string]string
	languages     map[SupportedLanguage]*LanguageInfo
	fallbacks     map[SupportedLanguage]SupportedLanguage
	translationsDir string
	mutex         sync.RWMutex
	log           *logrus.Entry
}

// NewTranslator 创建翻译器
func NewTranslator(defaultLang SupportedLanguage, translationsDir string) *Translator {
	t := &Translator{
		defaultLang:     defaultLang,
		currentLang:     defaultLang,
		translations:    make(map[SupportedLanguage]map[string]string),
		languages:       make(map[SupportedLanguage]*LanguageInfo),
		translationsDir: translationsDir,
		log: logrus.WithFields(logrus.Fields{
			"component": "i18n_translator",
		}),
	}

	// 初始化支持的语言
	t.initLanguages()
	
	// 设置回退语言
	t.initFallbacks()
	
	// 加载翻译文件
	if err := t.loadTranslations(); err != nil {
		t.log.Errorf("加载翻译文件失败: %v", err)
	}

	return t
}

// initLanguages 初始化支持的语言
func (t *Translator) initLanguages() {
	t.languages = map[SupportedLanguage]*LanguageInfo{
		LangZhCN: {
			Code:       LangZhCN,
			Name:       "Chinese Simplified",
			NativeName: "简体中文",
			Flag:       "🇨🇳",
			RTL:        false,
			Enabled:    true,
			Progress:   100.0,
		},
		LangZhTW: {
			Code:       LangZhTW,
			Name:       "Chinese Traditional",
			NativeName: "繁體中文",
			Flag:       "🇹🇼",
			RTL:        false,
			Enabled:    true,
			Progress:   90.0,
		},
		LangEnUS: {
			Code:       LangEnUS,
			Name:       "English",
			NativeName: "English",
			Flag:       "🇺🇸",
			RTL:        false,
			Enabled:    true,
			Progress:   100.0,
		},
		LangJaJP: {
			Code:       LangJaJP,
			Name:       "Japanese",
			NativeName: "日本語",
			Flag:       "🇯🇵",
			RTL:        false,
			Enabled:    true,
			Progress:   95.0,
		},
		LangEsES: {
			Code:       LangEsES,
			Name:       "Spanish",
			NativeName: "Español",
			Flag:       "🇪🇸",
			RTL:        false,
			Enabled:    true,
			Progress:   85.0,
		},
		LangFrFR: {
			Code:       LangFrFR,
			Name:       "French",
			NativeName: "Français",
			Flag:       "🇫🇷",
			RTL:        false,
			Enabled:    true,
			Progress:   85.0,
		},
		LangRuRU: {
			Code:       LangRuRU,
			Name:       "Russian",
			NativeName: "Русский",
			Flag:       "🇷🇺",
			RTL:        false,
			Enabled:    true,
			Progress:   80.0,
		},
		LangKoKR: {
			Code:       LangKoKR,
			Name:       "Korean",
			NativeName: "한국어",
			Flag:       "🇰🇷",
			RTL:        false,
			Enabled:    false,
			Progress:   60.0,
		},
		LangDeDE: {
			Code:       LangDeDE,
			Name:       "German",
			NativeName: "Deutsch",
			Flag:       "🇩🇪",
			RTL:        false,
			Enabled:    false,
			Progress:   60.0,
		},
	}
}

// initFallbacks 初始化回退语言
func (t *Translator) initFallbacks() {
	t.fallbacks = map[SupportedLanguage]SupportedLanguage{
		LangZhTW: LangZhCN, // 繁体中文回退到简体中文
		LangJaJP: LangEnUS, // 日语回退到英语
		LangEsES: LangEnUS, // 西班牙语回退到英语
		LangFrFR: LangEnUS, // 法语回退到英语
		LangRuRU: LangEnUS, // 俄语回退到英语
		LangKoKR: LangEnUS, // 韩语回退到英语
		LangDeDE: LangEnUS, // 德语回退到英语
	}
}

// loadTranslations 加载翻译文件
func (t *Translator) loadTranslations() error {
	// 创建翻译目录（如果不存在）
	if err := os.MkdirAll(t.translationsDir, 0755); err != nil {
		return fmt.Errorf("创建翻译目录失败: %w", err)
	}

	// 遍历翻译目录
	return filepath.WalkDir(t.translationsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}

		// 从文件名提取语言代码
		filename := strings.TrimSuffix(d.Name(), ".json")
		lang := SupportedLanguage(filename)

		// 检查是否为支持的语言
		if _, exists := t.languages[lang]; !exists {
			t.log.Warnf("不支持的语言文件: %s", path)
			return nil
		}

		// 加载翻译数据
		if err := t.loadLanguageFile(lang, path); err != nil {
			t.log.Errorf("加载语言文件失败 %s: %v", path, err)
			return nil // 继续加载其他文件
		}

		t.log.Infof("成功加载语言文件: %s", path)
		return nil
	})
}

// loadLanguageFile 加载特定语言文件
func (t *Translator) loadLanguageFile(lang SupportedLanguage, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取文件失败: %w", err)
	}

	var translations map[string]string
	if err := json.Unmarshal(data, &translations); err != nil {
		return fmt.Errorf("解析JSON失败: %w", err)
	}

	t.mutex.Lock()
	t.translations[lang] = translations
	t.mutex.Unlock()

	return nil
}

// T 翻译函数
func (t *Translator) T(key string, args ...interface{}) string {
	return t.TLang(t.currentLang, key, args...)
}

// TLang 翻译指定语言的文本
func (t *Translator) TLang(lang SupportedLanguage, key string, args ...interface{}) string {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	// 尝试当前语言
	if translations, exists := t.translations[lang]; exists {
		if text, found := translations[key]; found {
			if len(args) > 0 {
				return fmt.Sprintf(text, args...)
			}
			return text
		}
	}

	// 尝试回退语言
	if fallback, exists := t.fallbacks[lang]; exists {
		if translations, exists := t.translations[fallback]; exists {
			if text, found := translations[key]; found {
				if len(args) > 0 {
					return fmt.Sprintf(text, args...)
				}
				return text
			}
		}
	}

	// 尝试默认语言
	if lang != t.defaultLang {
		if translations, exists := t.translations[t.defaultLang]; exists {
			if text, found := translations[key]; found {
				if len(args) > 0 {
					return fmt.Sprintf(text, args...)
				}
				return text
			}
		}
	}

	// 最后返回原始key
	if len(args) > 0 {
		return fmt.Sprintf(key, args...)
	}
	return key
}

// SetLanguage 设置当前语言
func (t *Translator) SetLanguage(lang SupportedLanguage) error {
	if _, exists := t.languages[lang]; !exists {
		return fmt.Errorf("不支持的语言: %s", lang)
	}

	if !t.languages[lang].Enabled {
		return fmt.Errorf("语言未启用: %s", lang)
	}

	t.mutex.Lock()
	changed := t.currentLang != lang
	t.currentLang = lang
	t.mutex.Unlock()

	if changed {
		// 降低日志噪音
		t.log.Debugf("语言切换为: %s", lang)
	}
	return nil
}

// GetCurrentLanguage 获取当前语言
func (t *Translator) GetCurrentLanguage() SupportedLanguage {
	t.mutex.RLock()
	defer t.mutex.RUnlock()
	return t.currentLang
}

// GetSupportedLanguages 获取支持的语言列表
func (t *Translator) GetSupportedLanguages() map[SupportedLanguage]*LanguageInfo {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	result := make(map[SupportedLanguage]*LanguageInfo)
	for code, info := range t.languages {
		if info.Enabled {
			result[code] = &LanguageInfo{
				Code:        info.Code,
				Name:        info.Name,
				NativeName:  info.NativeName,
				Flag:        info.Flag,
				RTL:         info.RTL,
				Enabled:     info.Enabled,
				Progress:    info.Progress,
				LastUpdated: info.LastUpdated,
			}
		}
	}

	return result
}

// DetectLanguageFromRequest 从HTTP请求检测语言
func (t *Translator) DetectLanguageFromRequest(acceptLanguage string) SupportedLanguage {
	if acceptLanguage == "" {
		return t.defaultLang
	}

	// 解析Accept-Language头
	languages := t.parseAcceptLanguage(acceptLanguage)

	// 按优先级匹配支持的语言
	for _, lang := range languages {
		if supportedLang := t.matchLanguage(lang); supportedLang != "" {
			if t.languages[supportedLang].Enabled {
				return supportedLang
			}
		}
	}

	return t.defaultLang
}

// parseAcceptLanguage 解析Accept-Language头
func (t *Translator) parseAcceptLanguage(acceptLanguage string) []string {
	var languages []string

	parts := strings.Split(acceptLanguage, ",")
	for _, part := range parts {
		// 移除质量值 (q=0.9)
		lang := strings.TrimSpace(strings.Split(part, ";")[0])
		if lang != "" {
			languages = append(languages, lang)
		}
	}

	return languages
}

// matchLanguage 匹配语言
func (t *Translator) matchLanguage(lang string) SupportedLanguage {
	lang = strings.ToLower(lang)

	// 精确匹配
	for supportedLang := range t.languages {
		if strings.ToLower(string(supportedLang)) == lang {
			return supportedLang
		}
	}

	// 语言代码匹配 (zh-CN -> zh)
	langCode := strings.Split(lang, "-")[0]
	for supportedLang := range t.languages {
		supportedCode := strings.Split(strings.ToLower(string(supportedLang)), "-")[0]
		if supportedCode == langCode {
			return supportedLang
		}
	}

	return ""
}

// HasTranslation 检查是否有翻译
func (t *Translator) HasTranslation(key string) bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	if translations, exists := t.translations[t.currentLang]; exists {
		_, found := translations[key]
		return found
	}

	return false
}

// GetTranslationKeys 获取所有翻译键
func (t *Translator) GetTranslationKeys(lang SupportedLanguage) []string {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	var keys []string
	if translations, exists := t.translations[lang]; exists {
		for key := range translations {
			keys = append(keys, key)
		}
	}

	return keys
}

// GetMissingTranslations 获取缺失的翻译
func (t *Translator) GetMissingTranslations(lang SupportedLanguage) []string {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	var missing []string
	
	// 以默认语言为基准
	defaultTranslations, exists := t.translations[t.defaultLang]
	if !exists {
		return missing
	}

	langTranslations := t.translations[lang]
	
	for key := range defaultTranslations {
		if _, found := langTranslations[key]; !found {
			missing = append(missing, key)
		}
	}

	return missing
}

// GetStats 获取翻译统计
func (t *Translator) GetStats() map[string]interface{} {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	stats := map[string]interface{}{
		"current_language":    t.currentLang,
		"default_language":    t.defaultLang,
		"supported_languages": len(t.languages),
		"enabled_languages":   0,
		"total_translations":  0,
	}

	var enabledCount int
	var totalTranslations int

	for _, lang := range t.languages {
		if lang.Enabled {
			enabledCount++
		}
	}

	for _, translations := range t.translations {
		totalTranslations += len(translations)
	}

	stats["enabled_languages"] = enabledCount
	stats["total_translations"] = totalTranslations

	// 各语言翻译统计
	langStats := make(map[string]interface{})
	for lang, translations := range t.translations {
		langStats[string(lang)] = map[string]interface{}{
			"translation_count": len(translations),
			"progress":         t.languages[lang].Progress,
		}
	}
	stats["language_stats"] = langStats

	return stats
}

// CreateTranslationTemplate 创建翻译模板
func (t *Translator) CreateTranslationTemplate(keys []string) map[string]string {
	template := make(map[string]string)
	for _, key := range keys {
		template[key] = ""
	}
	return template
}

// SaveTranslations 保存翻译到文件
func (t *Translator) SaveTranslations(lang SupportedLanguage, translations map[string]string) error {
	t.mutex.Lock()
	t.translations[lang] = translations
	t.mutex.Unlock()

	// 保存到文件
	filePath := filepath.Join(t.translationsDir, string(lang)+".json")
	data, err := json.MarshalIndent(translations, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化翻译数据失败: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("保存翻译文件失败: %w", err)
	}

	t.log.Infof("翻译文件已保存: %s", filePath)
	return nil
}

package assets

import (
	"embed"
	"io/fs"
)

// 嵌入HTML模板文件
//go:embed templates/*.html
var TemplatesFS embed.FS

// 嵌入翻译文件
//go:embed i18n/*.json
var I18nFS embed.FS

// GetTemplatesFS 获取模板文件系统
func GetTemplatesFS() fs.FS {
	templatesFS, err := fs.Sub(TemplatesFS, "templates")
	if err != nil {
		panic(err)
	}
	return templatesFS
}

// GetI18nFS 获取翻译文件系统
func GetI18nFS() fs.FS {
	i18nFS, err := fs.Sub(I18nFS, "i18n")
	if err != nil {
		panic(err)
	}
	return i18nFS
}

// ReadTemplate 读取模板文件
func ReadTemplate(name string) ([]byte, error) {
	return TemplatesFS.ReadFile("templates/" + name)
}

// ReadI18nFile 读取翻译文件
func ReadI18nFile(name string) ([]byte, error) {
	return I18nFS.ReadFile("i18n/" + name)
}

// ListTemplates 列出所有模板文件
func ListTemplates() ([]string, error) {
	entries, err := TemplatesFS.ReadDir("templates")
	if err != nil {
		return nil, err
	}
	
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && entry.Name()[len(entry.Name())-5:] == ".html" {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}

// ListI18nFiles 列出所有翻译文件
func ListI18nFiles() ([]string, error) {
	entries, err := I18nFS.ReadDir("i18n")
	if err != nil {
		return nil, err
	}
	
	var files []string
	for _, entry := range entries {
		if !entry.IsDir() && entry.Name()[len(entry.Name())-5:] == ".json" {
			files = append(files, entry.Name())
		}
	}
	return files, nil
}

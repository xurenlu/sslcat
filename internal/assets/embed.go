package assets

import (
	"embed"
	"io/fs"
)

// 嵌入翻译文件
//
//go:embed i18n/*.json
var I18nFS embed.FS

// 嵌入静态资源文件（CSS, JS, 字体）
//
//go:embed static/css/* static/js/* static/fonts/*
var StaticFS embed.FS

// GetI18nFS 获取翻译文件系统
func GetI18nFS() fs.FS {
	i18nFS, err := fs.Sub(I18nFS, "i18n")
	if err != nil {
		panic(err)
	}
	return i18nFS
}

// ReadI18nFile 读取翻译文件
func ReadI18nFile(name string) ([]byte, error) {
	return I18nFS.ReadFile("i18n/" + name)
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

// GetStaticFS 获取静态资源文件系统
func GetStaticFS() fs.FS {
	staticFS, err := fs.Sub(StaticFS, "static")
	if err != nil {
		panic(err)
	}
	return staticFS
}

// ReadStatic 读取静态资源文件
func ReadStatic(name string) ([]byte, error) {
	return StaticFS.ReadFile("static/" + name)
}

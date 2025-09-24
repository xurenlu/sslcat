package assets

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:frontend
var frontendFiles embed.FS

// GetFrontendFS 返回前端静态文件的文件系统
func GetFrontendFS() (fs.FS, error) {
	return fs.Sub(frontendFiles, "frontend")
}

// GetFrontendHandler 返回用于服务前端文件的 HTTP 处理器
func GetFrontendHandler() (http.Handler, error) {
	fsys, err := GetFrontendFS()
	if err != nil {
		return nil, err
	}
	return http.FileServer(http.FS(fsys)), nil
}

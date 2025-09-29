package cache

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"path/filepath"
	"strings"
)

// MIMEDetector 文件类型检测器
type MIMEDetector struct {
	// 文件头魔数映射
	magicNumbers map[string][]byte
	// 扩展名到MIME类型的映射
	extensionMap map[string]string
}

// NewMIMEDetector 创建新的MIME检测器
func NewMIMEDetector() *MIMEDetector {
	detector := &MIMEDetector{
		magicNumbers: make(map[string][]byte),
		extensionMap: make(map[string]string),
	}

	// 初始化文件头魔数
	detector.initMagicNumbers()

	// 初始化扩展名映射
	detector.initExtensionMap()

	return detector
}

// initMagicNumbers 初始化文件头魔数
func (md *MIMEDetector) initMagicNumbers() {
	// 图片格式
	md.magicNumbers["image/jpeg"] = []byte{0xFF, 0xD8, 0xFF}
	md.magicNumbers["image/png"] = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	md.magicNumbers["image/gif"] = []byte{0x47, 0x49, 0x46, 0x38}  // GIF8
	md.magicNumbers["image/webp"] = []byte{0x52, 0x49, 0x46, 0x46} // RIFF
	md.magicNumbers["image/bmp"] = []byte{0x42, 0x4D}              // BM
	md.magicNumbers["image/tiff"] = []byte{0x49, 0x49, 0x2A, 0x00} // II* (little endian)
	md.magicNumbers["image/tiff"] = []byte{0x4D, 0x4D, 0x00, 0x2A} // MM* (big endian)

	// 文档格式
	md.magicNumbers["application/pdf"] = []byte{0x25, 0x50, 0x44, 0x46} // %PDF
	md.magicNumbers["application/zip"] = []byte{0x50, 0x4B, 0x03, 0x04} // PK
	md.magicNumbers["application/x-rar"] = []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}
	md.magicNumbers["application/x-7z"] = []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}

	// 音频格式
	md.magicNumbers["audio/mpeg"] = []byte{0xFF, 0xFB}            // MP3
	md.magicNumbers["audio/wav"] = []byte{0x52, 0x49, 0x46, 0x46} // RIFF
	md.magicNumbers["audio/ogg"] = []byte{0x4F, 0x67, 0x67, 0x53} // OggS

	// 视频格式
	md.magicNumbers["video/mp4"] = []byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70} // ftyp
	md.magicNumbers["video/avi"] = []byte{0x52, 0x49, 0x46, 0x46}                         // RIFF

	// 字体格式
	md.magicNumbers["font/woff"] = []byte{0x77, 0x4F, 0x46, 0x46}  // wOFF
	md.magicNumbers["font/woff2"] = []byte{0x77, 0x4F, 0x46, 0x32} // wOF2
	md.magicNumbers["font/ttf"] = []byte{0x00, 0x01, 0x00, 0x00}   // TTF
	md.magicNumbers["font/otf"] = []byte{0x4F, 0x54, 0x54, 0x4F}   // OTTO

	// 文本格式
	md.magicNumbers["text/html"] = []byte{0x3C, 0x68, 0x74, 0x6D, 0x6C} // <html
	md.magicNumbers["text/xml"] = []byte{0x3C, 0x3F, 0x78, 0x6D, 0x6C}  // <?xml
	md.magicNumbers["application/json"] = []byte{0x7B}                  // {
	md.magicNumbers["application/json"] = []byte{0x5B}                  // [
}

// initExtensionMap 初始化扩展名映射
func (md *MIMEDetector) initExtensionMap() {
	// 图片格式
	md.extensionMap[".jpg"] = "image/jpeg"
	md.extensionMap[".jpeg"] = "image/jpeg"
	md.extensionMap[".png"] = "image/png"
	md.extensionMap[".gif"] = "image/gif"
	md.extensionMap[".webp"] = "image/webp"
	md.extensionMap[".bmp"] = "image/bmp"
	md.extensionMap[".tiff"] = "image/tiff"
	md.extensionMap[".tif"] = "image/tiff"
	md.extensionMap[".svg"] = "image/svg+xml"
	md.extensionMap[".ico"] = "image/x-icon"

	// 文档格式
	md.extensionMap[".pdf"] = "application/pdf"
	md.extensionMap[".zip"] = "application/zip"
	md.extensionMap[".rar"] = "application/x-rar-compressed"
	md.extensionMap[".7z"] = "application/x-7z-compressed"
	md.extensionMap[".tar"] = "application/x-tar"
	md.extensionMap[".gz"] = "application/gzip"

	// 音频格式
	md.extensionMap[".mp3"] = "audio/mpeg"
	md.extensionMap[".wav"] = "audio/wav"
	md.extensionMap[".ogg"] = "audio/ogg"
	md.extensionMap[".m4a"] = "audio/mp4"

	// 视频格式
	md.extensionMap[".mp4"] = "video/mp4"
	md.extensionMap[".avi"] = "video/x-msvideo"
	md.extensionMap[".mov"] = "video/quicktime"
	md.extensionMap[".wmv"] = "video/x-ms-wmv"
	md.extensionMap[".flv"] = "video/x-flv"
	md.extensionMap[".webm"] = "video/webm"

	// 字体格式
	md.extensionMap[".woff"] = "font/woff"
	md.extensionMap[".woff2"] = "font/woff2"
	md.extensionMap[".ttf"] = "font/ttf"
	md.extensionMap[".otf"] = "font/otf"
	md.extensionMap[".eot"] = "application/vnd.ms-fontobject"

	// 文本格式
	md.extensionMap[".html"] = "text/html"
	md.extensionMap[".htm"] = "text/html"
	md.extensionMap[".css"] = "text/css"
	md.extensionMap[".js"] = "application/javascript"
	md.extensionMap[".json"] = "application/json"
	md.extensionMap[".xml"] = "application/xml"
	md.extensionMap[".txt"] = "text/plain"
	md.extensionMap[".csv"] = "text/csv"
	md.extensionMap[".md"] = "text/markdown"
	md.extensionMap[".yaml"] = "application/x-yaml"
	md.extensionMap[".yml"] = "application/x-yaml"
}

// DetectMIME 检测文件MIME类型
func (md *MIMEDetector) DetectMIME(filename string, data []byte) string {
	// 1. 首先尝试通过文件头魔数检测
	if mimeType := md.detectByMagicNumber(data); mimeType != "" {
		return mimeType
	}

	// 2. 通过扩展名检测
	if mimeType := md.detectByExtension(filename); mimeType != "" {
		return mimeType
	}

	// 3. 使用系统MIME类型检测
	if mimeType := mime.TypeByExtension(filepath.Ext(filename)); mimeType != "" {
		return mimeType
	}

	// 4. 默认返回二进制类型
	return "application/octet-stream"
}

// detectByMagicNumber 通过文件头魔数检测
func (md *MIMEDetector) detectByMagicNumber(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	// 读取文件头（最多32字节）
	headerSize := 32
	if len(data) < headerSize {
		headerSize = len(data)
	}
	header := data[:headerSize]

	// 检查各种文件头魔数
	for mimeType, magic := range md.magicNumbers {
		if len(header) >= len(magic) && bytes.HasPrefix(header, magic) {
			// 特殊处理：WebP需要进一步验证
			if mimeType == "image/webp" {
				if len(header) >= 12 &&
					bytes.HasPrefix(header[8:], []byte{0x57, 0x45, 0x42, 0x50}) { // WEBP
					return mimeType
				}
				continue
			}
			return mimeType
		}
	}

	// 特殊处理：检查文本文件
	if md.isTextFile(header) {
		return "text/plain"
	}

	return ""
}

// detectByExtension 通过扩展名检测
func (md *MIMEDetector) detectByExtension(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	return md.extensionMap[ext]
}

// isTextFile 检查是否为文本文件
func (md *MIMEDetector) isTextFile(header []byte) bool {
	// 检查是否包含非打印字符
	for _, b := range header {
		if b < 32 && b != 9 && b != 10 && b != 13 { // 排除制表符、换行符、回车符
			return false
		}
	}
	return true
}

// DetectMIMEFromReader 从Reader检测MIME类型
func (md *MIMEDetector) DetectMIMEFromReader(filename string, reader io.Reader) (string, error) {
	// 读取文件头用于检测
	header := make([]byte, 32)
	n, err := reader.Read(header)
	if err != nil && err != io.EOF {
		return "", err
	}

	// 检测MIME类型
	mimeType := md.DetectMIME(filename, header[:n])
	return mimeType, nil
}

// GetMIMEDescription 获取MIME类型描述
func (md *MIMEDetector) GetMIMEDescription(mimeType string) string {
	descriptions := map[string]string{
		"image/jpeg":             "JPEG图片",
		"image/png":              "PNG图片",
		"image/gif":              "GIF图片",
		"image/webp":             "WebP图片",
		"image/svg+xml":          "SVG矢量图",
		"application/pdf":        "PDF文档",
		"text/html":              "HTML网页",
		"text/css":               "CSS样式表",
		"application/javascript": "JavaScript脚本",
		"application/json":       "JSON数据",
		"text/plain":             "纯文本",
		"application/zip":        "ZIP压缩包",
		"audio/mpeg":             "MP3音频",
		"video/mp4":              "MP4视频",
		"font/woff":              "WOFF字体",
		"font/woff2":             "WOFF2字体",
	}

	if desc, exists := descriptions[mimeType]; exists {
		return desc
	}
	return fmt.Sprintf("未知类型: %s", mimeType)
}

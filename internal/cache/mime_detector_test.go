package cache

import (
	"testing"
)

func TestMIMEDetector_DetectMIME(t *testing.T) {
	detector := NewMIMEDetector()

	tests := []struct {
		name     string
		filename string
		data     []byte
		expected string
	}{
		{
			name:     "JPEG图片",
			filename: "test.jpg",
			data:     []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46},
			expected: "image/jpeg",
		},
		{
			name:     "PNG图片",
			filename: "test.png",
			data:     []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D},
			expected: "image/png",
		},
		{
			name:     "GIF图片",
			filename: "test.gif",
			data:     []byte{0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00},
			expected: "image/gif",
		},
		{
			name:     "PDF文档",
			filename: "test.pdf",
			data:     []byte{0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34, 0x0A},
			expected: "application/pdf",
		},
		{
			name:     "ZIP压缩包",
			filename: "test.zip",
			data:     []byte{0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00},
			expected: "application/zip",
		},
		{
			name:     "HTML文件",
			filename: "test.html",
			data:     []byte{0x3C, 0x68, 0x74, 0x6D, 0x6C, 0x3E, 0x3C, 0x68, 0x65, 0x61, 0x64, 0x3E},
			expected: "text/html",
		},
		{
			name:     "CSS文件",
			filename: "test.css",
			data:     []byte{0x62, 0x6F, 0x64, 0x79, 0x20, 0x7B, 0x20, 0x63, 0x6F, 0x6C, 0x6F, 0x72, 0x3A, 0x20, 0x72, 0x65, 0x64, 0x3B, 0x20, 0x7D},
			expected: "text/css",
		},
		{
			name:     "JavaScript文件",
			filename: "test.js",
			data:     []byte{0x63, 0x6F, 0x6E, 0x73, 0x6F, 0x6C, 0x65, 0x2E, 0x6C, 0x6F, 0x67, 0x28, 0x22, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x22, 0x29, 0x3B},
			expected: "application/javascript",
		},
		{
			name:     "JSON文件",
			filename: "test.json",
			data:     []byte{0x7B, 0x22, 0x6E, 0x61, 0x6D, 0x65, 0x22, 0x3A, 0x20, 0x22, 0x74, 0x65, 0x73, 0x74, 0x22, 0x7D},
			expected: "application/json",
		},
		{
			name:     "纯文本文件",
			filename: "test.txt",
			data:     []byte{0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21},
			expected: "text/plain",
		},
		{
			name:     "未知文件类型",
			filename: "test.unknown",
			data:     []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05},
			expected: "application/octet-stream",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detector.DetectMIME(tt.filename, tt.data)
			if result != tt.expected {
				t.Errorf("DetectMIME() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMIMEDetector_DetectByExtension(t *testing.T) {
	detector := NewMIMEDetector()

	tests := []struct {
		filename string
		expected string
	}{
		{"test.jpg", "image/jpeg"},
		{"test.jpeg", "image/jpeg"},
		{"test.png", "image/png"},
		{"test.gif", "image/gif"},
		{"test.webp", "image/webp"},
		{"test.svg", "image/svg+xml"},
		{"test.pdf", "application/pdf"},
		{"test.zip", "application/zip"},
		{"test.html", "text/html"},
		{"test.css", "text/css"},
		{"test.js", "application/javascript"},
		{"test.json", "application/json"},
		{"test.xml", "application/xml"},
		{"test.txt", "text/plain"},
		{"test.mp3", "audio/mpeg"},
		{"test.mp4", "video/mp4"},
		{"test.woff", "font/woff"},
		{"test.woff2", "font/woff2"},
		{"test.ttf", "font/ttf"},
		{"test.otf", "font/otf"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			result := detector.DetectMIME(tt.filename, nil)
			if result != tt.expected {
				t.Errorf("DetectMIME() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestMIMEDetector_GetMIMEDescription(t *testing.T) {
	detector := NewMIMEDetector()

	tests := []struct {
		mimeType string
		expected string
	}{
		{"image/jpeg", "JPEG图片"},
		{"image/png", "PNG图片"},
		{"image/gif", "GIF图片"},
		{"application/pdf", "PDF文档"},
		{"text/html", "HTML网页"},
		{"text/css", "CSS样式表"},
		{"application/javascript", "JavaScript脚本"},
		{"application/json", "JSON数据"},
		{"text/plain", "纯文本"},
		{"application/zip", "ZIP压缩包"},
		{"audio/mpeg", "MP3音频"},
		{"video/mp4", "MP4视频"},
		{"font/woff", "WOFF字体"},
		{"font/woff2", "WOFF2字体"},
		{"unknown/type", "未知类型: unknown/type"},
	}

	for _, tt := range tests {
		t.Run(tt.mimeType, func(t *testing.T) {
			result := detector.GetMIMEDescription(tt.mimeType)
			if result != tt.expected {
				t.Errorf("GetMIMEDescription() = %v, want %v", result, tt.expected)
			}
		})
	}
}

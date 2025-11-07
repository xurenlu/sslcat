package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/html"
)

// ContentValidator 内容验证器
type ContentValidator struct {
	timeout int // 秒
}

// NewContentValidator 创建内容验证器
func NewContentValidator(timeout int) *ContentValidator {
	return &ContentValidator{
		timeout: timeout,
	}
}

// Validate 验证网页内容是否包含关键词
func (cv *ContentValidator) Validate(url string, keywords []string) (bool, []string, error) {
	// 获取网页内容
	content, err := cv.fetchContent(url)
	if err != nil {
		return false, nil, fmt.Errorf("获取网页内容失败: %w", err)
	}

	// 提取文本内容
	text := cv.extractText(content)

	// 检查关键词
	var matched []string
	lowerText := strings.ToLower(text)
	for _, keyword := range keywords {
		lowerKeyword := strings.ToLower(keyword)
		if strings.Contains(lowerText, lowerKeyword) {
			matched = append(matched, keyword)
		}
	}

	return len(matched) > 0, matched, nil
}

// fetchContent 获取网页内容
func (cv *ContentValidator) fetchContent(url string) (string, error) {
	client := &http.Client{
		Timeout: http.DefaultClient.Timeout,
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP 状态码: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// extractText 从 HTML 提取文本内容
func (cv *ContentValidator) extractText(htmlContent string) string {
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		// 如果解析失败，返回原始内容
		return htmlContent
	}

	var text strings.Builder
	cv.extractTextFromNode(doc, &text)
	return text.String()
}

// extractTextFromNode 递归提取节点文本
func (cv *ContentValidator) extractTextFromNode(n *html.Node, text *strings.Builder) {
	if n.Type == html.TextNode {
		text.WriteString(n.Data)
		text.WriteString(" ")
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		cv.extractTextFromNode(c, text)
	}
}

// ExtractKeywords 从产品名称提取关键词
func ExtractKeywords(productName string) []string {
	// 移除括号和特殊字符
	name := strings.TrimSpace(productName)
	
	// 移除括号内容
	if idx := strings.Index(name, "("); idx > 0 {
		name = name[:idx]
	}
	if idx := strings.Index(name, "（"); idx > 0 {
		name = name[:idx]
	}

	name = strings.TrimSpace(name)

	// 分割关键词（按空格、横线等）
	keywords := []string{name} // 完整名称作为第一个关键词

	// 添加单词作为关键词
	parts := strings.FieldsFunc(name, func(r rune) bool {
		return r == ' ' || r == '-' || r == '_' || r == '/'
	})

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if len(part) > 2 && !contains(keywords, part) {
			keywords = append(keywords, part)
		}
	}

	return keywords
}

// contains 检查切片是否包含元素
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}


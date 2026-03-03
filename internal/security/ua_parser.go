package security

import (
	"regexp"
	"strconv"
)

// UABrowserType 浏览器类型
type UABrowserType string

const (
	UABrowserChrome  UABrowserType = "chrome"
	UABrowserEdge    UABrowserType = "edge"
	UABrowserFirefox UABrowserType = "firefox"
	UABrowserSafari  UABrowserType = "safari"
	UABrowserOpera   UABrowserType = "opera"
	UABrowserUnknown UABrowserType = "unknown"
)

// UAVersionResult UA 版本解析结果
type UAVersionResult struct {
	Browser        UABrowserType
	MajorVersion   int  // 主版本号，解析失败为 0
	IsVeryOutdated bool // 极老（建议直接拦截）
	IsOutdated     bool // 较老（建议标记+快速拦截）
}

// 默认版本阈值（约 2018-2021 年）
var defaultVeryOutdatedMinVersion = map[UABrowserType]int{
	UABrowserChrome:  70,
	UABrowserEdge:    79, // Chromium Edge 从 79 开始
	UABrowserFirefox: 65,
	UABrowserSafari:  12,
	UABrowserOpera:   57,
}

var defaultOutdatedMinVersion = map[UABrowserType]int{
	UABrowserChrome:  90,
	UABrowserEdge:    90,
	UABrowserFirefox: 90,
	UABrowserSafari:  15,
	UABrowserOpera:   76,
}

// 版本解析正则（按 UA 中常见顺序）
var versionPatterns = []struct {
	browser UABrowserType
	re      *regexp.Regexp
}{
	{UABrowserEdge, regexp.MustCompile(`Edg/(\d+)`)},           // Edge 用 Edg
	{UABrowserChrome, regexp.MustCompile(`Chrome/(\d+)`)},       // Chrome 或 Chromium 系
	{UABrowserFirefox, regexp.MustCompile(`Firefox/(\d+)`)},
	{UABrowserOpera, regexp.MustCompile(`OPR/(\d+)`)},           // Opera 15+
	{UABrowserSafari, regexp.MustCompile(`Version/(\d+)`)},      // Safari 版本在 Version/ 中
}

// ParseUAVersion 解析 User-Agent 中的浏览器类型和主版本号
func ParseUAVersion(ua string) UAVersionResult {
	result := UAVersionResult{Browser: UABrowserUnknown}
	if ua == "" {
		return result
	}

	for _, p := range versionPatterns {
		matches := p.re.FindStringSubmatch(ua)
		if len(matches) >= 2 {
			ver, err := strconv.Atoi(matches[1])
			if err != nil {
				continue
			}
			result.Browser = p.browser
			result.MajorVersion = ver

			// Opera 基于 Chromium，版本号体系不同，放宽阈值
			if p.browser == UABrowserOpera {
				veryMin := defaultVeryOutdatedMinVersion[UABrowserOpera]
				outMin := defaultOutdatedMinVersion[UABrowserOpera]
				result.IsVeryOutdated = ver < veryMin
				result.IsOutdated = ver < outMin
			} else {
				veryMin := defaultVeryOutdatedMinVersion[p.browser]
				outMin := defaultOutdatedMinVersion[p.browser]
				result.IsVeryOutdated = ver < veryMin
				result.IsOutdated = ver < outMin
			}
			return result
		}
	}

	// 未识别为已知浏览器，不标记（由其他逻辑处理空/短 UA）
	return result
}

// IsVeryOutdatedBrowser 是否为极老浏览器（建议直接拦截）
func IsVeryOutdatedBrowser(ua string) bool {
	return ParseUAVersion(ua).IsVeryOutdated
}

// IsOutdatedBrowser 是否为较老浏览器（建议标记+快速拦截）
func IsOutdatedBrowser(ua string) bool {
	return ParseUAVersion(ua).IsOutdated
}

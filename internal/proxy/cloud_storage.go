package proxy

import (
	"net/url"
	"strings"
)

type CloudStorageInfo struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Region   string `json:"region"`
	Bucket   string `json:"bucket"`
	Endpoint string `json:"endpoint"`
}

func (m *Manager) isCloudStorageService(target string) bool {
	targetLower := strings.ToLower(target)
	return strings.Contains(targetLower, "aliyuncs.com") ||
		strings.Contains(targetLower, "amazonaws.com") ||
		strings.Contains(targetLower, "qcloud.com") ||
		strings.Contains(targetLower, "myqcloud.com") ||
		strings.Contains(targetLower, "oss-") ||
		strings.Contains(targetLower, ".s3.") ||
		strings.Contains(targetLower, ".cos.")
}

func (m *Manager) detectCloudStorageInfo(target string) *CloudStorageInfo {
	targetLower := strings.ToLower(target)
	extractHostname := func(value string) string {
		if strings.HasPrefix(strings.ToLower(value), "http://") || strings.HasPrefix(strings.ToLower(value), "https://") {
			if parsedURL, err := url.Parse(value); err == nil {
				return parsedURL.Hostname()
			}
		}
		return value
	}

	if strings.Contains(targetLower, "aliyuncs.com") || strings.Contains(targetLower, "oss-") {
		hostname := extractHostname(target)
		parts := strings.Split(hostname, ".")
		if len(parts) >= 3 {
			return &CloudStorageInfo{Type: "aliyun_oss", Name: "阿里云OSS", Bucket: parts[0], Region: extractRegionFromOSS(parts), Endpoint: hostname}
		}
		return &CloudStorageInfo{Type: "aliyun_oss", Name: "阿里云OSS", Endpoint: hostname}
	}

	if strings.Contains(targetLower, "amazonaws.com") || strings.Contains(targetLower, ".s3.") {
		hostname := extractHostname(target)
		parts := strings.Split(hostname, ".")
		if len(parts) >= 3 {
			return &CloudStorageInfo{Type: "aws_s3", Name: "AWS S3", Bucket: parts[0], Region: extractRegionFromS3(parts), Endpoint: hostname}
		}
		return &CloudStorageInfo{Type: "aws_s3", Name: "AWS S3", Endpoint: hostname}
	}

	if strings.Contains(targetLower, "qcloud.com") || strings.Contains(targetLower, "myqcloud.com") || strings.Contains(targetLower, ".cos.") {
		hostname := extractHostname(target)
		parts := strings.Split(hostname, ".")
		if len(parts) >= 3 {
			return &CloudStorageInfo{Type: "tencent_cos", Name: "腾讯云COS", Bucket: parts[0], Region: extractRegionFromCOS(parts), Endpoint: hostname}
		}
		return &CloudStorageInfo{Type: "tencent_cos", Name: "腾讯云COS", Endpoint: hostname}
	}
	return nil
}

func extractRegionFromOSS(parts []string) string {
	if len(parts) >= 2 && strings.HasPrefix(parts[1], "oss-") {
		return strings.TrimPrefix(parts[1], "oss-")
	}
	return ""
}

func extractRegionFromS3(parts []string) string {
	if len(parts) >= 2 && strings.HasPrefix(parts[1], "s3-") {
		return strings.TrimPrefix(parts[1], "s3-")
	}
	return ""
}

func extractRegionFromCOS(parts []string) string {
	if len(parts) >= 2 && strings.HasPrefix(parts[1], "cos-") {
		return strings.TrimPrefix(parts[1], "cos-")
	}
	return ""
}

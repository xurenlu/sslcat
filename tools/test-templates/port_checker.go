package main

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// PortChecker 端口检查器
type PortChecker struct {
	timeout time.Duration
	retries int
}

// NewPortChecker 创建端口检查器
func NewPortChecker(timeout time.Duration, retries int) *PortChecker {
	return &PortChecker{
		timeout: timeout,
		retries: retries,
	}
}

// CheckPort 检查端口是否可访问
func (pc *PortChecker) CheckPort(port int, protocol string) (bool, error) {
	for i := 0; i < pc.retries; i++ {
		if i > 0 {
			time.Sleep(2 * time.Second)
		}

		var err error
		switch strings.ToLower(protocol) {
		case "http", "https":
			err = pc.checkHTTPPort(port, protocol)
		case "tcp", "udp":
			err = pc.checkTCPPort(port)
		default:
			// 默认尝试 TCP
			err = pc.checkTCPPort(port)
		}

		if err == nil {
			return true, nil
		}

		if i == pc.retries-1 {
			return false, err
		}
	}

	return false, fmt.Errorf("端口 %d 检查失败，已重试 %d 次", port, pc.retries)
}

// checkTCPPort 检查 TCP 端口
func (pc *PortChecker) checkTCPPort(port int) error {
	address := fmt.Sprintf("localhost:%d", port)
	conn, err := net.DialTimeout("tcp", address, pc.timeout)
	if err != nil {
		return fmt.Errorf("TCP 连接失败: %w", err)
	}
	conn.Close()
	return nil
}

// checkHTTPPort 检查 HTTP/HTTPS 端口
func (pc *PortChecker) checkHTTPPort(port int, protocol string) error {
	scheme := "http"
	if protocol == "https" {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://localhost:%d", scheme, port)
	client := &http.Client{
		Timeout: pc.timeout,
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP 请求失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		return nil
	}

	return fmt.Errorf("HTTP 状态码: %d", resp.StatusCode)
}

// ExtractPorts 从模板服务配置提取端口
func ExtractPorts(services []TemplateService) []int {
	var ports []int
	seen := make(map[int]bool)

	for _, service := range services {
		for _, portConfig := range service.Ports {
			if portConfig.Internal > 0 && portConfig.Public && !seen[portConfig.Internal] {
				ports = append(ports, portConfig.Internal)
				seen[portConfig.Internal] = true
			}
		}
	}

	return ports
}


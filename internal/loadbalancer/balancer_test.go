package loadbalancer

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoadBalancer_RoundRobin(t *testing.T) {
	// 创建测试后端
	backends := []Backend{
		{ID: "backend1", Host: "192.168.1.1", Port: 8080, Weight: 1},
		{ID: "backend2", Host: "192.168.1.2", Port: 8080, Weight: 1},
		{ID: "backend3", Host: "192.168.1.3", Port: 8080, Weight: 1},
	}

	config := LoadBalancerConfig{
		Algorithm:          RoundRobin,
		Backends:           backends,
		HealthCheckEnabled: false, // 禁用健康检查以简化测试
	}

	lb := NewLoadBalancer(config)

	// 测试轮询算法
	req := httptest.NewRequest("GET", "/test", nil)

	// 第一次请求应该选择第一个后端
	backend1, err := lb.SelectBackend(req)
	if err != nil {
		t.Fatalf("Failed to select backend: %v", err)
	}
	if backend1.ID != "backend1" {
		t.Errorf("Expected backend1, got %s", backend1.ID)
	}

	// 第二次请求应该选择第二个后端
	backend2, err := lb.SelectBackend(req)
	if err != nil {
		t.Fatalf("Failed to select backend: %v", err)
	}
	if backend2.ID != "backend2" {
		t.Errorf("Expected backend2, got %s", backend2.ID)
	}

	// 第三次请求应该选择第三个后端
	backend3, err := lb.SelectBackend(req)
	if err != nil {
		t.Fatalf("Failed to select backend: %v", err)
	}
	if backend3.ID != "backend3" {
		t.Errorf("Expected backend3, got %s", backend3.ID)
	}

	// 第四次请求应该回到第一个后端
	backend4, err := lb.SelectBackend(req)
	if err != nil {
		t.Fatalf("Failed to select backend: %v", err)
	}
	if backend4.ID != "backend1" {
		t.Errorf("Expected backend1, got %s", backend4.ID)
	}
}

func TestLoadBalancer_WeightedRoundRobin(t *testing.T) {
	// 创建不同权重的后端
	backends := []Backend{
		{ID: "backend1", Host: "192.168.1.1", Port: 8080, Weight: 1},
		{ID: "backend2", Host: "192.168.1.2", Port: 8080, Weight: 2},
		{ID: "backend3", Host: "192.168.1.3", Port: 8080, Weight: 3},
	}

	config := LoadBalancerConfig{
		Algorithm:          WeightedRoundRobin,
		Backends:           backends,
		HealthCheckEnabled: false,
	}

	lb := NewLoadBalancer(config)

	// 统计每个后端被选中的次数
	counts := make(map[string]int)
	req := httptest.NewRequest("GET", "/test", nil)

	// 进行多次请求
	for i := 0; i < 60; i++ {
		backend, err := lb.SelectBackend(req)
		if err != nil {
			t.Fatalf("Failed to select backend: %v", err)
		}
		counts[backend.ID]++
	}

	// 验证权重分配是否正确（大致比例）
	// backend1:backend2:backend3 应该大致为 1:2:3
	if counts["backend3"] <= counts["backend2"] || counts["backend2"] <= counts["backend1"] {
		t.Errorf("Weight distribution incorrect: %v", counts)
	}
}

func TestLoadBalancer_LeastConnections(t *testing.T) {
	backends := []Backend{
		{ID: "backend1", Host: "192.168.1.1", Port: 8080, Weight: 1},
		{ID: "backend2", Host: "192.168.1.2", Port: 8080, Weight: 1},
	}

	config := LoadBalancerConfig{
		Algorithm:          LeastConnections,
		Backends:           backends,
		HealthCheckEnabled: false,
	}

	lb := NewLoadBalancer(config)
	req := httptest.NewRequest("GET", "/test", nil)

	// 手动增加第一个后端的连接数，使其连接数更高
	lb.backends[0].IncrementConnections()
	lb.backends[0].IncrementConnections() // 现在backend1有2个连接，backend2有0个连接

	// 请求应该选择连接数少的后端（backend2）
	backend, err := lb.SelectBackend(req)
	if err != nil {
		t.Fatalf("Failed to select backend: %v", err)
	}

	// 应该选择连接数少的后端
	if backend.ID != "backend2" {
		t.Errorf("Expected backend2 (least connections), got %s", backend.ID)
	}
}

func TestLoadBalancer_IPHash(t *testing.T) {
	backends := []Backend{
		{ID: "backend1", Host: "192.168.1.1", Port: 8080, Weight: 1},
		{ID: "backend2", Host: "192.168.1.2", Port: 8080, Weight: 1},
	}

	config := LoadBalancerConfig{
		Algorithm:          IPHash,
		Backends:           backends,
		HealthCheckEnabled: false,
	}

	lb := NewLoadBalancer(config)

	// 创建具有相同IP的请求
	req1 := httptest.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "192.168.1.100:12345"

	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "192.168.1.100:12346"

	// 同一IP应该选择相同的后端
	backend1, err := lb.SelectBackend(req1)
	if err != nil {
		t.Fatalf("Failed to select backend: %v", err)
	}

	backend2, err := lb.SelectBackend(req2)
	if err != nil {
		t.Fatalf("Failed to select backend: %v", err)
	}

	if backend1.ID != backend2.ID {
		t.Errorf("Same IP should select same backend, got %s and %s", backend1.ID, backend2.ID)
	}
}

func TestLoadBalancer_NoHealthyBackends(t *testing.T) {
	backends := []Backend{
		{ID: "backend1", Host: "192.168.1.1", Port: 8080, Weight: 1},
		{ID: "backend2", Host: "192.168.1.2", Port: 8080, Weight: 1},
	}

	config := LoadBalancerConfig{
		Algorithm:          RoundRobin,
		Backends:           backends,
		HealthCheckEnabled: false,
	}

	lb := NewLoadBalancer(config)

	// 将所有后端标记为不健康
	for i := range lb.backends {
		lb.backends[i].SetHealthy(false)
	}

	req := httptest.NewRequest("GET", "/test", nil)

	// 应该返回错误
	_, err := lb.SelectBackend(req)
	if err == nil {
		t.Error("Expected error when no healthy backends available")
	}
}

func TestBackend_HealthyOperations(t *testing.T) {
	backend := Backend{ID: "test", Host: "localhost", Port: 8080}

	// 手动设置为健康状态
	backend.SetHealthy(true)

	// 初始状态应该是健康的
	if !backend.IsHealthy() {
		t.Error("Backend should be healthy initially")
	}

	// 设置为不健康
	backend.SetHealthy(false)
	if backend.IsHealthy() {
		t.Error("Backend should be unhealthy after SetHealthy(false)")
	}

	// 设置为健康
	backend.SetHealthy(true)
	if !backend.IsHealthy() {
		t.Error("Backend should be healthy after SetHealthy(true)")
	}
}

func TestBackend_ConnectionOperations(t *testing.T) {
	backend := Backend{ID: "test", Host: "localhost", Port: 8080}

	// 初始连接数应该为0
	if backend.GetActiveConnections() != 0 {
		t.Errorf("Initial connections should be 0, got %d", backend.GetActiveConnections())
	}

	// 增加连接
	backend.IncrementConnections()
	if backend.GetActiveConnections() != 1 {
		t.Errorf("Connections should be 1 after increment, got %d", backend.GetActiveConnections())
	}

	// 再次增加连接
	backend.IncrementConnections()
	if backend.GetActiveConnections() != 2 {
		t.Errorf("Connections should be 2 after second increment, got %d", backend.GetActiveConnections())
	}

	// 减少连接
	backend.DecrementConnections()
	if backend.GetActiveConnections() != 1 {
		t.Errorf("Connections should be 1 after decrement, got %d", backend.GetActiveConnections())
	}
}

func TestBackend_RequestOperations(t *testing.T) {
	backend := Backend{ID: "test", Host: "localhost", Port: 8080}

	// 初始请求数应该为0
	if backend.GetTotalRequests() != 0 {
		t.Errorf("Initial requests should be 0, got %d", backend.GetTotalRequests())
	}

	if backend.GetFailedRequests() != 0 {
		t.Errorf("Initial failed requests should be 0, got %d", backend.GetFailedRequests())
	}

	// 增加总请求数
	backend.IncrementRequests()
	if backend.GetTotalRequests() != 1 {
		t.Errorf("Total requests should be 1 after increment, got %d", backend.GetTotalRequests())
	}

	// 增加失败请求数
	backend.IncrementFailures()
	if backend.GetFailedRequests() != 1 {
		t.Errorf("Failed requests should be 1 after increment, got %d", backend.GetFailedRequests())
	}

	// 计算成功率
	successRate := backend.GetSuccessRate()
	expected := 0.0 // 1个请求，1个失败，成功率为0%
	if successRate != expected {
		t.Errorf("Success rate should be %.1f%%, got %.1f%%", expected, successRate)
	}

	// 再增加一个成功请求
	backend.IncrementRequests()
	successRate = backend.GetSuccessRate()
	expected = 50.0 // 2个请求，1个失败，成功率为50%
	if successRate != expected {
		t.Errorf("Success rate should be %.1f%%, got %.1f%%", expected, successRate)
	}
}

func TestBackend_ResponseTime(t *testing.T) {
	backend := Backend{ID: "test", Host: "localhost", Port: 8080}

	// 初始响应时间应该为0
	if backend.GetResponseTime() != 0 {
		t.Errorf("Initial response time should be 0, got %v", backend.GetResponseTime())
	}

	// 设置响应时间
	responseTime := 100 * time.Millisecond
	backend.UpdateResponseTime(responseTime)

	if backend.GetResponseTime() != responseTime {
		t.Errorf("Response time should be %v, got %v", responseTime, backend.GetResponseTime())
	}
}

func TestLoadBalancer_Stats(t *testing.T) {
	backends := []Backend{
		{ID: "backend1", Host: "192.168.1.1", Port: 8080, Weight: 1},
		{ID: "backend2", Host: "192.168.1.2", Port: 8080, Weight: 1},
	}

	config := LoadBalancerConfig{
		Algorithm:          RoundRobin,
		Backends:           backends,
		HealthCheckEnabled: false,
	}

	lb := NewLoadBalancer(config)

	// 获取统计信息
	stats := lb.GetStats()

	if stats.Algorithm != RoundRobin {
		t.Errorf("Expected algorithm %s, got %s", RoundRobin, stats.Algorithm)
	}

	if stats.TotalBackends != 2 {
		t.Errorf("Expected 2 total backends, got %d", stats.TotalBackends)
	}

	if stats.HealthyBackends != 2 {
		t.Errorf("Expected 2 healthy backends, got %d", stats.HealthyBackends)
	}

	if stats.UnhealthyBackends != 0 {
		t.Errorf("Expected 0 unhealthy backends, got %d", stats.UnhealthyBackends)
	}

	if len(stats.BackendStats) != 2 {
		t.Errorf("Expected 2 backend stats, got %d", len(stats.BackendStats))
	}
}

func TestBackend_GetAddress(t *testing.T) {
	backend := Backend{Host: "192.168.1.1", Port: 8080}
	expected := "192.168.1.1:8080"
	if backend.GetAddress() != expected {
		t.Errorf("Expected address %s, got %s", expected, backend.GetAddress())
	}

	// 测试没有端口的情况
	backend2 := Backend{Host: "example.com", Port: 0}
	expected2 := "example.com"
	if backend2.GetAddress() != expected2 {
		t.Errorf("Expected address %s, got %s", expected2, backend2.GetAddress())
	}
}

func TestBackend_GetURL(t *testing.T) {
	// 测试HTTP
	backend := Backend{Host: "192.168.1.1", Port: 8080, TLSEnabled: false}
	expected := "http://192.168.1.1:8080/api/test"
	if backend.GetURL("/api/test") != expected {
		t.Errorf("Expected URL %s, got %s", expected, backend.GetURL("/api/test"))
	}

	// 测试HTTPS
	backend2 := Backend{Host: "example.com", Port: 443, TLSEnabled: true}
	expected2 := "https://example.com:443/"
	if backend2.GetURL("") != expected2 {
		t.Errorf("Expected URL %s, got %s", expected2, backend2.GetURL(""))
	}

	// 测试没有端口
	backend3 := Backend{Host: "example.com", Port: 0, TLSEnabled: true}
	expected3 := "https://example.com/health"
	if backend3.GetURL("/health") != expected3 {
		t.Errorf("Expected URL %s, got %s", expected3, backend3.GetURL("/health"))
	}
}

// 基准测试
func BenchmarkLoadBalancer_RoundRobin(b *testing.B) {
	backends := []Backend{
		{ID: "backend1", Host: "192.168.1.1", Port: 8080, Weight: 1},
		{ID: "backend2", Host: "192.168.1.2", Port: 8080, Weight: 1},
		{ID: "backend3", Host: "192.168.1.3", Port: 8080, Weight: 1},
	}

	config := LoadBalancerConfig{
		Algorithm:          RoundRobin,
		Backends:           backends,
		HealthCheckEnabled: false,
	}

	lb := NewLoadBalancer(config)
	req := httptest.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := lb.SelectBackend(req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLoadBalancer_LeastConnections(b *testing.B) {
	backends := []Backend{
		{ID: "backend1", Host: "192.168.1.1", Port: 8080, Weight: 1},
		{ID: "backend2", Host: "192.168.1.2", Port: 8080, Weight: 1},
		{ID: "backend3", Host: "192.168.1.3", Port: 8080, Weight: 1},
	}

	config := LoadBalancerConfig{
		Algorithm:          LeastConnections,
		Backends:           backends,
		HealthCheckEnabled: false,
	}

	lb := NewLoadBalancer(config)
	req := httptest.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := lb.SelectBackend(req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

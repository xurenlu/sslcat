package ddos

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// newTestProtector 创建用于测试的最小 Protector（不启动后台协程）
func newTestProtector() *Protector {
	p := &Protector{
		enabled:     true,
		level:       LevelMedium,
		clients:     make(map[string]*ClientInfo),
		attackQueue: make(chan attackRecord, 100),
		stopChan:    make(chan struct{}),
	}
	p.initThresholds()
	p.log = logrus.WithField("component", "test_ddos")
	return p
}

func makeRequest(path, rawQuery string) *http.Request {
	u := &url.URL{Path: path, RawQuery: rawQuery}
	return &http.Request{
		Method:     "GET",
		URL:        u,
		RemoteAddr: "4.204.201.85:1234",
		Header:     make(http.Header),
	}
}

// 测试1: 正常 REST URL 不应被误判为 SQL 注入
func TestIsSuspiciousPattern_NormalURLNotFlagged(t *testing.T) {
	p := newTestProtector()
	now := time.Now()
	client := &ClientInfo{
		FirstRequest: now.Add(-1 * time.Hour),
		LastRequest:  now,
	}

	cases := []struct {
		name     string
		path     string
		rawQuery string
	}{
		{"REST update 路径", "/api/users/update", ""},
		{"REST delete 路径", "/api/posts/delete/123", ""},
		{"query 含 select", "/search", "category=select"},
		{"REST insert 路径", "/api/v1/insert", ""},
		{"drop 单词", "/admin/drop", ""},
		{"union 单词", "/api/union", ""},
		{"update 查询参数", "/profile", "action=update"},
		{"delete 查询参数", "/items", "type=delete"},
	}

	for _, c := range cases {
		req := makeRequest(c.path, c.rawQuery)
		if p.isSuspiciousPattern(req, client) {
			t.Errorf("正常URL被误判为可疑: %s?%s", c.path, c.rawQuery)
		}
	}
}

// 测试2: 真正的 SQL 注入应被检测到
func TestIsSuspiciousPattern_RealInjectionFlagged(t *testing.T) {
	p := newTestProtector()
	now := time.Now()
	client := &ClientInfo{
		FirstRequest: now.Add(-1 * time.Hour),
		LastRequest:  now,
	}

	cases := []struct {
		name     string
		path     string
		rawQuery string
	}{
		{"UNION SELECT 联合查询", "/search", "id=1 union select * from users"},
		{"OR 1=1 布尔注入", "/login", "user=admin or 1=1"},
		{"引号 OR 注入", "/login", "user=admin' or '1'='1"},
		{"引号后注释", "/api", "id=1'--"},
		{"引号后分号", "/api", "id=1';"},
		{"xp_ 扩展存储过程", "/cmd", "exec=xp_cmdshell"},
		{"DROP TABLE", "/api", "q=1;drop table users"},
		{"INSERT INTO", "/api", "q=1;insert into admin values(1)"},
	}

	for _, c := range cases {
		req := makeRequest(c.path, c.rawQuery)
		if !p.isSuspiciousPattern(req, client) {
			t.Errorf("SQL注入未被检测到: %s?%s", c.path, c.rawQuery)
		}
	}
}

// 测试3: 新客户端（短观察窗口）不应因高 RequestRate 被误判
func TestIsSuspiciousPattern_NewClientNotFlaggedByRate(t *testing.T) {
	p := newTestProtector()
	now := time.Now()
	client := &ClientInfo{
		FirstRequest: now.Add(-2 * time.Second),
		LastRequest:  now,
		RequestCount: 5,
		RequestRate:  150, // > 120 但观察窗口不足 10 秒
	}

	req := makeRequest("/api/data", "")
	if p.isSuspiciousPattern(req, client) {
		t.Error("新客户端（观察窗口 < 10s）不应因 RequestRate 被误判")
	}
}

// 测试3b: 足够观察窗口且高 RequestRate 应被检测
func TestIsSuspiciousPattern_HighRateWithSufficientWindowFlagged(t *testing.T) {
	p := newTestProtector()
	now := time.Now()
	client := &ClientInfo{
		FirstRequest: now.Add(-30 * time.Second),
		LastRequest:  now,
		RequestCount: 200,
		RequestRate:  400, // > 120 且观察窗口 > 10 秒
	}

	req := makeRequest("/api/data", "")
	if !p.isSuspiciousPattern(req, client) {
		t.Error("足够观察窗口下高 RequestRate 应被检测")
	}
}

// 测试4: 冷却去重 — 同一 IP 5 分钟内多次可疑请求只记录一次
func TestSuspiciousPatternCooldownDedup(t *testing.T) {
	p := newTestProtector()

	// 路径遍历会触发 isSuspiciousPattern
	req := makeRequest("/api/../etc/passwd", "")

	// 第一次请求 — 应记录 1 条
	p.CheckRequest(req)
	if len(p.attackQueue) != 1 {
		t.Fatalf("第一次应记录 1 条攻击日志，实际 %d 条", len(p.attackQueue))
	}
	<-p.attackQueue // 取出第一条

	// 第二次请求（同一 IP，5 分钟内）— 不应再记录
	p.CheckRequest(req)
	if len(p.attackQueue) != 0 {
		t.Fatalf("冷却期内不应重复记录，实际有 %d 条", len(p.attackQueue))
	}

	// 验证 LastSuspiciousLog 已被设置且 Suspicious 已标记
	p.mutex.RLock()
	client, exists := p.clients["4.204.201.85"]
	p.mutex.RUnlock()
	if !exists {
		t.Fatal("客户端应存在")
	}
	if client.LastSuspiciousLog.IsZero() {
		t.Error("LastSuspiciousLog 应已被设置")
	}
	if !client.Suspicious {
		t.Error("客户端应标记为可疑")
	}
}

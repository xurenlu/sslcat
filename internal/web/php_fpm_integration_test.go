package web

import (
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

// TestPHPAdminValueAppliesToRealFPM 在真实 php-fpm 上验证 PHP_ADMIN_VALUE 是否生效。
// 需要外部 FPM 才能运行，因此默认跳过：
//
//	PHPTEST_FCGI=127.0.0.1:9123 PHPTEST_SCRIPT=/tmp/sslcat-fpm-test/test.php \
//	  go test ./internal/web/ -run TestPHPAdminValueAppliesToRealFPM -v
//
// 该测试回答的是“参数发出去后 FPM 是否真的改了 ini”，而不仅是“参数构造正确”。
func TestPHPAdminValueAppliesToRealFPM(t *testing.T) {
	fcgiAddr := os.Getenv("PHPTEST_FCGI")
	script := os.Getenv("PHPTEST_SCRIPT")
	if fcgiAddr == "" || script == "" {
		t.Skip("PHPTEST_FCGI/PHPTEST_SCRIPT 未设置，跳过真实 FPM 验证")
	}

	s := newTestServer()
	site := &config.PHPSite{
		Domain:   "fpm.test",
		Root:     "/tmp/sslcat-fpm-test",
		Index:    "test.php",
		FCGIAddr: fcgiAddr,
	}

	run := func(t *testing.T, adminIni map[string]string) string {
		t.Helper()
		site.PHPAdminIni = adminIni
		r := httptest.NewRequest("GET", "/test.php", nil)
		params := s.buildFastCGIParams(site, r, script)

		conn, err := dialFCGI(fcgiAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("dial FPM: %v", err)
		}
		defer conn.Close()

		const reqID = 1
		if err := writeBeginRequest(conn, reqID); err != nil {
			t.Fatalf("begin request: %v", err)
		}
		if err := writeParams(conn, reqID, params); err != nil {
			t.Fatalf("write params: %v", err)
		}
		if err := writeStdin(conn, reqID, r.Body); err != nil {
			t.Fatalf("write stdin: %v", err)
		}

		rec := httptest.NewRecorder()
		if err := fcgiServe(conn, reqID, rec); err != nil {
			t.Fatalf("fcgi serve: %v", err)
		}
		return rec.Body.String()
	}

	t.Run("baseline reflects pool defaults", func(t *testing.T) {
		body := run(t, nil)
		// 无干预时应拿到 FPM 的默认值，证明探测链路本身有效
		if !strings.Contains(body, "UP=") || !strings.Contains(body, "ML=") {
			t.Fatalf("unexpected FPM response: %q", body)
		}
	})

	t.Run("session.upload_progress.enabled is overridden", func(t *testing.T) {
		body := run(t, map[string]string{"session.upload_progress.enabled": "0"})
		if !strings.Contains(body, "UP=0") {
			t.Fatalf("PHP_ADMIN_VALUE did not take effect, got %q", body)
		}
	})

	t.Run("memory_limit is overridden", func(t *testing.T) {
		body := run(t, map[string]string{"memory_limit": "-1"})
		if !strings.Contains(body, "ML=-1") {
			t.Fatalf("memory_limit override failed, got %q", body)
		}
	})

	t.Run("max_execution_time is overridden", func(t *testing.T) {
		body := run(t, map[string]string{"max_execution_time": "7"})
		if !strings.Contains(body, "MET=7") {
			t.Fatalf("max_execution_time override failed, got %q", body)
		}
	})

	t.Run("session.use_strict_mode is overridden", func(t *testing.T) {
		body := run(t, map[string]string{"session.use_strict_mode": "1"})
		if !strings.Contains(body, "SM=1") {
			t.Fatalf("session.use_strict_mode override failed, got %q", body)
		}
	})
}

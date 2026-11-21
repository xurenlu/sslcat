package web

import (
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/xurenlu/sslcat/internal/config"
)

func newTestServer() *Server {
	return &Server{config: &config.Config{}, log: logrus.NewEntry(logrus.New())}
}

func TestBuildFastCGIParamsInjectsPHPAdminValue(t *testing.T) {
	s := newTestServer()
	site := &config.PHPSite{
		Domain:   "example.test",
		Root:     "/var/www/example",
		FCGIAddr: "unix:/run/php-fpm.sock",
		PHPAdminIni: map[string]string{
			"memory_limit":                    "-1",
			"session.upload_progress.enabled": "0",
		},
	}

	r := httptest.NewRequest("GET", "/index.php?x=1", nil)
	params := s.buildFastCGIParams(site, r, "/var/www/example/index.php")

	got, ok := params["PHP_ADMIN_VALUE"]
	if !ok {
		t.Fatal("PHP_ADMIN_VALUE missing from FastCGI params")
	}
	want := "memory_limit=-1\nsession.upload_progress.enabled=0"
	if got != want {
		t.Fatalf("PHP_ADMIN_VALUE = %q, want %q", got, want)
	}

	// 既有的环境变量注入行为不能被破坏
	if params["GATEWAY_INTERFACE"] != "CGI/1.1" {
		t.Fatalf("GATEWAY_INTERFACE = %q", params["GATEWAY_INTERFACE"])
	}
	if params["SCRIPT_FILENAME"] != "/var/www/example/index.php" {
		t.Fatalf("SCRIPT_FILENAME = %q", params["SCRIPT_FILENAME"])
	}
}

func TestBuildFastCGIParamsOmitsPHPAdminValueWhenUnset(t *testing.T) {
	s := newTestServer()
	site := &config.PHPSite{Domain: "example.test", Root: "/var/www/example"}
	r := httptest.NewRequest("GET", "/", nil)

	params := s.buildFastCGIParams(site, r, "/var/www/example/index.php")
	if _, ok := params["PHP_ADMIN_VALUE"]; ok {
		t.Fatal("PHP_ADMIN_VALUE should be absent when no site ini is configured")
	}
}

func TestBuildFastCGIParamsRejectsRawPHPOverrides(t *testing.T) {
	for _, name := range []string{"PHP_ADMIN_VALUE", "PHP_VALUE", "php_admin_value"} {
		for _, ini := range []map[string]string{nil, {"memory_limit": "128M"}, {"auto_prepend_file": "/tmp/invalid.php"}} {
			t.Run(name, func(t *testing.T) {
				s := newTestServer()
				site := &config.PHPSite{
					Root:        "/var/www/example",
					Vars:        map[string]string{name: "auto_prepend_file=/tmp/raw.php", "APP_ENV": "test"},
					PHPAdminIni: ini,
				}
				params := s.buildFastCGIParams(site, httptest.NewRequest("GET", "/", nil), "/var/www/example/index.php")
				for _, reserved := range []string{"PHP_VALUE", "php_admin_value"} {
					if _, ok := params[reserved]; ok {
						t.Fatalf("raw override %s reached FastCGI", reserved)
					}
				}
				want := ""
				if ini["memory_limit"] != "" {
					want = "memory_limit=128M"
				}
				if params["PHP_ADMIN_VALUE"] != want || params["APP_ENV"] != "test" {
					t.Fatalf("unexpected FastCGI override or lost environment: admin=%q app=%q", params["PHP_ADMIN_VALUE"], params["APP_ENV"])
				}
			})
		}
	}
}

func TestBuildFastCGIParamsKeepsServingOnInvalidIni(t *testing.T) {
	s := newTestServer()
	site := &config.PHPSite{
		Domain: "example.test",
		Root:   "/var/www/example",
		PHPAdminIni: map[string]string{
			"auto_prepend_file": "/tmp/payload.php",
		},
	}
	r := httptest.NewRequest("GET", "/", nil)

	params := s.buildFastCGIParams(site, r, "/var/www/example/index.php")
	// 非法指令应被丢弃，但请求本身仍可转发
	if _, ok := params["PHP_ADMIN_VALUE"]; ok {
		t.Fatal("invalid ini directive must not reach PHP_ADMIN_VALUE")
	}
	if params["SCRIPT_FILENAME"] != "/var/www/example/index.php" {
		t.Fatal("request params should still be built when ini validation fails")
	}
}

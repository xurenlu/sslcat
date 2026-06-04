package cli

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/config"
)

type proxyHealthResult struct {
	Domain    string `json:"domain"`
	RouteName string `json:"route_name,omitempty"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	OK        bool   `json:"ok"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

func (m *Manager) healthCheckProxy(args []string) error {
	if m.config == nil {
		return fmt.Errorf("no configuration loaded")
	}
	flags := parseLooseFlags(args)
	domain := strings.ToLower(strings.TrimSpace(flags["domain"]))
	includeRoutes := truthyFlag(flags, "include-routes")
	timeoutSec, err := parsePort(flags["timeout"], 2)
	if err != nil {
		return fmt.Errorf("--timeout must be seconds in 1..65535: %w", err)
	}
	timeout := time.Duration(timeoutSec) * time.Second

	targets := collectProxyHealthTargets(m.config, domain, includeRoutes)
	if len(targets) == 0 {
		if domain == "" {
			return fmt.Errorf("no proxy backends found")
		}
		return fmt.Errorf("no proxy backends found for domain %s", domain)
	}

	results := probeProxyTargets(targets, timeout)
	if hasFlag(args, "--json", "-json") {
		if err := printJSON(results); err != nil {
			return err
		}
	} else {
		fmt.Printf("%-28s %-18s %-24s %-7s %s\n", "DOMAIN", "ROUTE", "BACKEND", "STATUS", "LATENCY")
		for _, result := range results {
			status := "ok"
			latency := fmt.Sprintf("%dms", result.LatencyMS)
			if !result.OK {
				status = "fail"
				latency = result.Error
			}
			route := result.RouteName
			if route == "" {
				route = "-"
			}
			fmt.Printf("%-28s %-18s %-24s %-7s %s\n",
				result.Domain, route, normalizeHostPort(result.Host, result.Port), status, latency)
		}
	}

	failed := 0
	for _, result := range results {
		if !result.OK {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d backend(s) failed health check", failed)
	}
	return nil
}

func collectProxyHealthTargets(cfg *config.Config, domain string, includeRoutes bool) []proxyHealthResult {
	targets := []proxyHealthResult{}
	for i := range cfg.Proxy.Rules {
		rule := &cfg.Proxy.Rules[i]
		if domain != "" && !strings.EqualFold(rule.Domain, domain) {
			continue
		}
		for _, backend := range rule.GetEffectiveBackends() {
			if backend.Host == "" || backend.Port <= 0 || !backend.Enabled {
				continue
			}
			targets = append(targets, proxyHealthResult{
				Domain: rule.Domain,
				Host:   backend.Host,
				Port:   backend.Port,
			})
		}
		if includeRoutes {
			for _, route := range rule.PathPrefixRules {
				if !route.Enabled {
					continue
				}
				for _, backend := range route.Backends {
					if backend.Host == "" || backend.Port <= 0 || !backend.Enabled {
						continue
					}
					targets = append(targets, proxyHealthResult{
						Domain:    rule.Domain,
						RouteName: route.Name,
						Host:      backend.Host,
						Port:      backend.Port,
					})
				}
			}
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Domain != targets[j].Domain {
			return targets[i].Domain < targets[j].Domain
		}
		if targets[i].RouteName != targets[j].RouteName {
			return targets[i].RouteName < targets[j].RouteName
		}
		if targets[i].Host != targets[j].Host {
			return targets[i].Host < targets[j].Host
		}
		return targets[i].Port < targets[j].Port
	})
	return targets
}

func probeProxyTargets(targets []proxyHealthResult, timeout time.Duration) []proxyHealthResult {
	results := make([]proxyHealthResult, len(targets))
	done := make(chan int, len(targets))
	for i, target := range targets {
		results[i] = target
		go func(idx int) {
			start := time.Now()
			addr := normalizeHostPort(results[idx].Host, results[idx].Port)
			conn, err := net.DialTimeout("tcp", addr, timeout)
			results[idx].LatencyMS = time.Since(start).Milliseconds()
			if err != nil {
				results[idx].OK = false
				results[idx].Error = err.Error()
				done <- idx
				return
			}
			_ = conn.Close()
			results[idx].OK = true
			done <- idx
		}(i)
	}
	for range targets {
		<-done
	}
	return results
}

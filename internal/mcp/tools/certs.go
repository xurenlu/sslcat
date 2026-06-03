package tools

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xurenlu/sslcat/internal/mcp"
	"github.com/xurenlu/sslcat/internal/ssl"
)

// RegisterCertWriters 注册 P3 的证书 CRUD 工具。
func RegisterCertWriters(reg *mcp.Registry, d *Deps) error {
	for _, t := range []*mcp.Tool{
		certIssueTool(d),
		certRenewTool(d),
		certUploadTool(d),
		certDeleteTool(d),
		certDNSProviderListTool(d),
	} {
		if err := reg.RegisterTool(t); err != nil {
			return err
		}
	}
	return nil
}

// ---------- 共用 ----------

// runIssueAsync 启动一个 goroutine 执行证书申请，并把 ssl 包的 CertProgressEvent 翻译成 TaskEvent。
// kind 决定调用哪个 SSL 方法："issue" / "renew"。
// dnsProvider 为空时走 HTTP-01；否则走 DNS-01。
func runIssueAsync(d *Deps, taskID, domain, kind, dnsProvider string) {
	if d.Tasks == nil || d.SSL == nil {
		return
	}
	d.Tasks.Update(taskID, func(t *mcp.Task) {
		t.Status = mcp.TaskRunning
		t.Progress = 1
		t.Message = "preparing"
	})

	// 拿独占 progress channel
	ch, ok := d.SSL.TryCreateProgressChannel(domain)
	if !ok {
		// 同域并发：拿不到独占 channel；fall back 到不订阅事件
		ch = nil
	}

	// 事件桥接 goroutine
	done := make(chan struct{})
	if ch != nil {
		go func() {
			defer close(done)
			for ev := range ch {
				d.Tasks.AppendEvent(taskID, mcp.TaskEvent{
					Time:     ev.Timestamp,
					Progress: ev.Progress,
					Message:  ev.Message,
					Status:   ev.Status,
				})
			}
		}()
	} else {
		close(done)
	}

	// 实际申请（同步阻塞，可能 30 秒）
	var err error
	if dnsProvider != "" {
		err = d.SSL.RequestCertificateWithDNS(domain, dnsProvider)
	} else {
		err = d.SSL.EnsureDomainCert(domain)
	}

	// 关闭 channel；事件 goroutine 退出
	if ch != nil {
		d.SSL.CloseProgressChannelIfMatch(domain, ch)
	}
	<-done

	if err != nil {
		d.Tasks.MarkFailed(taskID, err.Error())
		return
	}
	// 成功：补一个 cert 详情快照
	result := map[string]any{
		"domain": domain,
		"kind":   kind,
	}
	if d.SSL != nil {
		for _, c := range d.SSL.GetCertificateList() {
			if c.Domain == domain {
				result["issuer"] = c.Issuer
				result["status"] = c.Status
				result["self_signed"] = c.SelfSigned
				result["expires_at"] = c.ExpiresAt
				result["days_remaining"] = int(time.Until(c.ExpiresAt).Hours() / 24)
				break
			}
		}
	}
	d.Tasks.MarkSucceeded(taskID, result)
}

// ---------- cert_issue ----------

var certIssueSchema = json.RawMessage(`{
  "type": "object",
  "required": ["domain"],
  "properties": {
    "domain":       {"type": "string", "description": "要申请证书的域名（支持通配 *.example.com，需 DNS-01）"},
    "challenge":    {"type": "string", "enum": ["http-01", "dns-01"], "description": "验证方式（默认 http-01）"},
    "dns_provider": {"type": "string", "description": "DNS-01 时必填；可用列表见 cert_dns_provider_list"}
  },
  "additionalProperties": false
}`)

type certIssueArgs struct {
	Domain      string `json:"domain"`
	Challenge   string `json:"challenge"`
	DNSProvider string `json:"dns_provider"`
}

func certIssueTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "cert_issue",
		Title:       "申请 SSL 证书（异步）",
		Description: "向 Let's Encrypt 申请证书。立即返回 task_id；用 task_status 轮询进度。通配域名只能用 dns-01。",
		InputSchema: certIssueSchema,
		Scope:       mcp.ScopeCertWrite,
		Handler:     certIssueHandler(d, "issue"),
	}
}

func certRenewTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "cert_renew",
		Title:       "强制续签证书（异步）",
		Description: "强制重新申请证书，会清空 ACME cache。立即返回 task_id；用 task_status 轮询。",
		InputSchema: certIssueSchema,
		Scope:       mcp.ScopeCertWrite,
		Handler:     certIssueHandler(d, "renew"),
	}
}

func certIssueHandler(d *Deps, kind string) mcp.ToolHandler {
	return func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
		var p certIssueArgs
		if err := json.Unmarshal(args, &p); err != nil {
			return mcp.ErrorResult("invalid params: " + err.Error()), nil
		}
		if err := validateDomain(p.Domain); err != nil {
			return mcp.ErrorResult(err.Error()), nil
		}
		if d.SSL == nil {
			return mcp.ErrorResult("ssl manager not available"), nil
		}
		if !d.SSL.ACMEEnabled() {
			return mcp.ErrorResult("ACME not enabled in config; set ssl.email and restart"), nil
		}

		challenge := p.Challenge
		if challenge == "" {
			// 通配必须 dns-01
			if strings.HasPrefix(p.Domain, "*.") {
				challenge = "dns-01"
			} else {
				challenge = "http-01"
			}
		}
		if strings.HasPrefix(p.Domain, "*.") && challenge != "dns-01" {
			return mcp.ErrorResult("wildcard domain requires challenge=dns-01"), nil
		}

		dnsProvider := ""
		if challenge == "dns-01" {
			if p.DNSProvider == "" {
				return mcp.ErrorResult("dns_provider required for dns-01"), nil
			}
			providers := d.SSL.GetDNSProviders()
			found := false
			for _, name := range providers {
				if name == p.DNSProvider {
					found = true
					break
				}
			}
			if !found {
				return mcp.ErrorResult(fmt.Sprintf("dns_provider %q not configured (available: %s)",
					p.DNSProvider, strings.Join(providers, ", "))), nil
			}
			if err := d.SSL.ValidateDNSProvider(p.DNSProvider); err != nil {
				return mcp.ErrorResult("dns_provider validation failed: " + err.Error()), nil
			}
			dnsProvider = p.DNSProvider
		}

		// 创建任务并立即返回
		ownerName := ""
		if caller != nil {
			ownerName = caller.TokenName
		}
		toolName := "cert_issue"
		if kind == "renew" {
			toolName = "cert_renew"
		}
		task := d.Tasks.Create(toolName, ownerName, map[string]any{
			"domain":       p.Domain,
			"challenge":    challenge,
			"dns_provider": dnsProvider,
		})

		// 后台执行
		go runIssueAsync(d, task.ID, p.Domain, kind, dnsProvider)

		return mcp.TextResult(map[string]any{
			"ok":           true,
			"task_id":      task.ID,
			"status":       string(task.Status),
			"poll_with":    "task_status",
			"poll_example": map[string]any{"task_id": task.ID},
			"message":      fmt.Sprintf("证书申请已启动，task_id=%s；用 task_status 轮询进度（典型耗时 10~30 秒）。", task.ID),
		}), nil
	}
}

// ---------- cert_upload ----------

var certUploadSchema = json.RawMessage(`{
  "type": "object",
  "required": ["domain", "cert_pem", "key_pem"],
  "properties": {
    "domain":   {"type": "string", "description": "证书域名（必须与证书 CN/SAN 匹配）"},
    "cert_pem": {"type": "string", "description": "证书 PEM（含可选中间证书）"},
    "key_pem":  {"type": "string", "description": "私钥 PEM"}
  },
  "additionalProperties": false
}`)

type certUploadArgs struct {
	Domain  string `json:"domain"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

func certUploadTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "cert_upload",
		Title:       "上传自有证书",
		Description: "上传用户自有的 SSL 证书与私钥（PEM 格式）。会校验证书与私钥配对、且证书 CN/SAN 包含指定 domain。同步操作，不需要 task_status 轮询。",
		InputSchema: certUploadSchema,
		Scope:       mcp.ScopeCertWrite,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			var p certUploadArgs
			if err := json.Unmarshal(args, &p); err != nil {
				return mcp.ErrorResult("invalid params: " + err.Error()), nil
			}
			if err := validateDomain(p.Domain); err != nil {
				return mcp.ErrorResult(err.Error()), nil
			}

			// 1. 校验 PEM 解析与配对（先做，不依赖 SSL manager；这样即便挂了也能给用户明确反馈）
			pair, err := tls.X509KeyPair([]byte(p.CertPEM), []byte(p.KeyPEM))
			if err != nil {
				return mcp.ErrorResult("cert and key do not match (or invalid PEM): " + err.Error()), nil
			}
			if len(pair.Certificate) == 0 {
				return mcp.ErrorResult("empty certificate"), nil
			}
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				return mcp.ErrorResult("parse leaf cert: " + err.Error()), nil
			}
			// 2. 校验 CN/SAN 是否包含 domain
			if !certCoversDomain(leaf, p.Domain) {
				return mcp.ErrorResult(fmt.Sprintf("cert does not cover domain %q (CN=%q, DNS SANs=%v)",
					p.Domain, leaf.Subject.CommonName, leaf.DNSNames)), nil
			}
			// 校验通过后再要求 SSL manager + config
			if d.SSL == nil || d.Config == nil {
				return mcp.ErrorResult("ssl manager not available"), nil
			}
			// 3. 写盘
			certDir := d.Config.SSL.CertDir
			keyDir := d.Config.SSL.KeyDir
			if err := os.MkdirAll(certDir, 0755); err != nil {
				return mcp.ErrorResult("mkdir cert dir: " + err.Error()), nil
			}
			if err := os.MkdirAll(keyDir, 0700); err != nil {
				return mcp.ErrorResult("mkdir key dir: " + err.Error()), nil
			}
			certPath := filepath.Join(certDir, p.Domain+".crt")
			keyPath := filepath.Join(keyDir, p.Domain+".key")
			if err := os.WriteFile(certPath, []byte(p.CertPEM), 0644); err != nil {
				return mcp.ErrorResult("write cert: " + err.Error()), nil
			}
			if err := os.WriteFile(keyPath, []byte(p.KeyPEM), 0600); err != nil {
				return mcp.ErrorResult("write key: " + err.Error()), nil
			}
			// 4. 让 ssl manager 重新加载
			if err := d.SSL.LoadCertificateFromDisk(p.Domain); err != nil {
				return mcp.ErrorResult("load uploaded cert: " + err.Error()), nil
			}
			return mcp.TextResult(map[string]any{
				"ok":               true,
				"domain":           p.Domain,
				"issuer":           leaf.Issuer.CommonName,
				"not_before":       leaf.NotBefore,
				"not_after":        leaf.NotAfter,
				"days_remaining":   int(time.Until(leaf.NotAfter).Hours() / 24),
				"sans":             leaf.DNSNames,
				"cert_path":        certPath,
				"key_path":         keyPath,
				"intermediates_in": len(pair.Certificate) - 1,
			}), nil
		},
	}
}

// certCoversDomain 检查证书是否覆盖 domain（精确或通配）。
func certCoversDomain(c *x509.Certificate, domain string) bool {
	d := strings.ToLower(strings.TrimSpace(domain))
	if d == "" {
		return false
	}
	candidates := append([]string{}, c.DNSNames...)
	if c.Subject.CommonName != "" {
		candidates = append(candidates, c.Subject.CommonName)
	}
	for _, n := range candidates {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == d {
			return true
		}
		if strings.HasPrefix(n, "*.") {
			// 通配匹配：*.example.com 覆盖 foo.example.com
			suffix := n[1:] // ".example.com"
			if strings.HasSuffix(d, suffix) && !strings.Contains(strings.TrimSuffix(d, suffix), ".") {
				return true
			}
			// 上传 wildcard 证书且 domain 本身也是 wildcard 时（少见）
			if d == n {
				return true
			}
		}
	}
	return false
}

// 兜底引用以避免编译器报 import 未使用（pem 包用于将来扩展，比如 chain 校验）。
var _ = pem.Block{}

// ---------- cert_delete ----------

var certDeleteSchema = json.RawMessage(`{
  "type": "object",
  "required": ["domain"],
  "properties": {
    "domain":  {"type": "string"},
    "confirm": {"type": "string", "description": "第一次留空，server 返回 confirm_token；第二次带上才真正删。"}
  },
  "additionalProperties": false
}`)

func certDeleteTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "cert_delete",
		Title:       "删除证书（destructive）",
		Description: "删除指定域名的证书（从内存缓存、ACME 缓存、磁盘文件三处一并清理）。不可逆。两阶段确认：第一次返回预演 + confirm_token，第二次带 confirm 才真正执行。注意：如果该域名还被反代规则引用，删除后用户访问将看到自签证书。",
		InputSchema: certDeleteSchema,
		Scope:       mcp.ScopeCertWrite,
		Destructive: true,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			var p struct {
				Domain  string `json:"domain"`
				Confirm string `json:"confirm,omitempty"`
			}
			if err := json.Unmarshal(args, &p); err != nil {
				return mcp.ErrorResult("invalid params: " + err.Error()), nil
			}
			if err := validateDomain(p.Domain); err != nil {
				return mcp.ErrorResult(err.Error()), nil
			}
			if d.SSL == nil {
				return mcp.ErrorResult("ssl manager not available"), nil
			}

			// 找证书快照
			var snapshot *ssl.CertificateInfo
			for _, c := range d.SSL.GetCertificateList() {
				if c.Domain == p.Domain {
					sc := c
					snapshot = &sc
					break
				}
			}
			if snapshot == nil {
				return mcp.ErrorResult(fmt.Sprintf("certificate for %q not found", p.Domain)), nil
			}

			// 站点引用警告
			usedBySite := false
			if d.Config != nil {
				if findRuleIndex(d.Config.Proxy.Rules, p.Domain) >= 0 {
					usedBySite = true
				}
			}

			if !caller.Confirmed {
				return mcp.TextResult(map[string]any{
					"requires_confirmation": true,
					"confirm_token":         caller.ConfirmToken,
					"message":               fmt.Sprintf("即将删除 %q 的证书。这是 dry-run 预演——若确定，请再次调用并加 \"confirm\": \"<token>\"（60 秒内有效）。", p.Domain),
					"preview": map[string]any{
						"action":         "delete",
						"domain":         p.Domain,
						"issuer":         snapshot.Issuer,
						"expires_at":     snapshot.ExpiresAt,
						"days_remaining": int(time.Until(snapshot.ExpiresAt).Hours() / 24),
						"self_signed":    snapshot.SelfSigned,
						"used_by_site":   usedBySite,
						"warning":        chooseWarning(usedBySite, snapshot),
					},
				}), nil
			}

			// 真正删除
			if err := d.SSL.DeleteCertificate(p.Domain); err != nil {
				return mcp.ErrorResult("delete failed: " + err.Error()), nil
			}
			return mcp.TextResult(map[string]any{
				"ok":              true,
				"deleted_domain":  p.Domain,
				"was_used_by_site": usedBySite,
			}), nil
		},
	}
}

func chooseWarning(usedBySite bool, c *ssl.CertificateInfo) string {
	parts := []string{}
	if usedBySite {
		parts = append(parts, "该域名仍被反代规则引用，删除后访问者将看到自签证书或浏览器警告")
	}
	if !c.SelfSigned && time.Until(c.ExpiresAt) > 30*24*time.Hour {
		parts = append(parts, "这是有效的真实证书，重新申请需要时间且会消耗 ACME 速率限额")
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "；")
}

// ---------- cert_dns_provider_list ----------

var dnsProviderListSchema = json.RawMessage(`{
  "type": "object",
  "properties": {},
  "additionalProperties": false
}`)

func certDNSProviderListTool(d *Deps) *mcp.Tool {
	return &mcp.Tool{
		Name:        "cert_dns_provider_list",
		Title:       "列出可用的 DNS 验证厂商",
		Description: "返回当前 sslcat 已配置且可用的 DNS 厂商列表（aliyun / cloudflare / aws / tencent / godaddy / namecheap / custom），用于 cert_issue 的 dns-01 模式。",
		InputSchema: dnsProviderListSchema,
		Scope:       mcp.ScopeRead,
		Handler: func(ctx context.Context, args json.RawMessage, caller *mcp.CallContext) (mcp.ToolResult, error) {
			if d.SSL == nil {
				return mcp.TextResult(map[string]any{
					"supported": false,
					"reason":    "ssl manager not available",
					"providers": []string{},
				}), nil
			}
			names := d.SSL.GetDNSProviders()
			health := d.SSL.GetDNSProviderHealth()
			items := make([]map[string]any, 0, len(names))
			for _, n := range names {
				items = append(items, map[string]any{
					"name":   n,
					"health": health[n],
				})
			}
			return mcp.TextResult(map[string]any{
				"supported":          d.SSL.SupportsDNSChallenge(),
				"has_any_provider":   d.SSL.HasAvailableDNSProvider(),
				"providers":          items,
				"configured_in_yaml": dnsProvidersFromConfig(d),
			}), nil
		},
	}
}

func dnsProvidersFromConfig(d *Deps) []map[string]any {
	if d.Config == nil {
		return nil
	}
	out := make([]map[string]any, 0, len(d.Config.SSL.DNSProviders))
	for _, p := range d.Config.SSL.DNSProviders {
		out = append(out, map[string]any{
			"name":     p.Name,
			"type":     p.Type,
			"enabled":  p.Enabled,
			"priority": p.Priority,
		})
	}
	return out
}

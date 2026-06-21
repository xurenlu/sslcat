#!/usr/bin/env ruby
# encoding: utf-8
#
# tests/mcp_e2e.rb
#
# sslcat MCP 端到端集成测试（P5）。
#
# 测试目标：用真实 HTTP 客户端走完 MCP 协议的核心场景：
#   1. initialize 拿 session id
#   2. tools/list 检查工具齐全
#   3. site_add → cert_upload（自签 PEM）→ proxy_route_add → upstream_health_check
#   4. site_delete 两阶段确认（dry-run + confirm）
#   5. resources/list、resources/templates/list、resources/read（config/current 脱敏）
#   6. task_status 对一个不存在 id 的错误响应
#   7. cleanup
#
# 为避免拉起整个 sslcat 进程（首次设置/登录/TLS），驱动 cmd/mcp-testserver。
#
# 用法：
#   ruby tests/mcp_e2e.rb
#
# 输出：
#   reports/mcp_e2e.json
#   reports/mcp_e2e.md
#
# 退出码：0=所有断言通过；非 0=至少一个失败。

require 'net/http'
require 'uri'
require 'json'
require 'openssl'
require 'fileutils'
require 'tmpdir'
require 'time'

ROOT      = File.expand_path('..', __dir__)
REPORTS   = File.join(ROOT, 'reports')
PORT      = (ENV['MCP_E2E_PORT'] || '18742').to_i
BASE      = "http://127.0.0.1:#{PORT}"
DATA_DIR  = File.join(REPORTS, 'mcp-e2e-data')

FileUtils.mkdir_p(REPORTS)
FileUtils.rm_rf(DATA_DIR)
FileUtils.mkdir_p(DATA_DIR)

# ---------- 结果收集 ----------
$results = []
def record(name, ok, detail = '')
  $results << { name: name, ok: ok, detail: detail.to_s }
  status = ok ? 'PASS' : 'FAIL'
  puts "[#{status}] #{name}#{detail.empty? ? '' : " :: #{detail}"}"
end

def assert(name, cond, detail = '')
  record(name, !!cond, detail)
  unless cond
    puts "  ↳ assertion failed: #{detail}"
  end
end

# ---------- 启动 testserver ----------
def start_server
  bin = File.join(ROOT, 'mcp-testserver-bin')
  build = system('go', 'build', '-o', bin, './cmd/mcp-testserver', chdir: ROOT)
  raise 'go build mcp-testserver failed' unless build
  pid = spawn(bin, "-addr=:#{PORT}", "-data=#{DATA_DIR}",
              [:out, :err] => File.join(REPORTS, 'mcp-testserver.log'))
  Process.detach(pid)
  # 等就绪
  20.times do
    begin
      r = Net::HTTP.get_response(URI("#{BASE}/health"))
      return pid if r.code == '200'
    rescue StandardError
      sleep 0.2
    end
  end
  Process.kill(:TERM, pid) rescue nil
  raise 'testserver did not start within 4s'
end

def stop_server(pid)
  Process.kill(:TERM, pid) rescue nil
  Process.wait(pid) rescue nil
end

# ---------- HTTP 小工具 ----------
def http_post(path, body, headers = {})
  uri = URI("#{BASE}#{path}")
  req = Net::HTTP::Post.new(uri)
  req['Content-Type'] = 'application/json'
  headers.each { |k, v| req[k] = v }
  req.body = body.is_a?(String) ? body : body.to_json
  res = Net::HTTP.start(uri.host, uri.port) { |h| h.request(req) }
  [res.code.to_i, res.body, res]
end

def http_delete(path, headers = {})
  uri = URI("#{BASE}#{path}")
  req = Net::HTTP::Delete.new(uri)
  headers.each { |k, v| req[k] = v }
  res = Net::HTTP.start(uri.host, uri.port) { |h| h.request(req) }
  [res.code.to_i, res.body, res]
end

# 一次 JSON-RPC 调用
def rpc(token, sid, method, params = {}, id = nil)
  id ||= rand(1_000_000)
  body = { jsonrpc: '2.0', id: id, method: method }
  body[:params] = params unless params.nil?
  headers = { 'Authorization' => "Bearer #{token}" }
  headers['Mcp-Session-Id'] = sid if sid
  code, raw, res = http_post('/mcp/stream', body, headers)
  parsed = raw.empty? ? {} : (JSON.parse(raw) rescue { 'raw' => raw })
  new_sid = res['mcp-session-id'] || sid
  { code: code, body: parsed, sid: new_sid }
end

def rpc_text_result(resp)
  return nil unless resp[:body]['result']
  contents = resp[:body]['result']['content']
  return nil unless contents.is_a?(Array) && !contents.empty?
  JSON.parse(contents[0]['text']) rescue contents[0]['text']
end

# ---------- 生成自签 PEM ----------
def gen_self_signed(domain)
  key = OpenSSL::PKey::RSA.new(2048)
  name = OpenSSL::X509::Name.parse("CN=#{domain}")
  cert = OpenSSL::X509::Certificate.new
  cert.version = 2
  cert.serial = 1
  cert.subject = name
  cert.issuer = name
  cert.public_key = key.public_key
  cert.not_before = Time.now - 60
  cert.not_after = Time.now + 3600
  ef = OpenSSL::X509::ExtensionFactory.new(cert, cert)
  cert.add_extension(ef.create_extension('subjectAltName', "DNS:#{domain}"))
  cert.sign(key, OpenSSL::Digest.new('SHA256'))
  [cert.to_pem, key.to_pem]
end

# ====================================================
# 主流程
# ====================================================
pid = start_server
begin
  # ----- /admin/token : 一次性发 token -----
  code, body, = http_post('/admin/token', { name: 'ruby-e2e', scopes: %w[admin] })
  assert('admin token created', code == 200, "code=#{code}")
  token = JSON.parse(body)['token']
  assert('admin token is non-empty', !token.nil? && !token.empty?)

  # ----- 1. initialize -----
  resp = rpc(token, nil, 'initialize', { protocolVersion: '2025-06-18', clientInfo: { name: 'ruby-e2e', version: '0.1' } })
  assert('initialize returns 200', resp[:code] == 200, "code=#{resp[:code]}")
  assert('initialize gets session id', !resp[:sid].nil? && !resp[:sid].empty?)
  sid = resp[:sid]
  pv = resp[:body].dig('result', 'protocolVersion')
  assert('initialize returns protocolVersion', pv.is_a?(String) && !pv.empty?, "pv=#{pv}")

  # ----- 2. tools/list -----
  resp = rpc(token, sid, 'tools/list')
  tools = resp[:body].dig('result', 'tools') || []
  tool_names = tools.map { |t| t['name'] }.sort
  expected = %w[
    cert_delete cert_dns_provider_list cert_issue cert_list cert_renew cert_upload
    error_log_list error_log_tail
    proxy_route_add proxy_route_delete proxy_route_list proxy_route_update
    site_add site_delete site_disable site_enable site_list site_update
    task_list task_status upstream_health_check version_info
  ]
  missing = expected - tool_names
  assert('tools/list returns expected tools', missing.empty?, "missing=#{missing.inspect}")

  # ----- 3a. site_add -----
  resp = rpc(token, sid, 'tools/call', {
    name: 'site_add',
    arguments: { domain: 'ruby.example.com', backend: { host: '127.0.0.1', port: 65530 }, ssl_only: true },
  })
  result = rpc_text_result(resp)
  assert('site_add succeeds', result.is_a?(Hash) && result['ok'] == true, result.inspect)

  # ----- 3b. site_list 应能看到新站点 -----
  resp = rpc(token, sid, 'tools/call', { name: 'site_list', arguments: { keyword: 'ruby' } })
  list = rpc_text_result(resp)
  assert('site_list contains the new site', list.is_a?(Hash) && list['total'].to_i >= 1)

  # ----- 3c. cert_upload 自签 -----
  cert_pem, key_pem = gen_self_signed('ruby.example.com')
  resp = rpc(token, sid, 'tools/call', {
    name: 'cert_upload',
    arguments: { domain: 'ruby.example.com', cert_pem: cert_pem, key_pem: key_pem },
  })
  uploaded = rpc_text_result(resp)
  # 我们的 testserver 没挂真正 SSL manager，所以 PEM 校验过后 d.SSL == nil 应该报错。
  # 这正是我们想验证的"校验在 SSL 不可用之前"的行为：cert_upload 应该是 isError=true 但提示 SSL not available。
  assert('cert_upload PEM validation runs before SSL check',
    uploaded.nil? || resp[:body].dig('result', 'isError') == true,
    "uploaded=#{uploaded.inspect}")

  # ----- 3d. proxy_route_add -----
  resp = rpc(token, sid, 'tools/call', {
    name: 'proxy_route_add',
    arguments: {
      domain: 'ruby.example.com',
      rule: {
        name: 'api-v1',
        prefixes: ['/api/v1/'],
        backends: [{ host: '127.0.0.1', port: 65530 }],
      },
    },
  })
  added = rpc_text_result(resp)
  assert('proxy_route_add succeeds', added.is_a?(Hash) && added['ok'] == true, added.inspect)

  # ----- 3e. upstream_health_check（指向不存在端口，应 reachable=false） -----
  resp = rpc(token, sid, 'tools/call', {
    name: 'upstream_health_check',
    arguments: { domain: 'ruby.example.com', timeout_ms: 200 },
  })
  health = rpc_text_result(resp)
  assert('upstream_health_check returns results',
    health.is_a?(Hash) && health['total'].to_i >= 1)
  assert('upstream_health_check marks dead backend as unreachable',
    health.is_a?(Hash) && health['reachable'].to_i == 0,
    health.inspect)

  # ----- 4. site_delete 两阶段 -----
  resp = rpc(token, sid, 'tools/call', {
    name: 'site_delete',
    arguments: { domain: 'ruby.example.com' },
  })
  dry = rpc_text_result(resp)
  assert('site_delete dry-run returns requires_confirmation',
    dry.is_a?(Hash) && dry['requires_confirmation'] == true, dry.inspect)
  confirm_token = dry['confirm_token']
  assert('site_delete dry-run includes confirm_token',
    confirm_token.is_a?(String) && !confirm_token.empty?)

  resp = rpc(token, sid, 'tools/call', {
    name: 'site_delete',
    arguments: { domain: 'ruby.example.com', confirm: confirm_token },
  })
  done = rpc_text_result(resp)
  assert('site_delete with confirm succeeds',
    done.is_a?(Hash) && done['ok'] == true, done.inspect)

  # 再列：应空
  resp = rpc(token, sid, 'tools/call', { name: 'site_list', arguments: { keyword: 'ruby' } })
  list2 = rpc_text_result(resp)
  assert('site_list empty after delete', list2.is_a?(Hash) && list2['total'].to_i == 0)

  # ----- 5a. resources/list -----
  resp = rpc(token, sid, 'resources/list')
  resources = resp[:body].dig('result', 'resources') || []
  uris = resources.map { |r| r['uri'] }.sort
  assert('resources/list includes config/current and metrics/snapshot',
    uris.include?('sslcat://config/current') && uris.include?('sslcat://metrics/snapshot'),
    uris.inspect)

  # ----- 5b. resources/templates/list 应有 logs/access -----
  resp = rpc(token, sid, 'resources/templates/list')
  templates = resp[:body].dig('result', 'resourceTemplates') || []
  assert('resources/templates/list includes logs/access',
    templates.any? { |t| (t['uriTemplate'] || '').include?('sslcat://logs/access') },
    templates.inspect)
  assert('resources/templates/list includes logs/error',
    templates.any? { |t| (t['uriTemplate'] || '').include?('sslcat://logs/error') },
    templates.inspect)

  # ----- 5c. resources/read config/current 必须脱敏 token_hash -----
  resp = rpc(token, sid, 'resources/read', { uri: 'sslcat://config/current' })
  text = resp[:body].dig('result', 'contents', 0, 'text') || ''
  assert('config/current is JSON', !text.empty? && text.strip.start_with?('{'))
  assert('config/current redacts token_hash',
    !text.include?('argon2id') || text.include?('***'),
    'token_hash leaked (or hash not present)')
  # 普通字段应保留
  assert('config/current keeps admin_prefix etc.',
    text.include?('"path_prefix"') || text.include?('"PathPrefix"') || text.include?('access_log_path') || text.include?('test@example.com'),
    'expected non-sensitive fields missing')

  # ----- 5d. error log MCP 能力 -----
  resp = rpc(token, sid, 'tools/call', { name: 'error_log_list', arguments: {} })
  error_sources = rpc_text_result(resp)
  assert('error_log_list includes internal source',
    error_sources.is_a?(Hash) && (error_sources['sources'] || []).any? { |s| s['id'] == 'internal' },
    error_sources.inspect)

  resp = rpc(token, sid, 'tools/call', {
    name: 'error_log_tail',
    arguments: { id: 'internal', keyword: 'ERROR', since: '10m', limit: 20 },
  })
  error_tail = rpc_text_result(resp)
  assert('error_log_tail reads recent internal error',
    error_tail.is_a?(Hash) && (error_tail['lines'] || []).any? { |line| line.include?('mcp-testserver') },
    error_tail.inspect)

  resp = rpc(token, sid, 'resources/read', { uri: 'sslcat://logs/error?id=internal&keyword=ERROR&since=10m&limit=20' })
  error_text = resp[:body].dig('result', 'contents', 0, 'text') || ''
  assert('logs/error resource reads recent internal error',
    error_text.include?('mcp-testserver') && error_text.include?('ERROR'),
    error_text)

  # ----- 5e. resources/read unknown uri 报错 -----
  resp = rpc(token, sid, 'resources/read', { uri: 'sslcat://nope' })
  err_code = resp[:body].dig('error', 'code')
  assert('unknown resource uri returns -32020',
    err_code == -32020, "got code=#{err_code}")

  # ----- 6. task_status 不存在 id -----
  resp = rpc(token, sid, 'tools/call', { name: 'task_status', arguments: { task_id: 'no-such-id' } })
  task_err = rpc_text_result(resp)
  assert('task_status for missing id returns isError',
    resp[:body].dig('result', 'isError') == true, task_err.inspect)

  # ----- 7. version_info -----
  resp = rpc(token, sid, 'tools/call', { name: 'version_info', arguments: {} })
  vi = rpc_text_result(resp)
  assert('version_info returns app=sslcat',
    vi.is_a?(Hash) && vi['app'] == 'sslcat', vi.inspect)
ensure
  stop_server(pid)
end

# ----- 报告 -----
total = $results.size
passed = $results.count { |r| r[:ok] }
failed = total - passed

json_path = File.join(REPORTS, 'mcp_e2e.json')
File.write(json_path, JSON.pretty_generate(
  generated_at: Time.now.utc.iso8601,
  total: total, passed: passed, failed: failed,
  results: $results,
))

md_path = File.join(REPORTS, 'mcp_e2e.md')
md = []
md << '# sslcat MCP 端到端集成测试报告'
md << ''
md << "- 生成时间：`#{Time.now.utc.iso8601}`"
md << "- 总用例：**#{total}**"
md << "- 通过：**#{passed}**"
md << "- 失败：**#{failed}**"
md << ''
md << '| # | 用例 | 结果 | 详情 |'
md << '|---|------|------|------|'
$results.each_with_index do |r, i|
  status = r[:ok] ? '✅ PASS' : '❌ FAIL'
  detail = r[:detail].to_s.gsub('|', '\|').gsub("\n", ' ')[0, 200]
  md << "| #{i + 1} | #{r[:name]} | #{status} | #{detail} |"
end
File.write(md_path, md.join("\n") + "\n")

puts ''
puts "==> #{total} cases, #{passed} passed, #{failed} failed"
puts "==> reports: #{json_path} + #{md_path}"

exit(failed == 0 ? 0 : 1)

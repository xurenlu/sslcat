#!/usr/bin/env ruby
# frozen_string_literal: true

# 只访问公开 GET 接口；保留 curl 的证书链和主机名验证，不保存响应正文。
require 'digest'
require 'json'
require 'open3'
require 'openssl'
require 'optparse'
require 'time'

options = { ip: '47.96.250.173', version: nil, api_fingerprint: nil,
            wildcard_fingerprint: nil, json: nil, markdown: nil }
OptionParser.new do |parser|
  parser.banner = 'Usage: ruby tests/tls_gateway_regression.rb [options]'
  parser.on('--ip ADDRESS') { |value| options[:ip] = value }
  parser.on('--version VERSION') { |value| options[:version] = value }
  parser.on('--api-fingerprint SHA256') { |value| options[:api_fingerprint] = value }
  parser.on('--wildcard-fingerprint SHA256') { |value| options[:wildcard_fingerprint] = value }
  parser.on('--json PATH') { |value| options[:json] = value }
  parser.on('--markdown PATH') { |value| options[:markdown] = value }
end.parse!

normalize_fingerprint = lambda { |value| value&.delete(':')&.upcase }
options[:api_fingerprint] = normalize_fingerprint.call(options[:api_fingerprint])
options[:wildcard_fingerprint] = normalize_fingerprint.call(options[:wildcard_fingerprint])

probe = lambda do |label, host, path, expected_status, expected_fingerprint|
  command = ['curl', '--silent', '--show-error', '--noproxy', '*',
             '--connect-timeout', '8', '--max-time', '25',
             '--resolve', "#{host}:443:#{options[:ip]}",
             '--output', '/dev/null', '--write-out', "%{json}\n%header{x-app-version}",
             "https://#{host}#{path}"]
  output, error_output, process = Open3.capture3(*command)
  json_text, version_header = output.split("\n", 2)
  data = JSON.parse(json_text || '{}')
  pem = data.fetch('certs', '')[/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m]
  leaf = pem && OpenSSL::X509::Certificate.new(pem)
  fingerprint = leaf && Digest::SHA256.hexdigest(leaf.to_der).upcase
  reasons = []
  reasons << 'curl failed' unless process.success?
  reasons << 'TLS verification failed' unless data['ssl_verify_result'] == 0
  reasons << 'unexpected destination' unless data['remote_ip'] == options[:ip]
  reasons << 'no leaf certificate' unless leaf
  reasons << 'unexpected HTTP status' if expected_status && data['http_code'] != expected_status
  reasons << 'unexpected gateway version' if options[:version] && version_header.to_s.strip != options[:version]
  reasons << 'unexpected certificate fingerprint' if expected_fingerprint && fingerprint != expected_fingerprint
  {
    label: label, host: host, path: path, http_status: data['http_code'],
    expected_http_status: expected_status, tls_verify: data['ssl_verify_result'],
    gateway_version: version_header.to_s.strip, remote_ip: data['remote_ip'],
    leaf_sha256: fingerprint, subject: leaf&.subject&.to_s,
    expires_at: leaf&.not_after&.utc&.iso8601,
    passed: reasons.empty?, failures: reasons,
    curl_error: error_output.empty? ? nil : error_output.lines.first.to_s.strip
  }
rescue JSON::ParserError, OpenSSL::X509::CertificateError => error
  { label: label, host: host, path: path, passed: false,
    failures: ["invalid probe result: #{error.class}"] }
end

# 先访问只有泛域名覆盖的主机，再检查 API，覆盖泛域名缓存已被使用的场景。
checks = [probe.call('warm wildcard', 'h1.niuwoai.com', '/', nil, options[:wildcard_fingerprint])]
checks << probe.call('API root', 'api.niuwoai.com', '/', 200, options[:api_fingerprint])
checks.concat(Array.new(6) do |index|
  Thread.new do
    probe.call("API concurrent health #{index + 1}", 'api.niuwoai.com', '/health', 200,
               options[:api_fingerprint])
  end
end.map(&:value))
[
  ['wd.niuwoai.com', 200], ['share.niuwoai.com', nil],
  ['teamify.niuwoai.com', 200], ['q4.niuwoai.com', nil],
  ['qlite.niuwoai.com', nil], ['api.wxside.com', 200], ['83d.me', 200]
].each do |host, status|
  checks << probe.call('other virtual host', host, '/', status, nil)
end

report = {
  checked_at: Time.now.iso8601, target_ip: options[:ip], strict_tls: true,
  expected_gateway_version: options[:version],
  checks_total: checks.length, checks_passed: checks.count { |check| check[:passed] },
  passed: checks.all? { |check| check[:passed] },
  scope: 'GET routing, strict TLS, optional certificate identity and gateway version',
  limitation: 'TLS-only virtual hosts may return 404 or 503; this does not assert all applications are healthy. ACME renewal is validated by offline Go tests, not by this probe.',
  checks: checks
}
markdown = [
  '# TLS gateway regression', '',
  "Checked: #{report[:checked_at]}",
  "Target: #{options[:ip]}; passed: #{report[:checks_passed]}/#{report[:checks_total]}", '',
  '| Check | Host | HTTP | TLS verify | Gateway version | Result |',
  '| --- | --- | --- | --- | --- | --- |'
]
checks.each do |check|
  markdown << "| #{check[:label]} | #{check[:host]} | #{check[:http_status]} | #{check[:tls_verify]} | #{check[:gateway_version]} | #{check[:passed] ? 'PASS' : check[:failures].join('; ')} |"
end
markdown.concat(['', report[:limitation], ''])
File.write(options[:json], JSON.pretty_generate(report) + "\n") if options[:json]
File.write(options[:markdown], markdown.join("\n")) if options[:markdown]
puts markdown.join("\n")
exit(report[:passed] ? 0 : 1)

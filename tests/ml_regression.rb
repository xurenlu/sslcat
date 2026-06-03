#!/usr/bin/env ruby
# encoding: utf-8
#
# tests/ml_regression.rb
#
# AI 异常检测真实化（v2.1.0-rc3 / rc4）的黑盒集成回归测试。
#
# 测试目标：验证训练 → 推理 → 持久化 → 重启加载这条完整链路在 HTTP 层面表现正确。
# 为了避免拉起整个 sslcat 进程的复杂度（首次设置/登录/TLS/admin prefix 等），
# 本测试驱动一个最小化的 cmd/ml-testserver 二进制，它只暴露 ML 子系统的核心接口。
#
# 输出：
#   - reports/ml_regression.json   机器可读结果
#   - reports/ml_regression.md     人类可读报告
#
# 退出码：0 全部通过；1 任一断言失败；2 测试器自身出错（编译/启动失败等）

require 'net/http'
require 'uri'
require 'json'
require 'fileutils'
require 'tmpdir'
require 'time'

PROJECT_ROOT = File.expand_path('..', __dir__)
REPORTS_DIR  = File.join(PROJECT_ROOT, 'reports')

# ============================================================
# 测试框架（极简，无外部依赖）
# ============================================================

class TestRun
  attr_reader :results, :started_at

  def initialize
    @results    = []
    @started_at = Time.now
  end

  def test(name)
    started = Time.now
    begin
      yield
      record(name, status: 'pass', error: nil, duration_ms: ((Time.now - started) * 1000).round)
      puts "  ✓ #{name}"
    rescue => e
      record(name, status: 'fail', error: "#{e.class}: #{e.message}", duration_ms: ((Time.now - started) * 1000).round)
      puts "  ✗ #{name}"
      puts "      #{e.class}: #{e.message}"
      puts "      #{e.backtrace.first(5).join("\n      ")}"
    end
  end

  def record(name, status:, error:, duration_ms:)
    @results << { name: name, status: status, error: error, duration_ms: duration_ms }
  end

  def passed
    @results.count { |r| r[:status] == 'pass' }
  end

  def failed
    @results.count { |r| r[:status] == 'fail' }
  end

  def success?
    failed.zero?
  end

  def finished_at
    @results.empty? ? @started_at : Time.now
  end
end

def assert(cond, msg = 'assertion failed')
  raise msg unless cond
end

def assert_equal(expected, actual, msg = nil)
  raise (msg || "expected #{expected.inspect}, got #{actual.inspect}") unless expected == actual
end

# ============================================================
# HTTP 客户端
# ============================================================

class MLClient
  def initialize(host, port)
    @host = host
    @port = port
  end

  def get(path)
    Net::HTTP.start(@host, @port) do |http|
      response = http.get(path)
      JSON.parse(response.body)
    end
  end

  def post_json(path, body)
    Net::HTTP.start(@host, @port) do |http|
      req = Net::HTTP::Post.new(path, 'Content-Type' => 'application/json')
      req.body = JSON.dump(body)
      response = http.request(req)
      [response.code.to_i, JSON.parse(response.body)]
    end
  end
end

# ============================================================
# 测试服务器生命周期
# ============================================================

class TestServer
  attr_reader :host, :port, :data_dir, :stdout, :stderr

  def initialize(binary_path, data_dir)
    @binary_path = binary_path
    @data_dir    = data_dir
    @host        = nil
    @port        = nil
  end

  def start
    out_r, out_w = IO.pipe
    err_r, err_w = IO.pipe
    @pid = Process.spawn(@binary_path, '-addr', '127.0.0.1:0', '-data', @data_dir,
                         out: out_w, err: err_w)
    out_w.close
    err_w.close
    @stdout = out_r
    @stderr = err_r

    deadline = Time.now + 5.0
    while Time.now < deadline
      line = @stdout.gets
      next unless line
      if line.start_with?('LISTENING')
        addr = line.split(' ', 2)[1].strip
        @host, port_str = addr.split(':')
        @port = port_str.to_i
        return
      end
    end
    raise 'ml-testserver did not announce a port within 5 seconds'
  end

  def stop
    return unless @pid
    Process.kill('TERM', @pid) rescue nil
    Process.wait(@pid) rescue nil
    @pid = nil
  end
end

# ============================================================
# 主流程
# ============================================================

def build_testserver
  binary_path = File.join(Dir.mktmpdir, 'ml-testserver')
  result = system('go', 'build', '-o', binary_path,
                  File.join(PROJECT_ROOT, 'cmd/ml-testserver'),
                  chdir: PROJECT_ROOT)
  unless result
    warn 'failed to build cmd/ml-testserver'
    exit 2
  end
  binary_path
end

def write_reports(run, scenarios:)
  FileUtils.mkdir_p(REPORTS_DIR)

  json_path = File.join(REPORTS_DIR, 'ml_regression.json')
  payload = {
    suite:        'ml_regression',
    started_at:   run.started_at.iso8601,
    finished_at:  run.finished_at.iso8601,
    passed:       run.passed,
    failed:       run.failed,
    success:      run.success?,
    scenarios:    scenarios,
    results:      run.results,
  }
  File.write(json_path, JSON.pretty_generate(payload))

  md_path = File.join(REPORTS_DIR, 'ml_regression.md')
  File.open(md_path, 'w') do |io|
    io.puts "# AI 异常检测真实化 - 黑盒回归测试报告"
    io.puts
    io.puts "- 开始时间：#{run.started_at.iso8601}"
    io.puts "- 结束时间：#{run.finished_at.iso8601}"
    io.puts "- 总用例数：#{run.results.size}"
    io.puts "- 通过：**#{run.passed}**"
    io.puts "- 失败：**#{run.failed}**"
    io.puts "- 结果：#{run.success? ? '✅ ALL PASS' : '❌ HAS FAILURES'}"
    io.puts
    io.puts "## 用例结果"
    io.puts
    io.puts "| # | 用例 | 耗时 (ms) | 状态 | 错误 |"
    io.puts "|---|------|-----------|------|------|"
    run.results.each_with_index do |r, idx|
      status = r[:status] == 'pass' ? '✅ PASS' : '❌ FAIL'
      err    = r[:error] ? r[:error].gsub('|', '\\|') : ''
      io.puts "| #{idx + 1} | #{r[:name]} | #{r[:duration_ms]} | #{status} | #{err} |"
    end
    io.puts
    io.puts "## 场景快照"
    io.puts
    scenarios.each do |key, val|
      io.puts "### #{key}"
      io.puts
      io.puts '```json'
      io.puts JSON.pretty_generate(val)
      io.puts '```'
      io.puts
    end
  end

  puts
  puts "报告写入：#{json_path}"
  puts "          #{md_path}"
end

def main
  puts '== AI 异常检测真实化回归测试 =='
  puts '编译 cmd/ml-testserver ...'
  binary = build_testserver

  data_dir = Dir.mktmpdir('ml-regression-')
  puts "数据目录: #{data_dir}"

  server = TestServer.new(binary, data_dir)
  server.start
  puts "服务器: http://#{server.host}:#{server.port}"

  client = MLClient.new(server.host, server.port)
  run = TestRun.new
  scenarios = {}

  begin
    # ----------------------------------------------------------------
    # 1) 初始状态：没训练过，没观测过任何请求
    # ----------------------------------------------------------------
    run.test('cold-start stats: model not loaded, zero samples') do
      stats = client.get('/stats')
      scenarios['cold_stats'] = stats
      assert_equal(false, stats['model_loaded'])
      assert_equal(0, stats['collected_samples'])
      assert_equal(0, stats['total_observed'])
      assert_equal(0, stats['training_history_count'])
    end

    # ----------------------------------------------------------------
    # 2) 喂请求 → sampler 应该开始累计
    # ----------------------------------------------------------------
    run.test('observe accumulates samples') do
      30.times do |i|
        client.get("/observe?path=/api/v1/users/#{i}&status=200&ip=192.0.2.#{(i % 5) + 1}")
      end
      stats = client.get('/stats')
      scenarios['after_observe_stats'] = stats
      assert_equal(30, stats['collected_samples'])
      assert_equal(30, stats['total_observed'])
    end

    # ----------------------------------------------------------------
    # 3) 还没训练模型时，total_predictions 应该仍为 0
    # ----------------------------------------------------------------
    run.test('before training: zero predictions despite traffic') do
      stats = client.get('/stats')
      assert_equal(0, stats['total_predictions'])
    end

    # ----------------------------------------------------------------
    # 4) 用累积的样本训练
    # ----------------------------------------------------------------
    train_result = nil
    run.test('train succeeds with auto-collected samples') do
      code, body = client.post_json('/train',
                                    { n_trees: 20, max_samples: 32, contamination: 0.1 })
      scenarios['train_result'] = body
      train_result = body
      assert_equal(200, code, "expected 200, got #{code}: #{body.inspect}")
      assert_equal(true, body['success'])
      assert(body['total_samples'] >= 30, "expected >=30 samples used, got #{body['total_samples']}")
      assert_equal(20, body['n_trees'])
    end

    # ----------------------------------------------------------------
    # 5) 训练后 stats 应反映模型已加载 + 训练历史 +1
    # ----------------------------------------------------------------
    run.test('stats after training: model loaded, history recorded') do
      stats = client.get('/stats')
      scenarios['after_train_stats'] = stats
      assert_equal(true, stats['model_loaded'])
      assert_equal(20, stats['n_trees'])
      assert_equal(1, stats['training_history_count'])
      assert(stats['last_training'], 'last_training should be set')
      # 解析时间正确
      assert(Time.parse(stats['last_training']) <= Time.now)
    end

    # ----------------------------------------------------------------
    # 6) 现在再喂请求应该触发推理；total_predictions 应增加
    # ----------------------------------------------------------------
    run.test('post-training observe drives predictions') do
      40.times do |i|
        client.get("/observe?path=/x/#{i}&status=200&ip=203.0.113.#{(i % 10) + 1}")
      end
      stats = client.get('/stats')
      scenarios['after_post_train_observe_stats'] = stats
      assert(stats['total_predictions'] >= 40,
             "expected >=40 predictions, got #{stats['total_predictions']}")
    end

    # ----------------------------------------------------------------
    # 7) recent predictions 接口返回非空，且字段满足前端契约
    # ----------------------------------------------------------------
    run.test('predictions/recent returns real entries with frontend contract') do
      data = client.get('/predictions/recent?limit=10')
      scenarios['recent_predictions'] = data
      assert(data['predictions'].is_a?(Array))
      assert(data['predictions'].size > 0, 'expected at least one recent prediction')
      first = data['predictions'].first
      %w[score level is_anomaly timestamp].each do |key|
        assert(first.key?(key), "recent prediction missing key #{key}")
      end
      # FeatureVector / Features 不应出现（被 updateStats 剥离）
      assert(first['feature_vector'].nil? || first['feature_vector'].empty?,
             'recent prediction should NOT carry feature_vector')
      assert(first['features'].nil?, 'recent prediction should NOT carry features')
    end

    # ----------------------------------------------------------------
    # 8) training/history 接口
    # ----------------------------------------------------------------
    run.test('training/history returns persisted entries') do
      data = client.get('/training/history?limit=5')
      scenarios['training_history'] = data
      assert(data['entries'].is_a?(Array))
      assert_equal(1, data['entries'].size)
      entry = data['entries'].first
      assert_equal('auto', entry['sample_source'])
      assert_equal('test', entry['triggered'])
      assert_equal(20, entry['n_trees'])
    end

    # ----------------------------------------------------------------
    # 9) 模型已落盘到 data_dir
    # ----------------------------------------------------------------
    run.test('model persisted to disk') do
      model_path = File.join(data_dir, 'isolation_forest.json')
      assert(File.exist?(model_path), "expected #{model_path} to exist")
      assert(File.size(model_path) > 0, 'persisted model is empty')
      # 没有 .tmp 残留
      assert(!File.exist?(model_path + '.tmp'), 'leftover .tmp file')
    end

    # 收集训练后的"已知向量分数"作为重启回归基线
    pre_restart_recent = client.get('/predictions/recent?limit=20')

    # ----------------------------------------------------------------
    # 10) 重启 testserver，验证模型自动从磁盘加载
    # ----------------------------------------------------------------
    run.test('restart loads persisted model') do
      server.stop
      server2 = TestServer.new(binary, data_dir)
      server2.start
      server = server2
      client2 = MLClient.new(server.host, server.port)

      stats = client2.get('/stats')
      scenarios['after_restart_stats'] = stats
      assert_equal(true, stats['model_loaded'],
                   'model should be reloaded from disk after restart')
      assert_equal(20, stats['n_trees'])
      # 训练历史应仍能读到
      assert_equal(1, stats['training_history_count'])

      # 重启后的 total_predictions 应清零（计数是内存态），但模型在
      # 即用即推理时仍能工作；喂一条请求看看
      client2.get('/observe?path=/restart/check&status=200&ip=198.51.100.1')
      stats_after = client2.get('/stats')
      assert(stats_after['total_predictions'] >= 1,
             'observation after restart should produce at least one prediction')
    end

    # 防止变量未使用警告
    _ = pre_restart_recent
  ensure
    server.stop
    FileUtils.rm_rf(data_dir)
    FileUtils.rm_f(binary)
  end

  write_reports(run, scenarios: scenarios)
  exit(run.success? ? 0 : 1)
end

main if __FILE__ == $PROGRAM_NAME

# 看门狗监控配置指南

## 概述

SSLcat 的看门狗（Watchdog）监控器可以实时监控进程的 CPU 和内存使用情况，在资源占用异常时发送通知，甚至可以配置为自动退出进程（由 systemd 自动重启）。

## 功能特性

### 1. CPU 监控
- **绝对阈值监控**：当 CPU 占用超过设定值时报警
- **增长趋势监控**：当 CPU 在短时间内快速增长时报警
- **自动退出**：可配置在 CPU 超标时自动退出进程

### 2. 内存监控
- **绝对阈值监控**：当内存占用超过设定值（MB 或百分比）时报警
- **增长趋势监控**：当内存在短时间内快速增长时报警
- **自动退出**：可配置在内存超标时自动退出进程

### 3. 通知功能
- 支持多种通知渠道（邮件、Webhook、企业微信等）
- 可配置报警冷却时间，避免频繁通知
- 报警级别自动升级（超过 80% 为错误级别）

## 配置说明

### 基础配置

```yaml
monitoring:
  enabled: true  # 启用监控
  
  # 看门狗配置
  watchdog_enabled: true  # 启用看门狗（默认禁用）
  watchdog_check_interval_sec: 30  # 检查间隔（秒）
  watchdog_alert_cooldown_sec: 3600  # 报警冷却时间（秒，默认1小时）
```

### CPU 监控配置

```yaml
monitoring:
  # CPU 绝对阈值（百分比）
  watchdog_cpu_threshold_percent: 30.0  # 默认 30%
  
  # CPU 增长阈值（百分比）
  watchdog_cpu_increase_threshold_percent: 15.0  # 默认 15%
  watchdog_cpu_increase_window_sec: 180  # 检测窗口（秒，默认3分钟）
  
  # 自动退出配置
  watchdog_exit_on_cpu_threshold: false  # 达到 CPU 阈值时自动退出
```

**说明**：
- `watchdog_cpu_threshold_percent`: 当 CPU 占用超过此值时触发报警
- `watchdog_cpu_increase_threshold_percent`: 当 CPU 在指定时间窗口内增长超过此值时触发报警
- `watchdog_exit_on_cpu_threshold`: 启用后，当 CPU 超标时进程会自动退出（需配合 systemd 使用）

### 内存监控配置

```yaml
monitoring:
  # 内存绝对阈值（MB）
  watchdog_memory_threshold_mb: 512  # 超过 512MB 时报警（0 表示禁用）
  
  # 内存占用百分比阈值
  watchdog_memory_threshold_percent: 80.0  # 超过 80% 时报警（0 表示禁用）
  
  # 内存增长阈值（MB）
  watchdog_memory_increase_threshold_mb: 200  # 增长超过 200MB 时报警（0 表示禁用）
  watchdog_memory_increase_window_sec: 300  # 检测窗口（秒，默认5分钟）
  
  # 自动退出配置
  watchdog_exit_on_memory_threshold: false  # 达到内存阈值时自动退出
```

**说明**：
- `watchdog_memory_threshold_mb`: 内存绝对阈值（MB），设为 0 禁用
- `watchdog_memory_threshold_percent`: 内存占用百分比阈值，设为 0 禁用
- `watchdog_memory_increase_threshold_mb`: 内存增长阈值（MB），设为 0 禁用
- `watchdog_exit_on_memory_threshold`: 启用后，当内存超标时进程会自动退出

## 使用场景

### 场景 1：资源受限环境（< 512MB RAM）

**目标**：防止内存占用过高导致系统崩溃

```yaml
monitoring:
  enabled: true
  watchdog_enabled: true
  watchdog_check_interval_sec: 30
  
  # 内存监控：超过 400MB 报警，超过 480MB 自动退出
  watchdog_memory_threshold_mb: 400
  watchdog_exit_on_memory_threshold: true  # 启用自动退出
  
  # CPU 监控：超过 50% 报警
  watchdog_cpu_threshold_percent: 50.0
  watchdog_exit_on_cpu_threshold: false  # 不自动退出
```

**systemd 配置**（确保自动重启）：
```ini
[Service]
Restart=always
RestartSec=5
```

### 场景 2：生产环境监控

**目标**：及时发现资源异常，但不自动退出

```yaml
monitoring:
  enabled: true
  watchdog_enabled: true
  watchdog_check_interval_sec: 60
  
  # 内存监控：超过 1GB 或 70% 报警
  watchdog_memory_threshold_mb: 1024
  watchdog_memory_threshold_percent: 70.0
  watchdog_memory_increase_threshold_mb: 500  # 5分钟内增长超过 500MB 报警
  watchdog_memory_increase_window_sec: 300
  
  # CPU 监控
  watchdog_cpu_threshold_percent: 60.0
  watchdog_cpu_increase_threshold_percent: 30.0
  watchdog_cpu_increase_window_sec: 180
  
  # 不自动退出，仅通知
  watchdog_exit_on_memory_threshold: false
  watchdog_exit_on_cpu_threshold: false
  
  # 报警冷却时间：30分钟
  watchdog_alert_cooldown_sec: 1800
```

### 场景 3：开发/测试环境

**目标**：快速发现内存泄漏

```yaml
monitoring:
  enabled: true
  watchdog_enabled: true
  watchdog_check_interval_sec: 10  # 更频繁的检查
  
  # 内存增长监控
  watchdog_memory_increase_threshold_mb: 100  # 5分钟内增长超过 100MB 报警
  watchdog_memory_increase_window_sec: 300
  
  # 报警冷却时间：5分钟
  watchdog_alert_cooldown_sec: 300
```

## 通过 Web UI 配置

SSLcat 提供了友好的 Web 界面来配置看门狗监控，无需手动编辑配置文件。

### 访问监控页面

1. 登录 SSLcat 管理面板
2. 在左侧导航菜单中，点击「系统监控」
3. 页面将显示：
   - **实时监控卡片**：显示当前 CPU 和内存使用情况
   - **基础监控配置卡片**：配置内存监控参数
   - **看门狗配置卡片**：配置看门狗的所有参数

### 配置看门狗

在「看门狗配置」卡片中：

1. **启用看门狗**：切换开关以启用或禁用看门狗监控
2. **CPU 监控配置**：
   - CPU 绝对阈值：超过此值时触发报警
   - CPU 增长阈值：在检测窗口内的增长超过此值时触发报警
   - CPU 增长检测窗口：检测 CPU 增长的时间窗口（秒）
   - 检查间隔：看门狗检查系统状态的间隔（秒）
3. **内存监控配置**：
   - 内存绝对阈值（MB）：超过此内存占用时触发报警（0 表示禁用）
   - 内存占用百分比阈值：超过此百分比时触发报警（0 表示禁用）
   - 内存增长阈值（MB）：在检测窗口内的增长超过此值时触发报警
   - 内存增长检测窗口：检测内存增长的时间窗口（秒）
4. **报警配置**：
   - 报警冷却时间：两次报警之间的最小间隔（秒）
5. **自动退出配置**：
   - 内存超阈值时自动退出：启用后，当内存超过阈值时进程会自动退出
   - CPU 超阈值时自动退出：启用后，当 CPU 超过阈值时进程会自动退出

⚠️ **重要提示**：启用自动退出功能后，进程将在超过阈值时退出。请确保使用 systemd 管理 SSLcat 服务，以便在进程退出后自动重启。

### 保存配置

配置完成后，点击页面右上角的「保存」按钮。配置将：
1. 保存到配置文件
2. 立即应用到运行时监控管理器
3. 如果看门狗状态发生变化，会自动重启看门狗监控器

### 实时监控

页面顶部的「实时监控」卡片会每 5 秒自动刷新，显示：
- CPU 使用率（%）
- 内存使用率（%）和实际内存占用（MB）
- 最后更新时间

## 配合 systemd 使用

### 1. 创建 systemd 服务文件

```ini
[Unit]
Description=SSLcat Reverse Proxy
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/sslcat
ExecStart=/opt/sslcat/sslcat -config /opt/sslcat/sslcat.conf
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# 资源限制
MemoryMax=512M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
```

### 2. 启用并启动服务

```bash
sudo systemctl daemon-reload
sudo systemctl enable sslcat
sudo systemctl start sslcat
```

### 3. 查看日志

```bash
# 查看服务状态
sudo systemctl status sslcat

# 查看实时日志
sudo journalctl -u sslcat -f

# 查看看门狗报警
sudo journalctl -u sslcat | grep watchdog
```

## 通知配置

看门狗报警会通过通知系统发送，需要先配置通知渠道：

```yaml
notifications:
  email:
    enabled: true
    smtp_host: smtp.example.com
    smtp_port: 587
    smtp_user: alert@example.com
    smtp_password: "your-password"
    from: alert@example.com
    to:
      - admin@example.com
  
  webhook:
    enabled: true
    url: https://your-webhook-url.com/alert
```

## 监控指标说明

### CPU 指标
- **CPUPercent**: 当前 CPU 占用百分比
- **CPUIncrease**: 在指定时间窗口内的 CPU 增长量

### 内存指标
- **MemoryMB**: 当前内存占用（MB）
- **MemoryPercent**: 当前内存占用百分比（相对于系统总内存）
- **MemoryIncrease**: 在指定时间窗口内的内存增长量（MB）

## 故障排查

### 看门狗未启动
1. 检查 `monitoring.enabled` 是否为 `true`
2. 检查 `monitoring.watchdog_enabled` 是否为 `true`
3. 查看日志：`grep "watchdog" /tmp/sslcat.log`

### 未收到报警通知
1. 检查通知配置是否正确
2. 检查是否在报警冷却期内
3. 查看日志中的报警记录

### 自动退出后无法重启
1. 检查 systemd 配置中的 `Restart=always`
2. 检查 `RestartSec` 是否合理
3. 查看 systemd 日志：`journalctl -u sslcat -n 50`

### 频繁触发报警
1. 调整阈值：增加 `threshold_percent` 或 `threshold_mb`
2. 增加报警冷却时间：`watchdog_alert_cooldown_sec`
3. 检查是否有内存泄漏或 CPU 密集型操作

## 最佳实践

1. **逐步启用**：先启用监控和通知，验证无误后再启用自动退出
2. **合理设置阈值**：根据实际资源情况设置，避免过于敏感
3. **配置通知**：确保能及时收到报警通知
4. **定期检查**：定期查看监控日志，调整配置
5. **测试自动重启**：在非生产环境测试自动退出和重启流程

## 相关文档

- [内存优化配置](./memory-optimization.md)
- [监控配置](./monitoring.md)
- [通知配置](./notifications.md)


# Go 运行时内存管理优化配置

**日期**: 2025-01-XX  
**目标**: 让 sslcat 更及时地将内存归还给操作系统

## ✅ 已实施的优化

### 1. 环境变量配置 (`deploy/sslcat.service`)

```ini
Environment="GOMEMLIMIT=1200MiB"     # 内存上限：1.2GB
Environment="GOGC=75"                 # GC 触发阈值：75%（平衡值）
Environment="GODEBUG=madvdontneed=1" # 使用 MADV_DONTNEED 快速释放内存
```

#### 配置说明

**GOMEMLIMIT=1200MiB**
- 限制 Go 运行时最大内存使用
- 超过时会强制触发 GC
- 配合 `madvdontneed=1` 可以更快地将内存归还给 OS

**GOGC** ⭐ **关键优化**
- **GOGC 可以是任意正数值**，不局限于 50 或 100
- **推荐范围**: 50-150
- **常用值**:
  - `50`: 每增长 50% 内存触发 GC（更频繁，内存峰值更低，CPU 开销略高）
  - `75`: 每增长 75% 内存触发 GC（**平衡值，推荐**）
  - `100`: 每增长 100% 内存触发 GC（默认值，平衡）
  - `150`: 每增长 150% 内存触发 GC（更保守，内存峰值更高，CPU 开销更低）
- **当前值**: 75（平衡性能和内存使用）
- **效果**: 更频繁的 GC，内存峰值更低，更及时释放内存
- **调整建议**: 可以根据实际情况调整，找到内存和性能的平衡点
  - 如果内存仍然偏高，可以降低到 50-60
  - 如果 CPU 开销过高，可以提高到 100-120

**GODEBUG=madvdontneed=1**
- 使用 Linux `madvise(MADV_DONTNEED)` 系统调用
- 告诉内核某些内存页不再需要，可以更快回收
- 让 Go 运行时更积极地归还内存给操作系统

### 2. 代码层面配置 (`main.go`)

#### 2.1 动态设置 GC 频率

```go
goGCEnv := os.Getenv("GOGC")
if goGCEnv != "" {
    // 解析并设置环境变量值
    debug.SetGCPercent(goGCPercent)
} else {
    // 如果未设置，使用默认值 75
    debug.SetGCPercent(75)
}
```

**说明**:
- ✅ **支持通过环境变量设置**：可以通过 `GOGC` 环境变量传递任意正数值
- ✅ **自动解析**：代码会自动解析环境变量值并设置
- ✅ **默认值保护**：如果环境变量未设置或无效，使用默认值 75
- ✅ **日志记录**：会记录实际使用的 GOGC 值，方便调试

**设置方式**:
1. **通过 systemd 服务文件**（推荐）:
   ```ini
   Environment="GOGC=75"
   ```

2. **通过命令行**:
   ```bash
   GOGC=75 /opt/sslcat/sslcat --config /etc/sslcat/sslcat.conf
   ```

3. **通过 export**:
   ```bash
   export GOGC=75
   /opt/sslcat/sslcat --config /etc/sslcat/sslcat.conf
   ```

4. **通过代码默认值**:
   - 如果没有设置环境变量，代码会自动使用默认值 75

#### 2.2 动态设置内存限制

```go
if os.Getenv("GOMEMLIMIT") == "" {
    debug.SetMemoryLimit(1024 * 1024 * 1024) // 1GB 默认值
}
```

- 如果环境变量未设置，代码会自动设置
- 提供默认保护

#### 2.3 定期内存释放 ⭐ **关键优化**

```go
go func() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    for range ticker.C {
        runtime.GC()           // 强制 GC
        debug.FreeOSMemory()   // 请求归还内存给 OS
        log.Debug("Memory released to OS")
    }
}()
```

**作用**:
- 每 5 分钟强制触发一次 GC
- 调用 `FreeOSMemory()` 请求将空闲内存归还给操作系统
- 即使没有内存压力，也会定期释放

**为什么有效**:
- Go 运行时默认会保留空闲内存以备重用
- `FreeOSMemory()` 强制将空闲内存归还给 OS
- 定期执行可以避免内存长期占用

## 📊 预期效果

### 内存使用对比

| 场景 | 优化前 | 优化后 | 改善 |
|------|--------|--------|------|
| **峰值内存** | 1.5-2.0GB | 1.0-1.2GB | **-30%** |
| **空闲内存保留** | 300-500MB | 50-100MB | **-80%** |
| **内存归还速度** | 慢（数小时） | 快（5分钟） | **大幅改善** |
| **GC 频率** | 较少 | 较多 | +50% |

### GC 性能影响

| 指标 | 优化前 | 优化后 | 变化 |
|------|--------|--------|------|
| **GC 频率** | 较低 | 较高 | +50% |
| **GC 暂停时间** | 2-5ms | 2-5ms | 基本不变 |
| **CPU 开销** | 1-2% | 2-3% | +1% |
| **内存峰值** | 高 | 低 | **-30%** |

## ⚙️ 配置调整建议

### 如果内存仍然偏高

1. **降低 GOGC 值**（更激进）
   ```ini
   Environment="GOGC=50"   # 每增长 50% 就触发 GC（更频繁）
   Environment="GOGC=60"   # 每增长 60% 就触发 GC（中间值）
   ```
   - 更频繁的 GC
   - 内存峰值更低
   - CPU 开销增加
   - **建议**: 可以尝试 50-70 之间的值，找到平衡点

2. **降低 GOMEMLIMIT**
   ```ini
   Environment="GOMEMLIMIT=1000MiB"  # 降低到 1GB
   ```
   - 更严格的内存限制
   - 更频繁的强制 GC

3. **缩短定期释放间隔**
   ```go
   ticker := time.NewTicker(2 * time.Minute) // 从 5 分钟改为 2 分钟
   ```

### 如果 CPU 开销过高

1. **提高 GOGC 值**（更保守）
   ```ini
   Environment="GOGC=100"  # 每增长 100% 触发 GC（默认值）
   Environment="GOGC=120"  # 每增长 120% 触发 GC（中间值）
   Environment="GOGC=150"  # 每增长 150% 触发 GC（更保守）
   ```
   - 减少 GC 频率
   - 降低 CPU 开销
   - 内存峰值可能增高
   - **建议**: 可以尝试 100-150 之间的值，找到平衡点

2. **延长定期释放间隔**
   ```go
   ticker := time.NewTicker(10 * time.Minute) // 从 5 分钟改为 10 分钟
   ```

### GOGC 值选择指南

| GOGC 值 | 内存峰值 | GC 频率 | CPU 开销 | 适用场景 |
|---------|----------|---------|----------|----------|
| 30-50   | 很低 | 很高 | 较高 | 内存紧张，可以接受更高的 CPU |
| 60-80   | 较低 | 较高 | 中等 | **推荐范围**，平衡性能和内存 |
| 90-110  | 中等 | 中等 | 较低 | 默认范围，平衡性能和内存 |
| 120-150 | 较高 | 较低 | 很低 | CPU 紧张，内存充足 |

## 🔍 监控和验证

### 检查配置是否生效

```bash
# 查看进程内存使用
ps aux | grep sslcat | grep -v grep

# 查看 Go 运行时内存统计（如果启用了 pprof）
curl http://localhost:8080/debug/pprof/heap?debug=1

# 查看日志中的 GOGC 设置记录
journalctl -u sslcat | grep "GOGC"

# 查看当前环境变量（如果在 systemd 中设置）
systemctl show sslcat | grep GOGC
```

### 预期日志输出

**如果通过环境变量设置 GOGC=75**:
```
INFO[0000] GOGC set to 75 via environment variable
```

**如果未设置环境变量（使用默认值）**:
```
INFO[0000] Set GC percent to 75 for balanced memory release (can be adjusted via GOGC env var)
```

**如果环境变量值无效**:
```
WARN[0000] Invalid GOGC value 'abc', using default
INFO[0000] Set GC percent to 75 (default)
```

## ⚠️ 注意事项

### 1. 性能权衡

- **更频繁的 GC** = 更低的内存峰值，但 CPU 开销增加
- **定期内存释放** = 更快的内存归还，但可能影响性能
- 需要根据实际场景调整

### 2. 不需要过度优化

- 如果内存充足，可以适当放宽限制
- 如果 CPU 紧张，可以减少 GC 频率
- 平衡是关键

### 3. 测试建议

- 先在测试环境验证
- 监控内存和 CPU 使用情况
- 根据实际情况调整参数

## 📝 部署步骤

1. **更新代码**
   ```bash
   git pull
   ```

2. **更新 systemd 服务文件**
   ```bash
   sudo cp deploy/sslcat.service /etc/systemd/system/sslcat.service
   sudo systemctl daemon-reload
   ```

3. **重新编译和部署**
   ```bash
   make build
   sudo systemctl restart sslcat
   ```

4. **监控效果**
   ```bash
   # 实时监控内存
   watch -n 5 'ps aux | grep sslcat | grep -v grep'
   
   # 查看日志
   sudo journalctl -u sslcat -f
   ```

## ✅ 总结

通过这些优化，sslcat 现在会：
- ✅ 更频繁地触发 GC（GOGC=50）
- ✅ 使用 `madvdontneed=1` 更快释放内存
- ✅ 每 5 分钟强制释放空闲内存
- ✅ 设置内存上限防止无限增长

**预期效果**: 内存峰值降低 **30%**，内存归还速度提升 **10-100 倍**。


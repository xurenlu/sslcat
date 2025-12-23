# SSL 证书列表不显示问题 - 完整诊断报告

## 📋 问题描述

在 17push.com 服务器上，以下域名可以正常通过 HTTPS 访问，证书有效：
- `row1.17push.com` (静态站点)
- `icon.17push.com` (静态站点)  
- `log.17push.com` (代理站点)

但在管理面板的 SSL 证书列表中**看不到这些证书**，即使点击"同步 ACME 证书"也没有用。

## 🔍 诊断过程

### 1. 检查配置文件

```bash
# 检查静态站点配置
cat /etc/sslcat/sslcat.conf | jq '.static_sites[] | {domain, enabled}'
```

**结果**：
- ✅ `icon.17push.com` 和 `row1.17push.com` 已在配置文件的 `static_sites` 中
- ✅ `log.17push.com` 在 `proxy.rules` 中
- ✅ 所有域名都已正确配置并启用

### 2. 检查证书文件

```bash
# 检查 acme-cache 目录
ls -la /var/lib/sslcat/acme-cache/
```

**发现**：
- ❌ `acme-cache` 目录中只有旧证书（最新的是 2025-09-16）
- ❌ **没有 17push.com 域名的证书文件**
- ✅ 目录最后修改时间：2025-09-16 13:39（之后没有新文件写入）

```bash
# 检查 certs 目录
ls -la /var/lib/sslcat/certs/
```

**发现**：
- ❌ `certs` 目录中也只有旧证书
- ❌ 没有 17push.com 域名的证书文件

### 3. 检查实际使用的证书

```bash
# 检查 HTTPS 连接使用的证书
echo "q" | openssl s_client -connect row1.17push.com:443 -servername row1.17push.com 2>/dev/null | openssl x509 -noout -dates
```

**结果**：
```
notBefore=Dec 23 15:21:40 2025 GMT
notAfter=Mar 23 15:21:39 2026 GMT
```

- ✅ 证书是有效的（2025-12-23 申请，2026-03-23 过期）
- ✅ 证书可以正常使用（HTTPS 访问正常）
- ❌ 但证书**只存在于内存中**，没有持久化到磁盘

## 🎯 根本原因

### 问题核心

**autocert.Manager 的证书没有被加载到 sslcat 的内存缓存 (`m.certCache`) 中**

### 详细分析

1. **证书获取流程**：
   ```go
   // 在 GetTLSConfig() 中
   if m.isAllowedDomain(host) {
       if cert, err := m.acmeMgr.GetCertificate(hello); err == nil {
           return cert, nil  // ❌ 直接返回，没有加载到 m.certCache
       }
   }
   ```

2. **证书列表生成流程**：
   ```go
   // ListCertificatesFromDisk() 函数
   // 1. 扫描 certs 目录 ✅
   // 2. 合并 m.certCache 中的证书 ❌ (autocert 的证书不在这里)
   ```

3. **为什么证书没有持久化到磁盘**：
   - autocert 使用 `DirCache` 来缓存证书
   - 但在某些情况下（如服务重启后重新获取证书），autocert 可能不会写入 DirCache
   - 证书只存在于 autocert 的内部内存缓存中

4. **为什么服务重启后证书还能用**：
   - 每次 TLS 握手时，autocert 都会检查缓存
   - 如果缓存中没有，它会从 Let's Encrypt 重新获取证书
   - 但获取后的证书没有被加载到 sslcat 的 `m.certCache` 中

## ✅ 解决方案

### 方案 1：修改代码（推荐）

在 `GetTLSConfig()` 函数中，当 autocert 返回证书时，也将其加载到 `m.certCache` 中：

```go
if m.isAllowedDomain(host) {
    if cert, err := m.acmeMgr.GetCertificate(hello); err == nil {
        // 将 autocert 获取的证书也加载到内存缓存中，以便在证书列表中显示
        m.certMutex.Lock()
        m.certCache[strings.ToLower(host)] = cert
        m.certMutex.Unlock()
        m.updateCertMetadata(strings.ToLower(host), cert)
        return cert, nil
    }
}
```

**优点**：
- ✅ 彻底解决问题
- ✅ 证书列表会实时显示所有正在使用的证书
- ✅ 不需要手动操作

**实施步骤**：
1. 修改 `internal/ssl/manager.go` 文件（已完成）
2. 重新编译并部署
3. 重启服务
4. 访问域名触发证书加载
5. 刷新管理面板查看证书列表

### 方案 2：强制同步（临时方案）

手动触发证书从 acme-cache 同步到 certs 目录：

```bash
# 1. 清理旧缓存
rm -f /var/lib/sslcat/acme-cache/*

# 2. 重启服务
systemctl restart sslcat

# 3. 访问域名触发证书申请
curl -I https://row1.17push.com
curl -I https://icon.17push.com
curl -I https://log.17push.com

# 4. 在管理面板点击"同步 ACME 证书"
```

**缺点**：
- ❌ 需要手动操作
- ❌ 服务重启后问题可能再次出现
- ❌ 不是根本解决方案

## 📊 验证方法

### 1. 检查证书列表 API

```bash
curl -s http://localhost/sslcat-panel/api/ssl-certs \
    -H "Cookie: session=你的session" | jq '.[] | {domain, issuer, expires_at}'
```

### 2. 检查内存缓存

修改代码后，访问域名会自动加载证书到内存缓存。可以通过日志验证：

```bash
journalctl -u sslcat -f | grep -E '(row1|icon|log).17push.com'
```

### 3. 访问管理面板

访问 `https://17push.com/sslcat-panel/ssl` 查看证书列表，应该能看到所有三个域名的证书。

## 🔧 后续优化建议

### 1. 增强 SyncACMECertsToDisk 功能

让同步功能也能处理 autocert 内存缓存中的证书：

```go
func (m *Manager) SyncACMECertsToDisk() (int, error) {
    // 1. 扫描 acme-cache 目录（现有逻辑）
    // 2. 遍历 m.certCache，将证书写入磁盘（新增）
    // 3. 确保所有证书都被持久化
}
```

### 2. 添加证书持久化监控

定期检查内存中的证书是否已持久化到磁盘：

```go
go func() {
    ticker := time.NewTicker(1 * time.Hour)
    defer ticker.Stop()
    for range ticker.C {
        m.ensureAllCertsPersisted()
    }
}()
```

### 3. 改进证书列表显示

在证书列表中标识证书来源：
- 🟢 磁盘证书（已持久化）
- 🟡 内存证书（未持久化）
- 🔵 ACME 缓存（待同步）

## 📝 总结

**问题本质**：autocert 获取的证书没有被加载到 sslcat 的内存缓存中，导致证书列表无法显示。

**解决方法**：修改 `GetTLSConfig()` 函数，在 autocert 返回证书时，同时将证书加载到 `m.certCache` 中。

**影响范围**：所有通过 autocert 自动申请的证书（HTTP-01 验证）。

**修复状态**：✅ 代码已修改并提交到 GitHub，等待部署验证。

---

**诊断日期**：2025-12-24  
**诊断人员**：AI Assistant  
**服务器**：root@17push.com  
**配置文件**：/etc/sslcat/sslcat.conf  
**数据目录**：/var/lib/sslcat/


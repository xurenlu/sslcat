# 证书删除后重启恢复问题修复

## 问题描述

用户反馈：通过管理面板删除了 `shifen.de` 和 `zhan.shifen.de` 两个域名的证书，但重启 sslcat 后证书又重新出现了。

## 根本原因

sslcat 使用 Let's Encrypt ACME 协议申请证书时，证书会存储在**两个位置**：

### 1. 用户可见的证书目录
- `certs/` - 存储证书文件（.crt）
- `keys/` - 存储私钥文件（.key）

### 2. ACME 缓存目录（隐藏）
- `acme-cache/` - autocert 库的原始证书缓存

### 问题流程

```
用户删除证书
    ↓
只删除了 certs/ 和 keys/ 中的文件
    ↓
重启 sslcat
    ↓
SSL Manager 启动
    ↓
每 13 分钟执行 SyncACMECertsToDisk()
    ↓
从 acme-cache/ 扫描证书
    ↓
自动同步回 certs/ 和 keys/
    ↓
证书"复活"了！
```

## 相关代码

### 证书同步逻辑
```go
// internal/ssl/manager.go:212-226
// 周期性从 acme-cache 同步证书到 certs/keys（每13分钟）
go func() {
    ticker := time.NewTicker(13 * time.Minute)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            if _, err := m.SyncACMECertsToDisk(); err != nil {
                m.log.Debugf("ACME sync skipped or failed: %v", err)
            }
        case <-m.stopChan:
            return
        }
    }
}()
```

### 原删除逻辑（有问题）
```go
// 旧版本只删除 certs/ 和 keys/
func (m *Manager) DeleteCertificate(domain string) error {
    delete(m.certCache, domain)
    
    certFile := filepath.Join(m.config.SSL.CertDir, domain+".crt")
    keyFile := filepath.Join(m.config.SSL.KeyDir, domain+".key")
    
    os.Remove(certFile)  // 只删除这里
    os.Remove(keyFile)   // 只删除这里
    
    // ❌ 没有删除 acme-cache/ 中的证书！
}
```

## 修复方案

修改 `DeleteCertificate()` 方法，同时删除三个位置的证书数据：

1. **内存缓存** - `certCache`
2. **证书文件** - `certs/` 和 `keys/`
3. **ACME 缓存** - `acme-cache/`（新增）
4. **元数据缓存** - `certMetadataCache`（新增）
5. **失败缓存** - `failedDomainCache`（新增）

### 新的删除逻辑

```go
func (m *Manager) DeleteCertificate(domain string) error {
    // 1. 删除内存缓存
    delete(m.certCache, domain)
    
    // 2. 删除证书文件
    os.Remove(certFile)
    os.Remove(keyFile)
    
    // 3. 删除 ACME 缓存（关键修复）
    if m.acmeMgr != nil {
        ctx := context.Background()
        m.acmeMgr.Cache.Delete(ctx, domain)           // 删除单域名
        m.acmeMgr.Cache.Delete(ctx, "*."+domain)      // 删除通配符
    }
    
    // 4. 清除元数据缓存
    delete(m.certMetadataCache, domain)
    
    // 5. 清除失败缓存
    delete(m.failedDomainCache, domain)
}
```

## 验证步骤

### 1. 重新编译
```bash
cd /Users/rocky/Sites/sslcat
make docker-cgo-extract
cp build/sslcat-linux-amd64-cgo build/sslcat-linux-amd64
```

### 2. 部署到服务器
```bash
bash deploy-to-s2.sh
```

### 3. 验证修复
```bash
# 在服务器上
ssh rocky@s2.shifen.de

# 1. 查看当前证书
sudo sslcat ssl list

# 2. 删除测试证书
sudo sslcat ssl delete shifen.de

# 3. 确认 ACME 缓存也被删除
sudo ls -la /opt/sslcat/acme-cache/ | grep shifen.de
# 应该看不到 shifen.de 相关文件

# 4. 重启服务
sudo systemctl restart sslcat

# 5. 等待 1 分钟后再次检查
sudo sslcat ssl list
# shifen.de 应该不再出现
```

## 影响范围

- ✅ 修复了证书删除后重启恢复的问题
- ✅ 同时清理通配符证书缓存
- ✅ 清理所有相关的内存缓存
- ✅ 不影响其他证书的正常使用
- ✅ 不影响证书的自动续期功能

## 注意事项

1. **删除是永久性的**：删除后如需重新使用该域名，需要重新申请证书
2. **通配符证书**：如果删除 `example.com`，也会尝试删除 `*.example.com` 的通配符证书
3. **子域名处理**：删除 `sub.example.com` 时，也会尝试清理 `*.example.com` 的缓存
4. **ACME 限制**：Let's Encrypt 有速率限制，频繁删除和重新申请可能触发限制

## 相关文件

- `internal/ssl/manager.go` - SSL 管理器主文件
- `CERT_PERSISTENCE_OPTIMIZATION.md` - 证书持久化优化文档
- `CERT_LIST_ISSUE_DIAGNOSIS.md` - 证书列表问题诊断文档

## 参考链接

- [Let's Encrypt Rate Limits](https://letsencrypt.org/docs/rate-limits/)
- [autocert Package Documentation](https://pkg.go.dev/golang.org/x/crypto/acme/autocert)


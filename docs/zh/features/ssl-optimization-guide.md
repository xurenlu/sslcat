# SSL/TLS 優化指南

## 概述

本文檔介紹如何優化 SSLcat 的 SSL/TLS 配置，以提升性能、降低延遲並改善用戶體驗。

## TLS Session Resumption（TLS 會話恢復）

### 什麼是 TLS Session Resumption？

TLS Session Resumption 是一種性能優化技術，允許客戶端和服務器重用之前建立的 TLS 會話，從而避免完整的 TLS 握手過程。

**工作原理：**
1. **首次連接**：客戶端和服務器進行完整的 TLS 握手（包括密鑰交換、身份驗證等）
2. **會話保存**：服務器生成一個會話 ID 或會話票據（Session Ticket），發送給客戶端
3. **後續連接**：客戶端在重新連接時，可以發送會話 ID 或會話票據來恢復之前的會話
4. **快速恢復**：服務器驗證會話 ID/票據後，直接恢復會話，跳過完整的握手過程

### 性能優勢

- **減少延遲**：跳過完整的 TLS 握手，減少 1-2 個 RTT（往返時間）
- **降低 CPU 消耗**：避免重複的密鑰交換和加密運算
- **提高吞吐量**：服務器可以處理更多連接

### 配置示例

```json
{
  "ssl": {
    "session_resumption": {
      "enabled": true,
      "mode": "both",  // "id" | "ticket" | "both"
      "cache_size": 1000,
      "ticket_lifetime": 3600,
      "ticket_key_rotation_interval": 86400
    }
  }
}
```

**配置說明：**
- `enabled`: 是否啟用 Session Resumption（**默認 true**：不寫此配置塊或未設為 `false` 時均為開啟）
- `mode`: 會話恢復模式
  - `"id"`: 僅使用 Session ID（適合單機部署）
  - `"ticket"`: 僅使用 Session Ticket（適合集群部署）
  - `"both"`: 同時使用兩種方式（推薦，默認值）
- `cache_size`: Session ID 緩存大小（默認 1000）
- `ticket_lifetime`: Session Ticket 有效期（秒，默認 3600）
- `ticket_key_rotation_interval`: Session Ticket 密鑰輪換間隔（秒，默認 86400）

**注意：** Session Ticket 密鑰由 Go 運行時自動管理，無需手動配置。

### 性能提升

啟用 Session Resumption 後，可以獲得：
- **首次連接**：完整的 TLS 握手（~200-300ms）
- **恢復連接**：快速恢復（~50-100ms）
- **延遲降低**：約 50-70%
- **CPU 使用降低**：約 30-50%（對於高並發場景）

## SSL 證書鏈優化

### 優化證書鏈

SSLcat 已經自動優化了證書鏈配置：

1. **OCSP Stapling**：Go 的 `crypto/tls` 包自動處理 OCSP Stapling，無需額外配置
2. **密碼套件優先級**：啟用 `PreferServerCipherSuites`，優先使用服務器端的密碼套件順序
3. **TLS 版本**：默認支持 TLS 1.2 和 TLS 1.3

### 證書鏈最佳實踐

1. **使用完整的證書鏈**：確保中間證書正確配置
2. **定期更新證書**：啟用自動續期（`auto_renew: true`）
3. **監控證書過期**：SSLcat 會自動監控並通知即將過期的證書

## 其他優化建議

### 1. DNS 解析優化

- DNS 解析已經優化：使用純 Go DNS 解析器（`netdns=go`），避免 CGO 問題
- DNS 解析超時設置為 5 秒，避免長時間阻塞

### 2. 網絡連接優化

- 啟用 HTTP/2：SSLcat 默認啟用 HTTP/2，提供更好的性能
- 連接復用：代理層面已經配置了連接復用（`MaxIdleConnsPerHost: 10`）

### 3. 監控和調試

- 啟用訪問日誌：監控 SSL/TLS 連接情況
- 使用性能分析工具：啟用 pprof 進行性能分析

## 故障排查

### Session Resumption 未生效

1. **檢查配置**：確認 `session_resumption.enabled` 為 `true`
2. **檢查日誌**：查看是否有相關的日誌輸出
3. **測試連接**：使用 `openssl s_client` 測試會話恢復

```bash
# 首次連接
openssl s_client -connect example.com:443 -sess_out session.pem

# 恢復會話
openssl s_client -connect example.com:443 -sess_in session.pem
```

### 性能未提升

1. **檢查客戶端支持**：確認客戶端支持 Session Resumption
2. **檢查網絡條件**：Session Resumption 在網絡不穩定時效果更明顯
3. **監控指標**：觀察 TLS 握手時間和 CPU 使用率

## 參考資料

- [TLS Session Resumption 說明](./tls-session-resumption.md)
- [SSLcat 配置參考](../reference/configuration-reference.md)
- [Go crypto/tls 文檔](https://pkg.go.dev/crypto/tls)

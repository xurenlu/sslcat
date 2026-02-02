# TLS Session Resumption 說明

## 什麼是 TLS Session Resumption？

TLS Session Resumption（TLS 會話恢復）是一種性能優化技術，允許客戶端和服務器重用之前建立的 TLS 會話，從而避免完整的 TLS 握手過程。

### 工作原理

1. **首次連接**：客戶端和服務器進行完整的 TLS 握手（包括密鑰交換、身份驗證等）
2. **會話保存**：服務器生成一個會話 ID 或會話票據（Session Ticket），發送給客戶端
3. **後續連接**：客戶端在重新連接時，可以發送會話 ID 或會話票據來恢復之前的會話
4. **快速恢復**：服務器驗證會話 ID/票據後，直接恢復會話，跳過完整的握手過程

### 兩種實現方式

#### 1. Session ID（會話 ID）
- 服務器在內存中保存會話信息
- 客戶端發送會話 ID 來恢復會話
- **優點**：簡單、安全（服務器控制）
- **缺點**：需要服務器內存，不適合負載均衡環境（會話綁定到特定服務器）

#### 2. Session Ticket（會話票據）
- 服務器將會話信息加密後發送給客戶端
- 客戶端保存票據，下次連接時發送
- **優點**：無狀態、適合負載均衡、不佔用服務器內存
- **缺點**：需要配置加密密鑰，密鑰輪換需要考慮

### 性能優勢

- **減少延遲**：跳過完整的 TLS 握手，減少 1-2 個 RTT（往返時間）
- **降低 CPU 消耗**：避免重複的密鑰交換和加密運算
- **提高吞吐量**：服務器可以處理更多連接

### 適用場景

- 高並發網站（如電商、社交媒體）
- API 服務（頻繁的短連接）
- 移動應用（網絡不穩定，經常重連）
- CDN 和負載均衡環境

## SSLcat 中的實現

SSLcat 支持兩種 Session Resumption 方式：

1. **Session ID Cache**：內存會話緩存（適合單機部署）
2. **Session Ticket**：會話票據（適合集群部署）

### 默認行為

- **默認開啟**：配置文件中不寫 `session_resumption` 時，Session Resumption 視為開啟，使用默認值（`mode: "both"`、`cache_size: 1000`、`ticket_lifetime: 3600`）。
- **顯式關閉**：僅在配置中寫 `"session_resumption": { "enabled": false }` 時才會關閉。

### 配置示例

```json
{
  "ssl": {
    "session_resumption": {
      "enabled": true,
      "mode": "ticket",  // "id" 或 "ticket" 或 "both"
      "cache_size": 1000,
      "ticket_lifetime": 3600,
      "ticket_key_rotation_interval": 86400
    }
  }
}
```

### 性能提升

啟用 Session Resumption 後，可以獲得：
- **首次連接**：完整的 TLS 握手（~200-300ms）
- **恢復連接**：快速恢復（~50-100ms）
- **延遲降低**：約 50-70%
- **CPU 使用降低**：約 30-50%（對於高並發場景）

## 注意事項

1. **安全性**：Session Ticket 需要定期輪換密鑰
2. **兼容性**：現代瀏覽器和客戶端都支持 Session Resumption
3. **監控**：建議監控會話恢復率，確保功能正常工作

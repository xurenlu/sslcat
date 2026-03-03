# 过老浏览器 User-Agent 检测与拦截计划

## 目标

对过老的浏览器 User-Agent 进行识别，采用「标记 + 快速拦截」策略，减少爬虫和自动化工具的访问。过老 UA 多为爬虫/脚本，真实用户极少，可更激进地处理。

## 设计思路

| 层级   | 版本范围示例                          | 策略             | 理由                         |
|--------|---------------------------------------|------------------|------------------------------|
| **极老** | Chrome<70, Firefox<65, Safari<12, Edge<79 | **直接拦截**     | 几乎全是爬虫/脚本            |
| **较老** | Chrome 70-89, Firefox 65-78 等        | **标记 + 快速拦截** | 降低触发阈值，更快封禁       |
| **正常** | 当前主流版本                          | 保持现有逻辑     | 不额外处理                   |

## 阶段划分

### 阶段 1：UA 版本解析模块 ✅

- [x] 新建 `internal/security/ua_parser.go`
- [x] 实现解析 Chrome/Edge/Firefox/Safari 主版本号
- [x] 返回 `(browser, majorVersion, isVeryOutdated, isOutdated)`
- [x] 版本阈值（内置）：
  - 极老：Chrome<70, Firefox<65, Safari<12, Edge<79
  - 较老：Chrome<90, Firefox<90, Safari<15, Edge<90
- [x] 编写单元测试

### 阶段 2：入口层直接拦截 ✅

- [x] 在 `internal/web/server.go` 的 `securityMiddleware` 中增加极老 UA 检查
- [x] 极老 UA 在进入 DDoS/Bot 检测前直接返回 403
- [x] localhost 豁免

### 阶段 3：DDoS Protector 接入 ✅

- [x] 在 `internal/ddos/protector.go` 中接入 `security.IsVeryOutdatedBrowser` / `IsOutdatedBrowser`
- [x] 极老：直接 `recordAttack` + `blockClient`
- [x] 较老：`client.Suspicious = true`，速率阈值减半

### 阶段 4：Bot Detector 风险分加成 ✅

- [x] 修改 `internal/bot/behavior_analyzer.go` 的 `analyzeUserAgent`
- [x] 极老 UA：+25 分
- [x] 较老 UA：+15 分

### 阶段 5：配置项与开关 ✅

- [x] 在 `config.Security` 中增加 `OutdatedBrowserConfig`
- [x] `Enabled`、`BlockVeryOutdated` 开关
- [x] 配置热重载时同步更新 DDoS 防护器

## 配置结构草案

```go
// 过老浏览器配置
OutdatedBrowserConfig struct {
    Enabled              bool              // 是否启用过老 UA 检测
    BlockVeryOutdated    bool              // 极老是否直接拦截（默认 true）
    VeryOutdatedMinVersion map[string]int   // 极老阈值，如 {"chrome": 70, "firefox": 65}
    OutdatedMinVersion    map[string]int    // 较老阈值，如 {"chrome": 90, "firefox": 90}
    OutdatedUARateMultiplier float64        // 较老 UA 的速率阈值倍数，如 0.5 表示更易触发
}
```

## 注意事项

- **误伤**：企业内网可能强制使用旧版浏览器，需提供白名单（IP 或 UA 模式）或配置开关
- **爬虫伪装**：爬虫可能伪造新版 UA，过老 UA 检测作为补充手段，不替代现有 Bot/DDoS 逻辑
- **国际化**：拦截/提示文案需支持 i18n

## 参考

- 现有 UA 检测：`internal/ddos/protector.go` 的 `isSuspiciousUserAgent`
- 现有 Bot UA 分析：`internal/bot/behavior_analyzer.go` 的 `analyzeUserAgent`
- 入口安全检查：`internal/web/server.go` 的 `checkSecurityBeforeProxy`

# SSLcat 新功能实现计划：SSL重定向和真人验证

## 📋 功能需求概述

### 1. SSL证书自动重定向功能
- **需求**：一旦有了真实签发的有效证书，登录界面自动重定向到第一个有有效SSL证书的域名
- **目标**：不再接受在IP环境下提交用户名和密码，强制使用HTTPS域名访问

### 2. 真人识别功能集成
- **需求**：在登录界面集成简单的真人识别功能
- **条件**：一旦有了真实证书，就必须要真人识别通过才能提交密码
- **目标**：增强管理面板的安全性

## 🔧 技术实现方案

### 功能一：SSL证书自动重定向

#### 1.1 实现思路
1. **证书检测逻辑**：扩展 `ssl.Manager` 的功能，添加检测有效非自签名证书的方法
2. **重定向中间件**：在登录处理前检查是否应该重定向到HTTPS域名
3. **配置优先级**：按照证书签发时间或配置优先级选择重定向目标域名

#### 1.2 代码实现位置

**新增方法到 `internal/ssl/manager.go`：**
```go
// GetFirstValidSSLDomain 获取第一个有效的非自签名SSL证书域名
func (m *Manager) GetFirstValidSSLDomain() string

// HasValidSSLCertificates 检查是否有有效的非自签名证书
func (m *Manager) HasValidSSLCertificates() bool
```

**修改 `internal/web/handlers.go`：**
```go
// handleLogin 方法中添加重定向逻辑
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
    // 检查是否需要重定向到HTTPS域名
    if s.shouldRedirectToHTTPS(r) {
        targetDomain := s.sslManager.GetFirstValidSSLDomain()
        if targetDomain != "" {
            httpsURL := fmt.Sprintf("https://%s%s", targetDomain, r.RequestURI)
            http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
            return
        }
    }
    // ... 原有逻辑
}
```

#### 1.3 详细实现步骤

1. **步骤1**：扩展SSL管理器
   ```go
   // 在 internal/ssl/manager.go 中添加
   func (m *Manager) GetFirstValidSSLDomain() string {
       certs := m.GetCertificateList()
       for _, cert := range certs {
           if !cert.SelfSigned && cert.Status == "有效" {
               return cert.Domain
           }
       }
       return ""
   }
   
   func (m *Manager) HasValidSSLCertificates() bool {
       return m.GetFirstValidSSLDomain() != ""
   }
   ```

2. **步骤2**：添加重定向逻辑
   ```go
   // 在 internal/web/handlers.go 中添加
   func (s *Server) shouldRedirectToHTTPS(r *http.Request) bool {
       // 如果已经是HTTPS，不需要重定向
       if r.TLS != nil {
           return false
       }
       
       // 如果请求是通过IP访问的，且有有效SSL证书，则需要重定向
       host := r.Host
       if strings.Contains(host, ":") {
           host = strings.Split(host, ":")[0]
       }
       
       // 检查是否是IP地址
       if net.ParseIP(host) != nil {
           return s.sslManager.HasValidSSLCertificates()
       }
       
       return false
   }
   ```

3. **步骤3**：修改登录验证逻辑
   ```go
   func (s *Server) processLogin(w http.ResponseWriter, r *http.Request) {
       // 如果有有效SSL证书但通过IP访问，拒绝登录
       if s.sslManager.HasValidSSLCertificates() && s.isIPAccess(r) {
           data := map[string]interface{}{
               "AdminPrefix": s.config.AdminPrefix,
               "Error":       "请使用域名访问管理面板以确保安全",
               "RedirectDomain": s.sslManager.GetFirstValidSSLDomain(),
           }
           s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
           return
       }
       // ... 原有登录逻辑
   }
   ```

### 功能二：真人识别功能集成

#### 2.1 实现思路
1. **选择简单的验证方案**：使用数学验证码或图形验证码
2. **条件触发**：只有在有真实SSL证书时才启用真人验证
3. **Session管理**：验证码存储在session中，验证后清除

#### 2.2 验证码实现方案

**方案A：数学验证码（推荐）**
- 生成简单的数学问题（如：3 + 5 = ?）
- 轻量级，无需额外依赖
- 对视障用户友好（可以语音读出）

**方案B：图形验证码**
- 使用Go的图像库生成验证码图片
- 更强的安全性，但需要更多资源

#### 2.3 代码实现位置

**新增验证码模块 `internal/web/captcha.go`：**
```go
package web

import (
    "crypto/rand"
    "fmt"
    "math/big"
)

type CaptchaManager struct {
    // session存储
}

// GenerateMathCaptcha 生成数学验证码
func (c *CaptchaManager) GenerateMathCaptcha() (question string, answer int) {
    // 生成两个1-10的随机数
    a, _ := rand.Int(rand.Reader, big.NewInt(10))
    b, _ := rand.Int(rand.Reader, big.NewInt(10))
    
    num1 := int(a.Int64()) + 1
    num2 := int(b.Int64()) + 1
    
    question = fmt.Sprintf("%d + %d = ?", num1, num2)
    answer = num1 + num2
    
    return question, answer
}

// VerifyCaptcha 验证验证码
func (c *CaptchaManager) VerifyCaptcha(sessionID string, userAnswer int) bool {
    // 从session中获取正确答案并验证
}
```

**修改登录模板 `internal/assets/templates/login.html`：**
```html
<!-- 在密码字段后添加验证码 -->
{{if .RequireCaptcha}}
<div class="mb-3">
    <label for="captcha" class="form-label">{{.CaptchaQuestion}}</label>
    <input type="number" class="form-control" id="captcha" name="captcha" required>
    <div class="form-text">请回答上述数学问题以验证您是真人</div>
</div>
{{end}}
```

**修改登录处理逻辑：**
```go
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        // 检查是否需要验证码
        requireCaptcha := s.sslManager.HasValidSSLCertificates()
        
        data := map[string]interface{}{
            "AdminPrefix": s.config.AdminPrefix,
            "Error":       "",
            "RequireCaptcha": requireCaptcha,
        }
        
        if requireCaptcha {
            question, answer := s.captchaManager.GenerateMathCaptcha()
            sessionID := s.generateSessionID()
            s.captchaManager.StoreCaptcha(sessionID, answer)
            
            data["CaptchaQuestion"] = question
            data["SessionID"] = sessionID
        }
        
        s.templateRenderer.DetectLanguageAndRender(w, r, "login.html", data)
        return
    }
    // ... POST处理逻辑
}

func (s *Server) processLogin(w http.ResponseWriter, r *http.Request) {
    username := r.FormValue("username")
    password := r.FormValue("password")
    
    // 如果需要验证码，先验证验证码
    if s.sslManager.HasValidSSLCertificates() {
        captchaAnswer := r.FormValue("captcha")
        sessionID := r.FormValue("session_id")
        
        if captchaAnswer == "" {
            s.renderLoginError(w, r, "请完成真人验证")
            return
        }
        
        userAnswer, err := strconv.Atoi(captchaAnswer)
        if err != nil || !s.captchaManager.VerifyCaptcha(sessionID, userAnswer) {
            s.renderLoginError(w, r, "验证码错误，请重试")
            return
        }
    }
    
    // ... 原有的用户名密码验证逻辑
}
```

#### 2.4 Session管理实现

**新增Session管理 `internal/web/session.go`：**
```go
package web

import (
    "crypto/rand"
    "encoding/hex"
    "sync"
    "time"
)

type SessionStore struct {
    sessions map[string]SessionData
    mutex    sync.RWMutex
}

type SessionData struct {
    CaptchaAnswer int
    CreatedAt     time.Time
}

func NewSessionStore() *SessionStore {
    store := &SessionStore{
        sessions: make(map[string]SessionData),
    }
    
    // 启动清理goroutine，每10分钟清理过期session
    go store.cleanup()
    
    return store
}

func (s *SessionStore) GenerateSessionID() string {
    bytes := make([]byte, 16)
    rand.Read(bytes)
    return hex.EncodeToString(bytes)
}

func (s *SessionStore) StoreCaptcha(sessionID string, answer int) {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    
    s.sessions[sessionID] = SessionData{
        CaptchaAnswer: answer,
        CreatedAt:     time.Now(),
    }
}

func (s *SessionStore) VerifyAndDelete(sessionID string, userAnswer int) bool {
    s.mutex.Lock()
    defer s.mutex.Unlock()
    
    session, exists := s.sessions[sessionID]
    if !exists {
        return false
    }
    
    // 删除使用过的session
    delete(s.sessions, sessionID)
    
    // 检查session是否过期（10分钟）
    if time.Since(session.CreatedAt) > 10*time.Minute {
        return false
    }
    
    return session.CaptchaAnswer == userAnswer
}

func (s *SessionStore) cleanup() {
    ticker := time.NewTicker(10 * time.Minute)
    defer ticker.Stop()
    
    for range ticker.C {
        s.mutex.Lock()
        now := time.Now()
        for id, session := range s.sessions {
            if now.Sub(session.CreatedAt) > 10*time.Minute {
                delete(s.sessions, id)
            }
        }
        s.mutex.Unlock()
    }
}
```

## 🎯 实施计划

### 阶段一：SSL重定向功能（优先级：高）
1. **第1天**：实现SSL证书检测逻辑
2. **第2天**：添加重定向中间件和IP检测
3. **第3天**：修改登录处理逻辑，添加域名强制访问
4. **第4天**：测试和调试

### 阶段二：真人验证功能（优先级：中）
1. **第5天**：实现验证码生成和session管理
2. **第6天**：修改登录模板和前端逻辑
3. **第7天**：集成验证码到登录流程
4. **第8天**：测试和优化用户体验

### 阶段三：文档和测试（优先级：中）
1. **第9天**：更新文档和配置说明
2. **第10天**：编写单元测试和集成测试

## 🧪 测试策略

### SSL重定向功能测试
1. **测试场景1**：只有自签名证书时，允许IP访问
2. **测试场景2**：有真实证书时，IP访问自动重定向到域名
3. **测试场景3**：已经通过域名访问时，不进行重定向
4. **测试场景4**：多个有效证书时，选择第一个证书的域名

### 真人验证功能测试
1. **测试场景1**：无SSL证书时，不显示验证码
2. **测试场景2**：有SSL证书时，必须完成验证码
3. **测试场景3**：验证码错误时，拒绝登录并重新生成
4. **测试场景4**：验证码过期时，拒绝登录
5. **测试场景5**：验证码正确时，正常进行用户名密码验证

## 📋 配置项设计

### 新增配置选项
```yaml
security:
  # 强制HTTPS访问（有真实证书时生效）
  force_https_when_available: true
  
  # 启用真人验证（有真实证书时生效）
  enable_human_verification: true
  
  # 验证码超时时间（分钟）
  captcha_timeout: 10
  
  # 验证码难度级别（simple/medium/hard）
  captcha_difficulty: "simple"
```

### 环境变量支持
```bash
SSL_FORCE_HTTPS=true
SSL_ENABLE_CAPTCHA=true
SSL_CAPTCHA_TIMEOUT=10
```

## 🚀 未来扩展

### 可选的增强功能
1. **图形验证码**：使用更复杂的图像验证码
2. **滑块验证**：实现滑块拖拽验证
3. **行为分析**：基于鼠标轨迹的行为分析
4. **多因素认证**：集成TOTP或短信验证

### 安全考虑
1. **防暴力破解**：限制验证码尝试次数
2. **防爬虫**：验证码图片添加随机噪点
3. **Session安全**：使用加密的session标识
4. **CSRF保护**：在验证码中包含CSRF token

---

**文档版本**: v1.0  
**创建日期**: 2025-01-03  
**预计完成**: 2025-01-13

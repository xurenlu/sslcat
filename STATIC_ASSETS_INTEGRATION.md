# 静态资源本地化集成说明

## 概述

为了提高系统稳定性和减少对外部 CDN 的依赖，我们已将 Bootstrap 和 Bootstrap Icons 资源下载并集成到项目中，作为嵌入资源一起打包。

## 已集成的资源

### CSS 文件
- `/static/css/bootstrap.min.css` (161KB) - Bootstrap 5.1.3 核心样式
- `/static/css/bootstrap-icons.css` (72KB) - Bootstrap Icons 1.7.2 图标样式

### JavaScript 文件
- `/static/js/bootstrap.bundle.min.js` (77KB) - Bootstrap 5.1.3 JS（包含 Popper.js）

### 字体文件
- `/static/fonts/bootstrap-icons.woff2` (90KB) - Bootstrap Icons 字体（WOFF2 格式）
- `/static/fonts/bootstrap-icons.woff` (121KB) - Bootstrap Icons 字体（WOFF 格式）

**总计：约 521KB 的静态资源**

## 技术实现

### 1. 文件结构
```
internal/assets/
├── static/
│   ├── css/
│   │   ├── bootstrap.min.css
│   │   └── bootstrap-icons.css
│   ├── js/
│   │   └── bootstrap.bundle.min.js
│   └── fonts/
│       ├── bootstrap-icons.woff2
│       └── bootstrap-icons.woff
├── embed.go
└── templates/
    └── *.html
```

### 2. 嵌入配置（embed.go）
```go
// 嵌入静态资源文件（CSS, JS, 字体）
//go:embed static/css/* static/js/* static/fonts/*
var StaticFS embed.FS
```

### 3. HTTP 路由
在 `internal/web/frontend_routes.go` 中添加了 `/static/` 路由处理器：
- 支持所有静态资源类型（CSS、JS、字体等）
- 设置了适当的 Content-Type 和缓存头
- CSS/JS/字体文件缓存 1 年（max-age=31536000）

### 4. 字体路径更新
将 `bootstrap-icons.css` 中的字体路径从相对路径更新为绝对路径：
```css
@font-face {
  font-family: "bootstrap-icons";
  src: url("/static/fonts/bootstrap-icons.woff2?30af91bf14e37666a085fb8a161ff36d") format("woff2"),
       url("/static/fonts/bootstrap-icons.woff?30af91bf14e37666a085fb8a161ff36d") format("woff");
}
```

## 已更新的文件

### HTML 模板文件
- `internal/assets/templates/*.html` (所有模板)
- `web/templates/base.html`

### Go 源码文件（内嵌 HTML）
- `internal/web/handlers.go`
- `internal/web/ssl_handlers.go`
- `internal/web/config_handlers.go`
- `internal/web/proxy_html.go`
- `internal/web/html_generators.go`
- `internal/web/git_server_html.go`
- `internal/web/dns_html.go`

### 新增/修改的核心文件
- `internal/assets/embed.go` - 添加了静态资源嵌入
- `internal/web/frontend_routes.go` - 添加了 `/static/` 路由处理器

## CDN 引用替换

### 替换前
```html
<link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css" rel="stylesheet">
<script src="https://cdnproxy.shifen.de/cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
```

### 替换后
```html
<link href="/static/css/bootstrap.min.css" rel="stylesheet">
<link href="/static/css/bootstrap-icons.css" rel="stylesheet">
<script src="/static/js/bootstrap.bundle.min.js"></script>
```

## 优势

1. **稳定性**：不再依赖外部 CDN，即使在网络受限环境也能正常访问
2. **性能**：本地资源加载更快，无需跨域请求
3. **可靠性**：避免了 CDN 服务中断或被屏蔽的风险
4. **简化部署**：单一二进制文件包含所有资源，部署更简单
5. **版本控制**：资源版本与代码版本同步，避免兼容性问题

## 注意事项

1. **二进制文件大小增加**：嵌入资源后，编译后的二进制文件增加约 500KB
2. **缓存策略**：静态资源设置了 1 年的浏览器缓存，更新版本后客户端会自动获取新资源
3. **保留的 CDN 引用**：Axios 等其他库仍使用 CDN（可根据需要后续集成）

## 验证测试

编译测试已通过：
```bash
go build -o sslcat-test main.go
# 编译成功，二进制文件大小：28M
```

所有嵌入资源验证：
- ✅ CSS 文件：bootstrap.min.css, bootstrap-icons.css
- ✅ JS 文件：bootstrap.bundle.min.js
- ✅ 字体文件：bootstrap-icons.woff2, bootstrap-icons.woff

## 后续建议

如需进一步优化，可考虑：
1. 集成 Axios.js 到本地资源
2. 使用 Brotli 压缩进一步减小资源大小
3. 实现资源版本化（在 URL 中添加版本号或哈希）

---

**更新时间**：2025-10-10  
**版本**：v1.3.11-rc2


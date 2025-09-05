# WithSSL 部署包

此部署包包含了使用 Go embed 特性的 WithSSL 二进制文件，所有 HTML 模板和翻译文件都已嵌入到二进制文件中。

## 部署优势

✅ **单文件部署**: 只需要一个二进制文件，无需手工复制模板和翻译文件
✅ **零依赖**: 所有资源都嵌入在二进制文件中
✅ **简化运维**: 不用担心文件丢失或路径问题
✅ **版本一致**: 确保模板和代码版本完全一致

## 快速部署

### 方法一：一键部署（推荐）

```bash
# 上传整个deploy目录到服务器
scp -r deploy/ user@server:/tmp/withssl-deploy

# 在服务器上运行一键部署脚本
ssh user@server "cd /tmp/withssl-deploy && sudo bash deploy-commands.sh"
```

### 方法二：手动部署

1. 上传二进制文件到服务器
2. 复制并修改配置文件
3. 运行服务

```bash
# 1. 复制配置文件
cp withssl.conf.example withssl.conf

# 2. 编辑配置
nano withssl.conf

# 3. 启动服务
./withssl --config withssl.conf
```

### 方法三：systemd服务部署

```bash
# 1. 手动安装二进制文件
sudo mkdir -p /opt/withssl
sudo cp withssl-linux /opt/withssl/withssl
sudo chmod +x /opt/withssl/withssl

# 2. 安装配置文件
sudo mkdir -p /etc/withssl
sudo cp withssl.conf /etc/withssl/
sudo chown withssl:withssl /etc/withssl/withssl.conf

# 3. 安装systemd服务
sudo cp withssl.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable withssl
sudo systemctl start withssl
```

## 文件说明

- `withssl` / `withssl-linux`: 主程序二进制文件（包含所有嵌入资源）
- `withssl.conf`: 配置文件示例
- `withssl-advanced.conf.example`: 高级配置示例
- `deploy-commands.sh`: 一键部署脚本（推荐）
- `withssl.service`: systemd服务文件
- `install.sh`: 系统安装脚本（可选）
- `start.sh`: 快速启动脚本（可选）

## 嵌入的资源

### HTML 模板
- base.html - 基础模板
- login.html - 登录页面
- dashboard.html - 仪表板
- mobile.html - 移动端界面
- charts.html - 图表分析页面
- default.html - 默认页面

### 多语言翻译
- zh-CN.json - 简体中文
- en-US.json - 英语
- ja-JP.json - 日语
- es-ES.json - 西班牙语
- fr-FR.json - 法语
- ru-RU.json - 俄语

## 技术说明

本版本使用了 Go 1.16+ 的 embed 特性，将所有静态资源嵌入到二进制文件中：

```go
//go:embed templates/*.html
var TemplatesFS embed.FS

//go:embed i18n/*.json
var I18nFS embed.FS
```

这确保了：
- 部署简单（单文件）
- 资源版本一致
- 运行时性能优异
- 无外部文件依赖

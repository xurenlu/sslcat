# SSLcat Release 包规划

## 🎯 目标

将 SSLcat 的 release 包从仅包含二进制文件改为包含完整安装文件的包，让用户下载后能够一键安装。

## 📦 Release 包内容

每个 release 包现在包含以下文件：

### 核心文件
- **`sslcat`** - SSLcat 二进制文件
- **`sslcat.conf`** - 默认配置文件
- **`sslcat.service`** - systemd 服务文件（Linux 专用）
- **`install-sslcat.sh`** - 自动安装脚本
- **`README.md`** - 安装说明文档

## 🚀 安装流程

### 用户使用流程
```bash
# 1. 下载 release 包
curl -fsSL https://github.com/xurenlu/sslcat/releases/download/v1.3.3/sslcat_v1.3.3_linux-amd64.tar.gz -o sslcat.tgz

# 2. 解压文件
tar -xzf sslcat.tgz
cd sslcat_*/

# 3. 运行安装脚本
sudo ./install-sslcat.sh
```

### 安装脚本功能

#### Linux 系统
1. **检查系统要求**：验证 Linux 系统和 systemd 支持
2. **创建目录结构**：
   - `/etc/sslcat` - 配置文件目录
   - `/opt/sslcat/` - 程序目录
   - `/var/log/sslcat` - 日志目录
   - `/var/www` - Web 目录
   - `/home/git` - Git 用户目录
3. **创建 git 用户**：设置 Git 用户和权限
4. **安装二进制文件**：复制到 `/opt/sslcat/sslcat`
5. **安装配置文件**：复制到 `/etc/sslcat/sslcat.conf`
6. **安装 systemd 服务**：设置自动启动
7. **启动服务**：自动启动 SSLcat 服务

#### macOS 系统
1. **检查系统要求**：验证 macOS 系统
2. **创建目录结构**：
   - `/usr/local/etc/sslcat` - 配置文件目录
   - `/usr/local/var/sslcat/` - 程序数据目录
   - `/usr/local/var/www` - Web 目录
   - `/usr/local/var/git` - Git 用户目录
3. **创建 git 用户**：设置 Git 用户和权限
4. **安装二进制文件**：复制到 `/usr/local/bin/sslcat`
5. **安装配置文件**：复制到 `/usr/local/etc/sslcat/sslcat.conf`
6. **跳过服务安装**：macOS 不支持 systemd
7. **提供手动启动说明**

## 🔧 配置文件说明

### Linux 默认配置
```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 443,
    "debug": false
  },
  "ssl": {
    "email": "admin@example.com",
    "staging": false,
    "auto_renew": true
  },
  "admin": {
    "username": "admin",
    "password_file": "/opt/sslcat/data/admin.pass",
    "first_run": true
  }
}
```

### macOS 默认配置
```json
{
  "server": {
    "host": "0.0.0.0",
    "port": 8080,
    "debug": true
  },
  "ssl": {
    "email": "admin@example.com",
    "staging": true,
    "auto_renew": false
  },
  "admin": {
    "username": "admin",
    "password_file": "/usr/local/var/sslcat/data/admin.pass",
    "first_run": true
  }
}
```

## 📋 安装后管理

### Linux 系统管理
```bash
# 服务管理
sudo systemctl start sslcat      # 启动服务
sudo systemctl stop sslcat       # 停止服务
sudo systemctl restart sslcat    # 重启服务
sudo systemctl status sslcat     # 查看状态
sudo journalctl -u sslcat -f      # 查看日志

# 配置文件
sudo nano /etc/sslcat/sslcat.conf

# 访问管理界面
http://your-server-ip/sslcat-panel
```

### macOS 系统管理
```bash
# 启动服务
sslcat --config /usr/local/etc/sslcat/sslcat.conf

# 后台运行
nohup sslcat --config /usr/local/etc/sslcat/sslcat.conf &

# 配置文件
sudo nano /usr/local/etc/sslcat/sslcat.conf

# 访问管理界面
http://localhost:8080/sslcat-panel
```

## 🛠️ 技术实现

### GitHub Actions 工作流修改

#### Linux 打包流程
```yaml
- name: Package Linux
  run: |
    # 创建发布包目录
    mkdir -p release-package
    
    # 复制所有必要文件
    cp build/${BIN_NAME} release-package/${BIN_NAME}
    cp sslcat.conf release-package/sslcat.conf
    cp sslcat.service release-package/sslcat.service
    cp install-sslcat.sh release-package/install-sslcat.sh
    chmod +x release-package/install-sslcat.sh
    
    # 创建 README
    cat > release-package/README.md << 'EOF'
    # SSLcat Release Package
    ## 快速安装
    ```bash
    tar -xzf sslcat_*.tar.gz
    cd sslcat_*/
    sudo ./install-sslcat.sh
    ```
    EOF
    
    # 打包
    tar -C release-package -czf artifacts/${NAME}.tar.gz .
```

#### macOS 打包流程
```yaml
- name: Package macOS
  run: |
    # 创建发布包目录
    mkdir -p release-package
    
    # 复制所有必要文件
    cp build/${BIN_NAME} release-package/${BIN_NAME}
    cp sslcat.conf release-package/sslcat.conf
    cp sslcat.service release-package/sslcat.service
    cp install-sslcat.sh release-package/install-sslcat.sh
    chmod +x release-package/install-sslcat.sh
    
    # 创建 macOS 专用 README
    cat > release-package/README.md << 'EOF'
    # SSLcat Release Package (macOS)
    ## 快速安装
    ```bash
    tar -xzf sslcat_*.tar.gz
    cd sslcat_*/
    sudo ./install-sslcat.sh
    ```
    EOF
    
    # 打包
    tar -C release-package -czf artifacts/${NAME}.tar.gz .
```

## 🎉 优势

### 用户体验提升
1. **一键安装**：下载后直接运行安装脚本
2. **自动配置**：自动创建目录、用户、服务
3. **跨平台支持**：Linux 和 macOS 都支持
4. **完整文档**：每个包都包含详细说明

### 开发者优势
1. **标准化安装**：统一的安装流程
2. **减少支持**：用户问题减少
3. **专业形象**：企业级安装体验
4. **易于维护**：集中管理安装逻辑

## 📊 文件大小对比

### 之前（仅二进制文件）
- Linux AMD64: ~45 MB
- Linux ARM64: ~45 MB
- macOS Intel: ~45 MB
- macOS Apple Silicon: ~45 MB

### 现在（完整安装包）
- Linux AMD64: ~45 MB + 配置文件 (~50 KB)
- Linux ARM64: ~45 MB + 配置文件 (~50 KB)
- macOS Intel: ~45 MB + 配置文件 (~50 KB)
- macOS Apple Silicon: ~45 MB + 配置文件 (~50 KB)

**增加大小**: 约 50 KB（可忽略不计）

## 🔄 向后兼容

- 现有的安装方式仍然支持
- 新的安装方式作为推荐方式
- 用户可以选择使用哪种方式

## 📝 更新说明

### Release Notes 更新
```markdown
## 🚀 快速安装

### 新版本（推荐）
```bash
# 下载并解压
curl -fsSL https://github.com/xurenlu/sslcat/releases/download/v1.3.3/sslcat_v1.3.3_linux-amd64.tar.gz -o sslcat.tgz
tar -xzf sslcat.tgz
cd sslcat_*/

# 一键安装
sudo ./install-sslcat.sh
```

### 传统方式（仍然支持）
```bash
curl -fsSL https://github.com/xurenlu/sslcat/releases/download/v1.3.3/sslcat_v1.3.3_linux-amd64.tar.gz -o sslcat.tgz
tar -xzf sslcat.tgz && sudo install -m 0755 sslcat /usr/local/bin/sslcat
```
```

## 🎯 下一步计划

1. **测试安装脚本**：在各种 Linux 发行版和 macOS 版本上测试
2. **完善错误处理**：添加更多的错误检查和恢复机制
3. **添加卸载功能**：创建卸载脚本
4. **优化用户体验**：添加进度条和更友好的提示
5. **文档完善**：创建详细的安装指南

---

*这个新的 release 包规划将大大提升 SSLcat 的用户体验，让安装过程更加简单和专业。*

# SSLcat 维护者发布指南

本指南面向项目维护者，涵盖版本发布、产物构建与打包（GitHub Releases、DEB/RPM/Homebrew、Docker Compose）、以及升级流程。

## 0) 版本与分支
- 在 `main` 分支完成验证后发布
- 更新版本：`main.go` 中 `version` 变量或通过 `-ldflags -X main.version=` 注入
- 更新 `CHANGELOG.md` 顶部版本记录

## 1) 构建多架构产物并发布到 GitHub Releases
```
# 1. 设置版本号（例如 v1.0.2）
VER=1.0.2

# 2. 构建多架构二进制（产物在 dist/）
VER=$VER scripts/release/build-matrix.sh

# 3. 创建 Git tag（可选：先本地验证产物）
git add -A
git commit -m "chore(release): $VER"
git tag v$VER
git push origin main --tags

# 4. 发布到 GitHub Releases（自动上传 dist/*）
VER=$VER scripts/release/upload-github-release.sh
```

说明：
- 如未安装 GitHub CLI，请先 `gh auth login`
- 也可在 Release 页面手动上传 dist 产物与 `sha256sum.txt`

## 2) 生成系统安装包
### 2.1 DEB（x86_64）
```
VER=1.0.2 scripts/release/package-deb.sh
# 输出: dist/withssl_1.0.2_linux_amd64.deb
```

### 2.2 RPM（x86_64）
```
VER=1.0.2 scripts/release/package-rpm.sh
# 依赖: rpmbuild
# 输出: dist/withssl_1.0.2_x86_64.rpm
```

### 2.3 Homebrew 公式
```
# 先在 GitHub Releases 上传 darwin_arm64 包并获得 tarball 的 sha256
VER=1.0.2 SHA256=<tarball_sha256> scripts/release/package-brew.sh
# 输出: build/homebrew-tap/Formula/withssl.rb
# 将 withssl.rb 推送到你的 tap 仓库（如 github.com/<you>/homebrew-tap）
```

## 3) Docker Compose 一键启动
项目根目录已提供 `docker-compose.yml`：
```
docker compose up -d
```

## 4) 升级助手（服务器端）
```
# 将 REPO 与 VER 指定到你的仓库与目标版本
env VER=1.0.2 REPO=xurenlu/sslcat \
scripts/release/upgrade-helper.sh
```
- 步骤：下载 → 备份当前 `/opt/sslcat/withssl` → 替换 → 重启 systemd 服务
- 回滚：从 `/opt/sslcat-backups/<timestamp>/withssl` 拷回覆盖后重启

## 5) 环境变量（可选）
- Webhook：`WITHSSL_WEBHOOK_URL` → 发送审计/到期等事件
- Syslog(UDP)：`WITHSSL_SYSLOG_ADDR`（host:port）
- Loki：`WITHSSL_LOKI_URL`（http(s)://host:3100/loki/api/v1/push）

## 6) 发布前检查清单
- [ ] README 顶部“一分钟快速上手”可用
- [ ] 版本号与 CHANGELOG 已更新
- [ ] dist 产物完整（含 sha256sum.txt）
- [ ] 安装包（DEB/RPM/Homebrew）按需生成
- [ ] 重要变更已在 Release Note 编写

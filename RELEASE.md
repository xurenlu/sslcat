# sslcat 发布指引

本项目提供脚本一键构建多架构产物并上传到 GitHub Release。

## 1) 前置条件
- 安装 Go 1.21+（或与本仓库 go.mod 兼容的版本）
- macOS/Linux 推荐
- 可选：安装 GitHub CLI gh 并 gh auth login 登录

## 2) 构建多架构产物
- 全量矩阵构建（产物在 dist/）：
```
VER=1.0.0 scripts/release/build-matrix.sh
```
- 常用单平台示例：
```
VER=1.0.0 scripts/release/build-linux-amd64.sh
VER=1.0.0 scripts/release/build-darwin-arm64.sh
```
脚本会自动：
- 将二进制命名为 sslcat_${VER}_${GOOS}_${GOARCH}
- 非 Windows 打包为 .tar.gz，Windows 打包为 .zip
- 写入 dist/sha256sum.txt 校验文件

## 3) 上传到 GitHub Release
```
VER=1.0.0 scripts/release/upload-github-release.sh
## 4) 打包系统安装包
- 生成 DEB（x86_64）：
```
VER=1.0.1 scripts/release/package-deb.sh
```
- 生成 RPM（x86_64）：
```
VER=1.0.1 scripts/release/package-rpm.sh
```
- 生成 Homebrew 公式（需先上传产物并获取 sha256）：
```
VER=1.0.1 SHA256=<tarball_sha256> scripts/release/package-brew.sh
```

## 5) Docker Compose 一键起
```
docker compose up -d
```

## 6) 升级助手
```
VER=1.0.1 scripts/release/upgrade-helper.sh
```
```
- 若不存在 v${VER}，脚本会创建；存在则覆盖上传

## 4) 二进制内版本信息
- 通过 -ldflags 注入：
  - main.version=${VER}
  - main.build=${GIT_SHA}（提交短 SHA）

## 5) 常见问题
- gh: command not found：请安装 GitHub CLI 或手动在 Release 页面上传 dist/ 中的产物
- macOS Gatekeeper：首次运行可能需 chmod +x 并允许执行
- 交叉编译 OpenSSL/CGo：本项目默认 CGO_ENABLED=0，若后续引入 cgo，请为目标平台准备交叉工具链

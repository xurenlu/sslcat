#!/usr/bin/env bash
set -euo pipefail

# sslcat 一键安装脚本（通过 sslcat.com 代理亦可）
# 用法：
#   curl -fsSL https://sslcat.com/xurenlu/sslcat/main/scripts/install-from-release-zh.sh | sudo bash -s -- -v 1.3.2

VER=""
DEST_LINUX="/opt/sslcat"
CONF_LINUX="/etc/sslcat/sslcat.conf"
LANG_CODE=""
INSTALL_DOCKER=false
INSTALL_GIT_USER=false

normalize_lang() {
  local x="${1,,}"
  case "$x" in
    zh*|cn*) echo zh;;
    en*|us*) echo en;;
    fr*|fr-*) echo fr;;
    es*|es-*) echo es;;
    ja*|jp*) echo ja;;
    *) echo en;;
  esac
}

detect_lang() {
  local c="${LANGUAGE:-}"; [[ -n "$c" ]] || c="${LC_ALL:-}"; [[ -n "$c" ]] || c="${LC_MESSAGES:-}"; [[ -n "$c" ]] || c="${LANG:-}"; [[ -n "$c" ]] || c="en"
  LANG_CODE="$(normalize_lang "$c")"
}

set_lang() {
  local u="${1:-}"
  if [[ -n "$u" ]]; then LANG_CODE="$(normalize_lang "$u")"; else detect_lang; fi
}

i18n() {
  local key="$1"
  case "$LANG_CODE:$key" in
    zh:missing_version) echo "[sslcat] 你未指定版本，默认安装 v%s";;
    en:missing_version) echo "[sslcat] You didn't specify a version; defaulting to v%s";;
    fr:missing_version) echo "[sslcat] Vous n'avez pas spécifié de version ; utilisation par défaut v%s";;
    es:missing_version) echo "[sslcat] No especificaste versión; usando por defecto v%s";;
    ja:missing_version) echo "[sslcat] バージョンが指定されていません。デフォルトは v%s です";;

    zh:unsupported_arch) echo "[sslcat] 不支持的架构: %s";;
    en:unsupported_arch) echo "[sslcat] Unsupported architecture: %s";;
    fr:unsupported_arch) echo "[sslcat] Architecture non prise en charge : %s";;
    es:unsupported_arch) echo "[sslcat] Arquitectura no soportada: %s";;
    ja:unsupported_arch) echo "[sslcat] サポートされていないアーキテクチャです: %s";;

    zh:prefer_download) echo "[sslcat] 优先使用中国大陆镜像: %s";;
    en:prefer_download) echo "[sslcat] Prefer China mirror: %s";;
    fr:prefer_download) echo "[sslcat] Miroir Chine prioritaire : %s";;
    es:prefer_download) echo "[sslcat] Preferir espejo de China: %s";;
    ja:prefer_download) echo "[sslcat] 中国ミラーを優先: %s";;

    zh:mirror_failed_fallback_github) echo "[sslcat] 镜像下载失败，改用 GitHub 原地址: %s";;
    en:mirror_failed_fallback_github) echo "[sslcat] Mirror download failed, falling back to GitHub: %s";;
    fr:mirror_failed_fallback_github) echo "[sslcat] Échec du miroir, utilisation de GitHub : %s";;
    es:mirror_failed_fallback_github) echo "[sslcat] Falló el espejo, usando GitHub: %s";;
    ja:mirror_failed_fallback_github) echo "[sslcat] ミラーのダウンロードに失敗。GitHub にフォールバック: %s";;

    zh:installed_path) echo "[sslcat] 安装完成: %s";;
    en:installed_path) echo "[sslcat] Installed: %s";;
    fr:installed_path) echo "[sslcat] Installé : %s";;
    es:installed_path) echo "[sslcat] Instalado: %s";;
    ja:installed_path) echo "[sslcat] インストール完了: %s";;

    zh:run_hint) echo "[sslcat] 运行: %s";;
    en:run_hint) echo "[sslcat] Run: %s";;
    fr:run_hint) echo "[sslcat] Exécuter : %s";;
    es:run_hint) echo "[sslcat] Ejecuta: %s";;
    ja:run_hint) echo "[sslcat] 実行: %s";;

    zh:config_path) echo "[sslcat] 配置: %s";;
    en:config_path) echo "[sslcat] Config: %s";;
    fr:config_path) echo "[sslcat] Configuration : %s";;
    es:config_path) echo "[sslcat] Configuración: %s";;
    ja:config_path) echo "[sslcat] 設定: %s";;

    zh:panel_hint) echo "[sslcat] 管理面板: http://%s:80/sslcat-panel/ 或 https://<你的域名>/sslcat-panel/ (首次登录将强制改密)";;
    en:panel_hint) echo "[sslcat] Admin panel: http://%s:80/sslcat-panel/ or https://<your-domain>/sslcat-panel/ (you will be asked to change password on first login)";;
    fr:panel_hint) echo "[sslcat] Panneau d'admin : http://%s:80/sslcat-panel/ ou https://<votre-domaine>/sslcat-panel/ (changement de mot de passe au premier login)";;
    es:panel_hint) echo "[sslcat] Panel de administración: http://%s:80/sslcat-panel/ o https://<tu-dominio>/sslcat-panel/ (se solicitará cambiar la contraseña en el primer inicio)";;
    ja:panel_hint) echo "[sslcat] 管理パネル: http://%s:80/sslcat-panel/ または https://<あなたのドメイン>/sslcat-panel/（初回ログイン時にパスワード変更が必要）";;

    zh:checking_docker) echo "[sslcat] 检查 Docker 是否已安装...";;
    en:checking_docker) echo "[sslcat] Checking if Docker is installed...";;
    fr:checking_docker) echo "[sslcat] Vérification de l'installation de Docker...";;
    es:checking_docker) echo "[sslcat] Verificando si Docker está instalado...";;
    ja:checking_docker) echo "[sslcat] Docker がインストールされているかチェック中...";;

    zh:docker_not_found) echo "[sslcat] Docker 未安装，尝试安装 Docker...";;
    en:docker_not_found) echo "[sslcat] Docker not found, attempting to install Docker...";;
    fr:docker_not_found) echo "[sslcat] Docker non trouvé, tentative d'installation...";;
    es:docker_not_found) echo "[sslcat] Docker no encontrado, intentando instalar...";;
    ja:docker_not_found) echo "[sslcat] Docker が見つかりません。インストールを試行中...";;

    zh:docker_installed) echo "[sslcat] Docker 安装成功";;
    en:docker_installed) echo "[sslcat] Docker installed successfully";;
    fr:docker_installed) echo "[sslcat] Docker installé avec succès";;
    es:docker_installed) echo "[sslcat] Docker instalado exitosamente";;
    ja:docker_installed) echo "[sslcat] Docker のインストールが完了しました";;

    zh:docker_install_failed) echo "[sslcat] Docker 安装失败，请手动安装: https://docs.docker.com/get-docker/";;
    en:docker_install_failed) echo "[sslcat] Docker installation failed, please install manually: https://docs.docker.com/get-docker/";;
    fr:docker_install_failed) echo "[sslcat] Échec de l'installation de Docker, installez manuellement: https://docs.docker.com/get-docker/";;
    es:docker_install_failed) echo "[sslcat] Falló la instalación de Docker, instale manualmente: https://docs.docker.com/get-docker/";;
    ja:docker_install_failed) echo "[sslcat] Docker のインストールに失敗しました。手動でインストールしてください: https://docs.docker.com/get-docker/";;

    zh:checking_git_user) echo "[sslcat] 检查 git 用户是否存在...";;
    en:checking_git_user) echo "[sslcat] Checking if git user exists...";;
    fr:checking_git_user) echo "[sslcat] Vérification de l'existence de l'utilisateur git...";;
    es:checking_git_user) echo "[sslcat] Verificando si existe el usuario git...";;
    ja:checking_git_user) echo "[sslcat] git ユーザーが存在するかチェック中...";;

    zh:git_user_not_found) echo "[sslcat] git 用户不存在，创建 git 用户...";;
    en:git_user_not_found) echo "[sslcat] git user not found, creating git user...";;
    fr:git_user_not_found) echo "[sslcat] Utilisateur git non trouvé, création en cours...";;
    es:git_user_not_found) echo "[sslcat] Usuario git no encontrado, creando usuario git...";;
    ja:git_user_not_found) echo "[sslcat] git ユーザーが見つかりません。作成中...";;

    zh:git_user_created) echo "[sslcat] git 用户创建成功";;
    en:git_user_created) echo "[sslcat] git user created successfully";;
    fr:git_user_created) echo "[sslcat] Utilisateur git créé avec succès";;
    es:git_user_created) echo "[sslcat] Usuario git creado exitosamente";;
    ja:git_user_created) echo "[sslcat] git ユーザーが作成されました";;

    zh:git_user_exists) echo "[sslcat] git 用户已存在";;
    en:git_user_exists) echo "[sslcat] git user already exists";;
    fr:git_user_exists) echo "[sslcat] Utilisateur git existe déjà";;
    es:git_user_exists) echo "[sslcat] Usuario git ya existe";;
    ja:git_user_exists) echo "[sslcat] git ユーザーは既に存在します";;

    zh:installing_dependencies) echo "[sslcat] 安装系统依赖...";;
    en:installing_dependencies) echo "[sslcat] Installing system dependencies...";;
    fr:installing_dependencies) echo "[sslcat] Installation des dépendances système...";;
    es:installing_dependencies) echo "[sslcat] Instalando dependencias del sistema...";;
    ja:installing_dependencies) echo "[sslcat] システム依存関係をインストール中...";;

    *) echo "[sslcat] %s";;
  esac
}

msg() { local fmt; fmt="$(i18n "$1")"; shift; printf "$fmt\n" "$@"; }
msg_err() { local fmt; fmt="$(i18n "$1")"; shift; printf "$fmt\n" "$@" >&2; }

USER_LANG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--version)
      VER="${2:-}"; shift 2 ;;
    -l|--lang)
      USER_LANG="${2:-}"; shift 2 ;;
    --install-docker)
      INSTALL_DOCKER=true
      shift ;;
    --install-git-user)
      INSTALL_GIT_USER=true
      shift ;;
    *) shift ;;
  esac
done

set_lang "$USER_LANG"

if [[ -z "$VER" ]]; then
  VER="1.3.2"
  msg missing_version "$VER"
fi

# 检测并安装系统依赖
install_dependencies() {
  msg installing_dependencies
  
  # 检测操作系统类型
  if [[ -f /etc/debian_version ]]; then
    # Debian/Ubuntu 系统
    apt-get update -qq
    apt-get install -y curl wget tar gzip git
  elif [[ -f /etc/redhat-release ]]; then
    # RHEL/CentOS/Fedora 系统
    if command -v dnf >/dev/null 2>&1; then
      dnf install -y curl wget tar gzip git
    elif command -v yum >/dev/null 2>&1; then
      yum install -y curl wget tar gzip git
    fi
  elif [[ -f /etc/arch-release ]]; then
    # Arch Linux
    pacman -S --noconfirm curl wget tar gzip git
  elif [[ "$OS" == "darwin" ]]; then
    # macOS - 检查 Homebrew
    if ! command -v brew >/dev/null 2>&1; then
      echo "请先安装 Homebrew: https://brew.sh/"
      exit 1
    fi
    brew install curl wget git
  fi
}

# 检测并安装 Docker
install_docker() {
  msg checking_docker
  
  if command -v docker >/dev/null 2>&1; then
    echo "Docker 已安装"
    return 0
  fi
  
  msg docker_not_found
  
  # 检测操作系统并安装 Docker
  if [[ -f /etc/debian_version ]]; then
    # Debian/Ubuntu
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    systemctl enable docker
    systemctl start docker
    rm get-docker.sh
  elif [[ -f /etc/redhat-release ]]; then
    # RHEL/CentOS/Fedora
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    systemctl enable docker
    systemctl start docker
    rm get-docker.sh
  elif [[ "$OS" == "darwin" ]]; then
    # macOS
    if command -v brew >/dev/null 2>&1; then
      brew install --cask docker
    else
      msg docker_install_failed
      return 1
    fi
  else
    msg docker_install_failed
    return 1
  fi
  
  if command -v docker >/dev/null 2>&1; then
    msg docker_installed
  else
    msg docker_install_failed
    return 1
  fi
}

# 检测并创建 git 用户
setup_git_user() {
  msg checking_git_user
  
  if id -u git >/dev/null 2>&1; then
    msg git_user_exists
    return 0
  fi
  
  msg git_user_not_found
  
  # 创建 git 用户
  useradd -r -s /bin/bash -m -d /home/git git
  
  if id -u git >/dev/null 2>&1; then
    msg git_user_created
  else
    echo "创建 git 用户失败"
    return 1
  fi
}

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv7|armhf) ARCH=arm ;;
  *) msg_err unsupported_arch "$ARCH_RAW"; exit 1 ;;
esac

PREFERRED="sslcat_v${VER}_${OS}-${ARCH}"
EXT=.tar.gz
[[ "$OS" == "windows" ]] && EXT=.zip

# 使用 sslcat.com 代理加速 GitHub Releases（仅新命名）
TMP=$(mktemp -d)
URL_CN="https://sslcat.com/xurenlu/sslcat/releases/download/v${VER}/sslcat_v${VER}_${OS}-${ARCH}${EXT}"
URL_GH="https://github.com/xurenlu/sslcat/releases/download/v${VER}/sslcat_v${VER}_${OS}-${ARCH}${EXT}"
msg prefer_download "$URL_CN"
if ! curl -fsSL "$URL_CN" -o "$TMP/pkg${EXT}"; then
  msg mirror_failed_fallback_github "$URL_GH"
  curl -fsSL "$URL_GH" -o "$TMP/pkg${EXT}"
fi

if [[ "$OS" == "darwin" ]]; then
  tar -xzf "$TMP/pkg${EXT}" -C "$TMP"
  sudo install -m 0755 "$TMP/sslcat" /usr/local/bin/sslcat
  msg installed_path "/usr/local/bin/sslcat"
  msg run_hint "sslcat --config sslcat.conf --port 8080"
  exit 0
fi

# 安装系统依赖
install_dependencies

# 安装 Docker（如果需要）
if [[ "$INSTALL_DOCKER" == "true" ]]; then
  install_docker
fi

# 设置 git 用户（如果需要）
if [[ "$INSTALL_GIT_USER" == "true" ]]; then
  setup_git_user
fi

# 安装 git hook wrapper 脚本
install_git_hook() {
  echo "[sslcat] 安装 git hook wrapper 脚本..."
  
  # 检查是否已安装
  if [[ -f "/usr/local/bin/sslcat-git-hook" ]]; then
    echo "[sslcat] git hook wrapper 脚本已存在"
    return 0
  fi
  
  # 创建脚本目录
  sudo mkdir -p /opt/sslcat/scripts
  
  # 下载 sslcat-git-hook 脚本
  if ! curl -fsSL "https://sslcat.com/xurenlu/sslcat/main/scripts/sslcat-git-hook" -o /tmp/sslcat-git-hook; then
    echo "[sslcat] 下载 sslcat-git-hook 脚本失败，跳过安装"
    return 1
  fi
  
  # 安装脚本
  sudo install -m 0755 /tmp/sslcat-git-hook /usr/local/bin/sslcat-git-hook
  sudo install -m 0755 /tmp/sslcat-git-hook /opt/sslcat/scripts/sslcat-git-hook
  
  # 创建配置文件
  sudo mkdir -p /etc/sslcat
  sudo bash -c "cat > /etc/sslcat/git-hook.conf" <<EOF
# SSLcat Git Hook 配置文件
# 自动生成于: $(date)

# SSLcat API 地址
export SSLCAT_API_URL="http://localhost:80/sslcat-panel"

# Git 仓库存储目录
export SSLCAT_REPOS_DIR="/var/lib/sslcat/runners/git"
EOF
  
  echo "[sslcat] git hook wrapper 脚本安装成功"
  rm -f /tmp/sslcat-git-hook
}

# 安装 git hook wrapper 脚本
install_git_hook

# Linux: 安装到 /opt/sslcat 并写入 systemd 与默认配置
sudo mkdir -p "$DEST_LINUX" /var/lib/sslcat/{certs,keys,logs} /etc/sslcat
tar -xzf "$TMP/pkg${EXT}" -C "$TMP"
sudo install -m 0755 "$TMP/sslcat" "$DEST_LINUX/sslcat"

if [[ ! -f "$CONF_LINUX" ]]; then
  sudo bash -c "cat > $CONF_LINUX" <<'JSON'
{
  "server": {
    "host": "0.0.0.0",
    "port": 443,
    "debug": false,
    "access_log_enabled": true,
    "access_log_format": "nginx",
    "access_log_path": "/var/lib/sslcat/logs/access.log",
    "access_log_max_size": 104857600,
    "access_log_max_files": 10,
    "read_timeout_sec": 1800,
    "write_timeout_sec": 1800,
    "idle_timeout_sec": 120,
    "max_upload_bytes": 1073741824
  },
  "ssl": {
    "email": "",
    "staging": false,
    "domains": [],
    "cert_dir": "/var/lib/sslcat/certs",
    "key_dir": "/var/lib/sslcat/keys",
    "auto_renew": true,
    "disable_self_signed": false
  },
  "admin": {
    "username": "admin",
    "first_run": true,
    "password_file": "/var/lib/sslcat/admin.pass",
    "enable_totp": false,
    "totp_secret_file": "/var/lib/sslcat/admin.totp"
  },
  "proxy": {
    "rules": [],
    "unmatched_behavior": "502",
    "unmatched_redirect_url": ""
  },
  "security": {
    "max_attempts": 3,
    "block_duration": "0s",
    "max_attempts_5min": 10,
    "block_file": "/var/lib/sslcat/withssl.block",
    "allowed_user_agents": [
      "Mozilla/",
      "Chrome/",
      "Firefox/",
      "Safari/",
      "Edge/"
    ],
    "ua_invalid_max_1min": 30,
    "ua_invalid_max_5min": 100,
    "tls_fp_window_sec": 60,
    "tls_fp_max_per_min": 60000,
    "tls_fp_top_n": 20,
    "enable_ua_filter": false,
    "enable_waf": false,
    "enable_ddos": true,
    "enable_captcha": false,
    "min_form_ms": 800
  },
  "cdn_cache": {
    "enabled": false,
    "cache_dir": "/var/lib/sslcat/cache/static",
    "max_size_bytes": 5368709120,
    "default_ttl_seconds": 3600,
    "clean_interval_seconds": 60,
    "max_object_bytes": 20971520,
    "rules": []
  },
  "compression": {
    "enabled": true,
    "algorithms": ["br", "gzip"],
    "min_size": 1024,
    "level": {
      "gzip": 6,
      "brotli": 6
    },
    "types": [".js", ".css", ".html", ".htm", ".xml", ".json", ".txt", ".svg"],
    "excluded_types": [".gz", ".br", ".zip", ".rar", ".7z", ".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".pdf"],
    "content_types": ["text/css", "text/plain", "application/javascript", "application/json", "application/xml", "image/svg+xml"]
  },
  "admin_prefix": "/sslcat-panel",
  "cluster": {
    "mode": "standalone",
    "node_id": "",
    "node_name": "Node-1",
    "master": {
      "host": "",
      "port": 0,
      "auth_key": "",
      "timeout": 30,
      "retry_interval": 10
    },
    "sync": {
      "config_enabled": true,
      "cert_enabled": true,
      "interval": 30,
      "timeout": 10,
      "exclude_configs": [
        "admin.password",
        "admin.password_file",
        "admin_prefix",
        "cluster"
      ]
    },
    "port": 8443,
    "auth_key": ""
  },
  "static_sites": [],
  "php_sites": [],
  "runners": {
    "git": {
      "enabled": true,
      "repos_dir": "/var/lib/sslcat/runners/git",
      "max_concurrent": 3,
      "clone_timeout": 300,
      "auto_cleanup": true,
      "cleanup_interval": 7200
    }
  }
}
JSON
fi

SERVICE=/etc/systemd/system/sslcat.service
sudo bash -c "cat > $SERVICE" <<'UNIT'
[Unit]
Description=SSLcat Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/sslcat/sslcat --config /etc/sslcat/sslcat.conf
Restart=always
RestartSec=3
User=root

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable sslcat || true
sudo systemctl restart sslcat || sudo systemctl start sslcat || true

# 获取公网IP
PUBLIC_IP=$(curl -s https://ip4.dev/myip | tr -d '\n' | xargs)

msg installed_path "$DEST_LINUX/sslcat"
msg config_path "$CONF_LINUX"
msg panel_hint "$PUBLIC_IP"



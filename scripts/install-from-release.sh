#!/usr/bin/env bash
set -euo pipefail

# sslcat 一键安装脚本（Linux/macOS）
# 用法（推荐传版本）：
#   curl -fsSL https://raw.githubusercontent.com/xurenlu/sslcat/main/scripts/install-from-release.sh | sudo bash -s -- -v 1.0.4

VER=""
DEST_LINUX="/opt/sslcat"
CONF_LINUX="/etc/sslcat/sslcat.conf"
LANG_CODE=""

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

    zh:prefer_download) echo "[sslcat] 优先下载: %s";;
    en:prefer_download) echo "[sslcat] Prefer download: %s";;
    fr:prefer_download) echo "[sslcat] Téléchargement prioritaire : %s";;
    es:prefer_download) echo "[sslcat] Descarga preferida: %s";;
    ja:prefer_download) echo "[sslcat] 優先してダウンロード: %s";;

    zh:github_failed_fallback_mirror) echo "[sslcat] GitHub下载失败，尝试中国大陆镜像: %s";;
    en:github_failed_fallback_mirror) echo "[sslcat] GitHub download failed, trying China mirror: %s";;
    fr:github_failed_fallback_mirror) echo "[sslcat] Échec du téléchargement GitHub, tentative via miroir Chine : %s";;
    es:github_failed_fallback_mirror) echo "[sslcat] Falló la descarga desde GitHub, intentando espejo de China: %s";;
    ja:github_failed_fallback_mirror) echo "[sslcat] GitHub のダウンロードに失敗。中国ミラーを試します: %s";;

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

    *) echo "[sslcat] %s";;
  esac
}

msg() { local fmt; fmt="$(i18n "$1")"; shift; printf "$fmt\n" "$@"; }
msg_err() { local fmt; fmt="$(i18n "$1")"; shift; printf "$fmt\n" "$@" >&2; }

USER_LANG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v|--version)
      VER="${2:-}"
      shift 2 ;;
    -l|--lang)
      USER_LANG="${2:-}"
      shift 2 ;;
    *) shift ;;
  esac
done

set_lang "$USER_LANG"

if [[ -z "$VER" ]]; then
  VER="1.0.13"
  msg missing_version "$VER"
fi

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  armv7l|armv7|armhf) ARCH=arm ;;
  *) msg_err unsupported_arch "$ARCH_RAW"; exit 1 ;;
esac

PREFERRED="sslcat_v${VER}_${OS}-${ARCH}"
EXT=".tar.gz"
if [[ "$OS" == "windows" ]]; then EXT=".zip"; fi
TMP="$(mktemp -d)"
URL_GH="https://github.com/xurenlu/sslcat/releases/download/v${VER}/sslcat_v${VER}_${OS}-${ARCH}${EXT}"
URL_CN="https://sslcat.com/xurenlu/sslcat/releases/download/v${VER}/sslcat_v${VER}_${OS}-${ARCH}${EXT}"
msg prefer_download "$URL_GH"
if ! curl -fsSL "$URL_GH" -o "$TMP/pkg${EXT}"; then
  msg github_failed_fallback_mirror "$URL_CN"
  curl -fsSL "$URL_CN" -o "$TMP/pkg${EXT}"
fi

if [[ "$OS" == "darwin" ]]; then
  tar -xzf "$TMP/pkg${EXT}" -C "$TMP"
  sudo install -m 0755 "$TMP/sslcat" /usr/local/bin/sslcat
  msg installed_path "/usr/local/bin/sslcat"
  msg run_hint "sslcat --config sslcat.conf --port 8080"
  exit 0
fi

# Linux: 安装到 /opt/sslcat 并写入 systemd 与默认配置
sudo mkdir -p "$DEST_LINUX" /var/lib/sslcat/{certs,keys,logs} /etc/sslcat
tar -xzf "$TMP/pkg${EXT}" -C "$TMP"
sudo install -m 0755 "$TMP/sslcat" "$DEST_LINUX/sslcat"

if [[ ! -f "$CONF_LINUX" ]]; then
  sudo bash -c "cat > $CONF_LINUX" <<'JSON'
{
  "server": {"host": "0.0.0.0", "port": 443, "debug": false},
  "ssl": {"staging": false, "cert_dir": "/var/lib/sslcat/certs", "key_dir": "/var/lib/sslcat/keys", "auto_renew": true},
  "admin": {"username": "admin", "first_run": true, "password_file": "/var/lib/sslcat/admin.pass"},
  "proxy": {"rules": []},
  "security": {"max_attempts": 3, "block_duration": "1m", "max_attempts_5min": 10, "block_file": "/var/lib/sslcat/sslcat.block", "allowed_user_agents": ["Mozilla/","Chrome/","Firefox/","Safari/","Edge/"]},
  "admin_prefix": "/sslcat-panel"
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
sudo systemctl disable withssl --now >/dev/null 2>&1 || true
sudo systemctl enable sslcat || true
sudo systemctl restart sslcat || sudo systemctl start sslcat || true

# 获取公网IP
PUBLIC_IP=$(curl -s https://ip4.dev/myip | tr -d '\n' | xargs)

msg installed_path "$DEST_LINUX/sslcat"
msg config_path "$CONF_LINUX"
msg panel_hint "$PUBLIC_IP"



#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log(){ echo -e "${GREEN}[INFO]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERR ]${NC} $*"; }

on_err(){
  local ec=$?
  err "安装失败（exit=${ec}，line=${BASH_LINENO[0]}，cmd=${BASH_COMMAND}）"
  exit "$ec"
}
trap on_err ERR

APP_DIR="/opt/sui-panel"
SERVICE_NAME="sui-panel"
ENV_FILE="/etc/default/${SERVICE_NAME}"
BIN_URL="https://raw.githubusercontent.com/Spittingjiu/sui/main/dist/sui-panel-full-linux-amd64"
SERVER_URL="https://raw.githubusercontent.com/Spittingjiu/sui/main/server.mjs"
PANEL_INDEX_URL="https://raw.githubusercontent.com/Spittingjiu/sui/main/public/index.html"
REPO_API_URL="https://api.github.com/repos/Spittingjiu/sui/commits/main"
PANEL_TAR_URL="https://sui.wuhai.eu.org/sui-panel.tar.gz"
BACKUP_ROOT="/var/lib/sui-installer"
BACKUP_DIR="$BACKUP_ROOT/backup"

require_root(){ [[ ${EUID} -eq 0 ]] || { err "请用 root 执行"; exit 1; }; }

preflight(){
  local root_mb tmp_mb
  root_mb=$(df -Pm / | awk 'NR==2{print $4}')
  tmp_mb=$(df -Pm /tmp | awk 'NR==2{print $4}')
  log "环境检测：/ 可用 ${root_mb}MB, /tmp 可用 ${tmp_mb}MB"
  (( root_mb >= 700 && tmp_mb >= 200 )) || { err "磁盘不足（要求 / >=700MB /tmp>=200MB）"; exit 1; }
}

apt_base(){
  export DEBIAN_FRONTEND=noninteractive
  dpkg --configure -a || true
  if command -v apt-get >/dev/null 2>&1; then
    apt-get -f install -y || true
    apt-get update
    apt-get install -y curl ca-certificates rsync unzip socat
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl ca-certificates rsync unzip socat
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl ca-certificates rsync unzip socat
  else
    err "未找到受支持的包管理器（apt-get/dnf/yum）"
    exit 1
  fi
}

write_env(){
  [[ -s "$ENV_FILE" ]] && return
  cat > "$ENV_FILE" <<EOF
PORT=8810
PANEL_USER=admin
PANEL_PASS=admin123
PANEL_TOKEN=sui2026
XRAY_PUBLIC_HOST=
EOF
}

backup_existing_state(){
  local has=0 keep="Y"
  if [[ -s /opt/sui-panel/inbounds.json || -s /etc/sui-xray/config.json ]]; then
    read -r -p "检测到已有节点配置，是否保留并迁移？[Y/n]: " keep < /dev/tty || true
    keep="${keep:-Y}"
  fi
  if [[ "$keep" =~ ^[Nn]$ ]]; then
    rm -rf "$BACKUP_ROOT"
    return
  fi
  mkdir -p "$BACKUP_DIR"
  if [[ -s /opt/sui-panel/inbounds.json ]]; then
    mkdir -p "$BACKUP_DIR/opt-sui-panel"
    cp -a /opt/sui-panel/inbounds.json "$BACKUP_DIR/opt-sui-panel/"
    has=1
  fi
  if [[ -s /etc/sui-xray/config.json ]]; then
    mkdir -p "$BACKUP_DIR/etc-sui-xray"
    cp -a /etc/sui-xray/config.json "$BACKUP_DIR/etc-sui-xray/"
    has=1
  fi
  if [[ "$has" -eq 1 ]]; then
    date -Iseconds > "$BACKUP_ROOT/created_at"
  fi
  return 0
}

restore_existing_state(){
  local restored=0
  if [[ -s "$BACKUP_DIR/opt-sui-panel/inbounds.json" ]]; then
    mkdir -p /opt/sui-panel
    cp -a "$BACKUP_DIR/opt-sui-panel/inbounds.json" /opt/sui-panel/inbounds.json
    restored=1
  fi
  if [[ -s "$BACKUP_DIR/etc-sui-xray/config.json" ]]; then
    mkdir -p /etc/sui-xray
    cp -a "$BACKUP_DIR/etc-sui-xray/config.json" /etc/sui-xray/config.json
    restored=1
  fi
  if [[ "$restored" -eq 1 ]]; then
    if [[ ! -s /opt/sui-panel/panel-settings.json ]]; then
      cat > /opt/sui-panel/panel-settings.json <<EOT
{"username":"admin","password":"admin123","panelPath":"/","forceResetPassword":false}
EOT
    else
      sed -i 's/"forceResetPassword"[[:space:]]*:[[:space:]]*true/"forceResetPassword":false/g' /opt/sui-panel/panel-settings.json || true
    fi
  fi
}

fetch_latest_commit(){
  curl -fsSL "$REPO_API_URL" | sed -n 's/^[[:space:]]*"sha": "\([a-f0-9]\{40\}\)".*/\1/p' | head -n1
}

write_version_meta(){
  local action="${1:-install}" commit=""
  commit=$(fetch_latest_commit || true)
  cat > "$APP_DIR/VERSION" <<EOF
source=github-main
action=$action
commit=${commit:-unknown}
updated_at=$(date -Iseconds)
binary_sha256=$(sha256sum "$APP_DIR/sui-panel-bin" 2>/dev/null | awk '{print $1}')
server_sha256=$(sha256sum "$APP_DIR/server.mjs" 2>/dev/null | awk '{print $1}')
index_sha256=$(sha256sum "$APP_DIR/public/index.html" 2>/dev/null | awk '{print $1}')
EOF
}

install_xray_if_needed(){
  if [[ ! -x /usr/local/bin/xray ]]; then
    log "安装 Xray core..."
    local tag tmp
    tag=$(curl -fsSL https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep '"tag_name"' | head -n1 | sed -E 's/.*"([^"]+)".*/\1/')
    [[ -n "$tag" ]] || tag="v26.2.4"
    tmp=$(mktemp -d)
    curl -fL --retry 3 -o "$tmp/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/${tag}/Xray-linux-64.zip"
    unzip -o "$tmp/xray.zip" -d "$tmp" >/dev/null
    install -m 0755 "$tmp/xray" /usr/local/bin/xray
    rm -rf "$tmp"
  fi
}

setup_binary_mode(){
  mkdir -p "$APP_DIR/public"

  systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
  pkill -f '/opt/sui-panel/sui-panel-bin' >/dev/null 2>&1 || true
  sleep 0.3

  log "下载二进制与面板文件..."
  local tmp_bin old_bin tmp
  tmp_bin=$(mktemp)
  old_bin="$APP_DIR/sui-panel-bin.old.$(date +%s)"
  curl -fL --retry 3 -o "$tmp_bin" "$BIN_URL"
  [[ -f "$APP_DIR/sui-panel-bin" ]] && mv -f "$APP_DIR/sui-panel-bin" "$old_bin" 2>/dev/null || true
  install -m 0755 "$tmp_bin" "$APP_DIR/sui-panel-bin"
  rm -f "$tmp_bin"
  # 清理历史旧二进制，避免占盘（仅保留最近2个）
  ls -1t "$APP_DIR"/sui-panel-bin.old.* 2>/dev/null | awk 'NR>2' | xargs -r rm -f

  if ! curl -fL --retry 3 -o "$APP_DIR/server.mjs" "$SERVER_URL"; then
    warn "GitHub 获取 server.mjs 失败，回退到历史包源"
    tmp=$(mktemp -d)
    curl -fL --retry 3 -o "$tmp/panel.tar.gz" "$PANEL_TAR_URL"
    tar -xzf "$tmp/panel.tar.gz" -C "$tmp"
    cp -f "$tmp/sui-panel/server.mjs" "$APP_DIR/server.mjs"
    cp -f "$tmp/sui-panel/public/index.html" "$APP_DIR/public/index.html"
    rm -rf "$tmp"
  else
    curl -fL --retry 3 -o "$APP_DIR/public/index.html" "$PANEL_INDEX_URL?t=$(date +%s)" || warn "GitHub 获取前端失败，保留现有前端文件"
  fi

  write_version_meta install

  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=SUI Panel (Binary)
After=network.target
[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$APP_DIR/sui-panel-bin
Restart=always
RestartSec=2
User=root
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "$SERVICE_NAME"
}

write_sui_cli(){
cat > /usr/local/bin/sui <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ENV_FILE=/etc/default/sui-panel
SERVICE=sui-panel.service
BIN_PATH=/opt/sui-panel/sui-panel-bin
BIN_URL=https://raw.githubusercontent.com/Spittingjiu/sui/main/dist/sui-panel-full-linux-amd64
SERVER_URL=https://raw.githubusercontent.com/Spittingjiu/sui/main/server.mjs
PANEL_INDEX_URL=https://raw.githubusercontent.com/Spittingjiu/sui/main/public/index.html
REPO_API_URL=https://api.github.com/repos/Spittingjiu/sui/commits/main
PANEL_TAR_URL=https://sui.wuhai.eu.org/sui-panel.tar.gz
INSTALL_URL=https://raw.githubusercontent.com/Spittingjiu/sui/main/install.sh
MENU_SOURCE=/opt/sui-panel/sui-menu.sh

set_kv(){ k="$1"; v="$2"; grep -q "^${k}=" "$ENV_FILE" 2>/dev/null && sed -i "s#^${k}=.*#${k}=${v}#" "$ENV_FILE" || echo "${k}=${v}" >> "$ENV_FILE"; }
reload_apply(){ systemctl daemon-reload; systemctl restart "$SERVICE"; }

fetch_latest_commit(){
  curl -fsSL "$REPO_API_URL" | sed -n 's/^[[:space:]]*"sha": "\([a-f0-9]\{40\}\)".*/\1/p' | head -n1
}

write_version_meta(){
  local action="${1:-update}" commit=""
  commit=$(fetch_latest_commit || true)
  cat > /opt/sui-panel/VERSION <<EOV
source=github-main
action=$action
commit=${commit:-unknown}
updated_at=$(date -Iseconds)
binary_sha256=$(sha256sum "$BIN_PATH" 2>/dev/null | awk '{print $1}')
server_sha256=$(sha256sum /opt/sui-panel/server.mjs 2>/dev/null | awk '{print $1}')
index_sha256=$(sha256sum /opt/sui-panel/public/index.html 2>/dev/null | awk '{print $1}')
EOV
}

show_current_version(){
  echo "--- 当前版本信息 ---"
  if [[ -s /opt/sui-panel/VERSION ]]; then
    cat /opt/sui-panel/VERSION
  else
    echo "VERSION 文件不存在（可先执行一次 4) 更新 SUI）"
  fi
  echo
  echo "本地文件时间:"
  stat -c 'sui-panel-bin: %y' "$BIN_PATH" 2>/dev/null || true
  stat -c 'server.mjs:   %y' /opt/sui-panel/server.mjs 2>/dev/null || true
  stat -c 'index.html:   %y' /opt/sui-panel/public/index.html 2>/dev/null || true
}

extract_remote_menu(){
  local remote="$1" out="$2"
  awk 'f{ if($0=="EOF"){exit} print } /cat > \/usr\/local\/bin\/sui <<'\''EOF'\''/{f=1}' "$remote" > "$out"
  [[ -s "$out" ]]
}

self_update_menu(){
  local work remote_menu
  work=$(mktemp -d)
  remote_menu="$work/sui.remote"
  if curl -fsSL "$INSTALL_URL" -o "$work/install.sh" && extract_remote_menu "$work/install.sh" "$remote_menu"; then
    if cmp -s "$remote_menu" /usr/local/bin/sui; then
      echo "菜单已是最新"
    else
      install -m 0755 "$remote_menu" /usr/local/bin/sui
      echo "菜单已更新到最新版"
    fi
  elif [[ -s "$MENU_SOURCE" ]]; then
    install -m 0755 "$MENU_SOURCE" /usr/local/bin/sui
    echo "菜单已从本机模板更新"
  else
    rm -rf "$work"
    echo "菜单更新失败"
    return 1
  fi
  rm -rf "$work"
}

update_sui_bin(){
  # 统一走“最新安装脚本重装”路径，确保与手工重装效果一致
  local tmp_inst
  tmp_inst=$(mktemp)
  echo "正在拉取最新安装脚本..."
  curl -fL --retry 3 -o "$tmp_inst" "$INSTALL_URL?t=$(date +%s)"
  echo "开始执行重装（会保留你现有配置，按提示选 Y）..."
  bash "$tmp_inst"
  rm -f "$tmp_inst"
}

opt_bbr(){
cat >/etc/sysctl.d/99-sui-bbr.conf <<'EOT'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOT
modprobe tcp_bbr || true
sysctl --system >/dev/null
}

opt_dns(){
mkdir -p /etc/systemd/resolved.conf.d
cat >/etc/systemd/resolved.conf.d/99-sui-dns.conf <<'EOT'
[Resolve]
DNS=1.1.1.1 8.8.8.8 2606:4700:4700::1111 2001:4860:4860::8888
FallbackDNS=9.9.9.9 1.0.0.1 2620:fe::fe 2606:4700:4700::1001
DNSStubListener=yes
DNSSEC=no
EOT
systemctl restart systemd-resolved || true
}

opt_sysctl(){
cat >/etc/sysctl.d/99-sui-net.conf <<'EOT'
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 2000
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.ip_local_port_range = 1024 65535
EOT
sysctl --system >/dev/null
}

setup_panel_https_proxy(){
  local domain cert_file key_file panel_port caddyfile
  domain="$1"
  cert_file="$2"
  key_file="$3"
  panel_port=$(grep -E '^PORT=' "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2-)
  panel_port=${panel_port:-8810}

  if ! command -v caddy >/dev/null 2>&1; then
    apt-get update && apt-get install -y caddy
  fi

  # 若已有 Web 服务占用 80/443，先停止，避免 Caddy 启动失败
  systemctl stop nginx apache2 httpd >/dev/null 2>&1 || true

  caddyfile=/etc/caddy/Caddyfile
  cat > "$caddyfile" <<EOC
${domain} {
    tls ${cert_file} ${key_file}
    encode gzip
    reverse_proxy 127.0.0.1:${panel_port}
}

http://${domain} {
    redir https://${domain}{uri} 308
}
EOC

  # 让 caddy 用户可读私钥
  chgrp caddy "$key_file" >/dev/null 2>&1 || true
  chmod 640 "$key_file" >/dev/null 2>&1 || true

  systemctl enable --now caddy
  systemctl restart caddy
}

issue_tls_cert_and_apply(){
  local domain email acme cert_dir cert_file key_file
  read -r -p "请输入证书域名（如: node.zzao.de）: " domain
  [[ -n "${domain:-}" ]] || { echo "域名不能为空"; return 1; }
  if [[ ! "$domain" =~ ^[A-Za-z0-9.-]+$ ]]; then
    echo "域名格式不合法"
    return 1
  fi

  read -r -p "请输入邮箱（可留空）: " email
  email="${email:-admin@${domain#*.}}"

  if ss -lntp 2>/dev/null | grep -q ':80 '; then
    echo "检测到 80 端口被占用，standalone 验证需要临时释放 80。"
    echo "请先停止占用 80 的服务后重试（例如: systemctl stop nginx/caddy/apache2）。"
    return 1
  fi

  command -v curl >/dev/null 2>&1 || { echo "缺少 curl，正在安装..."; apt-get update && apt-get install -y curl; }
  command -v socat >/dev/null 2>&1 || { echo "缺少 socat，正在安装..."; apt-get update && apt-get install -y socat; }
  command -v python3 >/dev/null 2>&1 || { echo "缺少 python3，正在安装..."; apt-get update && apt-get install -y python3; }

  acme="${HOME}/.acme.sh/acme.sh"
  if [[ ! -x "$acme" ]]; then
    echo "正在安装 acme.sh..."
    curl -fsSL https://get.acme.sh | sh -s email="$email"
  fi
  [[ -x "$acme" ]] || acme="/root/.acme.sh/acme.sh"
  [[ -x "$acme" ]] || { echo "acme.sh 安装失败"; return 1; }

  "$acme" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true

  echo "开始申请证书（standalone，无需 nginx/caddy）..."
  "$acme" --issue --standalone -d "$domain" --keylength ec-256 --force

  cert_dir="/opt/sui-panel/certs/${domain}"
  cert_file="${cert_dir}/fullchain.cer"
  key_file="${cert_dir}/private.key"
  mkdir -p "$cert_dir"

  "$acme" --install-cert -d "$domain" --ecc \
    --fullchain-file "$cert_file" \
    --key-file "$key_file" \
    --reloadcmd "systemctl restart sui-xray-core.service >/dev/null 2>&1 || true"

  if [[ -s /etc/sui-xray/config.json ]]; then
    CERT_FILE="$cert_file" KEY_FILE="$key_file" python3 - <<'PY'
import json, os
p = '/etc/sui-xray/config.json'
cert = os.environ['CERT_FILE']
key = os.environ['KEY_FILE']
with open(p, 'r', encoding='utf-8') as f:
    cfg = json.load(f)
changed = False
for ib in cfg.get('inbounds', []):
    ss = ib.get('streamSettings') or {}
    if isinstance(ss, str):
        continue
    sec = (ss.get('security') or '').lower()
    if sec != 'tls':
        continue
    ts = ss.setdefault('tlsSettings', {})
    certs = ts.get('certificates')
    if not isinstance(certs, list) or not certs:
        certs = [{}]
        ts['certificates'] = certs
    certs[0]['certificateFile'] = cert
    certs[0]['keyFile'] = key
    changed = True
if changed:
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
print('changed' if changed else 'no_tls_inbound')
PY
    systemctl restart sui-xray-core.service >/dev/null 2>&1 || true
  fi

  echo "正在配置面板 HTTPS 入口（Caddy 反代到面板端口）..."
  setup_panel_https_proxy "$domain" "$cert_file" "$key_file"

  set_kv XRAY_PUBLIC_HOST "$domain"
  reload_apply

  echo "证书与面板 HTTPS 已完成："
  echo "  cert: $cert_file"
  echo "  key : $key_file"
  echo "已自动写入 /etc/sui-xray/config.json 中所有 TLS 入站（若存在）并重启 xray。"
  echo "面板访问地址: https://${domain}/"
}

while true; do
  echo "===== SUI 菜单 ====="
  echo "1) 修改面板用户名"
  echo "2) 修改面板密码"
  echo "3) 修改面板端口"
  echo "4) 更新 SUI（面板+二进制）"
  echo "5) 查看状态（增强）"
  echo "6) 启用 BBR + fq"
  echo "7) DNS 优化"
  echo "8) 系统网络栈优化"
  echo "9) 一键应用全部优化(6+7+8)"
  echo "10) 一键SSL（申请证书 + Xray TLS + 面板HTTPS）"
  echo "11) 检查并更新 SUI 菜单"
  echo "12) 显示当前版本"
  echo "0) 退出"
  read -r -p "选择: " c
  case "$c" in
    1) read -r -p "新用户名: " u; [[ -n "${u:-}" ]] || { echo "用户名不能为空"; read -r -p "回车继续"; continue; }; set_kv PANEL_USER "$u"; reload_apply; echo "用户名已更新"; read -r -p "回车继续" ;;
    2) read -r -p "新密码: " p; [[ -n "${p:-}" ]] || { echo "密码不能为空"; read -r -p "回车继续"; continue; }; set_kv PANEL_PASS "$p"; reload_apply; echo "密码已更新"; read -r -p "回车继续" ;;
    3) read -r -p "新端口: " pt; set_kv PORT "$pt"; reload_apply; echo "已更新端口为 $pt"; read -r -p "回车继续" ;;
    4) update_sui_bin; echo "SUI 面板与二进制已更新并重启"; read -r -p "回车继续" ;;
    5)
      echo "--- SUI 状态 ---"
      current_port=$(grep -E '^PORT=' "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2-)
      echo "当前端口: ${current_port:-8810}"
      if [[ -s /opt/sui-panel/VERSION ]]; then
        echo "版本摘要: $(grep '^commit=' /opt/sui-panel/VERSION | cut -d= -f2 | cut -c1-12)"
      fi
      echo
      echo "[sui-panel.service]"
      systemctl --no-pager status "$SERVICE" | sed -n '1,25p' || true
      echo
      echo "[sui-xray-core.service]"
      systemctl --no-pager status sui-xray-core.service | sed -n '1,25p' || true
      echo
      echo "[监听端口]"
      ss -lntp | grep -E ':8810|:443|:80' || true
      read -r -p "回车继续"
      ;;
    6) opt_bbr; echo "已启用 BBR + fq"; read -r -p "回车继续" ;;
    7) opt_dns; echo "已应用 DNS 优化"; read -r -p "回车继续" ;;
    8) opt_sysctl; echo "已应用网络栈优化"; read -r -p "回车继续" ;;
    9) opt_bbr; opt_dns; opt_sysctl; echo "已应用全部优化"; read -r -p "回车继续" ;;
    10) issue_tls_cert_and_apply; read -r -p "回车继续" ;;
    11) self_update_menu; read -r -p "回车继续" ;;
    12) show_current_version; read -r -p "回车继续" ;;
    0) exit 0 ;;
  esac
done
EOF
chmod +x /usr/local/bin/sui
}

main(){
  log "Step 1/7: 权限检查"
  require_root
  log "Step 2/7: 环境预检"
  preflight
  log "Step 3/7: 备份旧配置"
  backup_existing_state
  log "Step 4/7: 安装基础依赖"
  apt_base
  log "Step 5/7: 检查/安装 Xray"
  install_xray_if_needed
  log "Step 6/7: 写入默认环境配置"
  write_env

  log "已固定为二进制安装模式"
  setup_binary_mode
  echo binary > /etc/sui-panel.mode
  restore_existing_state
  systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl restart sui-xray-core.service >/dev/null 2>&1 || true
  write_sui_cli

  local effective_port
  effective_port=$(grep -E '^PORT=' "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2-)
  effective_port=${effective_port:-8810}

  log "安装完成 ✅"
  echo "访问: http://<你的服务器IP>:${effective_port}"
  echo "提示: 如需修改端口，执行命令: sui -> 3) 修改面板端口"
}

main "$@"

#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log(){ echo -e "${GREEN}[INFO]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERR ]${NC} $*"; }

APP_DIR="/opt/sui-panel"
SERVICE_NAME="sui-panel"
ENV_FILE="/etc/default/${SERVICE_NAME}"
BIN_URL="https://raw.githubusercontent.com/Spittingjiu/sui/main/dist/sui-panel-full-linux-amd64"
SERVER_URL="https://raw.githubusercontent.com/Spittingjiu/sui/main/server.mjs"
PANEL_INDEX_URL="https://raw.githubusercontent.com/Spittingjiu/sui/main/public/index.html"
REPO_API_URL="https://api.github.com/repos/Spittingjiu/sui/commits/main"
PANEL_TAR_URL="https://cui.wuhai.eu.org/sui-panel.tar.gz"
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
  apt-get -f install -y || true
  apt-get update -y
  apt-get install -y curl ca-certificates rsync unzip
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
  if [[ -s /opt/cui-panel/inbounds.json || -s /etc/cui-xray/config.json ]]; then
    read -r -p "检测到已有节点配置，是否保留并迁移？[Y/n]: " keep < /dev/tty || true
    keep="${keep:-Y}"
  fi
  if [[ "$keep" =~ ^[Nn]$ ]]; then
    rm -rf "$BACKUP_ROOT"
    return
  fi
  mkdir -p "$BACKUP_DIR"
  if [[ -s /opt/cui-panel/inbounds.json ]]; then
    mkdir -p "$BACKUP_DIR/opt-cui-panel"
    cp -a /opt/cui-panel/inbounds.json "$BACKUP_DIR/opt-cui-panel/"
    has=1
  fi
  if [[ -s /etc/cui-xray/config.json ]]; then
    mkdir -p "$BACKUP_DIR/etc-cui-xray"
    cp -a /etc/cui-xray/config.json "$BACKUP_DIR/etc-cui-xray/"
    has=1
  fi
  [[ "$has" -eq 1 ]] && date -Iseconds > "$BACKUP_ROOT/created_at"
}

restore_existing_state(){
  local restored=0
  if [[ -s "$BACKUP_DIR/opt-cui-panel/inbounds.json" ]]; then
    mkdir -p /opt/cui-panel
    cp -a "$BACKUP_DIR/opt-cui-panel/inbounds.json" /opt/cui-panel/inbounds.json
    restored=1
  fi
  if [[ -s "$BACKUP_DIR/etc-cui-xray/config.json" ]]; then
    mkdir -p /etc/cui-xray
    cp -a "$BACKUP_DIR/etc-cui-xray/config.json" /etc/cui-xray/config.json
    restored=1
  fi
  if [[ "$restored" -eq 1 ]]; then
    if [[ ! -s /opt/cui-panel/panel-settings.json ]]; then
      cat > /opt/cui-panel/panel-settings.json <<EOT
{"username":"admin","password":"admin123","panelPath":"/","forceResetPassword":false}
EOT
    else
      sed -i 's/"forceResetPassword"[[:space:]]*:[[:space:]]*true/"forceResetPassword":false/g' /opt/cui-panel/panel-settings.json || true
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
PANEL_TAR_URL=https://cui.wuhai.eu.org/sui-panel.tar.gz
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
  self_update_menu >/dev/null 2>&1 || true
  local work
  work=$(mktemp -d)
  mkdir -p /opt/sui-panel/public

  systemctl stop "$SERVICE" >/dev/null 2>&1 || true
  pkill -f '/opt/sui-panel/sui-panel-bin' >/dev/null 2>&1 || true
  sleep 0.3

  curl -fL --retry 3 -o "$work/sui-panel-bin" "$BIN_URL"
  [[ -f "$BIN_PATH" ]] && mv -f "$BIN_PATH" "${BIN_PATH}.old.$(date +%s)" 2>/dev/null || true
  install -m 0755 "$work/sui-panel-bin" "$BIN_PATH"

  if ! curl -fL --retry 3 -o /opt/sui-panel/server.mjs "$SERVER_URL"; then
    echo "GitHub server.mjs 拉取失败，回退到历史包源"
    curl -fL --retry 3 -o "$work/panel.tar.gz" "$PANEL_TAR_URL"
    tar -xzf "$work/panel.tar.gz" -C "$work"
    [ -f "$work/sui-panel/server.mjs" ] && cp -f "$work/sui-panel/server.mjs" /opt/sui-panel/server.mjs
    [ -f "$work/sui-panel/public/index.html" ] && cp -f "$work/sui-panel/public/index.html" /opt/sui-panel/public/index.html
  else
    curl -fL --retry 3 -o /opt/sui-panel/public/index.html "$PANEL_INDEX_URL?t=$(date +%s)" || echo "GitHub index.html 拉取失败，保留现有前端"
  fi

  write_version_meta update
  install -m 0755 /usr/local/bin/sui /opt/sui-panel/sui-menu.sh 2>/dev/null || true
  rm -rf "$work"
  systemctl restart "$SERVICE"
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
  echo "10) 检查并更新 SUI 菜单"
  echo "11) 显示当前版本"
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
      echo "[cui-xray-core.service]"
      systemctl --no-pager status cui-xray-core.service | sed -n '1,25p' || true
      echo
      echo "[监听端口]"
      ss -lntp | grep -E ':8810|:443|:80' || true
      read -r -p "回车继续"
      ;;
    6) opt_bbr; echo "已启用 BBR + fq"; read -r -p "回车继续" ;;
    7) opt_dns; echo "已应用 DNS 优化"; read -r -p "回车继续" ;;
    8) opt_sysctl; echo "已应用网络栈优化"; read -r -p "回车继续" ;;
    9) opt_bbr; opt_dns; opt_sysctl; echo "已应用全部优化"; read -r -p "回车继续" ;;
    10) self_update_menu; read -r -p "回车继续" ;;
    11) show_current_version; read -r -p "回车继续" ;;
    0) exit 0 ;;
  esac
done
EOF
chmod +x /usr/local/bin/sui
}

main(){
  require_root
  preflight
  backup_existing_state
  apt_base
  install_xray_if_needed
  write_env

  log "已固定为二进制安装模式"
  setup_binary_mode
  echo binary > /etc/sui-panel.mode
  restore_existing_state
  systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl restart cui-xray-core.service >/dev/null 2>&1 || true
  write_sui_cli

  local effective_port
  effective_port=$(grep -E '^PORT=' "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2-)
  effective_port=${effective_port:-8810}

  log "安装完成 ✅"
  echo "访问: http://<你的服务器IP>:${effective_port}"
  echo "提示: 如需修改端口，执行命令: sui -> 3) 修改面板端口"
}

main "$@"

#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log(){ echo -e "${GREEN}[INFO]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERR ]${NC} $*"; }

APP_DIR="/opt/sui-panel"
PKG_URL="https://cui.wuhai.eu.org/sui-panel.tar.gz"
SERVICE_NAME="sui-panel"
ENV_FILE="/etc/default/${SERVICE_NAME}"
CONTAINER_NAME="sui-panel"
BIN_URL="https://raw.githubusercontent.com/Spittingjiu/sui/main/dist/sui-panel-full-linux-amd64"
SERVER_URL="https://raw.githubusercontent.com/Spittingjiu/sui/main/server.mjs"
PANEL_INDEX_URL="https://raw.githubusercontent.com/Spittingjiu/sui/main/public/index.html"
PANEL_TAR_URL="https://cui.wuhai.eu.org/sui-panel.tar.gz"
BACKUP_ROOT="/var/lib/sui-installer"
BACKUP_DIR="$BACKUP_ROOT/backup"

require_root(){ [[ ${EUID} -eq 0 ]] || { err "请用 root 执行"; exit 1; }; }
preflight(){
  local root_mb tmp_mb
  root_mb=$(df -Pm / | awk 'NR==2{print $4}'); tmp_mb=$(df -Pm /tmp | awk 'NR==2{print $4}')
  log "环境检测：/ 可用 ${root_mb}MB, /tmp 可用 ${tmp_mb}MB"
  (( root_mb >= 700 && tmp_mb >= 200 )) || { err "磁盘不足（要求 / >=700MB /tmp>=200MB）"; exit 1; }
}
choose_mode(){
  local m
  local tty="/dev/tty"

  # 非交互环境（如 CI/管道）默认走 1，避免卡住
  if [[ -n "${SUI_MODE:-}" ]]; then
    m="${SUI_MODE}"
    [[ "$m" == "1" || "$m" == "2" ]] || { err "SUI_MODE 仅支持 1 或 2"; exit 1; }
    log "检测到 SUI_MODE=${m}，按指定模式安装" >&2
    echo "$m"; return
  fi

  if [[ ! -e "$tty" ]]; then
    warn "未检测到交互终端，默认使用模式 1（Docker）" >&2
    echo "1"; return
  fi

  while true; do
    cat > "$tty" <<'EOT'
========================================
SUI Panel 安装模式选择
----------------------------------------
1) Docker 一键版（推荐）
   - 自动装 Docker 并启动容器
   - 占用更稳，升级回滚方便

2) 全功能二进制版（推荐小内存）
   - 与线上 SUI 面板同功能
   - 直接下载预编译二进制（不安装 Go/Node）
========================================
EOT
    read -r -p "请选择安装模式 [1/2，默认1]: " m < "$tty" || true
    m="${m:-1}"
    [[ "$m" == "1" || "$m" == "2" ]] && { echo "$m"; return; }
    warn "输入无效，请输入 1 或 2" > "$tty"
    sleep 1
  done
}
apt_base(){
  export DEBIAN_FRONTEND=noninteractive
  dpkg --configure -a || true
  apt-get -f install -y || true
  apt-get update -y
  apt-get install -y curl ca-certificates rsync unzip
}
write_env(){
  if [[ -s "$ENV_FILE" ]]; then
    return
  fi
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
  if [[ "$has" -eq 1 ]]; then
    date -Iseconds > "$BACKUP_ROOT/created_at"
  fi
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
    # 老环境迁移时不强制首登改密，避免升级后看不到节点
    if [[ ! -s /opt/cui-panel/panel-settings.json ]]; then
      cat > /opt/cui-panel/panel-settings.json <<EOT
{"username":"admin","password":"admin123","panelPath":"/","forceResetPassword":false}
EOT
    else
      sed -i 's/"forceResetPassword"[[:space:]]*:[[:space:]]*true/"forceResetPassword":false/g' /opt/cui-panel/panel-settings.json || true
    fi
  fi
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

# Docker mode (现有完整面板)
install_app_node(){
  local tmp
  tmp=$(mktemp -d)
  curl -fL --retry 3 -o "$tmp/panel.tar.gz" "$PKG_URL"
  mkdir -p "$APP_DIR"
  tar -xzf "$tmp/panel.tar.gz" -C "$tmp"
  rsync -a --delete --exclude node_modules "$tmp/sui-panel/" "$APP_DIR/"
  rm -rf "$tmp"
}
install_docker_if_needed(){ command -v docker >/dev/null 2>&1 && return; curl -fsSL https://get.docker.com | sh; systemctl enable --now docker; }
setup_docker_mode(){
  install_app_node
  install_docker_if_needed
  systemctl enable --now docker || true
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  docker run -d --name "$CONTAINER_NAME" --restart always -p 8810:8810 --env-file "$ENV_FILE" -v "$APP_DIR:/app" -w /app node:20-bookworm sh -lc "npm install --omit=dev && node server.mjs"
}

# Binary mode (prebuilt)
setup_binary_mode(){
  mkdir -p "$APP_DIR/public"
  log "下载二进制与面板文件..."
  curl -fL --retry 3 -o "$APP_DIR/sui-panel-bin" "$BIN_URL"
  chmod +x "$APP_DIR/sui-panel-bin"
  # 代码文件优先从 GitHub 获取；失败时回退到历史 tar 包源
  if ! curl -fL --retry 3 -o "$APP_DIR/server.mjs" "$SERVER_URL"; then
    warn "GitHub 获取 server.mjs 失败，回退到历史包源"
    tmp=$(mktemp -d)
    curl -fL --retry 3 -o "$tmp/panel.tar.gz" "$PANEL_TAR_URL"
    tar -xzf "$tmp/panel.tar.gz" -C "$tmp"
    cp -f "$tmp/sui-panel/server.mjs" "$APP_DIR/server.mjs"
    cp -f "$tmp/sui-panel/public/index.html" "$APP_DIR/public/index.html"
    rm -rf "$tmp"
  else
    curl -fL --retry 3 -o "$APP_DIR/public/index.html" "$PANEL_INDEX_URL"
  fi
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
PANEL_TAR_URL=https://cui.wuhai.eu.org/sui-panel.tar.gz
INSTALL_URL=https://raw.githubusercontent.com/Spittingjiu/sui/main/install.sh
MENU_SOURCE=/opt/sui-panel/sui-menu.sh

set_kv(){ k="$1"; v="$2"; grep -q "^${k}=" "$ENV_FILE" 2>/dev/null && sed -i "s#^${k}=.*#${k}=${v}#" "$ENV_FILE" || echo "${k}=${v}" >> "$ENV_FILE"; }
reload_apply(){ systemctl daemon-reload; systemctl restart "$SERVICE"; }

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
  work=$(mktemp -d)
  mkdir -p /opt/sui-panel/public

  # 二进制与代码优先从 GitHub 拉最新
  curl -fL --retry 3 -o "$work/sui-panel-bin" "$BIN_URL"
  install -m 0755 "$work/sui-panel-bin" "$BIN_PATH"

  if ! curl -fL --retry 3 -o /opt/sui-panel/server.mjs "$SERVER_URL"; then
    echo "GitHub server.mjs 拉取失败，回退到历史包源"
    curl -fL --retry 3 -o "$work/panel.tar.gz" "$PANEL_TAR_URL"
    tar -xzf "$work/panel.tar.gz" -C "$work"
    [ -f "$work/sui-panel/server.mjs" ] && cp -f "$work/sui-panel/server.mjs" /opt/sui-panel/server.mjs
    [ -f "$work/sui-panel/public/index.html" ] && cp -f "$work/sui-panel/public/index.html" /opt/sui-panel/public/index.html
  else
    curl -fL --retry 3 -o /opt/sui-panel/public/index.html "$PANEL_INDEX_URL"
  fi

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
# 保守网络参数（避免激进配置导致降速）
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
  echo "0) 退出"
  read -r -p "选择: " c
  case "$c" in
    1)
      read -r -p "新用户名: " u
      [[ -n "${u:-}" ]] || { echo "用户名不能为空"; read -r -p "回车继续"; continue; }
      set_kv PANEL_USER "$u"
      reload_apply
      echo "用户名已更新"
      read -r -p "回车继续"
      ;;
    2)
      read -r -p "新密码: " p
      [[ -n "${p:-}" ]] || { echo "密码不能为空"; read -r -p "回车继续"; continue; }
      set_kv PANEL_PASS "$p"
      reload_apply
      echo "密码已更新"
      read -r -p "回车继续"
      ;;
    3)
      read -r -p "新端口: " pt
      set_kv PORT "$pt"
      reload_apply
      echo "已更新端口为 $pt"
      read -r -p "回车继续"
      ;;
    4)
      update_sui_bin
      echo "SUI 面板与二进制已更新并重启"
      read -r -p "回车继续"
      ;;
    5)
      echo "--- SUI 状态 ---"
      mode=$(cat /etc/sui-panel.mode 2>/dev/null || echo unknown)
      echo "安装模式: $mode"
      echo
      if [[ "$mode" == "docker" ]] || docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^sui-panel$'; then
        echo "[Docker 容器]"
        docker ps --filter name=sui-panel --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true
        echo
      fi
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
    0) exit 0 ;;
  esac
done
EOF
chmod +x /usr/local/bin/sui
}

main(){
  require_root; preflight; backup_existing_state; apt_base; install_xray_if_needed; write_env
  log "已固定为二进制安装模式（不再使用 Docker）"
  setup_binary_mode
  echo binary > /etc/sui-panel.mode
  restore_existing_state
  systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl restart cui-xray-core.service >/dev/null 2>&1 || true
  write_sui_cli
  log "安装完成 ✅"
  echo "访问: http://<你的服务器IP>:8810"
}
main "$@"

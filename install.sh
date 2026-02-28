#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log(){ echo -e "${GREEN}[INFO]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
err(){ echo -e "${RED}[ERR ]${NC} $*"; }

progress_step(){
  local n="$1" total="$2" text="$3" width=24
  local fill=$(( n * width / total ))
  local empty=$(( width - fill ))
  printf -v bar "%*s" "$fill" ""; bar=${bar// /█}
  printf -v pad "%*s" "$empty" ""; pad=${pad// /·}
  printf "[%s%s] %3d%% (%d/%d) %s\n" "$bar" "$pad" $(( n * 100 / total )) "$n" "$total" "$text"
}

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
FORWARDER_URL="https://raw.githubusercontent.com/Spittingjiu/sui/main/forwarder.mjs"
PANEL_INDEX_URL="https://raw.githubusercontent.com/Spittingjiu/sui/main/public/index.html"
PANEL_FAVICON_URL="https://raw.githubusercontent.com/Spittingjiu/sui/main/public/favicon.svg"
PANEL_PKG_URL="https://raw.githubusercontent.com/Spittingjiu/sui/main/package.json"
PANEL_LOCK_URL="https://raw.githubusercontent.com/Spittingjiu/sui/main/package-lock.json"
REPO_API_URL="https://api.github.com/repos/Spittingjiu/sui/commits/main"
PANEL_TAR_URL="https://codeload.github.com/Spittingjiu/sui/tar.gz/refs/heads/main"
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
    apt-get -f install -y >/dev/null 2>&1 || true
    apt-get update -y >/dev/null
    apt-get install -y curl ca-certificates rsync unzip socat >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y curl ca-certificates rsync unzip socat >/dev/null
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl ca-certificates rsync unzip socat >/dev/null
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
PANEL_TLS_ENABLE=0
PANEL_TLS_CERT=
PANEL_TLS_KEY=
XRAY_PUBLIC_HOST=
EOF
}

backup_existing_state(){
  local has=0 keep="Y"
  if [[ -s /opt/sui-panel/data/inbounds.json || -s /etc/sui-xray/config.json ]]; then
    read -r -p "检测到已有 SUI 配置，是否保留？[Y/n]: " keep < /dev/tty || true
    keep="${keep:-Y}"
  fi
  if [[ "$keep" =~ ^[Nn]$ ]]; then
    rm -rf "$BACKUP_ROOT"
    return
  fi
  mkdir -p "$BACKUP_DIR"
  if [[ -s /opt/sui-panel/data/inbounds.json ]]; then
    mkdir -p "$BACKUP_DIR/opt-sui-panel-data"
    cp -a /opt/sui-panel/data/inbounds.json "$BACKUP_DIR/opt-sui-panel-data/"
    has=1
  fi
  if [[ -s /opt/sui-panel/data/forwards.json ]]; then
    mkdir -p "$BACKUP_DIR/opt-sui-panel-data"
    cp -a /opt/sui-panel/data/forwards.json "$BACKUP_DIR/opt-sui-panel-data/"
    has=1
  fi
  if [[ -s /opt/sui-panel/data/panel-settings.json ]]; then
    mkdir -p "$BACKUP_DIR/opt-sui-panel-data"
    cp -a /opt/sui-panel/data/panel-settings.json "$BACKUP_DIR/opt-sui-panel-data/"
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
  if [[ -s "$BACKUP_DIR/opt-sui-panel-data/inbounds.json" ]]; then
    mkdir -p /opt/sui-panel/data
    cp -a "$BACKUP_DIR/opt-sui-panel-data/inbounds.json" /opt/sui-panel/data/inbounds.json
    restored=1
  fi
  if [[ -s "$BACKUP_DIR/opt-sui-panel-data/forwards.json" ]]; then
    mkdir -p /opt/sui-panel/data
    cp -a "$BACKUP_DIR/opt-sui-panel-data/forwards.json" /opt/sui-panel/data/forwards.json
    restored=1
  fi
  if [[ -s "$BACKUP_DIR/opt-sui-panel-data/panel-settings.json" ]]; then
    mkdir -p /opt/sui-panel/data
    cp -a "$BACKUP_DIR/opt-sui-panel-data/panel-settings.json" /opt/sui-panel/data/panel-settings.json
    restored=1
  fi
  if [[ -s "$BACKUP_DIR/etc-sui-xray/config.json" ]]; then
    mkdir -p /etc/sui-xray
    cp -a "$BACKUP_DIR/etc-sui-xray/config.json" /etc/sui-xray/config.json
    restored=1
  fi
  if [[ "$restored" -eq 1 ]]; then
    if [[ ! -s /opt/sui-panel/data/panel-settings.json ]]; then
      cat > /opt/sui-panel/data/panel-settings.json <<EOT
{"username":"admin","password":"admin123","panelPath":"/","forceResetPassword":false}
EOT
    else
      sed -i 's/"forceResetPassword"[[:space:]]*:[[:space:]]*true/"forceResetPassword":false/g' /opt/sui-panel/data/panel-settings.json || true
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
    curl -fsSL --retry 3 -o "$tmp/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/${tag}/Xray-linux-64.zip"
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
  curl -fsSL --retry 3 -o "$tmp_bin" "$BIN_URL"
  [[ -f "$APP_DIR/sui-panel-bin" ]] && mv -f "$APP_DIR/sui-panel-bin" "$old_bin" 2>/dev/null || true
  install -m 0755 "$tmp_bin" "$APP_DIR/sui-panel-bin"
  rm -f "$tmp_bin"
  # 清理历史旧二进制，避免占盘（仅保留最近2个）
  ls -1t "$APP_DIR"/sui-panel-bin.old.* 2>/dev/null | awk 'NR>2' | xargs -r rm -f

  if ! curl -fsSL --retry 3 -o "$APP_DIR/server.mjs" "$SERVER_URL"; then
    warn "GitHub 获取 server.mjs 失败，回退到历史包源"
    tmp=$(mktemp -d)
    curl -fsSL --retry 3 -o "$tmp/panel.tar.gz" "$PANEL_TAR_URL"
    tar -xzf "$tmp/panel.tar.gz" -C "$tmp"
    panel_root=$(dirname "$(find "$tmp" -maxdepth 3 -type f -name server.mjs | head -n1)")
    if [[ -n "${panel_root:-}" && -f "$panel_root/server.mjs" ]]; then
      cp -f "$panel_root/server.mjs" "$APP_DIR/server.mjs"
      [[ -f "$panel_root/forwarder.mjs" ]] && cp -f "$panel_root/forwarder.mjs" "$APP_DIR/forwarder.mjs"
      [[ -f "$panel_root/public/index.html" ]] && cp -f "$panel_root/public/index.html" "$APP_DIR/public/index.html"
      [[ -f "$panel_root/public/favicon.svg" ]] && cp -f "$panel_root/public/favicon.svg" "$APP_DIR/public/favicon.svg"
      [[ -f "$panel_root/package.json" ]] && cp -f "$panel_root/package.json" "$APP_DIR/package.json"
      [[ -f "$panel_root/package-lock.json" ]] && cp -f "$panel_root/package-lock.json" "$APP_DIR/package-lock.json"
    else
      warn "回退包中未找到 server.mjs，保留当前文件"
    fi
    rm -rf "$tmp"
  else
    curl -fsSL --retry 3 -o "$APP_DIR/forwarder.mjs" "$FORWARDER_URL?t=$(date +%s)" || warn "GitHub 获取 forwarder.mjs 失败，保留现有文件"
    curl -fsSL --retry 3 -o "$APP_DIR/public/index.html" "$PANEL_INDEX_URL?t=$(date +%s)" || warn "GitHub 获取前端失败，保留现有前端文件"
    curl -fsSL --retry 3 -o "$APP_DIR/public/favicon.svg" "$PANEL_FAVICON_URL?t=$(date +%s)" || warn "GitHub 获取 favicon 失败，保留现有图标文件"
    curl -fsSL --retry 3 -o "$APP_DIR/package.json" "$PANEL_PKG_URL?t=$(date +%s)" || warn "GitHub 获取 package.json 失败，保留现有文件"
    curl -fsSL --retry 3 -o "$APP_DIR/package-lock.json" "$PANEL_LOCK_URL?t=$(date +%s)" || warn "GitHub 获取 package-lock.json 失败，保留现有文件"
  fi

  # 运行模式为 Node Runtime，需要安装 JS 依赖；但不通过 apt 强装 node/npm，避免版本冲突
  if command -v npm >/dev/null 2>&1; then
    (cd "$APP_DIR" && npm install --omit=dev --no-audit --no-fund >/dev/null)
  elif command -v corepack >/dev/null 2>&1; then
    (cd "$APP_DIR" && corepack npm install --omit=dev --no-audit --no-fund >/dev/null)
  else
    err "未检测到 npm，无法安装运行依赖。请先安装 Node.js(含 npm) 后重试。"
    exit 1
  fi
  write_version_meta install

  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=SUI Panel (Node Runtime)
After=network.target
[Service]
Type=simple
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=/usr/bin/node $APP_DIR/server.mjs
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
PANEL_FAVICON_URL=https://raw.githubusercontent.com/Spittingjiu/sui/main/public/favicon.svg
PANEL_PKG_URL=https://raw.githubusercontent.com/Spittingjiu/sui/main/package.json
PANEL_LOCK_URL=https://raw.githubusercontent.com/Spittingjiu/sui/main/package-lock.json
REPO_API_URL=https://api.github.com/repos/Spittingjiu/sui/commits/main
PANEL_TAR_URL=https://codeload.github.com/Spittingjiu/sui/tar.gz/refs/heads/main
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

extract_remote_menu(){
  local remote="$1" out="$2"
  awk 'f{ if($0=="EOF"){exit} print } /cat > \/usr\/local\/bin\/sui <<'\''EOF'\''/{f=1}' "$remote" > "$out"
  [[ -s "$out" ]]
}

opt_bbr(){
cat >/etc/sysctl.d/99-sui-bbr.conf <<'EOT'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOT
modprobe tcp_bbr || true
sysctl --system >/dev/null
}

setup_panel_https_native(){
  local cert_file key_file
  cert_file="$1"
  key_file="$2"

  # 不安装/不依赖反代；仅切换面板为原生 TLS
  set_kv PORT "443"
  set_kv PANEL_TLS_ENABLE "1"
  set_kv PANEL_TLS_CERT "$cert_file"
  set_kv PANEL_TLS_KEY "$key_file"

  # 证书私钥只允许 root 读取
  chmod 600 "$key_file" >/dev/null 2>&1 || true
  reload_apply
}

issue_tls_cert_and_apply(){
  local domain email acme cert_dir cert_file key_file
  local -a stopped_services=()
  restore_80_services(){
    local s
    for s in "${stopped_services[@]}"; do
      systemctl restart "$s" >/dev/null 2>&1 || true
    done
  }
  trap restore_80_services RETURN

  read -r -p "请输入证书域名（如: panel.example.com）: " domain
  [[ -n "${domain:-}" ]] || { echo "域名不能为空"; return 1; }
  if [[ ! "$domain" =~ ^[A-Za-z0-9.-]+$ ]]; then
    echo "域名格式不合法"
    return 1
  fi

  read -r -p "请输入邮箱（可留空）: " email
  email="${email:-admin@${domain#*.}}"

  if ss -lntp 2>/dev/null | grep -q ':80 '; then
    echo "检测到 80 端口被占用，正在尝试自动临时释放..."
    for s in nginx caddy apache2 httpd lighttpd haproxy; do
      if systemctl is-active --quiet "$s"; then
        systemctl stop "$s" >/dev/null 2>&1 || true
        if ! systemctl is-active --quiet "$s"; then
          stopped_services+=("$s")
          echo "  - 已临时停止: $s"
        fi
      fi
    done
    # 再次检查 80 端口是否已释放
    sleep 1
    if ss -lntp 2>/dev/null | grep -q ':80 '; then
      echo "80 端口仍被占用，可能是非 systemd 服务（如 docker/自启进程）。"
      ss -lntp 2>/dev/null | grep ':80 ' || true
      return 1
    fi
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
    --reloadcmd "systemctl restart sui-panel.service >/dev/null 2>&1 || true; systemctl restart sui-xray-core.service >/dev/null 2>&1 || true"

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

  echo "正在配置面板原生 HTTPS（无 Nginx/Caddy 反代）..."
  setup_panel_https_native "$cert_file" "$key_file"

  set_kv XRAY_PUBLIC_HOST "$domain"

  echo "证书与面板 HTTPS 已完成："
  echo "  cert: $cert_file"
  echo "  key : $key_file"
  echo "已自动写入 /etc/sui-xray/config.json 中所有 TLS 入站（若存在）并重启 xray。"
  echo "面板访问地址: https://${domain}/"
}

while true; do
  echo "===== SUI 菜单 ====="
  echo "1) 修改面板账号密码"
  echo "2) 显示当前面板账号密码"
  echo "3) 修改面板端口"
  echo "4) 启用 BBR + fq"
  echo "5) 一键SSL（申请证书 + Xray TLS + 面板原生HTTPS）"
  echo "0) 退出"
  read -r -p "选择: " c
  case "$c" in
    1)
      read -r -p "新用户名: " u
      [[ -n "${u:-}" ]] || { echo "用户名不能为空"; read -r -p "回车继续"; continue; }
      read -r -p "新密码: " p
      [[ -n "${p:-}" ]] || { echo "密码不能为空"; read -r -p "回车继续"; continue; }
      set_kv PANEL_USER "$u"
      set_kv PANEL_PASS "$p"
      reload_apply
      echo "账号密码已更新"
      read -r -p "回车继续"
      ;;
    2)
      creds=$(python3 - <<'PY2'
import json
from pathlib import Path
u=''
p=''
ps=Path('/opt/sui-panel/data/panel-settings.json')
if ps.exists():
    try:
        o=json.loads(ps.read_text(encoding='utf-8'))
        u=str(o.get('username','') or '')
        p=str(o.get('password','') or '')
    except Exception:
        pass
if not u:
    env=Path('/etc/default/sui-panel')
    if env.exists():
        for line in env.read_text(encoding='utf-8', errors='ignore').splitlines():
            if line.startswith('PANEL_USER='): u=line.split('=',1)[1].strip()
            if line.startswith('PANEL_PASS='): p=line.split('=',1)[1].strip()
print((u or 'admin') + '\n' + (p or 'admin123'))
PY2
)
      cu=$(echo "$creds" | awk 'NR==1{print; exit}')
      cpw=$(echo "$creds" | awk 'NR==2{print; exit}')
      echo "当前用户名: ${cu}"
      echo "当前密码: ${cpw}"
      read -r -p "回车继续"
      ;;
    3) read -r -p "新端口: " pt; set_kv PORT "$pt"; reload_apply; echo "已更新端口为 $pt"; read -r -p "回车继续" ;;
    4) opt_bbr; echo "已启用 BBR + fq"; read -r -p "回车继续" ;;
    5) issue_tls_cert_and_apply; read -r -p "回车继续" ;;
    0) exit 0 ;;
  esac
done
EOF
chmod +x /usr/local/bin/sui
}

main(){
  local total=7
  progress_step 1 "$total" "权限检查"
  require_root
  progress_step 2 "$total" "环境预检"
  preflight
  progress_step 3 "$total" "备份旧配置"
  backup_existing_state
  progress_step 4 "$total" "安装基础依赖"
  apt_base
  progress_step 5 "$total" "检查/安装 Xray"
  install_xray_if_needed
  progress_step 6 "$total" "写入默认环境配置"
  write_env

  progress_step 7 "$total" "部署面板并收尾"
  setup_binary_mode
  echo binary > /etc/sui-panel.mode
  restore_existing_state
  systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
  systemctl restart sui-xray-core.service >/dev/null 2>&1 || true
  write_sui_cli

  local effective_port panel_user panel_pass
  effective_port=$(grep -E '^PORT=' "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2-)
  effective_port=${effective_port:-8810}
  panel_user=$(grep -E '^PANEL_USER=' "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2-)
  panel_pass=$(grep -E '^PANEL_PASS=' "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2-)
  panel_user=${panel_user:-admin}
  panel_pass=${panel_pass:-admin123}

  echo
  log "安装完成 ✅"
  echo "访问地址: https://<你的域名>/  或  http://<你的服务器IP>:${effective_port}"
  echo "默认用户名: ${panel_user}"
  echo "默认密码: ${panel_pass}"
  echo "提示: 如需修改端口，执行命令: sui -> 3) 修改面板端口"
}

main "$@"

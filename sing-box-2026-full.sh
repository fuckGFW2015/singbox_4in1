#!/bin/bash
# sing-box 2026 全功能部署脚本（含流量监控面板）
# 支持：Reality + Hysteria2（端口跳跃）+ TUIC5 + Argo + BBR + 自动续期 + Web 监控

set -e

# === 全局配置 ===
work_dir="/etc/sing-box"
use_domain=false
domain=""
enable_argo=false
OS=""

ARCH=$(uname -m)
case $ARCH in
  x86_64)   ARCH="amd64" ;;
  aarch64)  ARCH="arm64" ;;
  armv7l)   ARCH="armv7" ;;
  *) echo "不支持的架构: $ARCH"; exit 1 ;;
esac

HY2_PORT_START=20000
HY2_PORT_END=30000
HY2_LISTEN_PORT=443
MONITOR_PORT=8888

# === 日志函数 ===
log() { echo -e "\033[32m[INFO]\033[0m $1"; }
warn() { echo -e "\033[33m[WARN]\033[0m $1"; }
error() { echo -e "\033[31m[ERROR]\033[0m $1"; exit 1; }

# === 自动获取 sing-box 最新稳定版本（增强版 + 日志安全）===
get_latest_singbox_version() {
  echo -e "\033[32m[INFO]\033[0m 正在从 GitHub 获取 sing-box 最新版本..." >&2
  local latest_tag=""
  local attempt=1
  local max_attempts=3

  while [ $attempt -le $max_attempts ]; do
    local api_response
    api_response=$(curl -sL --max-time 10 \
      -H "Accept: application/vnd.github.v3+json" \
      -A "Mozilla/5.0 (sing-box-installer/2026)" \
      https://api.github.com/repos/SagerNet/sing-box/releases/latest)

    if [[ "$api_response" == *"\"tag_name\":"* ]] && \
       latest_tag=$(echo "$api_response" | grep -o '"tag_name":"[^"]*"' | head -1 | cut -d'"' -f4); then

      if [[ -n "$latest_tag" && "$latest_tag" == v* ]]; then
        echo "${latest_tag#v}"  # ← 唯一允许的 stdout 输出！
        return 0
      fi
    fi

    echo -e "\033[33m[WARN]\033[0m 第 $attempt 次尝试失败，3 秒后重试..." >&2
    attempt=$((attempt + 1))
    sleep 3
  done

  echo -e "\033[31m[ERROR]\033[0m 无法获取最新版本，请检查网络或手动指定 SBX_VERSION" >&2
  exit 1
}

# === 系统检测 ===
detect_os() {
  if [ -f /etc/os-release ]; then . /etc/os-release; OS=$ID; else OS=unknown; fi
}

# === 安装命令生成 ===
get_install_cmd() {
  case "$OS" in
    debian|ubuntu) echo "sudo apt update && sudo apt install -y curl openssl tar base64 socat ca-certificates qrencode iptables cron";;
    alpine) echo "sudo apk add curl openssl tar coreutils ca-certificates socat qrencode iptables cron";;
    centos|rocky|rhel) echo "sudo yum install -y curl openssl tar coreutils ca-certificates socat qrencode iptables cronie";;
    *) echo "请手动安装依赖";;
  esac
}

# === 依赖检查 ===
check_deps() {
  log "正在检查系统依赖..."
  for cmd in curl openssl tar base64 socat qrencode iptables; do
    command -v $cmd >/dev/null || error "缺少 $cmd\n$(get_install_cmd)"
  done
  log "所有依赖已就绪。"
}

# === 安装 sing-box ===
install_singbox() {
  url="https://github.com/SagerNet/sing-box/releases/download/v${SBX_VERSION}/sing-box-${SBX_VERSION}-linux-${ARCH}.tar.gz"
  sha_url="${url}.sha256sum"
  curl -Lf -o /tmp/sbx.tar.gz "$url"
  curl -Lf -o /tmp/sbx.sha256 "$sha_url"
  (cd /tmp && sha256sum -c sbx.sha256 --status) || error "校验失败"
  tar -xzf /tmp/sbx.tar.gz -C /tmp
  mkdir -p "$work_dir"
  mv "/tmp/sing-box-${SBX_VERSION}-linux-${ARCH}/sing-box" "${work_dir}/sing-box"
  chmod 755 "${work_dir}/sing-box"
  rm -rf /tmp/sbx*
  log "sing-box 安装完成。"
}

# ==============================
# === 脚本执行起点（关键！）===
# ==============================

detect_os
log "检测到系统: $OS"

# 自动获取最新稳定版（如 v1.12.18）
SBX_VERSION=$(get_latest_singbox_version)
log "将安装 sing-box v${SBX_VERSION}"

check_deps
install_singbox

# === 以下是你原有的交互和部署逻辑（请保留或补充）===
read -rp "是否使用真实域名？(y/N): " yn
case $yn in
  [Yy]*) 
    use_domain=true
    read -rp "请输入你的域名（必须已解析到本机 IP）: " domain
    [ -z "$domain" ] && error "域名不能为空"
    ;;
  *) 
    use_domain=false
    warn "启用无域名模式：仅 Reality + TUIC5（无 TLS）"
    ;;
esac

# 注意：此处应继续调用你的配置生成、服务启动等函数
# 例如：
# generate_config_and_links
# setup_port_hopping
# enable_services
# start_monitor_panel
# ...
# === 安装 cloudflared ===
install_cloudflared() {
  log "下载 cloudflared ..."
  curl -Lf -o "${work_dir}/cloudflared" "https://github.com/cloudflare/cloudflared/releases/download/2024.12.0/cloudflared-linux-${ARCH}"
  chmod 755 "${work_dir}/cloudflared"
}

# === 申请证书（带 reload）===
issue_cert() {
  log "申请 Let's Encrypt 证书..."
  if ! [ -f /root/.acme.sh/acme.sh ]; then
    curl -sL https://get.acme.sh | sh
  fi
  systemctl stop nginx apache2 httpd 2>/dev/null || true
  /root/.acme.sh/acme.sh --issue -d "$domain" --standalone -k ec-256 --force
  /root/.acme.sh/acme.sh --install-cert -d "$domain" \
    --ecc \
    --fullchain-file "${work_dir}/cert.pem" \
    --key-file "${work_dir}/key.pem" \
    --reloadcmd "systemctl reload sing-box"
  chmod 600 "${work_dir}"/*.pem
}

# === 确保证书自动续期 ===
ensure_acme_cron() {
  if [ "$use_domain" = true ]; then
    log "配置 Let's Encrypt 证书自动续期..."
    if ! command -v crontab >/dev/null; then
      case "$OS" in
        debian|ubuntu) apt install -y cron >/dev/null 2>&1 ;;
        alpine) apk add cron >/dev/null 2>&1 && rc-update add crond >/dev/null 2>&1 ;;
        centos|rocky) yum install -y cronie >/dev/null 2>&1 && systemctl enable --now crond >/dev/null 2>&1 ;;
      esac
    fi
    (
      crontab -l 2>/dev/null | grep -v acme.sh
      echo "0 0 * * * /root/.acme.sh/acme.sh --cron --home /root/.acme.sh > /dev/null"
    ) | crontab -
    log "✅ 证书续期任务已添加"
  fi
}

# === 内核优化：BBR + fq + IP 转发 ===
optimize_kernel() {
  log "优化内核参数：启用 BBR + fq + IP 转发..."
  for param in "net.ipv4.ip_forward=1" "net.core.default_qdisc=fq" "net.ipv4.tcp_congestion_control=bbr"; do
    if ! grep -q "^${param%%=*}=" /etc/sysctl.conf; then
      echo "$param" >> /etc/sysctl.conf
    fi
  done
  sysctl -p >/dev/null 2>&1 || true
  cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
  if [[ "$cc" == *"bbr"* ]]; then
    log "✅ BBR 已激活 (当前: $cc)"
  else
    warn "⚠️ BBR 未生效（内核可能 <4.9）。建议升级内核。"
  fi
}

# === 保存 iptables 规则 ===
save_iptables_rules() {
  if command -v iptables-save >/dev/null; then
    if [ "$OS" = "alpine" ]; then
      mkdir -p /etc/iptables
      iptables-save > /etc/iptables/rules-save
    elif [ -f /etc/debian_version ]; then
      apt install -y iptables-persistent 2>/dev/null || true
      iptables-save > /etc/iptables/rules.v4
    elif [ -f /etc/redhat-release ] || [ -f /etc/centos-release ]; then
      if command -v firewall-cmd >/dev/null 2>&1; then
        yum install -y iptables-services 2>/dev/null || true
        systemctl enable --now iptables
      fi
      iptables-save > /etc/sysconfig/iptables
    else
      iptables-save > /etc/iptables.rules
    fi
  fi
}

# === Hysteria2 端口跳跃 ===
setup_port_hopping() {
  if [ "$use_domain" = true ]; then
    log "配置 Hysteria2 端口跳跃: UDP ${HY2_PORT_START}-${HY2_PORT_END} → ${HY2_LISTEN_PORT}"
    iptables -t nat -C PREROUTING -p udp --dport $HY2_PORT_START:$HY2_PORT_END -j REDIRECT --to-ports $HY2_LISTEN_PORT 2>/dev/null || \
    iptables -t nat -A PREROUTING -p udp --dport $HY2_PORT_START:$HY2_PORT_END -j REDIRECT --to-ports $HY2_LISTEN_PORT
    save_iptables_rules
    sed -i "s|@$([0-9.]*):443/|@&${HY2_PORT_START}-${HY2_PORT_END}/|" "${work_dir}/nodes.txt"
    warn "⚠️ 客户端 Hysteria2 端口需设为: ${HY2_PORT_START}-${HY2_PORT_END}"
  fi
}

# === 启动流量监控面板 ===
start_monitor_service() {
  local monitor_dir="${work_dir}/monitor"
  mkdir -p "$monitor_dir"

  # 生成前端 HTML（内嵌 Chart.js）
  cat > "${monitor_dir}/index.html" <<'EOF'
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>sing-box 流量监控</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>body{font-family:sans-serif;margin:20px;background:#f9f9f9}h1{text-align:center;color:#333}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:20px;margin-top:20px}canvas{background:white;padding:10px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,0.1)}</style>
</head>
<body>
  <h1>📊 sing-box 实时流量监控 (2026)</h1>
  <div class="grid">
    <canvas id="trafficChart" height="200"></canvas>
    <canvas id="connChart" height="200"></canvas>
  </div>
  <pre id="stats" style="margin-top:20px;background:white;padding:15px;border-radius:8px;box-shadow:0 2px 5px rgba(0,0,0,0.1);overflow:auto;"></pre>

  <script>
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    const connCtx = document.getElementById('connChart').getContext('2d');
    
    const trafficChart = new Chart(trafficCtx, { type: 'line', data: { labels: [], datasets: [{ label: '下行 (KB/s)', data: [], borderColor: '#e74c3c', backgroundColor: 'rgba(231,76,60,0.1)', fill: true }] }, options: { animation: false, responsive: true, scales: { y: { beginAtZero: true } } } });
    const connChart = new Chart(connCtx, { type: 'line', data: { labels: [], datasets: [{ label: '活跃连接', data: [], borderColor: '#3498db', backgroundColor: 'rgba(52,152,219,0.1)', fill: true }] }, options: { animation: false, responsive: true, scales: { y: { beginAtZero: true } } } });

    async function update() {
      try {
        const res = await fetch('/api/stats');
        if (!res.ok) throw new Error('API error');
        const data = await res.json();
        
        const now = new Date().toLocaleTimeString();
        // Traffic
        trafficChart.data.labels.push(now);
        trafficChart.data.datasets[0].data.push((data.down / 1024).toFixed(1));
        if (trafficChart.data.labels.length > 60) {
          trafficChart.data.labels.shift();
          trafficChart.data.datasets[0].data.shift();
        }
        trafficChart.update();

        // Connections
        connChart.data.labels.push(now);
        connChart.data.datasets[0].data.push(data.connections);
        if (connChart.data.labels.length > 60) {
          connChart.data.labels.shift();
          connChart.data.datasets[0].data.shift();
        }
        connChart.update();

        // Stats text
        let statsText = 
          `总上行: ${(data.up_total / 1024 / 1024).toFixed(2)} MB\n` +
          `总下行: ${(data.down_total / 1024 / 1024).toFixed(2)} MB\n` +
          `当前上行: ${(data.up / 1024).toFixed(1)} KB/s\n` +
          `当前下行: ${(data.down / 1024).toFixed(1)} KB/s\n` +
          `活跃连接: ${data.connections}\n\n` +
          `协议分布:\n`;
        for (const [tag, bytes] of Object.entries(data.inbounds)) {
          statsText += `  ${tag}: ${(bytes / 1024 / 1024).toFixed(2)} MB\n`;
        }
        document.getElementById('stats').textContent = statsText;
      } catch (e) {
        document.getElementById('stats').textContent = '⚠️ 无法连接到 sing-box API\n请确保服务正在运行';
      }
      setTimeout(update, 1000);
    }
    update();
  </script>
</body>
</html>
EOF

  # 微型 Web 服务器（使用 socat）
  cat > "${monitor_dir}/web.sh" <<EOF
#!/bin/bash
cd "$monitor_dir"
while true; do
  {
    printf "HTTP/1.1 200 OK\r\n"
    printf "Content-Type: text/html; charset=utf-8\r\n"
    printf "Connection: close\r\n"
    printf "\r\n"
    cat index.html
  } | socat TCP-LISTEN:${MONITOR_PORT},reuseaddr,fork -
done
EOF

  chmod +x "${monitor_dir}/web.sh"
  nohup "${monitor_dir}/web.sh" >/dev/null 2>&1 &
  sleep 1

  # 获取公网 IP
  local ip=$(curl -s4m8 https://api.ipify.org || echo "YOUR_SERVER_IP")
  log "✅ 流量监控面板已启动！"
  log "   访问地址: http://$ip:$MONITOR_PORT"
  warn "🔒 强烈建议通过 SSH 隧道访问：ssh -L 8888:localhost:8888 user@server"
}

# === 生成配置与节点链接 ===
generate_config_and_links() {
  local ip=$(curl -s4m8 https://api.ipify.org || echo "YOUR_SERVER_IP")
  local uuid_real=$(cat /proc/sys/kernel/random/uuid)
  local uuid_tuic=$(cat /proc/sys/kernel/random/uuid)
  local uuid_hy2=$(cat /proc/sys/kernel/random/uuid)
  local uuid_argo=$(cat /proc/sys/kernel/random/uuid)
  local hy2_pass=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16)
  local tuic_pass=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16)

  local reality_sni=${domain:-www.cloudflare.com}

  keypair=$("${work_dir}/sing-box" generate reality-keypair)
  local reality_priv=$(echo "$keypair" | awk '/PrivateKey:/ {print $2}')
  local reality_pub=$(echo "$keypair" | awk '/PublicKey:/ {print $2}')

  > "${work_dir}/nodes.txt"

  echo "vless://$uuid_real@$ip:443?security=reality&encryption=none&pbk=$reality_pub&fp=chrome&sni=$reality_sni&type=tcp#Reality" >> "${work_dir}/nodes.txt"

  if [ "$use_domain" = true ]; then
    echo "hysteria2://$hy2_pass@$ip:443/?sni=$domain#Hysteria2" >> "${work_dir}/nodes.txt"
    echo "tuic://$uuid_tuic:$tuic_pass@$ip:444?sni=$domain&congestion_control=bbr#TUIC5" >> "${work_dir}/nodes.txt"
  else
    echo "tuic://$uuid_tuic:$tuic_pass@$ip:444?congestion_control=bbr#TUIC5-NoTLS" >> "${work_dir}/nodes.txt"
  fi

  if [ "$enable_argo" = true ]; then
    read -rp "请输入 Cloudflare 隧道绑定的域名: " argo_domain
    argo_domain=${argo_domain:-tunnel.example.com}
    vmess_json=$(printf '{"add":"%s","aid":"0","host":"","id":"%s","net":"ws","path":"/","port":"443","ps":"Argo","scy":"auto","sni":"","tls":"tls","type":"none","v":"2"}' "$argo_domain" "$uuid_argo")
    echo "vmess://$(echo -n "$vmess_json" | base64 -w0)#Argo" >> "${work_dir}/nodes.txt"
  fi

  # 构建 inbounds（含 experimental_api）
  local inbounds='[
    {
      "type": "vless",
      "listen": "::",
      "listen_port": 443,
      "users": [{"uuid": "'$uuid_real'"}],
      "tls": {
        "enabled": true,
        "server_name": "'$reality_sni'",
        "reality": {
          "enabled": true,
          "handshake": {"server": "'$reality_sni'", "server_port": 443},
          "private_key": "'$reality_priv'"
        }
      }
    }'

  if [ "$use_domain" = true ]; then
    inbounds="$inbounds,
    {
      \"type\": \"hysteria2\",
      \"listen\": \"::\",
      \"listen_port\": $HY2_LISTEN_PORT,
      \"users\": [{\"password\": \"$hy2_pass\"}],
      \"tls\": {
        \"enabled\": true,
        \"server_name\": \"$domain\",
        \"cert_path\": \"${work_dir}/cert.pem\",
        \"key_path\": \"${work_dir}/key.pem\"
      }
    },
    {
      \"type\": \"tuic\",
      \"listen\": \"::\",
      \"listen_port\": 444,
      \"users\": [{\"uuid\": \"$uuid_tuic\", \"password\": \"$tuic_pass\"}],
      \"congestion_control\": \"bbr\"
    }"
  else
    inbounds="$inbounds,
    {
      \"type\": \"tuic\",
      \"listen\": \"::\",
      \"listen_port\": 444,
      \"users\": [{\"uuid\": \"$uuid_tuic\", \"password\": \"$tuic_pass\"}],
      \"congestion_control\": \"bbr\"
    }"
  fi

  if [ "$enable_argo" = true ]; then
    inbounds="$inbounds,
    {
      \"type\": \"vmess\",
      \"listen\": \"127.0.0.1\",
      \"listen_port\": 8080,
      \"users\": [{\"uuid\": \"$uuid_argo\", \"alterId\": 0}]
    }"
  fi

  # 添加 experimental_api（用于监控）
  inbounds="$inbounds,
  {
    \"type\": \"experimental_api\",
    \"listen\": \"127.0.0.1\",
    \"listen_port\": 9090
  }"

  inbounds="$inbounds
  ]"

  cat > "${work_dir}/config.json" <<EOF
{
  "log": {"level": "info"},
  "inbounds": $inbounds,
  "outbounds": [{"type": "direct"}]
}
EOF

  chmod 600 "${work_dir}/nodes.txt"
}

# === 生成订阅与二维码 ===
generate_subscribe_and_qr() {
  cp "${work_dir}/nodes.txt" "${work_dir}/subscribe_plain.txt"
  if base64 --help 2>&1 | grep -q "GNU"; then
    base64 -w 0 "${work_dir}/nodes.txt" > "${work_dir}/subscribe.txt"
  else
    base64 "${work_dir}/nodes.txt" | tr -d '\n' > "${work_dir}/subscribe.txt"
  fi
  chmod 600 "${work_dir}/subscribe.txt"

  mkdir -p "${work_dir}/qrcodes"
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    name=$(echo "$line" | sed 's/.*#//' | tr -cd '[:alnum:]_.-')
    name=${name:-node}
    qrencode -s 10 -m 2 -o "${work_dir}/qrcodes/${name}.png" "$line"
  done < "${work_dir}/nodes.txt"

  log "✅ 订阅与二维码已生成！"
}

# === 安装 systemd 服务 ===
install_services() {
  cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box 2026 deployment with monitoring
After=network.target

[Service]
ExecStart=${work_dir}/sing-box run -c ${work_dir}/config.json
Restart=on-failure
User=root
AmbientCapabilities=CAP_NET_BIND_SERVICE
WorkingDirectory=${work_dir}

[Install]
WantedBy=multi-user.target
EOF

  if [ "$enable_argo" = true ]; then
    cat > /etc/systemd/system/cloudflared.service <<EOF
[Unit]
Description=Cloudflare Argo Tunnel
After=network.target

[Service]
ExecStart=${work_dir}/cloudflared tunnel --url http://127.0.0.1:8080
Restart=on-failure
User=root
WorkingDirectory=${work_dir}

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable cloudflared
    warn "⚠️ 请手动在 Cloudflare Zero Trust 配置隧道！"
  fi

  systemctl daemon-reload
  systemctl enable sing-box
}

# === 主流程 ===
main() {
  detect_os
  log "检测到系统: $OS"
  check_deps
  install_singbox

  read -rp "是否使用真实域名？(y/N): " yn
  case $yn in
    [Yy]*) 
      use_domain=true
      read -rp "请输入你的域名（必须已解析到本机 IP）: " domain
      [ -z "$domain" ] && error "域名不能为空"
      ;;
    *) 
      use_domain=false
      warn "启用无域名模式：仅 Reality + TUIC5（无 TLS）"
      ;;
  esac

  if [ "$use_domain" = true ]; then
    issue_cert
  fi

  read -rp "是否额外部署 Argo 隧道？(y/N): " yn2
  case $yn2 in
    [Yy]*) 
      enable_argo=true
      install_cloudflared
      ;;
    *) 
      enable_argo=false
      ;;
  esac

  generate_config_and_links
  setup_port_hopping
  generate_subscribe_and_qr
  install_services

  # === 2026 年关键增强 ===
  optimize_kernel
  ensure_acme_cron
  start_monitor_service   # ← 启动监控面板

  # 防火墙提示
  if [ "$use_domain" = true ]; then
    warn "请在云平台放行：TCP/UDP 443, UDP 444, UDP ${HY2_PORT_START}-${HY2_PORT_END}"
  else
    warn "请放行：TCP/UDP 443, UDP 444"
  fi

  log "🎉 部署完成！"
  log "启动服务: systemctl start sing-box"
  [ "$enable_argo" = true ] && log "           systemctl start cloudflared"

  log "🔒 2026 年特别提醒："
  log "   • GFW 已部署 AI 流量指纹识别，请勿长期使用同一 IP"
  log "   • 建议每 30-60 天更换服务器或 IP"
  log "   • Reality 的 SNI 可定期更换（如 www.bing.com → login.microsoftonline.com）"
  log "   • 避免晚 8-11 点高峰时段大流量传输"

  log "客户端链接:"
  cat "${work_dir}/nodes.txt"
  log "二维码路径: ${work_dir}/qrcodes/"
  log "监控面板: http://$(curl -s4m8 https://api.ipify.org):$MONITOR_PORT （推荐 SSH 隧道访问）"
}

main "$@"

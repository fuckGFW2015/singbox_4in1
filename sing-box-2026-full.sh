#!/bin/bash
# 2026 最终集成增强版：Reality + Hy2 + TUIC5 + Argo + Yacd-Meta Dashboard
# 安全修正版：面板仅监听 127.0.0.1，必须通过 SSH 隧道访问

set -e
work_dir="/etc/sing-box"
mkdir -p "$work_dir"

log() { echo -e "\033[32m[INFO]\033[0m $1"; }
warn() { echo -e "\033[33m[WARN]\033[0m $1"; }
error() { echo -e "\033[31m[ERROR]\033[0m $1"; exit 1; }

# 1. 环境清理与基础依赖
prepare_env() {
    log "正在清理冲突环境并安装依赖..."
    fuser -k 443/tcp 443/udp 8443/udp 2>/dev/null || true
    systemctl stop nginx apache2 cloudflared 2>/dev/null || true
    apt update -q && apt install -y curl wget openssl tar coreutils ca-certificates socat qrencode iptables unzip iptables-persistent net-tools dnsutils -y

    # 开启 BBR
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null
        log "BBR 已启用"
    fi
}

# 2. 创建专用用户
create_user() {
    if ! id "sing-box" &>/dev/null; then
        useradd -r -s /usr/sbin/nologin -d "$work_dir" sing-box
    fi
    chown -R sing-box:sing-box "$work_dir"
}

# 3. 安装核心与面板
install_singbox() {
    log "安装 sing-box 核心..."
    local arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    local tag=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d '"' -f 4)
    [ -z "$tag" ] && error "无法获取 sing-box 最新版本"
    
    wget -qO /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/$tag/sing-box-${tag#v}-linux-$arch.tar.gz"
    tar -xzf /tmp/sb.tar.gz -C /tmp
    mv /tmp/sing-box-*/sing-box "$work_dir/sing-box"
    chmod +x "$work_dir/sing-box"

log "部署 Yacd-Meta 可视化面板..."
    mkdir -p "$work_dir/ui"
    # 替换为 MetaCubeX 维护的稳定版，这个源已经编译好，解压即用
    wget -qO /tmp/yacd.zip https://github.com/MetaCubeX/Yacd-meta/archive/refs/heads/gh-pages.zip || warn "面板下载失败，请检查网络"
    
    if [ -f /tmp/yacd.zip ]; then
        unzip -qo /tmp/yacd.zip -d /tmp
        # 注意：gh-pages 分支解压后的文件夹名是 Yacd-meta-gh-pages
        # 且文件直接在根目录，不需要进入 dist 文件夹
        cp -rf /tmp/Yacd-meta-gh-pages/* "$work_dir/ui/" 2>/dev/null || true
        log "面板文件部署成功"
        rm -rf /tmp/yacd.zip /tmp/Yacd-meta-gh-pages
    else
        warn "未能下载面板，脚本将继续安装核心节点..."
    fi
    
    chown -R sing-box:sing-box "$work_dir"

# 4. 证书逻辑
request_acme_cert() {
    local domain="$1"
    [[ "$domain" == "www.bing.com" ]] && return 1
    local ip=$(curl -s4 ip.sb)
    local dns_ip=$(dig +short "$domain" A | head -n1)
    
    if [[ "$dns_ip" != "$ip" ]]; then
        warn "域名 $domain 未解析到本机 IP ($ip)，将使用自签名证书"
        return 1
    fi

    log "尝试申请 Let's Encrypt 证书..."
    [ ! -d ~/.acme.sh ] && curl -s https://get.acme.sh | sh
    ~/.acme.sh/acme.sh --issue -d "$domain" --standalone --force
    if [ -f ~/.acme.sh/"$domain"/fullchain.cer ]; then
        cp ~/.acme.sh/"$domain"/fullchain.cer "$work_dir/cert.pem"
        cp ~/.acme.sh/"$domain"/"$domain".key "$work_dir/key.pem"
        return 0
    else
        return 1
    fi
}

# 5. 生成配置 (面板锁定 127.0.0.1)
setup_config() {
    read -p "请输入你的解析域名 (Hy2需要): " domain
    [[ -z "$domain" ]] && domain="www.bing.com"
    read -p "请输入 Reality 伪装域名 (默认: www.apple.com): " reality_sni
    [[ -z "$reality_sni" ]] && reality_sni="www.apple.com"

    local uuid=$(cat /proc/sys/kernel/random/uuid)
    local pass=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 12)
    local secret=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16)
    local keypair=$("$work_dir/sing-box" generate reality-keypair)
    local priv=$(echo "$keypair" | awk '/PrivateKey:/ {print $2}')
    local pub=$(echo "$keypair" | awk '/PublicKey:/ {print $2}')
    local ip=$(curl -s4 ip.sb)

    if ! request_acme_cert "$domain"; then
        openssl req -x509 -newkey rsa:2048 -keyout "$work_dir/key.pem" -out "$work_dir/cert.pem" -days 3650 -nodes -subj "/CN=$domain" >/dev/null 2>&1
    fi
    chown sing-box:sing-box "$work_dir/cert.pem" "$work_dir/key.pem"

    cat <<EOF > "$work_dir/config.json"
{
  "log": { "level": "info" },
  "experimental": {
    "cache_file": { "enabled": true },
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "ui",
      "secret": "$secret"
    }
  },
  "inbounds": [
    {
      "type": "vless", "tag": "Reality", "listen": "::", "listen_port": 443,
      "users": [{"uuid": "$uuid"}],
      "tls": {
        "enabled": true, "server_name": "$reality_sni",
        "reality": { "enabled": true, "handshake": { "server": "$reality_sni", "server_port": 443 }, "private_key": "$priv" }
      }
    },
    {
      "type": "hysteria2", "tag": "Hy2", "listen": "::", "listen_port": 443,
      "users": [{"password": "$pass"}],
      "tls": { "enabled": true, "server_name": "$domain", "cert_path": "$work_dir/cert.pem", "key_path": "$work_dir/key.pem" }
    },
    {
      "type": "tuic", "tag": "TUIC5", "listen": "::", "listen_port": 8443,
      "users": [{"uuid": "$uuid", "password": "$pass"}],
      "tls": { "enabled": true, "server_name": "$domain", "cert_path": "$work_dir/cert.pem", "key_path": "$work_dir/key.pem" }
    },
    { "type": "vmess", "tag": "Argo-In", "listen": "127.0.0.1", "listen_port": 8080, "users": [{"uuid": "$uuid"}] }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF

    cat <<EOF > /etc/systemd/system/sing-box.service
[Unit]
Description=sing-box service
After=network.target
[Service]
ExecStart=$work_dir/sing-box run -c $work_dir/config.json
Restart=on-failure
User=sing-box
Group=sing-box
AmbientCapabilities=CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable --now sing-box

    clear
    log "========================================"
    log "🔒 安全模式已启用：面板仅限本地 SSH 隧道访问"
    log "🌐 访问地址: http://127.0.0.1:9090/ui"
    log "🔑 面板密钥: $secret"
    log "----------------------------------------"
    log "SSH 隧道指令（本地终端执行）:"
    log "ssh -L 9090:127.0.0.1:9090 root@$ip"
    log "----------------------------------------"
    log "1. Reality (TCP 443):"
    local rel_link="vless://$uuid@$ip:443?security=reality&pbk=$pub&sni=$reality_sni&fp=chrome&type=tcp#Reality_2026"
    echo "$rel_link" | qrencode -t UTF8
    log "2. Hy2 (UDP 443): hysteria2://$pass@$ip:443?sni=$domain#Hy2_2026"
    log "3. TUIC5 (UDP 8443): tuic://$uuid:$pass@$ip:8443?sni=$domain&alpn=h3#TUIC5_2026"
    log "========================================"
}

setup_argo() {
    read -p "配置 Argo 隧道? (y/n): " run_argo
    if [[ "$run_argo" == "y" ]]; then
        local arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
        curl -L -o /usr/local/bin/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$arch && chmod +x /usr/local/bin/cloudflared
        cloudflared tunnel login
        read -p "输入绑定域名: " argo_domain
        cloudflared tunnel delete -f singbox-tunnel 2>/dev/null || true
        tunnel_info=$(cloudflared tunnel create singbox-tunnel)
        tunnel_id=$(echo "$tunnel_info" | grep -oE "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        cloudflared tunnel route dns singbox-tunnel "$argo_domain"
        mkdir -p /etc/cloudflared
        cat <<EOF > /etc/cloudflared/config.yml
tunnel: $tunnel_id
credentials-file: /root/.cloudflared/$tunnel_id.json
ingress:
  - hostname: $argo_domain
    service: http://127.0.0.1:8080
  - service: http_status:404
EOF
        cloudflared service install && systemctl enable --now cloudflared
        log "✅ Argo 隧道就绪: $argo_domain"
    fi
}

prepare_env && create_user && install_singbox && setup_config && setup_argo

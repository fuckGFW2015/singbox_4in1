#!/bin/bash
# 2026 最终集成版：Reality + Hy2 + TUIC5 + Argo + Dashboard
# 系统要求：Ubuntu 20.04+ / Debian 11+

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
    systemctl stop nginx apache2 2>/dev/null || true
    apt update -q && apt install -y curl wget openssl tar coreutils ca-certificates socat qrencode iptables unzip iptables-persistent -y
    
    # 开启 BBR
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p
    fi
}

# 2. 安装 sing-box 核心与面板
install_singbox() {
    log "安装 sing-box 核心..."
    local arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    local tag=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d '"' -f 4)
    wget -qO /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/$tag/sing-box-${tag#v}-linux-$arch.tar.gz"
    tar -xzf /tmp/sb.tar.gz -C /tmp && mv /tmp/sing-box-*/sing-box "$work_dir/sing-box"
    chmod +x "$work_dir/sing-box"

    log "部署可视化面板..."
    mkdir -p "$work_dir/ui"
    wget -qO /tmp/ui.zip https://github.com/MetaCubeX/MetacubexD/archive/refs/heads/gh-pages.zip
    unzip -qo /tmp/ui.zip -d /tmp && mv /tmp/MetacubexD-gh-pages/* "$work_dir/ui/"
}

# 3. 证书与节点配置
setup_config() {
    read -p "请输入解析域名 (Hy2/TUIC5 需要): " domain
    [[ -z "$domain" ]] && domain="www.bing.com"
    
    local uuid=$(cat /proc/sys/kernel/random/uuid)
    local pass=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 12)
    local secret=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 12)
    local keypair=$("$work_dir/sing-box" generate reality-keypair)
    local priv=$(echo "$keypair" | awk '/PrivateKey:/ {print $2}')
    local pub=$(echo "$keypair" | awk '/PublicKey:/ {print $2}')
    local ip=$(curl -s4 ip.sb)

    # 生成自签名证书供 Hy2/TUIC5 使用
    openssl req -x509 -newkey rsa:2048 -keyout "$work_dir/key.pem" -out "$work_dir/cert.pem" -days 3650 -nodes -subj "/CN=$domain"

    cat <<EOF > "$work_dir/config.json"
{
  "log": { "level": "info" },
  "experimental": {
    "cache_file": { "enabled": true },
    "clash_api": { "external_controller": "0.0.0.0:9090", "external_ui": "ui", "secret": "$secret" }
  },
  "inbounds": [
    { "type": "vless", "tag": "Reality", "listen": "::", "listen_port": 443, "users": [{"uuid": "$uuid"}], "tls": { "enabled": true, "server_name": "www.apple.com", "reality": { "enabled": true, "handshake": { "server": "www.apple.com", "server_port": 443 }, "private_key": "$priv" } } },
    { "type": "hysteria2", "tag": "Hy2", "listen": "::", "listen_port": 443, "users": [{"password": "$pass"}], "tls": { "enabled": true, "server_name": "$domain", "cert_path": "$work_dir/cert.pem", "key_path": "$work_dir/key.pem" } },
    { "type": "tuic", "tag": "TUIC5", "listen": "::", "listen_port": 8443, "users": [{"uuid": "$uuid", "password": "$pass"}], "tls": { "enabled": true, "server_name": "$domain", "cert_path": "$work_dir/cert.pem", "key_path": "$work_dir/key.pem" } },
    { "type": "vmess", "tag": "Argo-In", "listen": "127.0.0.1", "listen_port": 8080, "users": [{"uuid": "$uuid"}] }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF

    # 注册服务
    cat <<EOF > /etc/systemd/system/sing-box.service
[Unit]
Description=sing-box service
After=network.target
[Service]
ExecStart=$work_dir/sing-box run -c $work_dir/config.json
Restart=on-failure
User=root
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable --now sing-box

    # 输出节点信息
    clear
    log "========================================"
    log "📊 可视化面板: http://$ip:9090/ui"
    log "🔑 面板密钥: $secret"
    log "----------------------------------------"
    log "1. Reality 节点 (TCP 443):"
    local rel_link="vless://$uuid@$ip:443?security=reality&pbk=$pub&sni=www.apple.com&fp=chrome&type=tcp#Reality_2026"
    echo "$rel_link" | qrencode -t UTF8
    log "链接: $rel_link"
    log "----------------------------------------"
    log "2. Hysteria2: hysteria2://$pass@$ip:443?sni=$domain#Hy2_2026"
    log "3. TUIC5: tuic://$uuid:$pass@$ip:8443?sni=$domain&alpn=h3#TUIC5_2026"
    log "========================================"
}

# 4. Argo 隧道自动化集成
setup_argo() {
    read -p "是否现在配置 Argo 隧道? (y/n): " run_argo
    if [[ "$run_argo" == "y" ]]; then
        log "正在安装 Cloudflared..."
        local arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
        curl -L -o /usr/local/bin/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$arch
        chmod +x /usr/local/bin/cloudflared

        log "请点击下方链接登录 Cloudflare 授权:"
        cloudflared tunnel login
        
        read -p "请输入你要绑定的 Argo 域名: " argo_domain
        tunnel_name="singbox-tunnel"
        cloudflared tunnel delete -f $tunnel_name 2>/dev/null || true
        tunnel_info=$(cloudflared tunnel create $tunnel_name)
        tunnel_id=$(echo "$tunnel_info" | grep -oE "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        
        cloudflared tunnel route dns $tunnel_name $argo_domain
        
        mkdir -p /etc/cloudflared
        cat <<EOF > /etc/cloudflared/config.yml
tunnel: $tunnel_id
credentials-file: /root/.cloudflared/$tunnel_id.json
ingress:
  - hostname: $argo_domain
    service: http://127.0.0.1:8080
  - service: http_status:404
EOF
        cloudflared service install
        systemctl enable --now cloudflared
        log "✅ Argo 隧道配置完成！域名: $argo_domain"
    fi
}

# 执行流程
prepare_env
install_singbox
setup_config
setup_argo

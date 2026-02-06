#!/bin/bash
# 2026 最终集成增强版：Reality + Hy2 + TUIC5 + Argo + Yacd-Meta Dashboard
# 修正：闭合所有逻辑块，支持参数化卸载

set -e
work_dir="/etc/sing-box"

log() { echo -e "\033[32m[INFO]\033[0m $1"; }
warn() { echo -e "\033[33m[WARN]\033[0m $1"; }
error() { echo -e "\033[31m[ERROR]\033[0m $1"; exit 1; }

prepare_env() {
    log "正在清理冲突环境、安装依赖并放行系统防火墙..."
    apt update -q && apt install -y curl wget openssl tar coreutils ca-certificates socat qrencode iptables unzip iptables-persistent net-tools dnsutils -y
    if command -v ufw >/dev/null; then ufw disable >/dev/null 2>&1 || true; fi
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -F && iptables -X
    iptables -t nat -F && iptables -t nat -X
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    iptables -A INPUT -p udp --dport 443 -j ACCEPT
    iptables -A INPUT -p udp --dport 8443 -j ACCEPT
    iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null
    fi
}

create_user() {
    if ! id "sing-box" &>/dev/null; then useradd -r -s /usr/sbin/nologin -d "$work_dir" sing-box; fi
    mkdir -p "$work_dir"
    chown -R sing-box:sing-box "$work_dir"
}

install_singbox() {
    log "安装 sing-box 核心..."
    local arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    local tag=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d '"' -f 4)
    wget -qO /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/$tag/sing-box-${tag#v}-linux-$arch.tar.gz"
    tar -xzf /tmp/sb.tar.gz -C /tmp
    mv /tmp/sing-box-*/sing-box "$work_dir/sing-box"
    chmod +x "$work_dir/sing-box"

    log "部署 Yacd-Meta 可视化面板..."
    mkdir -p "$work_dir/ui"
    wget -qO /tmp/yacd.zip https://github.com/MetaCubeX/Yacd-meta/archive/refs/heads/gh-pages.zip || warn "面板下载失败"
    if [ -f /tmp/yacd.zip ]; then
        unzip -qo /tmp/yacd.zip -d /tmp
        cp -rf /tmp/Yacd-meta-gh-pages/* "$work_dir/ui/" 2>/dev/null || true
        log "✅ 面板文件部署成功"
        rm -rf /tmp/yacd.zip /tmp/Yacd-meta-gh-pages
    fi
    chown -R sing-box:sing-box "$work_dir"
}

request_acme_cert() {
    local domain="$1"
    [[ "$domain" == "www.bing.com" ]] && return 1
    local ip=$(curl -s4 ip.sb)
    local dns_ip=$(dig +short "$domain" A | head -n1)
    if [[ "$dns_ip" != "$ip" ]]; then return 1; fi
    [ ! -d ~/.acme.sh ] && curl -s https://get.acme.sh | sh
    ~/.acme.sh/acme.sh --issue -d "$domain" --standalone --force
    if [ -f ~/.acme.sh/"$domain"/fullchain.cer ]; then
        cp ~/.acme.sh/"$domain"/fullchain.cer "$work_dir/cert.pem"
        cp ~/.acme.sh/"$domain"/"$domain".key "$work_dir/key.pem"
        return 0
    else return 1; fi
}

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
    "clash_api": { "external_controller": "127.0.0.1:9090", "external_ui": "ui", "secret": "$secret" }
  },
  "inbounds": [
    { "type": "vless", "tag": "Reality", "listen": "::", "listen_port": 443, "users": [{"uuid": "$uuid"}], "tls": { "enabled": true, "server_name": "$reality_sni", "reality": { "enabled": true, "handshake": { "server": "$reality_sni", "server_port": 443 }, "private_key": "$priv" } } },
    { "type": "hysteria2", "tag": "Hy2", "listen": "::", "listen_port": 443, "users": [{"password": "$pass"}], "tls": { "enabled": true, "server_name": "$domain", "cert_path": "$work_dir/cert.pem", "key_path": "$work_dir/key.pem" } },
    { "type": "tuic", "tag": "TUIC5", "listen": "::", "listen_port": 8443, "users": [{"uuid": "$uuid", "password": "$pass"}], "tls": { "enabled": true, "server_name": "$domain", "cert_path": "$work_dir/cert.pem", "key_path": "$work_dir/key.pem" } },
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
    log "🔑 面板密钥: $secret"
    log "SSH 隧道指令: ssh -L 9090:127.0.0.1:9090 root@$ip"
    log "Reality: vless://$uuid@$ip:443?security=reality&pbk=$pub&sni=$reality_sni&fp=chrome&type=tcp#Reality"
    log "Hy2: hysteria2://$pass@$ip:443?sni=$domain#Hy2"
    log "TUIC5: tuic://$uuid:$pass@$ip:8443?sni=$domain&alpn=h3#TUIC5"
    log "========================================"
}

uninstall_all() {
    log "正在启动彻底卸载流程..."
    systemctl stop sing-box 2>/dev/null || true
    rm -f /etc/systemd/system/sing-box.service
    rm -rf "$work_dir" /root/.cloudflared ~/.acme.sh
    iptables -F && iptables -t nat -F && iptables -X
    systemctl daemon-reload
    log "✅ 卸载完成。"
}

# 核心逻辑：区分安装与卸载
if [[ "$1" == "uninstall" ]]; then
    uninstall_all
else
    prepare_env
    create_user
    install_singbox
    setup_config
fi

#!/bin/bash
set -e
work_dir="/etc/sing-box"

log() { echo -e "\033[32m[INFO]\033[0m $1"; }
warn() { echo -e "\033[33m[WARN]\033[0m $1"; }
error() { echo -e "\033[31m[ERROR]\033[0m $1"; exit 1; }

prepare_env() {
    log "正在清理环境、安装依赖并优化系统参数..."
    apt-get update -y && apt-get install -y curl wget openssl tar qrencode iptables unzip iptables-persistent net-tools dnsutils
    if command -v ufw >/dev/null; then ufw disable || true; fi
    iptables -P INPUT ACCEPT && iptables -F && iptables -X
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    iptables -A INPUT -p udp --dport 443 -j ACCEPT
    iptables -A INPUT -p udp --dport 8443 -j ACCEPT
    iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
    netfilter-persistent save || true
}

install_singbox_and_ui() {
    log "下载 sing-box 核心..."
    local arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    local tag=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d '"' -f 4)
    wget -qO /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/$tag/sing-box-${tag#v}-linux-$arch.tar.gz"
    tar -xzf /tmp/sb.tar.gz -C /tmp && mv /tmp/sing-box-*/sing-box "$work_dir/sing-box"
    chmod +x "$work_dir/sing-box"

    log "部署 Yacd-Meta 可视化面板..."
    mkdir -p "$work_dir/ui"
    wget -qO /tmp/ui.zip https://github.com/MetaCubeX/Yacd-meta/archive/refs/heads/gh-pages.zip
    unzip -qo /tmp/ui.zip -d /tmp && cp -rf /tmp/Yacd-meta-gh-pages/* "$work_dir/ui/"
    rm -rf /tmp/ui.zip /tmp/Yacd-meta-gh-pages
}

setup_config() {
    read -p "请输入解析域名 (Hy2/TUIC用): " domain
    [[ -z "$domain" ]] && domain="www.bing.com"
    
    local uuid=$(cat /proc/sys/kernel/random/uuid)
    local pass=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 12)
    local secret=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16)
    local keypair=$("$work_dir/sing-box" generate reality-keypair)
    local priv=$(echo "$keypair" | awk '/PrivateKey:/ {print $2}')
    local pub=$(echo "$keypair" | awk '/PublicKey:/ {print $2}')
    local ip=$(curl -s4 ip.sb)

    openssl req -x509 -newkey rsa:2048 -keyout "$work_dir/key.pem" -out "$work_dir/cert.pem" -days 3650 -nodes -subj "/CN=$domain" >/dev/null 2>&1

    cat <<EOF > "$work_dir/config.json"
{
  "log": { "level": "info" },
  "experimental": {
    "clash_api": { "external_controller": "0.0.0.0:9090", "external_ui": "/etc/sing-box/ui", "secret": "$secret" }
  },
  "inbounds": [
    { "type": "vless", "tag": "Reality", "listen": "::", "listen_port": 443, "users": [{"uuid": "$uuid"}], "tls": { "enabled": true, "server_name": "www.apple.com", "reality": { "enabled": true, "handshake": { "server": "www.apple.com", "server_port": 443 }, "private_key": "$priv" } } },
    { "type": "hysteria2", "tag": "Hy2", "listen": "::", "listen_port": 443, "users": [{"password": "$pass"}], "tls": { "enabled": true, "server_name": "$domain", "certificate_path": "$work_dir/cert.pem", "key_path": "$work_dir/key.pem" } },
    { "type": "tuic", "tag": "TUIC5", "listen": "::", "listen_port": 8443, "users": [{"uuid": "$uuid", "password": "$pass"}], "tls": { "enabled": true, "server_name": "$domain", "certificate_path": "$work_dir/cert.pem", "key_path": "$work_dir/key.pem" } },
    { "type": "shadowsocks", "tag": "SS-2022", "listen": "::", "listen_port": 4433, "method": "2022-blake3-aes-128-gcm", "password": "$(openssl rand -base64 16)" },
    { "type": "vmess", "tag": "Argo-In", "listen": "127.0.0.1", "listen_port": 8080, "users": [{"uuid": "$uuid"}] }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF

    "$work_dir/sing-box" check -c "$work_dir/config.json"

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
    
    clear
    echo -e "\n\033[35m==============================================================\033[0m"
    log "✅ 部署完成！"
    echo -e "\033[33m🛡️  [可视化面板]\033[0m"
    echo -e "管理地址: \033[36mhttp://$ip:9090/ui/\033[0m"
    echo -e "访问密钥: \033[36m$secret\033[0m"
    
    echo -e "\n\033[33m🚀 [节点 1: Reality]\033[0m"
    local rel_url="vless://$uuid@$ip:443?security=reality&pbk=$pub&sni=www.apple.com&fp=chrome&type=tcp#Reality"
    echo "$rel_url" | qrencode -t UTF8
    
    echo -e "\n\033[33m🚀 [节点 2: Hysteria2]\033[0m"
    local hy2_url="hysteria2://$pass@$ip:443?sni=$domain&insecure=1#Hy2"
    echo "$hy2_url" | qrencode -t UTF8
    
    echo -e "\n\033[33m🚀 [节点 3: TUIC v5]\033[0m"
    echo -e "tuic://$uuid:$pass@$ip:8443?sni=$domain&alpn=h3&insecure=1#TUIC5"
    echo -e "\033[35m==============================================================\033[0m\n"
}

uninstall() {
    systemctl stop sing-box || true
    rm -rf "$work_dir" /etc/systemd/system/sing-box.service
    log "✅ 卸载完成。"
}

mkdir -p "$work_dir"
if [[ "$1" == "uninstall" ]]; then uninstall; else prepare_env; install_singbox_and_ui; setup_config; fi

#!/bin/bash
set -e

# --- 基礎配置 ---
work_dir="/etc/sing-box"
bin_path="/usr/local/bin/sing-box"

log() { echo -e "\033[32m[INFO]\033[0m $1"; }
warn() { echo -e "\033[33m[WARN]\033[0m $1"; }
error() { echo -e "\033[31m[ERROR]\033[0m $1"; exit 1; }

# --- 1. 優化後的卸載函數 (修復 Killed 報錯) ---
uninstall() {
    log "正在檢查並清理舊組件..."
    
    # 僅當服務存在時才停止，避免 systemd 報錯
    if systemctl list-unit-files | grep -q "sing-box.service"; then
        systemctl stop sing-box >/dev/null 2>&1 || true
        systemctl disable sing-box >/dev/null 2>&1 || true
    fi

    # 僅當進程存在時才殺掉，防止觸發系統保護
    if pgrep -x "sing-box" >/dev/null; then
        pkill -9 sing-box >/dev/null 2>&1 || true
    fi
    if pgrep -x "cloudflared" >/dev/null; then
        pkill -9 cloudflared >/dev/null 2>&1 || true
    fi

    # 刪除物理文件
    rm -rf "$work_dir"
    rm -f /etc/systemd/system/sing-box.service
    rm -f "$bin_path"
    rm -f /usr/local/bin/cloudflared
    
    systemctl daemon-reload >/dev/null 2>&1 || true
    log "✅ 環境清理完成。"
}

# --- 2. 環境準備 (適配 Ubuntu 24.04) ---
prepare_env() {
    log "正在配置環境與防火牆..."
    # 避免 Ubuntu 24.04 彈出內核重啟確認框
    export DEBIAN_FRONTEND=noninteractive
    
    apt-get update -y && apt-get install -y curl wget openssl tar qrencode iptables unzip net-tools iptables-persistent
    
    if command -v ufw >/dev/null; then ufw disable || true; fi
    
    # 防火牆策略
    iptables -P INPUT ACCEPT
    iptables -F
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    iptables -A INPUT -p udp --dport 443 -j ACCEPT
    iptables -A INPUT -p tcp --dport 2053 -j ACCEPT
    iptables -A INPUT -p udp --dport 8443 -j ACCEPT
    iptables -A INPUT -p tcp --dport 9090 -j ACCEPT
    
    # 保存防火牆規則
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
}

# --- 3. 安裝核心與 Metacubexd 面板 ---
install_singbox_and_ui() {
    log "正在安裝最新版 sing-box 核心与 Metacubexd 面板..."
    local arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    local tag=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d '"' -f 4)
    
    # 1. 安装 sing-box 核心
    wget -O /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/$tag/sing-box-${tag#v}-linux-$arch.tar.gz"
    tar -xzf /tmp/sb.tar.gz -C /tmp && mv /tmp/sing-box-*/sing-box "$bin_path"
    chmod +x "$bin_path"
    
    # 2. 安装 Metacubexd 面板 (采用更稳妥的目录处理方式)
    mkdir -p "$work_dir/ui"
    wget -O /tmp/ui.zip https://github.com/MetaCubeX/Metacubexd/archive/refs/heads/gh-pages.zip
    
    # 创建临时解压目录
    rm -rf /tmp/metacubexd_temp && mkdir -p /tmp/metacubexd_temp
    unzip -o /tmp/ui.zip -d /tmp/metacubexd_temp
    
    # 这里的关键修复：直接进入解压后的第一级子目录拷贝内容
    # 因为 GitHub zip 总是包含一个顶级文件夹
    find /tmp/metacubexd_temp -maxdepth 2 -name "index.html" -exec dirname {} \; | xargs -I {} cp -rf {}/. "$work_dir/ui/"
    
    # 3. 彻底清理
    rm -rf /tmp/ui.zip /tmp/sb.tar.gz /tmp/metacubexd_temp /tmp/sing-box-*
}
# --- 4. 配置生成與啟動 ---
setup_config() {
    read -p "請輸入解析域名: " domain
    [[ -z "$domain" ]] && domain="apple.com"
    read -p "是否配置 Argo 隧道？(y/n): " do_argo

    local uuid=$(cat /proc/sys/kernel/random/uuid)
    local pass=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 12)
    local secret=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16)
    
    # Reality 密鑰對
    local keypair=$("$bin_path" generate reality-keypair)
    local priv=$(echo "$keypair" | awk '/PrivateKey:/ {print $2}')
    local pub=$(echo "$keypair" | awk '/PublicKey:/ {print $2}')
    local short_id=$(openssl rand -hex 4)
    local ip=$(curl -s4 ip.sb)

    # 證書生成
    openssl req -x509 -newkey rsa:2048 -keyout "$work_dir/key.pem" -out "$work_dir/cert.pem" -days 3650 -nodes -subj "/CN=$domain" >/dev/null 2>&1
    chmod 600 "$work_dir/cert.pem" "$work_dir/key.pem"

    # 構造 JSON
    cat <<EOF > "$work_dir/config.json"
{
  "log": { "level": "info" },
  "experimental": {
    "clash_api": { "external_controller": "0.0.0.0:9090", "external_ui": "ui", "secret": "$secret" }
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "Reality",
      "listen": "::",
      "listen_port": 443,
      "users": [{"uuid": "$uuid"}],
      "tls": {
        "enabled": true,
        "server_name": "www.apple.com",
        "reality": {
          "enabled": true,
          "handshake": { "server": "www.apple.com", "server_port": 443 },
          "private_key": "$priv",
          "short_id": ["$short_id"]
        }
      }
    },
    {
      "type": "vless",
      "tag": "VLESS-WS-TLS",
      "listen": "::",
      "listen_port": 2053,
      "users": [{"uuid": "$uuid"}],
      "tls": {
        "enabled": true,
        "server_name": "$domain",
        "certificate_path": "$work_dir/cert.pem",
        "key_path": "$work_dir/key.pem"
      },
      "transport": { "type": "ws", "path": "/vless" }
    },
    {
      "type": "hysteria2",
      "tag": "Hy2",
      "listen": "::",
      "listen_port": 443,
      "users": [{"password": "$pass"}],
      "tls": {
        "enabled": true,
        "server_name": "$domain",
        "certificate_path": "$work_dir/cert.pem",
        "key_path": "$work_dir/key.pem"
      }
    },
    {
      "type": "tuic",
      "tag": "TUIC5",
      "listen": "::",
      "listen_port": 8443,
      "users": [{"uuid": "$uuid", "password": "$pass"}],
      "tls": {
        "enabled": true,
        "server_name": "$domain",
        "certificate_path": "$work_dir/cert.pem",
        "key_path": "$work_dir/key.pem",
        "alpn": ["h3"]
      }
    },
    {
      "type": "vmess",
      "tag": "Argo-In",
      "listen": "127.0.0.1",
      "listen_port": 8080,
      "users": [{"uuid": "$uuid"}],
      "transport": { "type": "ws", "path": "/vmess" }
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF

    # 驗證配置
    "$bin_path" check -c "$work_dir/config.json" || error "配置文件校驗失敗！"

    # Argo 隧道邏輯
    if [[ "$do_argo" == "y" ]]; then
        local arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
        wget -O /usr/local/bin/cloudflared "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-$arch"
        chmod +x /usr/local/bin/cloudflared
        nohup /usr/local/bin/cloudflared tunnel --url http://127.0.0.1:8080 > /tmp/argo.log 2>&1 &
        sleep 5
        argo_domain=$(grep -oE 'https://[a-zA-Z0-9.-]+\.trycloudflare\.com' /tmp/argo.log | head -n 1 | sed 's/https:\/\///')
    fi

    # 服務寫入
    systemctl stop sing-box >/dev/null 2>&1 || true
    cat <<EOF > /etc/systemd/system/sing-box.service
[Unit]
Description=sing-box service
After=network.target
[Service]
ExecStart=$bin_path run -c $work_dir/config.json
Restart=on-failure
User=root
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload && systemctl enable --now sing-box
    
    # 輸出結果
    clear
    echo -e "\n\033[35m==============================================================\033[0m"
    log "🌐 公網 IP: $ip"
    log "🔑 面板密鑰: $secret"
    echo -e "\033[36m管理面板: http://$ip:9090/ui/\033[0m"
    echo -e "\033[35m==============================================================\033[0m"

    echo -e "\n\033[33m🚀 [Reality 節點]\033[0m"
    # 修正 sid 參數為 shortId 參數，並確保 flow 為空或 xtls-rprx-vision
    local rel_url="vless://$uuid@$ip:443?security=reality&encryption=none&pbk=$pub&sni=www.apple.com&fp=chrome&shortId=$short_id&type=tcp&flow=xtls-rprx-vision#Reality"
    echo -e "\033[32m$rel_url\033[0m"
    echo -e "$rel_url" | qrencode -t UTF8

    echo -e "\n\033[33m🚀 [Hysteria2 節點]\033[0m"
    local hy2_url="hysteria2://$pass@$ip:443?sni=$domain&insecure=1#Hy2"
    echo -e "\033[32m$hy2_url\033[0m"

    echo -e "\n\033[33m🚀 [TUIC v5 節點]\033[0m"
    # 補全 TUIC 連結生成
    local tuic_url="tuic://$uuid:$pass@$ip:8443?sni=$domain&alpn=h3&congestion_control=bbr&udp_relay_mode=native&insecure=1#TUIC5"
    echo -e "\033[32m$tuic_url\033[0m"

    if [[ ! -z "$argo_domain" ]]; then
        echo -e "\n\033[33m🚀 [Argo VMess]\033[0m"
        local vmess_json='{"v":"2","ps":"Argo-VMess","add":"'$argo_domain'","port":"443","id":"'$uuid'","aid":"0","scy":"auto","net":"ws","type":"none","host":"'$argo_domain'","path":"/vmess","tls":"tls"}'
        echo -e "\033[32mvmess://$(echo -n $vmess_json | base64 -w 0)\033[0m"
    fi
    echo -e "\n\033[35m==============================================================\033[0m\n"
}

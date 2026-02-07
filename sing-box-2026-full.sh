#!/bin/bash
set -e

work_dir="/etc/sing-box"
bin_path="/usr/local/bin/sing-box"

log() { echo -e "\033[32m[INFO]\033[0m $1"; }
error() { echo -e "\033[31m[ERROR]\033[0m $1"; exit 1; }

# --- 卸载函数 ---
uninstall() {
    log "正在清理舊環境..."
    systemctl stop sing-box >/dev/null 2>&1 || true
    systemctl disable sing-box >/dev/null 2>&1 || true
    pgrep -x "sing-box" >/dev/null && pkill -9 -x "sing-box" || true
    pgrep -x "cloudflared" >/dev/null && pkill -9 -x "cloudflared" || true
    rm -rf "$work_dir" /etc/systemd/system/sing-box.service "$bin_path"
    systemctl daemon-reload >/dev/null 2>&1 || true
    log "✅ 已成功卸载所有组件。"
}
# ----------------------------------------

prepare_env() {
    log "配置系统組件..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y && apt-get install -y curl wget openssl tar qrencode unzip net-tools iptables-persistent file

    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1 || true
    fi

    iptables -F
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT   # Reality (TCP)
    iptables -A INPUT -p udp --dport 4443 -j ACCEPT  # Hysteria2 (UDP)
    iptables -A INPUT -p udp --dport 8443 -j ACCEPT  # TUIC (UDP)
    iptables -A INPUT -p tcp --dport 9090 -j ACCEPT  # Panel
    iptables-save > /etc/iptables/rules.v4
}

install_singbox_and_ui() {
    log "下載 sing-box 核心..."
    local arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    local tag=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d '"' -f 4)
    
    # 下载
    wget -O /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/$tag/sing-box-${tag#v}-linux-$arch.tar.gz"
    
    # 解压到临时目录
    mkdir -p /tmp/sb_extract
    tar -xzf /tmp/sb.tar.gz -C /tmp/sb_extract

    # ✅ 正确处理通配符并验证二进制
    local -a bins=(/tmp/sb_extract/sing-box-*/sing-box)
    if [[ ${#bins[@]} -eq 0 ]] || [[ ! -f "${bins[0]}" ]]; then
        error "❌ 未在压缩包中找到 sing-box 二进制文件！"
    fi

    if ! file "${bins[0]}" | grep -q "ELF.*executable"; then
        error "❌ 下載的 sing-box 二進制文件損壞或無效！"
    fi

    mv "${bins[0]}" "$bin_path"
    chmod +x "$bin_path"

    log "安裝面板..."
    mkdir -p "$work_dir/ui"
    wget -O /tmp/ui.zip https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip
    unzip -o /tmp/ui.zip -d /tmp/ui_temp
    local real_ui_path=$(find /tmp/ui_temp -name "index.html" | head -n 1 | xargs dirname)
    if [ ! -f "$real_ui_path/index.html" ]; then
        error "面板文件缺失"
    fi
    cp -rf "$real_ui_path"/* "$work_dir/ui/"
    rm -rf /tmp/ui.zip /tmp/ui_temp /tmp/sb.tar.gz /tmp/sb_extract
}

setup_config() {
    # --- SNI 分离策略（使用更稳定的域名）---
    reality_sni="www.cloudflare.com"      # ✅ 替换为高可用 SNI
    hy2_tuic_sni="www.microsoft.com"
    log "Reality 使用 SNI: $reality_sni"
    log "HY2/TUIC 使用 SNI: $hy2_tuic_sni"

    local uuid=$(cat /proc/sys/kernel/random/uuid)
    local pass=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 12)
    local secret=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16)
    local keypair=$("$bin_path" generate reality-keypair)
    local priv=$(echo "$keypair" | awk '/PrivateKey:/ {print $2}')
    local pub=$(echo "$keypair" | awk '/PublicKey:/ {print $2}')
    local short_id=$(openssl rand -hex 4)

    local ip=$(curl -s4m5 ip.sb || curl -s4m5 api.ipify.org)
    if [[ -z "$ip" ]]; then
        error "❌ 无法获取服务器公网 IPv4 地址，请检查网络连接"
    fi

    # 仅为 HY2/TUIC 生成自签名证书（CN 必须匹配其 SNI）
    openssl req -x509 -newkey rsa:2048 -keyout "$work_dir/key.pem" -out "$work_dir/cert.pem" \
        -days 3650 -nodes -subj "/CN=$hy2_tuic_sni" >/dev/null 2>&1

    # 彻底清理并重建配置目录
    rm -rf "$work_dir"
    mkdir -p "$work_dir"
    mv "$work_dir/../cert.pem" "$work_dir/" 2>/dev/null || true
    mv "$work_dir/../key.pem" "$work_dir/" 2>/dev/null || true

cat <<EOF > "$work_dir/config.json"
{
  "log": { "level": "info" },
  "experimental": {
    "clash_api": {
      "external_controller": "0.0.0.0:9090",
      "external_ui": "ui",
      "secret": "$secret"
    }
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "Reality-In",
      "listen": "::",
      "listen_port": 443,
      "tcp_fast_open": true,
      "sniff": true,
      "sniff_override_destination": true,
      "users": [{ "uuid": "$uuid", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "server_name": "$reality_sni",
        "alpn": ["h2", "http/1.1"],
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$reality_sni",
            "server_port": 443
          },
          "private_key": "$priv",
          "short_id": ["$short_id"]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "Hy2-In",
      "listen": "0.0.0.0",
      "listen_port": 4443,
      "users": [{"password": "$pass"}],
      "tls": {
        "enabled": true,
        "server_name": "$hy2_tuic_sni",
        "certificate_path": "$work_dir/cert.pem",
        "key_path": "$work_dir/key.pem"
      }
    },
    {
      "type": "tuic",
      "tag": "TUIC-In",
      "listen": "0.0.0.0",
      "listen_port": 8443,
      "users": [{"uuid": "$uuid", "password": "$pass"}],
      "tls": {
        "enabled": true,
        "server_name": "$hy2_tuic_sni",
        "certificate_path": "$work_dir/cert.pem",
        "key_path": "$work_dir/key.pem",
        "alpn": ["h3"]
      }
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}
EOF

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

    clear
    echo -e "\n\033[35m==============================================================\033[0m"
    log "🔑 面板地址: http://$ip:9090/ui/  密鑰: $secret"
    echo -e "\n\033[33m🚀 Reality 節點:\033[0m"
    echo "vless://$uuid@$ip:443?security=reality&encryption=none&pbk=$pub&sni=$reality_sni&fp=chrome&shortId=$short_id&type=tcp&flow=xtls-rprx-vision#Reality"
    echo -e "\n\033[33m🚀 Hy2 節點:\033[0m"
    echo "hysteria2://$pass@$ip:4443?sni=$hy2_tuic_sni&insecure=1#Hy2"
    echo -e "\n\033[33m🚀 TUIC5 節點:\033[0m"
    echo "tuic://$uuid:$pass@$ip:8443?sni=$hy2_tuic_sni&alpn=h3&insecure=1#TUIC5"
    echo -e "\033[35m==============================================================\033[0m\n"
}

show_menu() {
    clear
    echo -e "\033[36m      sing-box 多协议共存版 (Reality + HY2 + TUIC)\033[0m"
    echo "------------------------------------------"
    echo "  1. 安装 / 重新安装"
    echo "  2. 彻底卸载"
    echo "  3. 退出"
    echo "------------------------------------------"
    read -p "选择操作: " num
    case "$num" in
        1)
            uninstall
            prepare_env
            install_singbox_and_ui
            setup_config
            [[ -f "$0" ]] && rm -f "$0" && log "🧹 脚本已自动清理。"
            ;;
        2) uninstall ;;
        3) exit 0 ;;
        *) error "无效选择" ;;
    esac
}

if [[ $# -gt 0 ]]; then
    case "${1}" in
        uninstall) uninstall ;;
        *) show_menu ;;
    esac
else
    show_menu
fi

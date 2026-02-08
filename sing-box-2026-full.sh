#!/bin/bash
set -e

work_dir="/etc/sing-box"
bin_path="/usr/local/bin/sing-box"

# 全局端口变量
HY2_PORT=""
TUIC_PORT=""

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
    
    # 仅重置 filter 表，保留 nat/mangle
    iptables -F
    iptables -X
    iptables -Z
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    rm -f /etc/iptables/rules.v4
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

    # 清空规则，保持默认 ACCEPT（安全组已在云平台过滤）
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -F
    iptables -X
    iptables -Z

    # 基础安全规则（只放行，不 DROP）
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT   # SSH
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # Reality (TCP)
    iptables -A INPUT -p tcp --dport 9090 -j ACCEPT # Panel

    # ❌ 移除这行：iptables -A INPUT -j DROP

    iptables-save > /etc/iptables/rules.v4
    systemctl enable --now netfilter-persistent
}

install_singbox_and_ui() {
    log "下載 sing-box 核心..."
    local arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    local tag=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d '"' -f 4)
    
    wget -O /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/$tag/sing-box-${tag#v}-linux-$arch.tar.gz"
    mkdir -p /tmp/sb_extract
    tar -xzf /tmp/sb.tar.gz -C /tmp/sb_extract

    local -a bins=(/tmp/sb_extract/sing-box-*/sing-box)
    if [[ ${#bins[@]} -eq 0 ]] || [[ ! -f "${bins[0]}" ]]; then
        error "❌ 未在压缩包中找到 sing-box 二进制文件！"
    fi

    if ! file "${bins[0]}" | grep -q "ELF.*executable"; then
        error "❌ 下載的 sing-box 二進制文件損壞或無效！"
    fi

    mv "${bins[0]}" "$bin_path"
    chmod +x "$bin_path"

    log "安裝 Yacd Meta 面板..."
    mkdir -p "$work_dir/ui"
    wget -O /tmp/yacd-meta.zip https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip
    unzip -o /tmp/yacd-meta.zip -d /tmp/yacd_temp
    local yacd_dir="/tmp/yacd_temp/Yacd-meta-gh-pages"
    if [ ! -f "$yacd_dir/index.html" ]; then
        error "Yacd Meta 面板文件缺失"
    fi
    cp -rf "$yacd_dir"/* "$work_dir/ui/"
    
    # 清理所有临时文件
    rm -rf /tmp/sb.tar.gz /tmp/sb_extract /tmp/yacd-meta.zip /tmp/yacd_temp
}

setup_config() {
    reality_sni="www.cloudflare.com"
    hy2_tuic_sni="one.one.one.one"

    # 🔥 固定使用高穿透性 UDP 端口（不再随机！）
    HY2_PORT=8443   # Google QUIC 端口，阿里云友好
    TUIC_PORT=2053  # Cloudflare DoH 端口，穿透性强

    log "HY2 端口: $HY2_PORT (UDP), TUIC 端口: $TUIC_PORT (UDP)"

    local uuid=$(cat /proc/sys/kernel/random/uuid)
    local pass=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 12)
    local secret=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 16)
   # 安全生成 Reality 密钥对，确保命令成功且输出非空
if ! keypair_output=$("$bin_path" generate reality-keypair 2>/dev/null) || [[ -z "$keypair_output" ]]; then
    error "❌ 无法生成 Reality 密钥对！请确保 sing-box 版本 ≥ v1.8.0"
fi
local priv=$(echo "$keypair_output" | awk '/PrivateKey:/ {print $2}')
local pub=$(echo "$keypair_output" | awk '/PublicKey:/ {print $2}')
    local short_id=$(openssl rand -hex 4)

    local ip=$(curl -s4m5 ip.sb || curl -s4m5 api.ipify.org)
    if [[ -z "$ip" ]]; then
        error "❌ 无法获取服务器公网 IPv4 地址，请检查网络连接"
    fi

    rm -f "$work_dir/config.json" "$work_dir/cert.pem" "$work_dir/key.pem"
    mkdir -p "$work_dir"

    # 为 HY2/TUIC 生成证书（CN=one.one.one.one）
    openssl req -x509 -newkey rsa:2048 -keyout "$work_dir/key.pem" -out "$work_dir/cert.pem" \
        -days 3650 -nodes -subj "/CN=$hy2_tuic_sni" >/dev/null 2>&1

    # 写入配置
    cat <<EOF > "$work_dir/config.json"
{
  "log": { "level": "info" },
  "experimental": {
    "clash_api": {
      "external_controller": "0.0.0.0:9090",
      "external_ui": "/ui",
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
        "alpn": ["http/1.1"],
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
      "listen_port": $HY2_PORT,
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
      "listen_port": $TUIC_PORT,
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

    # 添加 UDP 端口到防火墙
    iptables -A INPUT -p udp --dport $HY2_PORT -j ACCEPT
    iptables -A INPUT -p udp --dport $TUIC_PORT -j ACCEPT
    iptables-save > /etc/iptables/rules.v4
    iptables-restore < /etc/iptables/rules.v4  # 立即生效

    # systemd 服务
    cat <<EOF > /etc/systemd/system/sing-box.service
[Unit]
Description=sing-box service
After=network.target
[Service]
WorkingDirectory=$work_dir
ExecStart=$bin_path run -c $work_dir/config.json
Restart=on-failure
User=root
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload && systemctl enable --now sing-box

    # === 生成完整节点链接 ===
    reality_link="vless://$uuid@$ip:443?security=reality&encryption=none&pbk=$pub&sni=$reality_sni&fp=chrome&sid=$short_id&type=tcp&flow=xtls-rprx-vision#Reality"
    hy2_link="hysteria2://$pass@$ip:$HY2_PORT?sni=$hy2_tuic_sni&insecure=1&alpn=h3#Hy2"
    tuic_link="tuic://$uuid:$pass@$ip:$TUIC_PORT?sni=$hy2_tuic_sni&alpn=h3&insecure=1#TUIC5"

    clear
    echo -e "\n\033[35m==============================================================\033[0m"
    log "🔑 面板地址: http://$ip:9090/ui/  密鑰: $secret"
    echo -e "\n\033[33m🚀 Reality 节点:\033[0m"
    echo "$reality_link"
    qrencode -t UTF8 "$reality_link" 2>/dev/null

    echo -e "\n\033[33m🚀 HY2 节点:\033[0m"
    echo "$hy2_link"
    qrencode -t UTF8 "$hy2_link" 2>/dev/null

    echo -e "\n\033[33m🚀 TUIC5 节点:\033[0m"
    echo "$tuic_link"
    qrencode -t UTF8 "$tuic_link" 2>/dev/null

    echo -e "\n\033[35m==============================================================\033[0m\n"
    log "📱 请用支持的客户端扫码导入（如 Sing-box、Clash Meta ≥ v1.12.0、Mihomo、V2RayN ≥ v5.0）"
}

show_menu() {
    clear
    echo -e "\033[36m      sing-box 多协议共存版 (Reality + HY2 + TUIC)\033[0m"
    echo "------------------------------------------"
    echo "  1. 安装 / 重新安装"
    echo "  2. 彻底卸载"
    echo "  3. 退出"
    echo "------------------------------------------"
    read -p "选择操作: " num </dev/tty
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

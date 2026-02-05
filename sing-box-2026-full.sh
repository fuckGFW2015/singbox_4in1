# 1. 强制安装基础包并创建目录
apt update && apt install -y curl qrencode unzip socat
mkdir -p /etc/sing-box

# 2. 定义一个本地安装函数
install_now() {
    local domain="www.apple.com" # 默认值
    read -p "请输入你的解析域名 (Hy2需要): " domain
    
    # 自动获取架构和最新版
    local arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    local tag=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d '"' -f 4)
    
    echo "正在下载 sing-box $tag..."
    curl -Lo /tmp/sb.tar.gz "https://github.com/SagerNet/sing-box/releases/download/$tag/sing-box-${tag#v}-linux-$arch.tar.gz"
    tar -xzf /tmp/sb.tar.gz -C /tmp
    mv /tmp/sing-box-*/sing-box /etc/sing-box/
    chmod +x /etc/sing-box/sing-box

    # 生成配置 (Reality + Hy2)
    local uuid=$(cat /proc/sys/kernel/random/uuid)
    local keypair=$(/etc/sing-box/sing-box generate reality-keypair)
    local priv=$(echo "$keypair" | awk '/PrivateKey:/ {print $2}')
    local pub=$(echo "$keypair" | awk '/PublicKey:/ {print $2}')

    cat <<EOF > /etc/sing-box/config.json
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "vless",
      "tag": "Reality",
      "listen": "::",
      "listen_port": 443,
      "users": [{"uuid": "$uuid"}],
      "tls": { "enabled": true, "server_name": "www.apple.com", "reality": { "enabled": true, "handshake": { "server": "www.apple.com", "server_port": 443 }, "private_key": "$priv" } }
    }
  ],
  "outbounds": [{"type": "direct"}]
}
EOF

    # 启动
    /etc/sing-box/sing-box run -c /etc/sing-box/config.json &
    
    echo -e "\n--- 部署成功 ---"
    echo "Reality 链接:"
    local link="vless://$uuid@$(curl -s4 ip.sb):443?security=reality&pbk=$pub&sni=www.apple.com&fp=chrome&type=tcp#Gemini_2026"
    echo "$link"
    echo "$link" | qrencode -t UTF8
}

# 3. 立即运行
install_now

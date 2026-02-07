cat <<EOF > /root/clean.sh
#!/bin/bash

log() { echo -e "\033[32m[INFO]\033[0m \$1"; }

log "--- 開始深度清理系統空間 ---"

# 1. 清理 APT 緩存和不再需要的依賴
log "清理軟件包緩存..."
apt-get autoremove -y
apt-get autoclean -y
apt-get clean

# 2. 清理系統日誌 (保留最近 2 天)
log "壓縮並清理系統日誌 (journalctl)..."
journalctl --vacuum-time=2d

# 3. 清理 /var/log 下的舊日誌文件
log "清理 /var/log 下的壓縮舊日誌..."
find /var/log -type f -name "*.gz" -delete
find /var/log -type f -name "*.1" -delete

# 4. 清理 /tmp 臨時文件 (保留最近 24 小時)
log "清理臨時文件..."
find /tmp -type f -atime +1 -delete

# 5. 清理 Docker (如果存在)
if command -v docker &> /dev/null; then
    log "檢測到 Docker，清理未使用的鏡像與容器..."
    docker system prune -f
fi

# 顯示清理後的結果
echo -e "\n\033[36m--- 當前磁盤使用情況 ---\033[0m"
df -h | grep -E '^/dev/'

# 空間警告
usage=\$(df / | grep / | awk '{ print \$5 }' | sed 's/%//g')
if [ "\$usage" -gt 85 ]; then
    echo -e "\n\033[31m[警告] 磁盤佔用仍高於 85%，請手動檢查大文件 (ncdu /)！\033[0m"
fi
EOF

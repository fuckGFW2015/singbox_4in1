### 这个版本所有功能：

3合1：Reality + Hy2 + TUIC5。
| 功能 | 状态 | 说明 |
|------|------|------|
| 多协议支持 | ✅ | Reality (VLESS) + Hysteria2 + TUIC5 全集成 |
| Web 面板 | ✅ | 使用 Yacd Meta（gh-pages），兼容 sing-box 的 `external_ui` |
| 自动防火墙 | ✅ | 放行 443/TCP、8443/UDP、2053/UDP、9090/TCP |
| 安全配置 | ✅ | 启用 `ip_forward`、生成自签名证书、随机密钥 |
| 用户友好 | ✅ | 自动生成带二维码的节点链接，支持扫码导入 |
| 清理警告 | ✅ | `qrencode 2>/dev/null` 隐藏无害警告 |
| 自动卸载 | ✅ | 彻底清除服务、二进制、配置、iptables 规则 |


## 一键安装、卸载、自动清理命令
```
curl -fsSL https://raw.githubusercontent.com/fuckGFW2015/singbox_3in1/refs/heads/main/sing-box-2026-full.sh -o /tmp/install.sh && chmod +x /tmp/install.sh && sudo /tmp/install.sh

```


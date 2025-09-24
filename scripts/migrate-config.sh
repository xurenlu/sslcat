#!/bin/bash

# SSLcat 配置文件迁移脚本
# 将 withssl.conf 迁移到 sslcat.conf

set -e

echo "🔄 开始配置文件迁移..."

# 检查是否存在 withssl.conf
if [ -f "/etc/sslcat/withssl.conf" ]; then
    echo "📁 发现现有配置文件: /etc/sslcat/withssl.conf"
    
    # 备份原配置文件
    cp /etc/sslcat/withssl.conf /etc/sslcat/withssl.conf.backup.$(date +%Y%m%d_%H%M%S)
    echo "💾 已备份原配置文件"
    
    # 重命名为 sslcat.conf
    mv /etc/sslcat/withssl.conf /etc/sslcat/sslcat.conf
    echo "✅ 配置文件已重命名为: /etc/sslcat/sslcat.conf"
    
    # 更新文件权限
    chown withssl:withssl /etc/sslcat/sslcat.conf
    chmod 600 /etc/sslcat/sslcat.conf
    echo "🔐 已更新文件权限"
    
elif [ -f "/etc/sslcat/sslcat.conf" ]; then
    echo "✅ 配置文件已存在: /etc/sslcat/sslcat.conf"
    
else
    echo "❌ 未找到配置文件，请先运行安装脚本"
    exit 1
fi

# 检查 systemd 服务配置
if [ -f "/etc/systemd/system/withssl.service" ]; then
    echo "🔧 更新 systemd 服务配置..."
    
    # 备份原服务文件
    cp /etc/systemd/system/withssl.service /etc/systemd/system/withssl.service.backup.$(date +%Y%m%d_%H%M%S)
    
    # 更新服务文件中的配置文件路径
    sed -i 's|--config /etc/sslcat/withssl.conf|--config /etc/sslcat/sslcat.conf|g' /etc/systemd/system/withssl.service
    
    # 重新加载 systemd
    systemctl daemon-reload
    
    echo "✅ systemd 服务配置已更新"
fi

# 检查当前运行的进程
if pgrep -f "withssl" > /dev/null; then
    echo "🔄 重启服务以应用新配置..."
    systemctl restart withssl
    echo "✅ 服务已重启"
fi

echo "🎉 配置文件迁移完成！"
echo ""
echo "📋 迁移总结："
echo "  - 配置文件: /etc/sslcat/sslcat.conf"
echo "  - 备份文件: /etc/sslcat/withssl.conf.backup.*"
echo "  - 服务状态: systemctl status withssl"
echo "  - 查看日志: journalctl -u withssl -f"

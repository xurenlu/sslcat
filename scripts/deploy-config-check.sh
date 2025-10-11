#!/bin/bash

# 通用的部署配置文件检查函数
# 用于在部署前检查并处理远程配置文件

check_remote_config() {
    local TARGET_HOST="$1"
    local TARGET_USER="$2"
    local LOCAL_CONFIG="$3"
    local REMOTE_CONFIG="${4:-/etc/sslcat/sslcat.conf}"
    
    echo "🔍 检查远程配置文件..."
    REMOTE_CONF_EXISTS=$(ssh $TARGET_USER@$TARGET_HOST "test -f $REMOTE_CONFIG && echo 'yes' || echo 'no'")
    
    if [ "$REMOTE_CONF_EXISTS" = "yes" ]; then
        echo "📥 发现远程配置文件，拉取进行对比..."
        mkdir -p /tmp/sslcat-deploy-check
        scp $TARGET_USER@$TARGET_HOST:$REMOTE_CONFIG /tmp/sslcat-deploy-check/sslcat.conf.remote
        
        LOCAL_MD5=$(md5 -q "$LOCAL_CONFIG" 2>/dev/null || md5sum "$LOCAL_CONFIG" | awk '{print $1}')
        REMOTE_MD5=$(md5 -q /tmp/sslcat-deploy-check/sslcat.conf.remote 2>/dev/null || md5sum /tmp/sslcat-deploy-check/sslcat.conf.remote | awk '{print $1}')
        
        if [ "$LOCAL_MD5" != "$REMOTE_MD5" ]; then
            echo ""
            echo "⚠️  警告：本地配置与远程配置不一致！"
            echo "   本地配置: $LOCAL_CONFIG (MD5: $LOCAL_MD5)"
            echo "   远程配置: $REMOTE_CONFIG (MD5: $REMOTE_MD5)"
            echo ""
            echo "   远程配置已保存到: /tmp/sslcat-deploy-check/sslcat.conf.remote"
            echo ""
            echo "请选择操作："
            echo "  1) 使用本地配置覆盖远程（会备份远程配置）"
            echo "  2) 保持远程配置不变，仅更新二进制文件"
            echo "  3) 先查看差异后决定"
            echo "  4) 用远程配置覆盖本地，然后继续部署"
            echo "  5) 取消部署"
            echo ""
            read -p "请输入选项 [1-5]: " choice
            
            case $choice in
                1)
                    echo "✅ 将使用本地配置覆盖远程"
                    rm -rf /tmp/sslcat-deploy-check
                    return 0
                    ;;
                2)
                    echo "⚠️  将保持远程配置，仅更新二进制"
                    # 用远程配置替换本地配置，这样部署时就不会覆盖
                    cp /tmp/sslcat-deploy-check/sslcat.conf.remote "$LOCAL_CONFIG"
                    rm -rf /tmp/sslcat-deploy-check
                    return 0
                    ;;
                3)
                    echo ""
                    echo "========== 配置文件差异 =========="
                    diff -u /tmp/sslcat-deploy-check/sslcat.conf.remote "$LOCAL_CONFIG" || true
                    echo "================================="
                    echo ""
                    read -p "查看差异后，是否继续部署？(使用本地配置) [y/N]: " continue_choice
                    if [[ ! "$continue_choice" =~ ^[Yy]$ ]]; then
                        echo "❌ 部署已取消"
                        rm -rf /tmp/sslcat-deploy-check
                        exit 0
                    fi
                    rm -rf /tmp/sslcat-deploy-check
                    return 0
                    ;;
                4)
                    echo "📥 使用远程配置覆盖本地..."
                    cp /tmp/sslcat-deploy-check/sslcat.conf.remote "$LOCAL_CONFIG"
                    echo "✅ 已更新本地配置文件"
                    rm -rf /tmp/sslcat-deploy-check
                    return 0
                    ;;
                5|*)
                    echo "❌ 部署已取消"
                    rm -rf /tmp/sslcat-deploy-check
                    exit 0
                    ;;
            esac
        else
            echo "✅ 本地配置与远程配置一致"
            rm -rf /tmp/sslcat-deploy-check
        fi
    else
        echo "📝 远程配置文件不存在，将使用本地配置"
    fi
    
    return 0
}


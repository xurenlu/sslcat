#!/bin/bash

# SSLcat 内存监控脚本
# 当内存使用过高时自动重启服务

LOG_FILE="/var/log/sslcat-monitor.log"
MAX_MEMORY_MB=1024  # 最大内存使用 1GB
CHECK_INTERVAL=30   # 检查间隔 30 秒

log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

check_sslcat_memory() {
    # 获取 sslcat 进程信息
    SSL_PID=$(pgrep sslcat)
    
    if [ -z "$SSL_PID" ]; then
        log_message "WARNING: SSLcat process not found"
        return 1
    fi
    
    # 获取内存使用（KB）
    MEMORY_KB=$(ps -p $SSL_PID -o rss --no-headers 2>/dev/null)
    
    if [ -z "$MEMORY_KB" ]; then
        log_message "WARNING: Cannot get memory info for PID $SSL_PID"
        return 1
    fi
    
    # 转换为 MB
    MEMORY_MB=$((MEMORY_KB / 1024))
    
    # 获取 CPU 使用率
    CPU_USAGE=$(ps -p $SSL_PID -o %cpu --no-headers 2>/dev/null)
    
    log_message "SSLcat PID: $SSL_PID, Memory: ${MEMORY_MB}MB, CPU: ${CPU_USAGE}%"
    
    # 检查内存使用是否过高
    if [ "$MEMORY_MB" -gt "$MAX_MEMORY_MB" ]; then
        log_message "CRITICAL: Memory usage too high (${MEMORY_MB}MB > ${MAX_MEMORY_MB}MB)"
        return 0  # 需要重启
    fi
    
    return 1  # 不需要重启
}

restart_sslcat() {
    log_message "Restarting SSLcat service..."
    
    # 停止服务
    systemctl stop sslcat
    sleep 5
    
    # 确保进程完全退出
    SSL_PID=$(pgrep sslcat)
    if [ -n "$SSL_PID" ]; then
        log_message "Force killing SSLcat process $SSL_PID"
        kill -9 $SSL_PID
        sleep 2
    fi
    
    # 启动服务
    systemctl start sslcat
    sleep 10
    
    # 检查服务状态
    if systemctl is-active --quiet sslcat; then
        log_message "SSLcat service restarted successfully"
    else
        log_message "ERROR: Failed to restart SSLcat service"
        systemctl status sslcat >> "$LOG_FILE" 2>&1
    fi
}

# 主循环
log_message "Starting SSLcat memory monitor (max: ${MAX_MEMORY_MB}MB, interval: ${CHECK_INTERVAL}s)"

while true; do
    if check_sslcat_memory; then
        restart_sslcat
        # 重启后等待更长时间再检查
        sleep 60
    else
        sleep $CHECK_INTERVAL
    fi
done

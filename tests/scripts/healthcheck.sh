#!/bin/sh
# Docker 容器健康检查脚本

# 检查 SSLcat 是否响应
curl -f http://localhost:8080/sslcat-panel/ > /dev/null 2>&1
exit $?


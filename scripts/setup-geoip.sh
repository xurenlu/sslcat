#!/bin/bash

# GeoIP数据库设置脚本
# 用于检查和设置MaxMind GeoLite2数据库

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置
GEOIP_DIR="./data/geoip"
CITY_DB="GeoLite2-City.mmdb"
ASN_DB="GeoLite2-ASN.mmdb"
CITY_DB_PATH="${GEOIP_DIR}/${CITY_DB}"
ASN_DB_PATH="${GEOIP_DIR}/${ASN_DB}"

# 打印带颜色的消息
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查文件是否存在
check_file() {
    local file_path="$1"
    local file_name="$2"
    
    if [ -f "$file_path" ]; then
        local file_size=$(du -h "$file_path" | cut -f1)
        print_success "$file_name 存在 (大小: $file_size)"
        return 0
    else
        print_warning "$file_name 不存在: $file_path"
        return 1
    fi
}

# 创建目录
create_directory() {
    if [ ! -d "$GEOIP_DIR" ]; then
        print_info "创建GeoIP数据库目录: $GEOIP_DIR"
        mkdir -p "$GEOIP_DIR"
        print_success "目录创建成功"
    else
        print_info "GeoIP数据库目录已存在: $GEOIP_DIR"
    fi
}

# 显示配置示例
show_config_example() {
    cat << EOF

📋 配置文件示例 (sslcat.conf 或 config.json):

{
  "security": {
    "geo_blocking": {
      "enabled": true,
      "database_path": "./data/geoip/GeoLite2-City.mmdb",
      "update_interval": 168,
      "allow_unknown": false,
      "allowed_countries": ["CN", "US", "JP", "KR", "SG"],
      "blocked_countries": ["RU", "KP"]
    }
  }
}

EOF
}

# 显示下载信息
show_download_info() {
    cat << EOF

📥 如何获取MaxMind GeoLite2数据库:

1. 访问 MaxMind 官网: https://www.maxmind.com/
2. 注册免费账户
3. 下载 GeoLite2 数据库:
   - GeoLite2-City.mmdb (必需)
   - GeoLite2-ASN.mmdb (可选)

4. 将文件复制到: $GEOIP_DIR/

或者使用命令行下载 (需要账户):
wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz"

EOF
}

# 验证数据库文件
validate_database() {
    local db_path="$1"
    local db_name="$2"
    
    if [ ! -f "$db_path" ]; then
        print_error "$db_name 文件不存在"
        return 1
    fi
    
    # 检查文件是否为有效的MMDB格式
    if file "$db_path" | grep -q "data"; then
        print_success "$db_name 文件格式验证通过"
        return 0
    else
        print_error "$db_name 文件格式可能有问题"
        return 1
    fi
}

# 生成测试配置
generate_test_config() {
    local config_file="config-geoip-test.json"
    
    cat > "$config_file" << EOF
{
  "server": {
    "port": 8443,
    "host": "0.0.0.0"
  },
  "security": {
    "geo_blocking": {
      "enabled": true,
      "database_path": "./data/geoip/GeoLite2-City.mmdb",
      "update_interval": 168,
      "allow_unknown": true,
      "allowed_countries": [],
      "blocked_countries": []
    },
    "enable_waf": false,
    "enable_ddos": false
  },
  "logging": {
    "level": "info"
  }
}
EOF
    
    print_success "生成测试配置文件: $config_file"
}

# 主函数
main() {
    echo "🌍 SSLcat GeoIP 数据库设置工具"
    echo "================================="
    echo
    
    # 创建目录
    create_directory
    echo
    
    # 检查数据库文件
    print_info "检查GeoIP数据库文件..."
    
    city_exists=0
    asn_exists=0
    
    if check_file "$CITY_DB_PATH" "$CITY_DB"; then
        city_exists=1
        validate_database "$CITY_DB_PATH" "$CITY_DB"
    fi
    
    echo
    
    if check_file "$ASN_DB_PATH" "$ASN_DB"; then
        asn_exists=1
        validate_database "$ASN_DB_PATH" "$ASN_DB"
    fi
    
    echo
    
    # 状态总结
    print_info "状态总结:"
    if [ $city_exists -eq 1 ]; then
        print_success "✅ 城市数据库已就绪 - 地理位置过滤功能可用"
    else
        print_warning "❌ 城市数据库缺失 - 地理位置过滤功能将被禁用"
    fi
    
    if [ $asn_exists -eq 1 ]; then
        print_success "✅ ASN数据库已就绪 - ISP信息可用"
    else
        print_warning "⚠️  ASN数据库缺失 - ISP信息不可用 (可选)"
    fi
    
    echo
    
    # 如果城市数据库不存在，显示下载信息
    if [ $city_exists -eq 0 ]; then
        show_download_info
    fi
    
    # 显示配置示例
    show_config_example
    
    # 生成测试配置
    if [ $city_exists -eq 1 ]; then
        generate_test_config
        echo
        print_info "可以使用以下命令测试GeoIP功能:"
        echo "  ./sslcat -config=config-geoip-test.json"
    fi
    
    echo
    print_info "设置完成！"
}

# 运行主函数
main "$@"

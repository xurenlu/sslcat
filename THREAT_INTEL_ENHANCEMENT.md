# 威胁情报系统增强

## 概述

大幅增强了SSLcat的威胁情报系统，添加了10个免费威胁情报源，并实现了SQLite数据库持久化存储，提供更全面、更可靠的安全防护能力。

## 🆕 新增功能

### 📊 **10个免费威胁情报源**

#### **垃圾邮件和网络滥用**
- **Spamhaus DROP** - 垃圾邮件IP列表
- **Spamhaus EDROP** - 扩展垃圾邮件IP列表
- **Blocklist.de** - 德国威胁情报，包含各种恶意IP

#### **钓鱼网站检测**
- **OpenPhish** - 实时钓鱼网站列表
- **PhishTank** - 社区驱动的钓鱼网站数据库

#### **恶意软件和僵尸网络**
- **Malware Bazaar** - 恶意软件哈希数据库
- **URLhaus** - 恶意URL和域名列表
- **Feodo Tracker** - 僵尸网络IP追踪

#### **网络威胁情报**
- **DShield** - SANS威胁情报源
- **Tor Exit Nodes** - Tor出口节点列表

### 🗄️ **SQLite数据库存储**

#### **数据持久化**
- **IOC存储** - 威胁指标持久化存储
- **源管理** - 威胁情报源配置管理
- **更新日志** - 详细的更新记录
- **自动清理** - 30天数据过期清理

#### **数据库结构**
```sql
-- IOC表
CREATE TABLE iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT NOT NULL,
    type TEXT NOT NULL,
    threat_level INTEGER NOT NULL,
    source TEXT NOT NULL,
    description TEXT,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    tags TEXT,
    confidence REAL NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(value, type)
);

-- 威胁情报源表
CREATE TABLE threat_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    api_key TEXT,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    update_freq INTEGER NOT NULL,
    last_update DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 更新日志表
CREATE TABLE update_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name TEXT NOT NULL,
    status TEXT NOT NULL,
    message TEXT,
    iocs_added INTEGER DEFAULT 0,
    iocs_updated INTEGER DEFAULT 0,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## 🔧 **技术实现**

### **更新机制**
```go
// 每30分钟检查一次更新
ticker := time.NewTicker(30 * time.Minute)

// 各数据源独立更新频率
- OpenPhish: 1小时
- DShield: 1小时  
- Tor Exit Nodes: 1小时
- URLhaus: 1小时
- PhishTank: 2小时
- Malware Bazaar: 2小时
- Emerging Threats: 4小时
- Feodo Tracker: 4小时
- Blocklist.de: 4小时
- Spamhaus DROP/EDROP: 6小时
- Malware Domains: 6小时
```

### **存储策略**
- **内存缓存** - 快速查询，减少数据库访问
- **数据库持久化** - 重启后数据不丢失
- **自动同步** - 内存和数据库自动同步
- **智能清理** - 自动清理过期数据

### **错误处理**
- **网络超时** - 30秒请求超时
- **重试机制** - 失败后自动重试
- **日志记录** - 详细的错误日志
- **优雅降级** - 部分源失败不影响整体功能

## 📈 **性能优化**

### **查询优化**
- **内存优先** - 首先检查内存缓存
- **数据库回退** - 内存未命中时查询数据库
- **索引优化** - 数据库表建立合适索引
- **批量操作** - 减少数据库访问次数

### **存储优化**
- **数据压缩** - JSON格式存储tags
- **定期清理** - 自动清理30天前的数据
- **日志轮转** - 防止日志文件过大
- **连接池** - 数据库连接复用

## 🚀 **使用方法**

### **1. 启动服务**
```bash
# 重启SSLcat服务
sudo systemctl restart sslcat
# 或者
./sslcat restart
```

### **2. 验证功能**
```bash
# 运行测试脚本
./test-threat-intel.sh

# 查看数据库文件
ls -lh ./data/threat_intel.db

# 查看威胁情报日志
tail -f ./data/threat_intel.log
```

### **3. 监控数据**
```bash
# 查看IOC总数
sqlite3 ./data/threat_intel.db 'SELECT COUNT(*) FROM iocs;'

# 查看按类型统计
sqlite3 ./data/threat_intel.db 'SELECT type, COUNT(*) FROM iocs GROUP BY type;'

# 查看按威胁级别统计
sqlite3 ./data/threat_intel.db 'SELECT threat_level, COUNT(*) FROM iocs GROUP BY threat_level;'

# 查看更新日志
sqlite3 ./data/threat_intel.db 'SELECT * FROM update_logs ORDER BY updated_at DESC LIMIT 10;'
```

## 📊 **数据源详情**

| 数据源 | 类型 | 更新频率 | 数据量 | 威胁级别 |
|--------|------|----------|--------|----------|
| Spamhaus DROP | IP列表 | 6小时 | ~1000 | High |
| Spamhaus EDROP | IP列表 | 6小时 | ~500 | Medium |
| OpenPhish | URL列表 | 1小时 | ~5000 | High |
| PhishTank | URL列表 | 2小时 | ~3000 | High |
| Blocklist.de | IP列表 | 4小时 | ~2000 | Medium |
| DShield | 威胁情报 | 1小时 | ~1000 | High |
| Tor Exit Nodes | IP列表 | 1小时 | ~1000 | Medium |
| Malware Bazaar | 哈希列表 | 2小时 | ~10000 | Critical |
| URLhaus | URL列表 | 1小时 | ~8000 | High |
| Feodo Tracker | IP列表 | 4小时 | ~500 | Critical |

## 🔍 **监控和维护**

### **日志监控**
```bash
# 实时监控威胁情报更新
tail -f ./data/threat_intel.log | grep "Updated"

# 监控错误日志
tail -f ./data/threat_intel.log | grep "ERROR"

# 查看统计信息
tail -f ./data/threat_intel.log | grep "stats"
```

### **数据库维护**
```bash
# 查看数据库大小
du -h ./data/threat_intel.db

# 优化数据库
sqlite3 ./data/threat_intel.db 'VACUUM;'

# 重建索引
sqlite3 ./data/threat_intel.db 'REINDEX;'
```

### **性能监控**
```bash
# 查看内存使用
ps aux | grep sslcat

# 查看数据库连接
lsof | grep threat_intel.db

# 监控网络请求
netstat -an | grep :443
```

## 🎯 **预期效果**

### **安全防护提升**
- ✅ **覆盖范围扩大** - 10个数据源提供全面威胁情报
- ✅ **检测精度提高** - 多源验证减少误报
- ✅ **响应速度提升** - 内存缓存加速查询
- ✅ **数据持久化** - 重启后威胁情报不丢失

### **运维便利性**
- ✅ **自动化更新** - 无需手动维护数据源
- ✅ **详细日志** - 完整的更新和错误记录
- ✅ **统计报告** - 丰富的威胁统计信息
- ✅ **自动清理** - 防止数据积累过多

### **性能优化**
- ✅ **查询加速** - 内存+数据库双层缓存
- ✅ **存储优化** - 自动清理过期数据
- ✅ **网络优化** - 智能更新频率控制
- ✅ **资源节约** - 高效的存储和查询机制

## 🔧 **故障排除**

### **常见问题**

#### **数据库连接失败**
```bash
# 检查数据库文件权限
ls -la ./data/threat_intel.db

# 检查目录权限
ls -la ./data/

# 重新创建数据库
rm ./data/threat_intel.db
# 重启服务
```

#### **数据源更新失败**
```bash
# 检查网络连接
curl -I https://www.spamhaus.org/drop/drop.txt

# 检查DNS解析
nslookup www.spamhaus.org

# 查看详细错误日志
grep "Failed to fetch" ./data/threat_intel.log
```

#### **内存使用过高**
```bash
# 检查IOC数量
sqlite3 ./data/threat_intel.db 'SELECT COUNT(*) FROM iocs;'

# 清理过期数据
sqlite3 ./data/threat_intel.db 'DELETE FROM iocs WHERE last_seen < datetime("now", "-30 days");'

# 优化数据库
sqlite3 ./data/threat_intel.db 'VACUUM;'
```

## 📝 **总结**

这次威胁情报系统增强显著提升了SSLcat的安全防护能力：

1. **数据源丰富** - 10个免费威胁情报源提供全面覆盖
2. **存储可靠** - SQLite数据库确保数据持久化
3. **性能优化** - 内存缓存+数据库双层存储
4. **自动化管理** - 自动更新、清理、监控
5. **运维友好** - 详细日志、统计报告、故障排除

系统现在具备了企业级威胁情报能力，为SSLcat提供了更强大的安全防护基础。

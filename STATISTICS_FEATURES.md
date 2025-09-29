# SSLcat 访问统计功能说明

## 功能概述

SSLcat 新增了强大的访问统计功能，提供多维度的访问数据分析，并采用创新的"漏斗模型"算法来优化高频访问统计，避免对服务器性能造成压力。

## 主要特性

### 📊 多时间维度统计
- **按小时统计**：适合高流量网站的实时监控
- **按天统计**：日常运营数据分析
- **按月统计**：长期趋势分析

### 📈 核心指标
- **总请求数**：当前时间维度内的总访问量
- **非20x请求数**：错误请求统计（4xx、5xx状态码）
- **请求成功率**：实时计算的成功率百分比
- **独立访客数**：唯一IP访问者数量

### 🏆 高频访问排行榜
- **高访问IP Top N**：基于漏斗模型的IP访问排行
- **高访问User-Agent Top N**：浏览器/客户端使用排行
- **高访问城市Top N**：地理位置访问分布（需启用GeoIP）

### 🎯 漏斗模型算法

#### 什么是漏斗模型？
传统的访问统计直接统计所有访问记录，在高流量环境下会产生大量计算负载。漏斗模型通过多级过滤，只保留真正有意义的高频访问者。

#### 过滤机制
1. **最小访问次数过滤**
   - IP地址：最少5次访问
   - User-Agent：最少3次访问  
   - 城市：最少10次访问

2. **时间跨度过滤**
   - IP地址：10分钟时间跨度
   - User-Agent：5分钟时间跨度
   - 城市：30分钟时间跨度

3. **加权评分算法**
   - 访问频次权重
   - 时间跨度权重（持续访问者获得更高权重）
   - 时间衰减权重（近期访问权重更高）

4. **数量限制**
   - IP排行榜：最多100条
   - User-Agent排行榜：最多50条
   - 城市排行榜：最多20条

#### 优势
- **性能优化**：避免统计偶发的大量访问
- **数据质量**：过滤掉无意义的短期访问
- **服务器友好**：降低计算资源消耗
- **真实反映**：展示真正的高频用户

## 功能模块

### 后端架构

#### 1. 漏斗模型核心 (`internal/statistics/funnel.go`)
```go
type FunnelModel struct {
    minOccurrences int           // 最小出现次数阈值
    minTimeSpan    time.Duration // 最小时间跨度
    maxEntries     int           // 最大保留条目数
    decayFactor    float64       // 衰减因子
}
```

#### 2. 统计收集器 (`internal/statistics/collector.go`)
- 实时访问数据收集
- 多时间维度数据聚合
- 漏斗模型应用
- 数据持久化

#### 3. 统计API (`internal/web/statistics.go`)
- RESTful API接口
- 配置管理
- 数据查询
- 中间件集成

### 前端界面

#### 1. 统计页面 (`frontend/src/pages/Statistics.tsx`)
- 响应式仪表板设计
- 实时数据刷新
- 交互式控制面板
- 多维度数据展示

#### 2. 功能组件
- 时间维度切换器
- 域名过滤器
- 配置管理菜单
- 排行榜表格

## API 接口

### 1. 获取统计数据
```
GET /admin/api/statistics
```

参数：
- `dimension`: 时间维度 (hour/day/month)
- `time_key`: 时间键 (可选)
- `domain`: 域名过滤 (可选)
- `top_n`: Top N数量 (可选，默认20)

### 2. 获取配置
```
GET /admin/api/statistics/config
```

### 3. 更新配置
```
POST /admin/api/statistics/config
```

参数：
- `enabled`: 是否启用统计
- `top_n`: Top N数量
- `geoip_enabled`: 是否启用地理位置

### 4. 获取时间键列表
```
GET /admin/api/statistics/time-keys?dimension=hour
```

## 配置选项

### 漏斗模型参数
```go
// IP漏斗：至少5次访问，10分钟时间跨度，最多100条
ipFunnel := NewFunnelModel(5, 10*time.Minute, 100)

// User-Agent漏斗：至少3次访问，5分钟时间跨度，最多50条  
uaFunnel := NewFunnelModel(3, 5*time.Minute, 50)

// 城市漏斗：至少10次访问，30分钟时间跨度，最多20条
cityFunnel := NewFunnelModel(10, 30*time.Minute, 20)
```

### 数据保留策略
- **小时数据**：保留7天
- **日数据**：保留30天
- **月数据**：保留1年

### 清理任务
- **运行频率**：每小时执行一次
- **数据清理**：自动清理过期的统计数据
- **内存优化**：清理漏斗条目缓存

## 使用指南

### 1. 启用统计功能
统计功能默认启用，可通过配置API控制：

```bash
# 启用统计
curl -X POST /admin/api/statistics/config \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'

# 禁用统计  
curl -X POST /admin/api/statistics/config \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'
```

### 2. 启用地理位置功能
```bash
curl -X POST /admin/api/statistics/config \
  -H "Content-Type: application/json" \
  -d '{"geoip_enabled": true}'
```

### 3. 访问统计页面
访问 `http://your-domain/admin/statistics` 查看统计仪表板

### 4. 数据查询示例
```bash
# 获取当前小时统计
curl "/admin/api/statistics?dimension=hour&top_n=10"

# 获取指定天的统计  
curl "/admin/api/statistics?dimension=day&time_key=2024-01-15&domain=example.com"

# 获取月度汇总
curl "/admin/api/statistics?dimension=month&time_key=2024-01"
```

## 性能说明

### 内存使用
- **漏斗条目缓存**：每个条目约100字节
- **域名统计缓存**：按时间维度分段存储
- **总内存占用**：通常小于10MB（中等流量网站）

### CPU开销
- **实时统计**：每个请求增加约0.1ms处理时间
- **漏斗计算**：后台异步处理，不影响请求响应
- **数据清理**：每小时执行，CPU占用极低

### 存储需求
- **统计数据文件**：JSON格式存储在 `./data/statistics/`
- **平均大小**：每小时约1KB，每天约24KB
- **自动清理**：过期数据自动删除

## 监控和调试

### 日志输出
统计模块会输出详细的日志信息：
```
INFO[0001] 统计收集器已启动 component=statistics_collector
DEBUG[0002] 完成数据清理 component=statistics_collector  
INFO[0003] 统计API路由已注册 component=statistics_api
```

### 健康检查
通过配置API查看统计服务状态：
```json
{
  "enabled": true,
  "top_n": 20,
  "geoip_enabled": false,
  "ip_entries": 1250,
  "ua_entries": 456,
  "city_entries": 89,
  "domain_count": 5
}
```

## 测试功能

项目包含测试脚本 `test-statistics.sh`：

```bash
# 运行测试
./test-statistics.sh
```

测试脚本会：
1. 检查服务状态
2. 模拟50个不同的访问请求
3. 测试所有统计API接口
4. 显示测试结果

## 故障排除

### 常见问题

1. **统计数据为空**
   - 检查统计功能是否启用
   - 确认有足够的访问量满足漏斗条件
   - 查看日志确认数据收集正常

2. **高频排行榜为空**
   - 漏斗模型需要一定时间和访问量
   - 降低漏斗阈值进行测试
   - 检查时间跨度设置

3. **地理位置数据缺失**
   - 确认GeoIP功能已启用
   - 检查GeoIP数据库是否可用
   - 验证IP解析功能

4. **性能问题**
   - 调整漏斗参数降低计算量
   - 增加数据清理频率
   - 减少保留的历史数据量

### 调试命令
```bash
# 查看统计配置
curl -s localhost:8080/admin/api/statistics/config | jq

# 检查当前统计数据
curl -s "localhost:8080/admin/api/statistics?dimension=hour" | jq

# 查看时间键
curl -s "localhost:8080/admin/api/statistics/time-keys?dimension=hour" | jq
```

## 后续扩展

### 计划功能
1. **图表可视化**：集成Chart.js展示趋势图
2. **告警系统**：异常访问模式告警  
3. **导出功能**：CSV/Excel数据导出
4. **API速率限制**：基于统计数据的智能限流
5. **机器学习**：异常检测和预测分析

### 自定义扩展
统计系统提供了良好的扩展接口：
- 自定义漏斗算法
- 新增统计维度
- 第三方数据源集成
- 自定义报告生成

---

*该功能完全整合到SSLcat现有架构中，无需额外依赖，即插即用。*

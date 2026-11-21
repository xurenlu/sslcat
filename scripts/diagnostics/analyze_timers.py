#!/usr/bin/env python3
"""
分析 SSLcat 所有定时器的间隔，计算它们同时执行的时间点
"""

import math
from datetime import datetime, timedelta

# 从代码中找到的所有固定间隔（秒）
timers = {
    # 最短间隔
    "实时日志检查": 1,
    "配置文件监听": 5,
    
    # 中等间隔
    "会话清理": 600,  # 10分钟
    "代理认证清理": 300,  # 5分钟
    "验证码清理": 300,  # 5分钟
    "SSLDNS验证-Cloudflare": 3,
    "SSLDNS验证-Aliyun": 5,
    "SSLDNS验证-Tencent": 5,
    "SSLDNS验证-GoDaddy": 10,
    "SSLDNS验证-Namecheap": 15,
    
    # 较长间隔
    "内存监控": 60,  # 1分钟
    "Goroutine监控": 60,  # 1分钟
    "性能监控": 30,  # 30秒
    "健康检查": 60,  # 60秒
    "负载均衡健康检查": 60,  # 60秒
    "LE域名刷新": 30,  # 30秒
    "ACME证书同步": 300,  # 5分钟
    "安全限流器清理": 300,  # 5分钟
    "内存缓存清理": 300,  # 5分钟
    "CDN缓存清理": 60,  # 60秒
    "威胁情报更新": 1800,  # 30分钟
    "威胁情报清理": 3600,  # 1小时
    "上游缓存清理": 3600,  # 1小时
    "Docker镜像清理-2小时": 7200,  # 2小时
    "Git清理-2小时": 7200,  # 2小时
    "证书到期提醒": 43200,  # 12小时
    "证书自动续期": 86400,  # 24小时
    "威胁情报每天清理": 86400,  # 24小时
    "WebSocket监控": 30,  # 30秒
    "实时日志心跳": 30,  # 30秒
}

print("=" * 80)
print("SSLcat 定时器分析")
print("=" * 80)
print(f"\n总定时器数量: {len(timers)}")
print("\n定时器列表（按间隔排序）:")
print("-" * 80)

# 按间隔排序
sorted_timers = sorted(timers.items(), key=lambda x: x[1])

for name, interval in sorted_timers:
    print(f"{name:30s} = {interval:6d}秒 ({interval//60:3d}分钟)")

print("\n" + "=" * 80)
print("关键问题：定时器叠加执行点")
print("=" * 80)

# 找出最有可能叠加的定时器
critical_intervals = [60, 300, 600, 1800, 3600, 7200, 43200, 86400]
print("\n最危险的叠加时间点：")
print("-" * 80)

# 60秒的倍数（每分钟）
print("\n1️⃣  每分钟触发（00秒）:")
for name, interval in sorted_timers:
    if interval == 60:
        print(f"   ✓ {name}")

# 300秒的倍数（每5分钟）
print("\n2️⃣  每5分钟触发（:00, :05, :10, :15, :20, :25, :30, :35, :40, :45, :50, :55）:")
for name, interval in sorted_timers:
    if interval == 300:
        print(f"   ✓ {name}")

# 600秒的倍数（每10分钟）
print("\n3️⃣  每10分钟触发（:00, :10, :20, :30, :40, :50）:")
for name, interval in sorted_timers:
    if interval == 600:
        print(f"   ✓ {name}")

# 3600秒的倍数（每小时）
print("\n4️⃣  每小时触发（:00分）:")
for name, interval in sorted_timers:
    if interval == 3600:
        print(f"   ✓ {name}")

# 7200秒的倍数（每2小时）
print("\n5️⃣  每2小时触发（:00分，偶数小时）:")
for name, interval in sorted_timers:
    if interval == 7200:
        print(f"   ✓ {name}")

# 43200秒的倍数（每12小时）
print("\n6️⃣  每12小时触发（00:00, 12:00）:")
for name, interval in sorted_timers:
    if interval == 43200:
        print(f"   ✓ {name}")

# 86400秒的倍数（每天）
print("\n7️⃣  每天触发（00:00）:")
for name, interval in sorted_timers:
    if interval == 86400:
        print(f"   ✓ {name}")

print("\n" + "=" * 80)
print("⚠️  最危险的叠加时间点")
print("=" * 80)

print("\n假设从 00:00:00 开始计时，同时触发的时间点：")
print("-" * 80)

# 计算 LCM（最小公倍数）
def lcm(numbers):
    """计算多个数字的最小公倍数"""
    result = numbers[0]
    for num in numbers[1:]:
        result = result * num // math.gcd(result, num)
    return result

# 找出所有主要的间隔值
intervals = list(set(timers.values()))
intervals.sort()

print("\n所有唯一间隔值:")
for i in intervals:
    count = sum(1 for v in timers.values() if v == i)
    print(f"  {i:6d}秒 ({i//60:3d}分钟) - {count}个定时器")

# 找出关键叠加点
print("\n🔴 最危险的时间点分析：")
print("-" * 80)

# 每小时整点
print("\n每小时整点（如 04:00, 05:00）同时触发的任务：")
hourly_tasks = [name for name, interval in timers.items() if interval in [3600, 7200, 43200, 86400]]
if hourly_tasks:
    for task in hourly_tasks:
        print(f"  ✓ {task}")
else:
    print("  (无每小时任务)")

# 每5分钟
print("\n每5分钟（如 :00, :05, :10, :15, :20, :25, :30, :35, :40, :45, :50, :55）同时触发的任务：")
five_min_tasks = [name for name, interval in timers.items() if interval == 300]
if five_min_tasks:
    for task in five_min_tasks:
        print(f"  ✓ {task}")
else:
    print("  (无每5分钟任务)")

# 每分钟
print("\n每分钟（:00秒）同时触发的任务：")
minute_tasks = [name for name, interval in timers.items() if interval == 60]
if minute_tasks:
    for task in minute_tasks:
        print(f"  ✓ {task}")
else:
    print("  (无每分钟任务)")

print("\n" + "=" * 80)
print("🎯 结论")
print("=" * 80)
print("""
最危险的叠加场景：

1. **每小时整点（如 04:00）**:
   - 威胁情报清理 (1小时)
   - 上游缓存清理 (1小时)
   - 可能还有其他每小时任务

2. **每5分钟（如 04:00, 04:05, 04:10...）**:
   - ACME证书同步 (5分钟)
   - 安全限流器清理 (5分钟)
   - 内存缓存清理 (5分钟)

3. **每小时整点 + 每5分钟 = 最危险！**
   例如 04:00, 04:05, 04:10, 04:15, 04:20...

4. **为什么是 4:18？**
   - 不是特定定时器在 4:18 触发
   - 而是前面的定时器（4:00, 4:05, 4:10, 4:15）累积的内存还未完全释放
   - 4:18 左右内存监控检测到异常

解决方案：
✓ 已设置 GOMEMLIMIT=1536MiB 限制内存上限
✓ 内存监控脚本会自动检测并重启
""")


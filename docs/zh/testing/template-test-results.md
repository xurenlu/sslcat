# 模板测试结果报告

本文档记录 SSLcat 模板库的自动化测试结果。

## 测试概览

- **测试日期**: {{TEST_DATE}}
- **测试服务器**: sg2.shifen.de
- **测试总数**: {{TOTAL_COUNT}}
- **通过数量**: {{PASSED_COUNT}}
- **失败数量**: {{FAILED_COUNT}}
- **跳过数量**: {{SKIPPED_COUNT}}
- **成功率**: {{SUCCESS_RATE}}%

## 按优先级统计

| 优先级 | 总数 | 通过 | 失败 | 跳过 | 成功率 |
|--------|------|------|------|------|--------|
| 高优先级 | {{HIGH_TOTAL}} | {{HIGH_PASSED}} | {{HIGH_FAILED}} | {{HIGH_SKIPPED}} | {{HIGH_RATE}}% |
| 中优先级 | {{MEDIUM_TOTAL}} | {{MEDIUM_PASSED}} | {{MEDIUM_FAILED}} | {{MEDIUM_SKIPPED}} | {{MEDIUM_RATE}}% |
| 低优先级 | {{LOW_TOTAL}} | {{LOW_PASSED}} | {{LOW_FAILED}} | {{LOW_SKIPPED}} | {{LOW_RATE}}% |

## 按分类统计

| 分类 | 总数 | 通过 | 失败 | 跳过 | 成功率 |
|------|------|------|------|------|--------|
| {{CATEGORY_STATS}} |

## 测试通过的模板

### 高优先级模板
{{HIGH_PRIORITY_PASSED_LIST}}

### 中优先级模板
{{MEDIUM_PRIORITY_PASSED_LIST}}

### 低优先级模板
{{LOW_PRIORITY_PASSED_LIST}}

## 测试失败的模板

### 镜像不存在
{{MISSING_IMAGES_LIST}}

### 启动失败
{{STARTUP_FAILED_LIST}}

### 其他错误
{{OTHER_ERRORS_LIST}}

## 详细测试结果

详细的测试结果请查看 JSON 文件：`test-results.json`

### JSON 文件结构

```json
{
  "summary": {
    "total": 365,
    "passed": 300,
    "failed": 50,
    "skipped": 15,
    "duration": "2h30m"
  },
  "results": [
    {
      "template_id": "gitlab",
      "template_name": "GitLab",
      "category": "devops",
      "priority": "high",
      "status": "passed",
      "stages": {
        "load": { "status": "passed", "duration": "100ms" },
        "image_check": { "status": "passed", "duration": "2s" },
        "container_start": { "status": "passed", "duration": "30s" },
        "port_check": { "status": "passed", "duration": "1s" }
      },
      "errors": [],
      "warnings": [],
      "image_names": ["gitlab/gitlab-ce:latest"],
      "start_time": "2024-01-01T10:00:00Z",
      "end_time": "2024-01-01T10:00:35Z",
      "duration": "35s"
    }
  ]
}
```

## 问题分析

### 常见问题

1. **镜像不存在**
   - 原因：Docker Hub 上不存在指定的镜像
   - 解决：更新模板中的镜像名称或使用替代镜像

2. **启动超时**
   - 原因：容器启动时间超过设定的超时时间
   - 解决：增加超时时间或优化容器启动配置

3. **端口冲突**
   - 原因：测试端口被占用
   - 解决：调整 base-port 参数或清理占用端口的进程

4. **资源不足**
   - 原因：服务器内存或磁盘空间不足
   - 解决：增加服务器资源或减少并发数

## 更新记录

- {{UPDATE_DATE}}: 初始测试报告

## 使用方法

### 查看测试结果

```bash
# 查看 JSON 结果
cat test-results.json | jq '.summary'

# 查看失败的模板
cat test-results.json | jq '.results[] | select(.status == "failed")'

# 查看镜像不存在的模板
cat test-results.json | jq '.results[] | select(.status == "skipped") | select(.errors[] | contains("镜像不存在"))'
```

### 重新测试失败的模板

```bash
# 测试单个模板
./tools/test-templates/test-templates --template gitlab

# 测试特定优先级的模板
./tools/test-templates/test-templates --priority high
```


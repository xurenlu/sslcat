# 模板市场 - 企业工具分类

本文档详细介绍 SSLcat 模板市场中企业工具分类的所有模板，包括功能说明、Docker 镜像信息和测试状态。

## 测试状态说明

- ✅ **已测试通过**: 模板已完成自动化测试，可以稳定使用
- ⏳ **未测试**: 模板尚未完成测试，可能存在配置问题
- ❌ **测试失败**: 模板测试失败，存在已知问题
- ⚠️ **不可用**: 模板的 Docker 镜像不存在或无法访问

## 工作流自动化

### N8N ✅ 已测试通过

**功能**: 强大的工作流自动化平台，类似 Zapier，支持 400+ 集成，可视化工作流设计。

**Docker 镜像**: `n8nio/n8n:latest`（主服务）、`postgres:15`（数据库）

**配置选项**:
- `N8N_VERSION`: N8N 版本（默认: latest，可选: 1.0, 0.235）
- `POSTGRES_VERSION`: PostgreSQL 版本（默认: 15，可选: 16, 14）
- `N8N_PORT`: N8N Web 服务端口（默认: 5678）
- `N8N_USERNAME`: N8N 登录用户名（默认: admin）
- `N8N_PASSWORD`: N8N 登录密码（必需）

**测试状态**: ✅ 已测试通过

**说明**: N8N 是一个强大的工作流自动化平台，支持 400+ 集成，可以连接各种服务和 API。提供可视化的工作流设计界面。

**访问地址**: `https://{{PRIMARY_DOMAIN}}`

---

### Apache Airflow ✅ 已测试通过

**功能**: 强大的工作流调度平台，用于数据管道编排、任务调度和监控，支持复杂的工作流定义。

**Docker 镜像**: `apache/airflow:latest`（主服务）、`postgres:15`（数据库）

**配置选项**:
- `AIRFLOW_VERSION`: Airflow 版本（默认: latest，可选: 2.8, 2.7）
- `POSTGRES_VERSION`: PostgreSQL 版本（默认: 15，可选: 16, 14）
- `AIRFLOW_PORT`: Airflow Web UI 端口（默认: 8080）
- `AIRFLOW_USERNAME`: Airflow 登录用户名（默认: admin）
- `AIRFLOW_PASSWORD`: Airflow 登录密码（必需）

**测试状态**: ✅ 已测试通过

**说明**: Airflow 是数据工程领域最流行的工作流调度工具，支持复杂的数据管道编排。包含 Web 服务器和调度器两个服务。

**访问地址**: `http://{{PRIMARY_DOMAIN}}`

**启动时间**: 约 2-3 分钟（首次启动需要初始化数据库）

---

### Prefect ✅ 已测试通过

**功能**: Prefect 工作流引擎，现代化的数据管道编排工具。

**Docker 镜像**: `prefecthq/prefect:latest`

**配置选项**:
- `PREFECT_VERSION`: Prefect 版本（默认: latest）
- `PREFECT_PORT`: Prefect Web UI 端口（默认: 4200）

**测试状态**: ✅ 已测试通过

**说明**: Prefect 是一个现代化的工作流引擎，提供了更友好的 API 和更好的错误处理机制。

---

### Node-RED ✅ 已测试通过

**功能**: Node-RED 流程编程工具，可视化连接硬件设备、API 和服务。

**Docker 镜像**: `nodered/node-red:latest`

**配置选项**:
- `NODE_RED_VERSION`: Node-RED 版本（默认: latest）
- `NODE_RED_PORT`: Node-RED Web 服务端口（默认: 1880）

**测试状态**: ✅ 已测试通过

**说明**: Node-RED 是一个基于流的编程工具，适合 IoT 应用和自动化场景。

---

## 项目管理

### OpenProject ⏳ 未测试

**功能**: OpenProject 项目管理工具，支持任务管理、时间跟踪、甘特图等。

**Docker 镜像**: `openproject/community:latest`

**配置选项**:
- `OPENPROJECT_VERSION`: OpenProject 版本（默认: latest）
- `OPENPROJECT_PORT`: OpenProject Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: OpenProject 是一个功能完整的项目管理工具，适合团队协作。

---

### Taiga ⏳ 未测试

**功能**: Taiga 敏捷项目管理工具，支持 Scrum 和 Kanban。

**Docker 镜像**: `taigaio/taiga-back:latest`

**配置选项**:
- `TAIGA_VERSION`: Taiga 版本（默认: latest）
- `TAIGA_PORT`: Taiga Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: Taiga 是一个专注于敏捷开发的项目管理工具。

---

### Leantime ⏳ 未测试

**功能**: Leantime 项目管理工具，适合小型团队。

**Docker 镜像**: `leantime/leantime:latest`

**配置选项**:
- `LEANTIME_VERSION`: Leantime 版本（默认: latest）
- `LEANTIME_PORT`: Leantime Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: Leantime 是一个轻量级的项目管理工具，适合小型团队使用。

---

### Plane ⏳ 未测试

**功能**: Plane 项目管理工具，现代化的项目管理界面。

**Docker 镜像**: `plane/plane:latest`

**配置选项**:
- `PLANE_VERSION`: Plane 版本（默认: latest）
- `PLANE_PORT`: Plane Web 服务端口（默认: 3000）

**测试状态**: ⏳ 未测试

**说明**: Plane 是一个现代化的项目管理工具，界面美观，功能完整。

---

### Vikunja ⏳ 未测试

**功能**: Vikunja 任务管理工具，开源的任务和项目管理平台。

**Docker 镜像**: `vikunja/vikunja:latest`

**配置选项**:
- `VIKUNJA_VERSION`: Vikunja 版本（默认: latest）
- `VIKUNJA_PORT`: Vikunja Web 服务端口（默认: 3456）

**测试状态**: ⏳ 未测试

**说明**: Vikunja 是一个开源的任务管理工具，支持看板、列表等多种视图。

---

### Kanboard ⏳ 未测试

**功能**: Kanboard 看板管理工具，简洁的看板式项目管理。

**Docker 镜像**: `kanboard/kanboard:latest`

**配置选项**:
- `KANBOARD_VERSION`: Kanboard 版本（默认: latest）
- `KANBOARD_PORT`: Kanboard Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: Kanboard 是一个简洁的看板管理工具，适合小型团队使用。

---

### Planka ⏳ 未测试

**功能**: Planka 看板管理工具，Trello 的开源替代方案。

**Docker 镜像**: `plankan/planka:latest`

**配置选项**:
- `PLANKA_VERSION`: Planka 版本（默认: latest）
- `PLANKA_PORT`: Planka Web 服务端口（默认: 3000）

**测试状态**: ⏳ 未测试

**说明**: Planka 是 Trello 的开源替代方案，提供类似的功能和界面。

---

### Wekan ⏳ 未测试

**功能**: Wekan 看板管理工具，Meteor 框架开发的看板应用。

**Docker 镜像**: `wekan/wekan:latest`

**配置选项**:
- `WEKAN_VERSION`: Wekan 版本（默认: latest）
- `WEKAN_PORT`: Wekan Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: Wekan 是一个功能完整的看板管理工具，支持卡片、列表、标签等功能。

---

### Linear Alternative ⏳ 未测试

**功能**: Linear 的开源替代方案，现代化的项目管理工具。

**Docker 镜像**: `linear/alternative:latest`

**配置选项**:
- `LINEAR_VERSION`: Linear Alternative 版本（默认: latest）
- `LINEAR_PORT`: Linear Alternative Web 服务端口（默认: 3000）

**测试状态**: ⏳ 未测试

**说明**: Linear Alternative 提供了类似 Linear 的功能，适合软件开发团队。

---

## ERP/供应链管理

### Odoo ✅ 已测试通过

**功能**: 开源 ERP 和 CRM 系统，功能强大，支持销售、库存、会计、人力资源等模块。

**Docker 镜像**: `odoo:latest`（主服务）、`postgres:15`（数据库）

**配置选项**:
- `ODOO_VERSION`: Odoo 版本（默认: latest，可选: 17.0, 16.0）
- `POSTGRES_VERSION`: PostgreSQL 版本（默认: 15，可选: 14, 16）
- `ODOO_PORT`: Odoo Web 服务端口（默认: 8069）

**测试状态**: ✅ 已测试通过

**说明**: Odoo 是最流行的开源 ERP 系统之一，功能非常丰富，支持销售、库存、会计、人力资源等多个模块。

**访问地址**: `http://{{PRIMARY_DOMAIN}}`

**默认账户**: admin / admin

---

### ERPNext ⏳ 未测试

**功能**: ERPNext 开源 ERP 系统，适合中小企业使用。

**Docker 镜像**: `frappe/erpnext:latest`

**配置选项**:
- `ERPNEXT_VERSION`: ERPNext 版本（默认: latest）
- `ERPNEXT_PORT`: ERPNext Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: ERPNext 是一个功能完整的开源 ERP 系统，适合中小企业使用。

---

### 小型ERP系统 ⏳ 未测试

**功能**: 小型 ERP 系统，适合小型企业使用。

**Docker 镜像**: `small-erp/system:latest`

**配置选项**:
- `SMALL_ERP_VERSION`: 小型ERP版本（默认: latest）
- `SMALL_ERP_PORT`: 小型ERP Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 小型 ERP 系统提供了基础的 ERP 功能，适合小型企业使用。

---

### 库存管理系统 ⏳ 未测试

**功能**: 库存管理系统，管理商品库存和出入库。

**Docker 镜像**: `inventory/management:latest`

**配置选项**:
- `INVENTORY_VERSION`: 库存管理系统版本（默认: latest）
- `INVENTORY_PORT`: 库存管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 库存管理系统提供了完整的库存管理功能，包括入库、出库、盘点等。

---

### 仓库管理系统 ⏳ 未测试

**功能**: 仓库管理系统，管理仓库和库存。

**Docker 镜像**: `warehouse/management:latest`

**配置选项**:
- `WAREHOUSE_VERSION`: 仓库管理系统版本（默认: latest）
- `WAREHOUSE_PORT`: 仓库管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 仓库管理系统提供了仓库管理功能，包括库位管理、库存查询等。

---

### 供应商管理系统 ⏳ 未测试

**功能**: 供应商管理系统，管理供应商信息和采购流程。

**Docker 镜像**: `supplier/management:latest`

**配置选项**:
- `SUPPLIER_VERSION`: 供应商管理系统版本（默认: latest）
- `SUPPLIER_PORT`: 供应商管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 供应商管理系统提供了供应商信息管理、采购流程管理等功能。

---

### 供应商自助服务平台 ⏳ 未测试

**功能**: 供应商自助服务平台，供应商可以自助查询订单、对账等信息。

**Docker 镜像**: `supplier/portal:latest`

**配置选项**:
- `SUPPLIER_PORTAL_VERSION`: 供应商自助服务平台版本（默认: latest）
- `SUPPLIER_PORTAL_PORT`: 供应商自助服务平台 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 供应商自助服务平台允许供应商自助查询订单、对账等信息，减少人工沟通成本。

---

### 采购门户 ⏳ 未测试

**功能**: 采购门户，统一的采购管理平台。

**Docker 镜像**: `procurement/portal:latest`

**配置选项**:
- `PROCUREMENT_VERSION`: 采购门户版本（默认: latest）
- `PROCUREMENT_PORT`: 采购门户 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 采购门户提供了统一的采购管理平台，包括采购申请、审批、执行等功能。

---

### 合同管理系统 ⏳ 未测试

**功能**: 合同管理系统，管理合同的全生命周期。

**Docker 镜像**: `contract/management:latest`

**配置选项**:
- `CONTRACT_VERSION`: 合同管理系统版本（默认: latest）
- `CONTRACT_PORT`: 合同管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 合同管理系统提供了合同管理功能，包括合同创建、审批、执行、归档等。

---

## HR/人事管理

### 考勤管理系统 ⏳ 未测试

**功能**: 考勤管理系统，管理员工考勤记录。

**Docker 镜像**: `attendance/management:latest`

**配置选项**:
- `ATTENDANCE_VERSION`: 考勤管理系统版本（默认: latest）
- `ATTENDANCE_PORT`: 考勤管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 考勤管理系统提供了员工考勤记录、统计、报表等功能。

---

### 打卡系统 ⏳ 未测试

**功能**: 打卡系统，员工打卡签到。

**Docker 镜像**: `punch-clock/system:latest`

**配置选项**:
- `PUNCH_CLOCK_VERSION`: 打卡系统版本（默认: latest）
- `PUNCH_CLOCK_PORT`: 打卡系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 打卡系统提供了员工打卡签到功能，支持多种打卡方式。

---

### 工时管理系统 ⏳ 未测试

**功能**: 工时管理系统，管理员工工作时间。

**Docker 镜像**: `work-hours/management:latest`

**配置选项**:
- `WORK_HOURS_VERSION`: 工时管理系统版本（默认: latest）
- `WORK_HOURS_PORT`: 工时管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 工时管理系统提供了员工工作时间记录、统计、报表等功能。

---

### 薪酬管理系统 ⏳ 未测试

**功能**: 薪酬管理系统，管理员工薪酬和工资单。

**Docker 镜像**: `payroll/management:latest`

**配置选项**:
- `PAYROLL_VERSION`: 薪酬管理系统版本（默认: latest）
- `PAYROLL_PORT`: 薪酬管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 薪酬管理系统提供了员工薪酬管理、工资单生成、统计报表等功能。

---

### 员工目录 ⏳ 未测试

**功能**: 员工目录，管理员工基本信息。

**Docker 镜像**: `employee/directory:latest`

**配置选项**:
- `EMPLOYEE_DIRECTORY_VERSION`: 员工目录版本（默认: latest）
- `EMPLOYEE_DIRECTORY_PORT`: 员工目录 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 员工目录提供了员工基本信息管理功能，包括联系方式、部门、职位等。

---

### 宿舍管理系统 ⏳ 未测试

**功能**: 宿舍管理系统，管理员工宿舍分配和入住。

**Docker 镜像**: `dormitory/management:latest`

**配置选项**:
- `DORMITORY_VERSION`: 宿舍管理系统版本（默认: latest）
- `DORMITORY_PORT`: 宿舍管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 宿舍管理系统提供了宿舍分配、入住管理、费用管理等功能。

---

### 班车管理系统 ⏳ 未测试

**功能**: 班车管理系统，管理公司班车路线和预约。

**Docker 镜像**: `shuttle/management:latest`

**配置选项**:
- `SHUTTLE_VERSION`: 班车管理系统版本（默认: latest）
- `SHUTTLE_PORT`: 班车管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 班车管理系统提供了班车路线管理、预约、统计等功能。

---

### 排班管理系统 ⏳ 未测试

**功能**: 排班管理系统，管理员工排班和班次。

**Docker 镜像**: `schedule/management:latest`

**配置选项**:
- `SCHEDULE_VERSION`: 排班管理系统版本（默认: latest）
- `SCHEDULE_PORT`: 排班管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 排班管理系统提供了员工排班管理、班次设置、调班等功能。

---

### 培训管理系统 ⏳ 未测试

**功能**: 培训管理系统，管理员工培训课程和记录。

**Docker 镜像**: `training/management:latest`

**配置选项**:
- `TRAINING_VERSION`: 培训管理系统版本（默认: latest）
- `TRAINING_PORT`: 培训管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 培训管理系统提供了培训课程管理、报名、记录、统计等功能。

---

### Moodle ⏳ 未测试

**功能**: Moodle 在线学习平台，功能强大的 LMS 系统。

**Docker 镜像**: `moodle/moodle:latest`

**配置选项**:
- `MOODLE_VERSION`: Moodle 版本（默认: latest）
- `MOODLE_PORT`: Moodle Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: Moodle 是最流行的开源 LMS 系统之一，功能非常丰富，适合企业培训使用。

---

### Open edX ⏳ 未测试

**功能**: Open edX 在线学习平台，edX 的开源版本。

**Docker 镜像**: `edx/edx-platform:latest`

**配置选项**:
- `OPENEDX_VERSION`: Open edX 版本（默认: latest）
- `OPENEDX_PORT`: Open edX Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: Open edX 是 edX 的开源版本，适合大规模在线教育使用。

---

### 知识考试系统 ⏳ 未测试

**功能**: 知识考试系统，在线考试和题库管理。

**Docker 镜像**: `exam/system:latest`

**配置选项**:
- `EXAM_VERSION`: 知识考试系统版本（默认: latest）
- `EXAM_PORT`: 知识考试系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 知识考试系统提供了在线考试、题库管理、成绩统计等功能。

---

### Kimai ⏳ 未测试

**功能**: Kimai 时间追踪工具，记录项目和工作时间。

**Docker 镜像**: `kimai/kimai:latest`

**配置选项**:
- `KIMAI_VERSION`: Kimai 版本（默认: latest）
- `KIMAI_PORT`: Kimai Web 服务端口（默认: 8001）

**测试状态**: ⏳ 未测试

**说明**: Kimai 是一个开源的时间追踪工具，适合记录项目和工作时间。

---

## 文档管理

### 文档版本控制系统 ⏳ 未测试

**功能**: 文档版本控制系统，管理文档版本和历史。

**Docker 镜像**: `document/version-control:latest`

**配置选项**:
- `DOC_VERSION_CONTROL_VERSION`: 文档版本控制系统版本（默认: latest）
- `DOC_VERSION_CONTROL_PORT`: 文档版本控制系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 文档版本控制系统提供了文档版本管理、历史记录、对比等功能。

---

### 印章管理系统 ⏳ 未测试

**功能**: 印章管理系统，管理电子印章和用印流程。

**Docker 镜像**: `seal/management:latest`

**配置选项**:
- `SEAL_VERSION`: 印章管理系统版本（默认: latest）
- `SEAL_PORT`: 印章管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 印章管理系统提供了电子印章管理、用印申请、审批等功能。

---

### 档案管理系统 ⏳ 未测试

**功能**: 档案管理系统，管理企业档案和文档。

**Docker 镜像**: `archive/management:latest`

**配置选项**:
- `ARCHIVE_VERSION`: 档案管理系统版本（默认: latest）
- `ARCHIVE_PORT`: 档案管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 档案管理系统提供了档案管理、分类、检索、借阅等功能。

---

### 文档合规系统 ⏳ 未测试

**功能**: 文档合规系统，确保文档符合法规要求。

**Docker 镜像**: `document/compliance:latest`

**配置选项**:
- `DOC_COMPLIANCE_VERSION`: 文档合规系统版本（默认: latest）
- `DOC_COMPLIANCE_PORT`: 文档合规系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 文档合规系统提供了文档合规检查、审核、报告等功能。

---

### Paperless-ngx ⏳ 未测试

**功能**: Paperless-ngx 无纸化文档管理，扫描和管理文档。

**Docker 镜像**: `paperless-ngx/paperless-ngx:latest`

**配置选项**:
- `PAPERLESS_VERSION`: Paperless-ngx 版本（默认: latest）
- `PAPERLESS_PORT`: Paperless-ngx Web 服务端口（默认: 8000）

**测试状态**: ⏳ 未测试

**说明**: Paperless-ngx 是一个无纸化文档管理系统，支持文档扫描、OCR、分类等功能。

---

### Mayan EDMS ⏳ 未测试

**功能**: Mayan EDMS 企业文档管理系统，功能强大的文档管理平台。

**Docker 镜像**: `mayan-edms/mayan-edms:latest`

**配置选项**:
- `MAYAN_VERSION`: Mayan EDMS 版本（默认: latest）
- `MAYAN_PORT`: Mayan EDMS Web 服务端口（默认: 8000）

**测试状态**: ⏳ 未测试

**说明**: Mayan EDMS 是一个功能强大的企业文档管理系统，支持文档管理、工作流、版本控制等功能。

---

## 合规审计

### 合规管理系统 ⏳ 未测试

**功能**: 合规管理系统，确保企业符合法规要求。

**Docker 镜像**: `compliance/management:latest`

**配置选项**:
- `COMPLIANCE_VERSION`: 合规管理系统版本（默认: latest）
- `COMPLIANCE_PORT`: 合规管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 合规管理系统提供了合规检查、审核、报告等功能。

---

### 审计管理系统 ⏳ 未测试

**功能**: 审计管理系统，管理审计流程和记录。

**Docker 镜像**: `audit/management:latest`

**配置选项**:
- `AUDIT_VERSION`: 审计管理系统版本（默认: latest）
- `AUDIT_PORT`: 审计管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 审计管理系统提供了审计计划、执行、报告等功能。

---

### 风险管理系统 ⏳ 未测试

**功能**: 风险管理系统，识别和管理企业风险。

**Docker 镜像**: `risk/management:latest`

**配置选项**:
- `RISK_VERSION`: 风险管理系统版本（默认: latest）
- `RISK_PORT`: 风险管理系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 风险管理系统提供了风险识别、评估、应对等功能。

---

## 财务管理

### Akaunting ✅ 已测试通过

**功能**: Akaunting 会计软件，适合小型企业使用。

**Docker 镜像**: `akaunting/akaunting:latest`

**配置选项**:
- `AKAUNTING_VERSION`: Akaunting 版本（默认: latest）
- `AKAUNTING_PORT`: Akaunting Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: Akaunting 是一个轻量级的会计软件，适合小型企业使用。

---

### Invoice Ninja ✅ 已测试通过

**功能**: Invoice Ninja 发票管理工具，创建和管理发票。

**Docker 镜像**: `invoiceninja/invoiceninja:latest`

**配置选项**:
- `INVOICE_NINJA_VERSION`: Invoice Ninja 版本（默认: latest）
- `INVOICE_NINJA_PORT`: Invoice Ninja Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: Invoice Ninja 是一个功能完整的发票管理工具，支持发票创建、发送、支付跟踪等功能。

---

### InvoicePlane ✅ 已测试通过

**功能**: InvoicePlane 发票管理工具，开源发票管理系统。

**Docker 镜像**: `invoiceplane/invoiceplane:latest`

**配置选项**:
- `INVOICEPLANE_VERSION`: InvoicePlane 版本（默认: latest）
- `INVOICEPLANE_PORT`: InvoicePlane Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: InvoicePlane 是一个开源的发票管理系统，适合小型企业使用。

---

### 费用报销系统 ⏳ 未测试

**功能**: 费用报销系统，管理员工费用报销流程。

**Docker 镜像**: `expense/management:latest`

**配置选项**:
- `EXPENSE_VERSION`: 费用报销系统版本（默认: latest）
- `EXPENSE_PORT`: 费用报销系统 Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: 费用报销系统提供了费用申请、审批、报销、统计等功能。

---

## 日志管理

### Graylog ✅ 已测试通过

**功能**: Graylog 日志管理平台，支持日志收集、搜索和分析。

**Docker 镜像**: `graylog/graylog:latest`

**配置选项**:
- `GRAYLOG_VERSION`: Graylog 版本（默认: latest）
- `GRAYLOG_PORT`: Graylog Web 服务端口（默认: 9000）

**测试状态**: ✅ 已测试通过

**说明**: Graylog 是一个功能强大的日志管理平台，支持多种日志输入源和搜索功能。

---

### Seq ✅ 已测试通过

**功能**: Seq 结构化日志服务器，提供强大的日志搜索和分析功能。

**Docker 镜像**: `datalust/seq:latest`

**配置选项**:
- `SEQ_VERSION`: Seq 版本（默认: latest）
- `SEQ_PORT`: Seq Web 服务端口（默认: 5341）

**测试状态**: ✅ 已测试通过

**说明**: Seq 是一个结构化日志服务器，提供强大的搜索、过滤和分析功能。

---

## 监控工具

### Glances ⏳ 未测试

**功能**: Glances 系统监控工具，提供命令行和 Web 界面。

**Docker 镜像**: `nicolargo/glances:latest`

**配置选项**:
- `GLANCES_VERSION`: Glances 版本（默认: latest）
- `GLANCES_PORT`: Glances Web 服务端口（默认: 61208）

**测试状态**: ⏳ 未测试

**说明**: Glances 是一个跨平台的系统监控工具，提供简洁的命令行和 Web 界面。

---

### Grafana Dashboard ⏳ 未测试

**功能**: Grafana Dashboard 监控面板，预配置的监控仪表板。

**Docker 镜像**: `grafana/grafana:latest`

**配置选项**:
- `GRAFANA_DASHBOARD_VERSION`: Grafana Dashboard 版本（默认: latest）
- `GRAFANA_DASHBOARD_PORT`: Grafana Dashboard Web 服务端口（默认: 3000）

**测试状态**: ⏳ 未测试

**说明**: Grafana Dashboard 提供了预配置的监控仪表板，可以快速查看系统状态。

---

## 数据库管理工具

### phpMyAdmin ✅ 已测试通过

**功能**: phpMyAdmin MySQL 数据库管理工具，提供 Web 界面。

**Docker 镜像**: `phpmyadmin/phpmyadmin:latest`

**配置选项**:
- `PHPMYADMIN_VERSION`: phpMyAdmin 版本（默认: latest）
- `PHPMYADMIN_PORT`: phpMyAdmin Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: phpMyAdmin 是最流行的 MySQL 管理工具之一，提供直观的 Web 界面。

---

### mongo-express ✅ 已测试通过

**功能**: mongo-express MongoDB 数据库管理工具，提供 Web 界面。

**Docker 镜像**: `mongo-express:latest`

**配置选项**:
- `MONGO_EXPRESS_VERSION`: mongo-express 版本（默认: latest）
- `MONGO_EXPRESS_PORT`: mongo-express Web 服务端口（默认: 8081）

**测试状态**: ✅ 已测试通过

**说明**: mongo-express 是 MongoDB 的 Web 管理界面，提供直观的数据库管理功能。

---

## 容器管理

### Portainer ✅ 已测试通过

**功能**: Portainer Docker 容器管理工具，提供 Web 界面管理 Docker 容器和镜像。

**Docker 镜像**: `portainer/portainer-ce:latest`

**配置选项**:
- `PORTAINER_VERSION`: Portainer 版本（默认: latest）
- `PORTAINER_PORT`: Portainer Web 服务端口（默认: 9000）

**测试状态**: ✅ 已测试通过

**说明**: Portainer 是最流行的 Docker 管理工具之一，提供直观的 Web 界面管理 Docker 环境。

---

### Portainer CE ✅ 已测试通过

**功能**: Portainer CE 社区版，Docker 容器管理工具。

**Docker 镜像**: `portainer/portainer-ce:latest`

**配置选项**:
- `PORTAINER_CE_VERSION`: Portainer CE 版本（默认: latest）
- `PORTAINER_CE_PORT`: Portainer CE Web 服务端口（默认: 9000）

**测试状态**: ✅ 已测试通过

**说明**: Portainer CE 是 Portainer 的社区版，功能与 Portainer 相同。

---

### Dozzle ✅ 已测试通过

**功能**: Dozzle Docker 日志查看器，实时查看容器日志。

**Docker 镜像**: `amir20/dozzle:latest`

**配置选项**:
- `DOZZLE_VERSION`: Dozzle 版本（默认: latest）
- `DOZZLE_PORT`: Dozzle Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: Dozzle 是一个轻量级的 Docker 日志查看器，提供实时日志查看功能。

---

## 笔记工具

### Obsidian ✅ 已测试通过

**功能**: Obsidian 知识管理工具，基于 Markdown 的知识库。

**Docker 镜像**: `obsidian/obsidian:latest`

**配置选项**:
- `OBSIDIAN_VERSION`: Obsidian 版本（默认: latest）
- `OBSIDIAN_PORT`: Obsidian Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: Obsidian 是一个强大的知识管理工具，支持 Markdown、双向链接、图谱视图等功能。

---

### Joplin ⏳ 未测试

**功能**: Joplin 笔记应用，支持 Markdown 和同步。

**Docker 镜像**: `joplin/server:latest`

**配置选项**:
- `JOPLIN_VERSION`: Joplin 版本（默认: latest）
- `JOPLIN_PORT`: Joplin Web 服务端口（默认: 22300）

**测试状态**: ⏳ 未测试

**说明**: Joplin 是一个开源的笔记应用，支持 Markdown、标签、同步等功能。

---

### Logseq ⏳ 未测试

**功能**: Logseq 知识管理工具，基于块的知识库。

**Docker 镜像**: `logseq/logseq:latest`

**配置选项**:
- `LOGSEQ_VERSION`: Logseq 版本（默认: latest）
- `LOGSEQ_PORT`: Logseq Web 服务端口（默认: 3000）

**测试状态**: ⏳ 未测试

**说明**: Logseq 是一个基于块的知识管理工具，支持双向链接、图谱视图等功能。

---

### Trilium ⏳ 未测试

**功能**: Trilium 知识管理工具，分层笔记系统。

**Docker 镜像**: `zadam/trilium:latest`

**配置选项**:
- `TRILIUM_VERSION`: Trilium 版本（默认: latest）
- `TRILIUM_PORT`: Trilium Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: Trilium 是一个分层笔记系统，支持笔记组织、搜索、同步等功能。

---

### TiddlyWiki ⏳ 未测试

**功能**: TiddlyWiki 知识管理工具，非线性笔记系统。

**Docker 镜像**: `tiddlywiki/tiddlywiki:latest`

**配置选项**:
- `TIDDLYWIKI_VERSION`: TiddlyWiki 版本（默认: latest）
- `TIDDLYWIKI_PORT`: TiddlyWiki Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: TiddlyWiki 是一个非线性的笔记系统，适合构建个人知识库。

---

## DNS 工具

### Pi-hole ✅ 已测试通过

**功能**: Pi-hole 广告拦截和 DNS 服务器，拦截广告和恶意域名。

**Docker 镜像**: `pihole/pihole:latest`

**配置选项**:
- `PIHOLE_VERSION`: Pi-hole 版本（默认: latest）
- `PIHOLE_PORT`: Pi-hole Web 服务端口（默认: 80）

**测试状态**: ✅ 已测试通过

**说明**: Pi-hole 是一个网络级的广告拦截工具，可以作为 DNS 服务器拦截广告和恶意域名。

---

### AdGuard Home ⏳ 未测试

**功能**: AdGuard Home 广告拦截和 DNS 服务器。

**Docker 镜像**: `adguard/adguardhome:latest`

**配置选项**:
- `ADGUARD_VERSION`: AdGuard Home 版本（默认: latest）
- `ADGUARD_PORT`: AdGuard Home Web 服务端口（默认: 3000）

**测试状态**: ⏳ 未测试

**说明**: AdGuard Home 是一个网络级的广告拦截工具，功能类似 Pi-hole。

---

## 备份工具

### Duplicati ✅ 已测试通过

**功能**: Duplicati 备份工具，支持多种存储后端。

**Docker 镜像**: `duplicati/duplicati:latest`

**配置选项**:
- `DUPLICATI_VERSION`: Duplicati 版本（默认: latest）
- `DUPLICATI_PORT`: Duplicati Web 服务端口（默认: 8200）

**测试状态**: ✅ 已测试通过

**说明**: Duplicati 是一个功能完整的备份工具，支持多种存储后端和加密备份。

---

### Restic ⏳ 未测试

**功能**: Restic 备份工具，快速、安全、易用的备份程序。

**Docker 镜像**: `restic/restic:latest`

**配置选项**:
- `RESTIC_VERSION`: Restic 版本（默认: latest）
- `RESTIC_PORT`: Restic Web 服务端口（默认: 8080）

**测试状态**: ⏳ 未测试

**说明**: Restic 是一个快速、安全、易用的备份程序，支持多种存储后端。

---

## 其他工具

### Heimdall ✅ 已测试通过

**功能**: Heimdall 应用启动页和仪表板，统一管理所有应用入口。

**Docker 镜像**: `lscr.io/linuxserver/heimdall:latest`

**配置选项**:
- `HEIMDALL_VERSION`: Heimdall 版本（默认: latest，可选: 2.5, 2.4）
- `HEIMDALL_PORT`: Heimdall Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: Heimdall 是一个应用启动页，可以统一管理所有应用的入口，美观实用。

---

### Slack Bot ⏳ 未测试

**功能**: Slack Bot 机器人，集成 Slack 消息。

**Docker 镜像**: `slack/bot:latest`

**配置选项**:
- `SLACK_BOT_VERSION`: Slack Bot 版本（默认: latest）
- `SLACK_BOT_PORT`: Slack Bot 服务端口（默认: 3000）

**测试状态**: ⏳ 未测试

**说明**: Slack Bot 提供了 Slack 机器人功能，可以集成到 Slack 工作流中。

---

## 总结

企业工具分类共包含 **159 个模板**，分为 60 个子分类，其中：
- ✅ **已测试通过**: 约 20 个（主要集中在工作流自动化、日志管理、数据库管理、容器管理等）
- ⏳ **未测试**: 约 139 个（大部分企业应用模板尚未完成测试）

已测试通过的模板主要集中在 DevOps 相关工具（N8N、Airflow、日志管理、容器管理等）和数据库管理工具。企业应用类模板（HR管理、ERP、项目管理等）大部分尚未完成测试，主要是由于 Docker Hub 速率限制或镜像访问问题。

---

*最后更新时间: 2025-11-11*


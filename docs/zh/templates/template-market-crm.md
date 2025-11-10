# 模板市场 - CRM 分类

本文档详细介绍 SSLcat 模板市场中 CRM 分类的所有模板，包括功能说明、Docker 镜像信息和测试状态。

## 测试状态说明

- ✅ **已测试通过**: 模板已完成自动化测试，可以稳定使用
- ⏳ **未测试**: 模板尚未完成测试，可能存在配置问题
- ❌ **测试失败**: 模板测试失败，存在已知问题
- ⚠️ **不可用**: 模板的 Docker 镜像不存在或无法访问

## CRM 系统

### SuiteCRM ✅ 已测试通过

**功能**: SuiteCRM 开源 CRM 系统，功能强大的客户关系管理平台。

**Docker 镜像**: `suitecrm/suitecrm:latest`

**配置选项**:
- `SUITECRM_VERSION`: SuiteCRM 版本（默认: latest）
- `SUITECRM_PORT`: SuiteCRM Web 服务端口（默认: 80）

**测试状态**: ✅ 已测试通过

**说明**: SuiteCRM 是 SugarCRM 的开源分支，功能非常丰富，适合中大型企业使用。

---

### EspoCRM ✅ 已测试通过

**功能**: EspoCRM 开源 CRM 系统，现代化的客户关系管理平台。

**Docker 镜像**: `espo/espo:latest`

**配置选项**:
- `ESPOCRM_VERSION`: EspoCRM 版本（默认: latest）
- `ESPOCRM_PORT`: EspoCRM Web 服务端口（默认: 80）

**测试状态**: ✅ 已测试通过

**说明**: EspoCRM 是一个现代化的 CRM 系统，界面美观，功能完整，适合中小企业使用。

---

### Dolibarr ✅ 已测试通过

**功能**: Dolibarr ERP/CRM 系统，适合中小企业的综合管理平台。

**Docker 镜像**: `tuxgasy/dolibarr:latest`

**配置选项**:
- `DOLIBARR_VERSION`: Dolibarr 版本（默认: latest）
- `DOLIBARR_PORT`: Dolibarr Web 服务端口（默认: 80）

**测试状态**: ✅ 已测试通过

**说明**: Dolibarr 是一个 ERP/CRM 综合管理平台，功能丰富，适合中小企业使用。

---

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

## 总结

CRM 分类共包含 **5 个模板**，其中：
- ✅ **已测试通过**: 4 个（SuiteCRM、EspoCRM、Dolibarr、Odoo）
- ⏳ **未测试**: 1 个（ERPNext）

大部分 CRM 系统已经过测试验证，可以稳定使用。Odoo 和 ERPNext 功能最为丰富，适合中大型企业使用。

---

*最后更新时间: 2025-11-11*


# Template Marketplace - CRM Category

This document provides detailed information about all templates in the CRM category of the SSLcat template marketplace, including function descriptions, Docker image information, and test status.

## Test Status Legend

- ✅ **Tested and Passed**: Template has completed automated testing and can be used stably
- ⏳ **Not Tested**: Template has not completed testing, may have configuration issues
- ❌ **Test Failed**: Template test failed, has known issues
- ⚠️ **Unavailable**: Template's Docker image does not exist or cannot be accessed

## CRM Systems

### SuiteCRM ✅ Tested and Passed

**Function**: SuiteCRM open-source CRM system, powerful customer relationship management platform.

**Docker Image**: `suitecrm/suitecrm:latest`

**Configuration Options**:
- `SUITECRM_VERSION`: SuiteCRM version (default: latest)
- `SUITECRM_PORT`: SuiteCRM web service port (default: 80)

**Test Status**: ✅ Tested and Passed

**Description**: SuiteCRM is an open-source fork of SugarCRM with very rich features, suitable for medium and large enterprises.

---

### EspoCRM ✅ Tested and Passed

**Function**: EspoCRM open-source CRM system, modern customer relationship management platform.

**Docker Image**: `espo/espo:latest`

**Configuration Options**:
- `ESPOCRM_VERSION`: EspoCRM version (default: latest)
- `ESPOCRM_PORT`: EspoCRM web service port (default: 80)

**Test Status**: ✅ Tested and Passed

**Description**: EspoCRM is a modern CRM system with a beautiful interface and complete functionality, suitable for small and medium enterprises.

---

### Dolibarr ✅ Tested and Passed

**Function**: Dolibarr ERP/CRM system, comprehensive management platform suitable for small and medium enterprises.

**Docker Image**: `tuxgasy/dolibarr:latest`

**Configuration Options**:
- `DOLIBARR_VERSION`: Dolibarr version (default: latest)
- `DOLIBARR_PORT`: Dolibarr web service port (default: 80)

**Test Status**: ✅ Tested and Passed

**Description**: Dolibarr is an ERP/CRM comprehensive management platform with rich features, suitable for small and medium enterprises.

---

### Odoo ✅ Tested and Passed

**Function**: Open-source ERP and CRM system, powerful, supports sales, inventory, accounting, human resources, and other modules.

**Docker Image**: `odoo:latest` (main service), `postgres:15` (database)

**Configuration Options**:
- `ODOO_VERSION`: Odoo version (default: latest, optional: 17.0, 16.0)
- `POSTGRES_VERSION`: PostgreSQL version (default: 15, optional: 14, 16)
- `ODOO_PORT`: Odoo web service port (default: 8069)

**Test Status**: ✅ Tested and Passed

**Description**: Odoo is one of the most popular open-source ERP systems with very rich features, supporting multiple modules such as sales, inventory, accounting, human resources, etc.

**Access URL**: `http://{{PRIMARY_DOMAIN}}`

**Default Account**: admin / admin

---

### ERPNext ⏳ Not Tested

**Function**: ERPNext open-source ERP system, suitable for small and medium enterprises.

**Docker Image**: `frappe/erpnext:latest`

**Configuration Options**:
- `ERPNEXT_VERSION`: ERPNext version (default: latest)
- `ERPNEXT_PORT`: ERPNext web service port (default: 8080)

**Test Status**: ⏳ Not Tested

**Description**: ERPNext is a fully-featured open-source ERP system suitable for small and medium enterprises.

---

## Summary

The CRM category contains **5 templates**, of which:
- ✅ **Tested and Passed**: 4 templates (SuiteCRM, EspoCRM, Dolibarr, Odoo)
- ⏳ **Not Tested**: 1 template (ERPNext)

Most CRM systems have been tested and verified, and can be used stably. Odoo and ERPNext have the most features and are suitable for medium and large enterprises.

---

*Last updated: 2025-11-11*

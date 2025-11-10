# Template Marketplace - E-commerce Platforms Category

This document provides detailed information about all templates in the E-commerce Platforms category of the SSLcat template marketplace, including function descriptions, Docker image information, and test status.

## Test Status Legend

- ✅ **Tested and Passed**: Template has completed automated testing and can be used stably
- ⏳ **Not Tested**: Template has not completed testing, may have configuration issues
- ❌ **Test Failed**: Template test failed, has known issues
- ⚠️ **Unavailable**: Template's Docker image does not exist or cannot be accessed

## E-commerce Platforms

### WooCommerce ⏳ Not Tested

**Function**: WooCommerce WordPress e-commerce plugin, e-commerce solution based on WordPress.

**Docker Image**: `wordpress:latest` (requires WooCommerce plugin installation)

**Configuration Options**:
- `WOOCOMMERCE_VERSION`: WordPress version (default: latest)
- `WOOCOMMERCE_PORT`: WooCommerce web service port (default: 80)

**Test Status**: ⏳ Not Tested

**Description**: WooCommerce is the most popular WordPress e-commerce plugin with complete functionality, suitable for small and medium e-commerce websites.

---

### Magento ⏳ Not Tested

**Function**: Magento e-commerce platform, powerful enterprise-level e-commerce system.

**Docker Image**: `magento/magento:latest`

**Configuration Options**:
- `MAGENTO_VERSION`: Magento version (default: latest)
- `MAGENTO_PORT`: Magento web service port (default: 80)

**Test Status**: ⏳ Not Tested

**Description**: Magento is a powerful enterprise-level e-commerce system suitable for large e-commerce websites.

**Resource Requirements**: Recommend at least 4GB RAM

---

### OpenCart ⏳ Not Tested

**Function**: OpenCart e-commerce system, fully-featured open-source e-commerce platform.

**Docker Image**: `opencart/opencart:latest`

**Configuration Options**:
- `OPENCART_VERSION`: OpenCart version (default: latest)
- `OPENCART_PORT`: OpenCart web service port (default: 80)

**Test Status**: ⏳ Not Tested

**Description**: OpenCart is a fully-featured open-source e-commerce platform suitable for small and medium e-commerce websites.

---

### PrestaShop ⏳ Not Tested

**Function**: PrestaShop e-commerce platform, powerful open-source e-commerce system.

**Docker Image**: `prestashop/prestashop:latest`

**Configuration Options**:
- `PRESTASHOP_VERSION`: PrestaShop version (default: latest)
- `PRESTASHOP_PORT`: PrestaShop web service port (default: 80)

**Test Status**: ⏳ Not Tested

**Description**: PrestaShop is a powerful open-source e-commerce system suitable for small and medium e-commerce websites.

---

### Shopware ⏳ Not Tested

**Function**: Shopware e-commerce platform, modern e-commerce system.

**Docker Image**: `shopware/shopware:latest`

**Configuration Options**:
- `SHOPWARE_VERSION`: Shopware version (default: latest)
- `SHOPWARE_PORT`: Shopware web service port (default: 80)

**Test Status**: ⏳ Not Tested

**Description**: Shopware is a modern e-commerce system with a beautiful interface and complete functionality.

---

## Summary

The E-commerce Platforms category contains **5 templates**, of which:
- ✅ **Tested and Passed**: 0 templates
- ⏳ **Not Tested**: 5 templates (WooCommerce, Magento, OpenCart, PrestaShop, Shopware)

All e-commerce platform templates have not completed testing, mainly due to Docker Hub rate limits or image access issues. E-commerce platforms typically require more resources, recommend deploying on servers with sufficient resources.

---

*Last updated: 2025-11-11*

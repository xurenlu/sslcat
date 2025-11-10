# 模板市场 - 电商平台分类

本文档详细介绍 SSLcat 模板市场中电商平台分类的所有模板，包括功能说明、Docker 镜像信息和测试状态。

## 测试状态说明

- ✅ **已测试通过**: 模板已完成自动化测试，可以稳定使用
- ⏳ **未测试**: 模板尚未完成测试，可能存在配置问题
- ❌ **测试失败**: 模板测试失败，存在已知问题
- ⚠️ **不可用**: 模板的 Docker 镜像不存在或无法访问

## 电商平台

### WooCommerce ⏳ 未测试

**功能**: WooCommerce WordPress 电商插件，基于 WordPress 的电商解决方案。

**Docker 镜像**: `wordpress:latest`（需要安装 WooCommerce 插件）

**配置选项**:
- `WOOCOMMERCE_VERSION`: WordPress 版本（默认: latest）
- `WOOCOMMERCE_PORT`: WooCommerce Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: WooCommerce 是最流行的 WordPress 电商插件，功能完整，适合中小型电商网站。

---

### Magento ⏳ 未测试

**功能**: Magento 电商平台，功能强大的企业级电商系统。

**Docker 镜像**: `magento/magento:latest`

**配置选项**:
- `MAGENTO_VERSION`: Magento 版本（默认: latest）
- `MAGENTO_PORT`: Magento Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: Magento 是一个功能强大的企业级电商系统，适合大型电商网站使用。

**资源需求**: 建议至少 4GB 内存

---

### OpenCart ⏳ 未测试

**功能**: OpenCart 电商系统，功能完整的开源电商平台。

**Docker 镜像**: `opencart/opencart:latest`

**配置选项**:
- `OPENCART_VERSION`: OpenCart 版本（默认: latest）
- `OPENCART_PORT`: OpenCart Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: OpenCart 是一个功能完整的开源电商平台，适合中小型电商网站使用。

---

### PrestaShop ⏳ 未测试

**功能**: PrestaShop 电商平台，功能强大的开源电商系统。

**Docker 镜像**: `prestashop/prestashop:latest`

**配置选项**:
- `PRESTASHOP_VERSION`: PrestaShop 版本（默认: latest）
- `PRESTASHOP_PORT`: PrestaShop Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: PrestaShop 是一个功能强大的开源电商系统，适合中小型电商网站使用。

---

### Shopware ⏳ 未测试

**功能**: Shopware 电商平台，现代化的电商系统。

**Docker 镜像**: `shopware/shopware:latest`

**配置选项**:
- `SHOPWARE_VERSION`: Shopware 版本（默认: latest）
- `SHOPWARE_PORT`: Shopware Web 服务端口（默认: 80）

**测试状态**: ⏳ 未测试

**说明**: Shopware 是一个现代化的电商系统，界面美观，功能完整。

---

## 总结

电商平台分类共包含 **4 个模板**，其中：
- ✅ **已测试通过**: 0 个
- ⏳ **未测试**: 4 个（WooCommerce、Magento、OpenCart、PrestaShop、Shopware）

所有电商平台模板尚未完成测试，主要是由于 Docker Hub 速率限制或镜像访问问题。电商平台通常需要较多资源，建议在资源充足的服务器上部署。

---

*最后更新时间: 2025-11-11*


# 模板市场 - CMS 分类

本文档详细介绍 SSLcat 模板市场中 CMS 分类的所有模板，包括功能说明、Docker 镜像信息和测试状态。

## 测试状态说明

- ✅ **已测试通过**: 模板已完成自动化测试，可以稳定使用
- ⏳ **未测试**: 模板尚未完成测试，可能存在配置问题
- ❌ **测试失败**: 模板测试失败，存在已知问题
- ⚠️ **不可用**: 模板的 Docker 镜像不存在或无法访问

## 传统 CMS

### WordPress ✅ 已测试通过

**功能**: 世界最流行的 CMS 平台，支持博客、网站和在线商店。包含 MySQL 数据库和可选的 Redis 缓存。

**Docker 镜像**: `wordpress:6.4.3`（主服务）、`mysql:8.0`（数据库）

**配置选项**:
- `WORDPRESS_VERSION`: WordPress 版本（默认: 6.4.3，可选: latest, 6.3.2, 6.2.2）
- `MYSQL_VERSION`: MySQL 版本（默认: 8.0，可选: 8.1, 5.7）
- `ENABLE_REDIS_CACHE`: 启用 Redis 缓存（默认: false）
- `WORDPRESS_PORT`: WordPress Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: WordPress 是最流行的 CMS 平台，拥有丰富的主题和插件生态。自动配置 MySQL 数据库，支持 Redis 缓存提升性能。

**安装地址**: `http://{{PRIMARY_DOMAIN}}/wp-admin/install.php`

**默认管理员**: admin / {首次访问时设置}

---

### Drupal ✅ 已测试通过

**功能**: 强大的企业级 CMS 平台，适合构建复杂的内容管理系统。

**Docker 镜像**: `drupal:10.2`（主服务）、`mysql:8.0`（数据库）

**配置选项**:
- `DRUPAL_VERSION`: Drupal 版本（默认: 10.2，可选: latest, 10.1, 9.5）
- `MYSQL_VERSION`: MySQL 版本（默认: 8.0，可选: 8.1, 5.7）
- `DRUPAL_PORT`: Drupal Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: Drupal 是企业级 CMS，适合构建复杂的内容管理系统。功能强大但学习曲线较陡。

**安装地址**: `http://{{PRIMARY_DOMAIN}}/core/install.php`

---

### Ghost ✅ 已测试通过

**功能**: Ghost 现代化的开源发布平台，专注于博客和在线出版物。简洁优雅的编辑体验。

**Docker 镜像**: `ghost:5`（主服务）、`mysql:8.0`（数据库）

**配置选项**:
- `GHOST_VERSION`: Ghost 版本（默认: 5，可选: latest, 4）
- `MYSQL_VERSION`: MySQL 版本（默认: 8.0，可选: 8.1, 5.7）
- `GHOST_PORT`: Ghost Web 服务端口（默认: 8080）

**测试状态**: ✅ 已测试通过

**说明**: Ghost 专注于博客和内容发布，提供现代化的编辑体验和美观的主题。

**管理地址**: `http://{{PRIMARY_DOMAIN}}/ghost`

**设置地址**: `http://{{PRIMARY_DOMAIN}}/ghost/#/setup`

---

## 无头 CMS

### Strapi ✅ 已测试通过

**功能**: 开源无头 CMS，使用 Node.js 和 PostgreSQL，提供强大的内容管理 API。

**Docker 镜像**: `strapi/strapi:latest`（主服务）、`postgres:15`（数据库）

**配置选项**:
- `STRAPI_VERSION`: Strapi 版本（默认: latest，可选: 4.18.4, 4.17.0）
- `POSTGRES_VERSION`: PostgreSQL 版本（默认: 15，可选: 14, 16）
- `STRAPI_PORT`: Strapi API 服务端口（默认: 1337）

**测试状态**: ✅ 已测试通过

**说明**: Strapi 是最流行的无头 CMS 之一，提供强大的内容管理 API 和直观的管理界面。自动生成 JWT Secret、API Token 等安全凭证。

**管理地址**: `http://{{PRIMARY_DOMAIN}}/admin`

**API 地址**: `http://{{PRIMARY_DOMAIN}}/api`

---

### Directus ✅ 已测试通过

**功能**: 开源无头 CMS 和数据平台，提供直观的管理界面和强大的 API。

**Docker 镜像**: `directus/directus:10.8.0`（主服务）、`postgres:15`（数据库）

**配置选项**:
- `DIRECTUS_VERSION`: Directus 版本（默认: 10.8.0，可选: latest, 10.7.0）
- `POSTGRES_VERSION`: PostgreSQL 版本（默认: 15，可选: 14, 16）
- `DIRECTUS_PORT`: Directus Web 服务端口（默认: 8055）

**测试状态**: ✅ 已测试通过

**说明**: Directus 是一个功能强大的无头 CMS，可以将任何 SQL 数据库转换为 RESTful API 和 GraphQL API。

**管理地址**: `http://{{PRIMARY_DOMAIN}}/admin`

**API 地址**: `http://{{PRIMARY_DOMAIN}}/items`

---

## 静态网站生成器

### Hexo ⏳ 未测试

**功能**: Hexo 静态博客框架，基于 Node.js。

**Docker 镜像**: `hexo/hexo:latest`

**配置选项**:
- `HEXO_VERSION`: Hexo 版本（默认: latest）
- `HEXO_PORT`: Hexo Web 服务端口（默认: 4000）

**测试状态**: ⏳ 未测试

**说明**: Hexo 是一个快速、简洁的静态博客框架，适合生成静态网站。

---

### Hugo ⏳ 未测试

**功能**: Hugo 静态网站生成器，速度极快。

**Docker 镜像**: `klakegg/hugo:latest`

**配置选项**:
- `HUGO_VERSION`: Hugo 版本（默认: latest）
- `HUGO_PORT`: Hugo Web 服务端口（默认: 1313）

**测试状态**: ⏳ 未测试

**说明**: Hugo 是最快的静态网站生成器之一，适合生成博客、文档网站等。

---

### Nuxt.js ⏳ 未测试

**功能**: Nuxt.js Vue.js 框架，用于构建服务端渲染应用。

**Docker 镜像**: `node:18-alpine`

**配置选项**:
- `NUXT_VERSION`: Nuxt.js 版本（默认: latest）
- `NUXT_PORT`: Nuxt.js Web 服务端口（默认: 3000）

**测试状态**: ⏳ 未测试

**说明**: Nuxt.js 是基于 Vue.js 的框架，支持服务端渲染和静态生成。

---

### Gatsby ⏳ 未测试

**功能**: Gatsby React 静态网站生成器，适合构建高性能网站。

**Docker 镜像**: `node:18-alpine`

**配置选项**:
- `GATSBY_VERSION`: Gatsby 版本（默认: latest）
- `GATSBY_PORT`: Gatsby Web 服务端口（默认: 8000）

**测试状态**: ⏳ 未测试

**说明**: Gatsby 是基于 React 的静态网站生成器，适合构建高性能的现代网站。

---

### Docusaurus ⏳ 未测试

**功能**: Docusaurus 文档网站生成器，专为文档网站设计。

**Docker 镜像**: `node:18-alpine`

**配置选项**:
- `DOCUSAURUS_VERSION`: Docusaurus 版本（默认: latest）
- `DOCUSAURUS_PORT`: Docusaurus Web 服务端口（默认: 3000）

**测试状态**: ⏳ 未测试

**说明**: Docusaurus 是 Facebook 开发的文档网站生成器，适合构建技术文档网站。

---

## 其他 CMS

### Wagtail ⏳ 未测试

**功能**: Wagtail Django CMS，适合构建内容驱动的网站。

**Docker 镜像**: `wagtail/wagtail:latest`

**配置选项**:
- `WAGTAIL_VERSION`: Wagtail 版本（默认: latest）
- `WAGTAIL_PORT`: Wagtail Web 服务端口（默认: 8000）

**测试状态**: ⏳ 未测试

**说明**: Wagtail 是基于 Django 的 CMS，适合构建内容驱动的网站。

---

### Plume ⏳ 未测试

**功能**: Plume 博客平台，去中心化的博客系统。

**Docker 镜像**: `plume/plume:latest`

**配置选项**:
- `PLUME_VERSION`: Plume 版本（默认: latest）
- `PLUME_PORT`: Plume Web 服务端口（默认: 7878）

**测试状态**: ⏳ 未测试

**说明**: Plume 是一个去中心化的博客平台，支持 ActivityPub 协议。

---

### Keystone ⏳ 未测试

**功能**: Keystone Node.js CMS，提供强大的内容管理功能。

**Docker 镜像**: `keystonejs/keystone:latest`

**配置选项**:
- `KEYSTONE_VERSION`: Keystone 版本（默认: latest）
- `KEYSTONE_PORT`: Keystone Web 服务端口（默认: 3000）

**测试状态**: ⏳ 未测试

**说明**: Keystone 是基于 Node.js 的 CMS，提供强大的内容管理功能。

---

## 总结

CMS 分类共包含 **12 个模板**，其中：
- ✅ **已测试通过**: 5 个（WordPress、Drupal、Ghost、Strapi、Directus）
- ⏳ **未测试**: 7 个（Hexo、Hugo、Nuxt.js、Gatsby、Docusaurus、Wagtail、Plume、Keystone）

传统 CMS（WordPress、Drupal、Ghost）和无头 CMS（Strapi、Directus）都已测试通过，可以稳定使用。静态网站生成器类模板尚未完成测试。

---

*最后更新时间: 2025-11-11*


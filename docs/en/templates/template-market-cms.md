# Template Marketplace - CMS Category

This document provides detailed information about all templates in the CMS category of the SSLcat template marketplace, including function descriptions, Docker image information, and test status.

## Test Status Legend

- ✅ **Tested and Passed**: Template has completed automated testing and can be used stably
- ⏳ **Not Tested**: Template has not completed testing, may have configuration issues
- ❌ **Test Failed**: Template test failed, has known issues
- ⚠️ **Unavailable**: Template's Docker image does not exist or cannot be accessed

## Traditional CMS

### WordPress ✅ Tested and Passed

**Function**: The world's most popular CMS platform, supports blogs, websites, and online stores. Includes MySQL database and optional Redis cache.

**Docker Image**: `wordpress:6.4.3` (main service), `mysql:8.0` (database)

**Configuration Options**:
- `WORDPRESS_VERSION`: WordPress version (default: 6.4.3, optional: latest, 6.3.2, 6.2.2)
- `MYSQL_VERSION`: MySQL version (default: 8.0, optional: 8.1, 5.7)
- `ENABLE_REDIS_CACHE`: Enable Redis cache (default: false)
- `WORDPRESS_PORT`: WordPress web service port (default: 8080)

**Test Status**: ✅ Tested and Passed

**Description**: WordPress is the most popular CMS platform with a rich theme and plugin ecosystem. Automatically configures MySQL database, supports Redis cache to improve performance.

**Installation URL**: `http://{{PRIMARY_DOMAIN}}/wp-admin/install.php`

**Default Admin**: admin / {set on first visit}

---

### Drupal ✅ Tested and Passed

**Function**: Powerful enterprise-level CMS platform, suitable for building complex content management systems.

**Docker Image**: `drupal:10.2` (main service), `mysql:8.0` (database)

**Configuration Options**:
- `DRUPAL_VERSION`: Drupal version (default: 10.2, optional: latest, 10.1, 9.5)
- `MYSQL_VERSION`: MySQL version (default: 8.0, optional: 8.1, 5.7)
- `DRUPAL_PORT`: Drupal web service port (default: 8080)

**Test Status**: ✅ Tested and Passed

**Description**: Drupal is an enterprise-level CMS suitable for building complex content management systems. Powerful but has a steeper learning curve.

**Installation URL**: `http://{{PRIMARY_DOMAIN}}/core/install.php`

---

### Ghost ✅ Tested and Passed

**Function**: Ghost modern open-source publishing platform, focused on blogs and online publications. Clean and elegant editing experience.

**Docker Image**: `ghost:5` (main service), `mysql:8.0` (database)

**Configuration Options**:
- `GHOST_VERSION`: Ghost version (default: 5, optional: latest, 4)
- `MYSQL_VERSION`: MySQL version (default: 8.0, optional: 8.1, 5.7)
- `GHOST_PORT`: Ghost web service port (default: 8080)

**Test Status**: ✅ Tested and Passed

**Description**: Ghost focuses on blogs and content publishing, providing a modern editing experience and beautiful themes.

**Admin URL**: `http://{{PRIMARY_DOMAIN}}/ghost`

**Setup URL**: `http://{{PRIMARY_DOMAIN}}/ghost/#/setup`

---

## Headless CMS

### Strapi ✅ Tested and Passed

**Function**: Open-source headless CMS, uses Node.js and PostgreSQL, provides powerful content management API.

**Docker Image**: `strapi/strapi:latest` (main service), `postgres:15` (database)

**Configuration Options**:
- `STRAPI_VERSION`: Strapi version (default: latest, optional: 4.18.4, 4.17.0)
- `POSTGRES_VERSION`: PostgreSQL version (default: 15, optional: 14, 16)
- `STRAPI_PORT`: Strapi API service port (default: 1337)

**Test Status**: ✅ Tested and Passed

**Description**: Strapi is one of the most popular headless CMS platforms, providing powerful content management API and intuitive admin interface. Automatically generates JWT Secret, API Token, and other security credentials.

**Admin URL**: `http://{{PRIMARY_DOMAIN}}/admin`

**API URL**: `http://{{PRIMARY_DOMAIN}}/api`

---

### Directus ✅ Tested and Passed

**Function**: Open-source headless CMS and data platform, provides intuitive admin interface and powerful API.

**Docker Image**: `directus/directus:10.8.0` (main service), `postgres:15` (database)

**Configuration Options**:
- `DIRECTUS_VERSION`: Directus version (default: 10.8.0, optional: latest, 10.7.0)
- `POSTGRES_VERSION`: PostgreSQL version (default: 15, optional: 14, 16)
- `DIRECTUS_PORT`: Directus web service port (default: 8055)

**Test Status**: ✅ Tested and Passed

**Description**: Directus is a powerful headless CMS that can convert any SQL database into RESTful API and GraphQL API.

**Admin URL**: `http://{{PRIMARY_DOMAIN}}/admin`

**API URL**: `http://{{PRIMARY_DOMAIN}}/items`

---

## Static Site Generators

### Hexo ⏳ Not Tested

**Function**: Hexo static blog framework, based on Node.js.

**Docker Image**: `hexo/hexo:latest`

**Configuration Options**:
- `HEXO_VERSION`: Hexo version (default: latest)
- `HEXO_PORT`: Hexo web service port (default: 4000)

**Test Status**: ⏳ Not Tested

**Description**: Hexo is a fast and concise static blog framework, suitable for generating static websites.

---

### Hugo ⏳ Not Tested

**Function**: Hugo static site generator, extremely fast.

**Docker Image**: `klakegg/hugo:latest`

**Configuration Options**:
- `HUGO_VERSION`: Hugo version (default: latest)
- `HUGO_PORT`: Hugo web service port (default: 1313)

**Test Status**: ⏳ Not Tested

**Description**: Hugo is one of the fastest static site generators, suitable for generating blogs, documentation websites, etc.

---

### Nuxt.js ⏳ Not Tested

**Function**: Nuxt.js Vue.js framework for building server-side rendered applications.

**Docker Image**: `node:18-alpine`

**Configuration Options**:
- `NUXT_VERSION`: Nuxt.js version (default: latest)
- `NUXT_PORT`: Nuxt.js web service port (default: 3000)

**Test Status**: ⏳ Not Tested

**Description**: Nuxt.js is a Vue.js-based framework that supports server-side rendering and static generation.

---

### Gatsby ⏳ Not Tested

**Function**: Gatsby React static site generator, suitable for building high-performance websites.

**Docker Image**: `node:18-alpine`

**Configuration Options**:
- `GATSBY_VERSION`: Gatsby version (default: latest)
- `GATSBY_PORT`: Gatsby web service port (default: 8000)

**Test Status**: ⏳ Not Tested

**Description**: Gatsby is a React-based static site generator, suitable for building high-performance modern websites.

---

### Docusaurus ⏳ Not Tested

**Function**: Docusaurus documentation website generator, designed specifically for documentation websites.

**Docker Image**: `node:18-alpine`

**Configuration Options**:
- `DOCUSAURUS_VERSION`: Docusaurus version (default: latest)
- `DOCUSAURUS_PORT`: Docusaurus web service port (default: 3000)

**Test Status**: ⏳ Not Tested

**Description**: Docusaurus is a documentation website generator developed by Facebook, suitable for building technical documentation websites.

---

## Other CMS

### Wagtail ⏳ Not Tested

**Function**: Wagtail Django CMS, suitable for building content-driven websites.

**Docker Image**: `wagtail/wagtail:latest`

**Configuration Options**:
- `WAGTAIL_VERSION`: Wagtail version (default: latest)
- `WAGTAIL_PORT`: Wagtail web service port (default: 8000)

**Test Status**: ⏳ Not Tested

**Description**: Wagtail is a Django-based CMS suitable for building content-driven websites.

---

### Plume ⏳ Not Tested

**Function**: Plume blog platform, decentralized blog system.

**Docker Image**: `plume/plume:latest`

**Configuration Options**:
- `PLUME_VERSION`: Plume version (default: latest)
- `PLUME_PORT`: Plume web service port (default: 7878)

**Test Status**: ⏳ Not Tested

**Description**: Plume is a decentralized blog platform that supports the ActivityPub protocol.

---

### Keystone ⏳ Not Tested

**Function**: Keystone Node.js CMS, provides powerful content management features.

**Docker Image**: `keystonejs/keystone:latest`

**Configuration Options**:
- `KEYSTONE_VERSION`: Keystone version (default: latest)
- `KEYSTONE_PORT`: Keystone web service port (default: 3000)

**Test Status**: ⏳ Not Tested

**Description**: Keystone is a Node.js-based CMS that provides powerful content management features.

---

## Summary

The CMS category contains **12 templates**, of which:
- ✅ **Tested and Passed**: 5 templates (WordPress, Drupal, Ghost, Strapi, Directus)
- ⏳ **Not Tested**: 7 templates (Hexo, Hugo, Nuxt.js, Gatsby, Docusaurus, Wagtail, Plume, Keystone)

Traditional CMS (WordPress, Drupal, Ghost) and headless CMS (Strapi, Directus) have all been tested and passed, and can be used stably. Static site generator templates have not completed testing.

---

*Last updated: 2025-11-11*

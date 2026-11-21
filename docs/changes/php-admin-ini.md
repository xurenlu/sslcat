# PHP 站点级指令

发布单元：SSLcat。类型：Added / Security。此片段不分配发布版本。

- PHP 站点 API 和编辑页面支持 `php_admin_ini`，经白名单校验后转换为 FastCGI `PHP_ADMIN_VALUE`。
- 规范化指令名并拒绝重复指令、CR/LF/NUL，避免解析歧义与多指令注入。
- 原始 `vars` 中的 `PHP_VALUE` 和 `PHP_ADMIN_VALUE` 不再透传，指令须迁移到 `php_admin_ini`。
- 页面只允许选择支持的指令，避免生成无效键名或重命名覆盖已有值；移除未经核实的 CVE 缓解预设。

兼容影响和故障行为见 [PHP 站点级指令](../configuration/php-admin-ini.md)。真实 PHP-FPM 验证需单独提供测试端点；默认单测不会启动服务或容器。
